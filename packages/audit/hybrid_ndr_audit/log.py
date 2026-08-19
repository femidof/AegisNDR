from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping


class AuditIntegrityError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("audit timestamps must be ISO-8601 with a timezone") from exc


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_metadata(value: Any, path: str = "$") -> None:
    """Restrict audit metadata to string-keyed, JSON-primitive values so the
    stored canonical form always round-trips byte-identically through verify().
    Non-string keys or non-finite floats would serialize and re-parse
    differently, producing false-positive integrity failures on valid chains."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"audit metadata key {path} must be a string")
            _validate_metadata(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_metadata(child, f"{path}[{index}]")
    elif isinstance(value, tuple):
        raise ValueError(f"audit metadata {path} must be a JSON array")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"audit metadata {path} must be a finite number")
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError(f"audit metadata {path} must be a JSON value")


class AuditLog:
    """SQLite audit log protected from update/delete and linked by SHA-256 hashes."""

    def __init__(self, database: str | sqlite3.Connection) -> None:
        self._owns_connection = isinstance(database, str)
        if isinstance(database, str):
            self.connection = sqlite3.connect(database, check_same_thread=False)
        else:
            self.connection = database
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._migrate()

    def _migrate(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT NOT NULL UNIQUE,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                global_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS audit_tenant_sequence
                ON audit_events (tenant_id, deployment_id, sequence DESC);
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END;
            """
        )
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(audit_events)")}
        if "global_hash" not in columns:
            self.connection.execute("ALTER TABLE audit_events ADD COLUMN global_hash TEXT")
        # Backfill the cross-scope chain deterministically from the stored
        # record hashes so upgraded volumes keep a verifiable global chain.
        pending = self.connection.execute(
            "SELECT sequence, record_hash FROM audit_events "
            "WHERE global_hash IS NULL ORDER BY sequence ASC"
        ).fetchall()
        previous_global = "0" * 64
        for sequence, record_hash in pending:
            previous_global = hashlib.sha256(
                (previous_global + record_hash).encode("utf-8")
            ).hexdigest()
            self.connection.execute(
                "UPDATE audit_events SET global_hash = ? WHERE sequence = ?",
                (previous_global, sequence),
            )
        self.connection.commit()

    def append(
        self,
        *,
        tenant_id: str,
        deployment_id: str,
        actor_id: str,
        actor_type: str,
        action: str,
        resource_type: str,
        resource_id: str,
        request_id: str | None = None,
        result: str = "success",
        metadata: Mapping[str, Any] | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        if actor_type not in {"human", "service", "system"}:
            raise ValueError("actor_type must be human, service, or system")
        if result not in {"success", "failure", "denied"}:
            raise ValueError("result must be success, failure, or denied")
        metadata = dict(metadata or {})
        _validate_metadata(metadata)
        created_at = created_at or _utc_now()
        parsed_created_at = _parse_timestamp(created_at)
        record = {
            "audit_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "actor_id": actor_id,
            "actor_type": actor_type,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "request_id": request_id or str(uuid.uuid4()),
            "result": result,
            "created_at": created_at,
            "metadata": metadata,
        }
        with self._lock:
            previous = self.connection.execute(
                """SELECT record_hash, created_at FROM audit_events
                   WHERE tenant_id = ? AND deployment_id = ?
                   ORDER BY sequence DESC LIMIT 1""",
                (tenant_id, deployment_id),
            ).fetchone()
            previous_hash = previous["record_hash"] if previous else "0" * 64
            if previous is not None and parsed_created_at < _parse_timestamp(previous["created_at"]):
                raise ValueError("audit created_at must not backdate the scope chain")
            record_hash = hashlib.sha256((previous_hash + _canonical(record)).encode("utf-8")).hexdigest()
            global_previous = self.connection.execute(
                """SELECT global_hash FROM audit_events
                   WHERE global_hash IS NOT NULL ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            previous_global = global_previous["global_hash"] if global_previous else "0" * 64
            global_hash = hashlib.sha256(
                (previous_global + record_hash).encode("utf-8")
            ).hexdigest()
            self.connection.execute(
                """INSERT INTO audit_events (
                       audit_id, tenant_id, deployment_id, actor_id, actor_type, action,
                       resource_type, resource_id, request_id, result, created_at,
                       metadata_json, previous_hash, record_hash, global_hash
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["audit_id"],
                    tenant_id,
                    deployment_id,
                    actor_id,
                    actor_type,
                    action,
                    resource_type,
                    resource_id,
                    record["request_id"],
                    result,
                    record["created_at"],
                    _canonical(record["metadata"]),
                    previous_hash,
                    record_hash,
                    global_hash,
                ),
            )
            self.connection.commit()
        return {**record, "previous_hash": previous_hash, "record_hash": record_hash, "global_hash": global_hash}

    def list(self, tenant_id: str, deployment_id: str | None = None, *, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        sql = "SELECT * FROM audit_events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        sql += " ORDER BY sequence DESC LIMIT ?"
        params.append(limit)
        rows = self.connection.execute(sql, params).fetchall()
        return [self._row(row) for row in rows]

    def verify(self, tenant_id: str, deployment_id: str) -> bool:
        rows = self.connection.execute(
            """SELECT * FROM audit_events WHERE tenant_id = ? AND deployment_id = ?
               ORDER BY sequence ASC""",
            (tenant_id, deployment_id),
        ).fetchall()
        previous_hash = "0" * 64
        for row in rows:
            record = self._row(row)
            payload = {
                key: record[key]
                for key in (
                    "audit_id",
                    "tenant_id",
                    "deployment_id",
                    "actor_id",
                    "actor_type",
                    "action",
                    "resource_type",
                    "resource_id",
                    "request_id",
                    "result",
                    "created_at",
                    "metadata",
                )
            }
            expected = hashlib.sha256((previous_hash + _canonical(payload)).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["record_hash"] != expected:
                raise AuditIntegrityError(f"audit chain failed at {row['audit_id']}")
            previous_hash = row["record_hash"]
        return True

    def verify_global(self) -> bool:
        """Verify the cross-scope chain that links every scope together.

        Per-scope chains let an attacker with write access delete an entire
        scope's rows without breaking any *other* scope's local chain. The
        global chain hashes each record into one sequence-wide digest, so any
        whole-scope deletion breaks the link for every subsequent record.
        """
        rows = self.connection.execute(
            "SELECT audit_id, record_hash, global_hash FROM audit_events ORDER BY sequence ASC"
        ).fetchall()
        previous_global = "0" * 64
        for row in rows:
            if row["global_hash"] is None:
                raise AuditIntegrityError(f"audit global chain is incomplete at {row['audit_id']}")
            expected = hashlib.sha256(
                (previous_global + row["record_hash"]).encode("utf-8")
            ).hexdigest()
            if row["global_hash"] != expected:
                raise AuditIntegrityError(f"audit global chain failed at {row['audit_id']}")
            previous_global = row["global_hash"]
        return True

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "audit_id": row["audit_id"],
            "tenant_id": row["tenant_id"],
            "deployment_id": row["deployment_id"],
            "actor_id": row["actor_id"],
            "actor_type": row["actor_type"],
            "action": row["action"],
            "resource_type": row["resource_type"],
            "resource_id": row["resource_id"],
            "request_id": row["request_id"],
            "result": row["result"],
            "created_at": row["created_at"],
            "metadata": json.loads(row["metadata_json"]),
            "previous_hash": row["previous_hash"],
            "record_hash": row["record_hash"],
            "global_hash": row["global_hash"],
        }

    def close(self) -> None:
        if self._owns_connection:
            self.connection.close()
