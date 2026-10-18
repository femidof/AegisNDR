from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from hybrid_ndr_audit import AuditLog
from hybrid_ndr_contracts import Alert, DetectionResult, NormalizedEvent, canonical_json, utc_now

from .administration import (
    default_detection_rules,
    normalize_detection_rule,
    normalize_integration,
    normalize_suppression,
    normalize_system_settings,
    public_integration,
    suppression_matches,
)


class NotFoundError(LookupError):
    pass


def _row_json(row: sqlite3.Row, column: str = "payload_json") -> dict[str, Any]:
    return json.loads(row[column])


def validate_export_document(document: Mapping[str, Any], export_id: str, evidence_ids: Iterable[str]) -> None:
    """Verify an evidence-export approval document against the export request.

    An approver supplies the document; without this check they could approve
    arbitrary content. The document must be the evidence-export schema, must
    name the export being approved, and must carry exactly the evidence
    identifiers the export request asked for.
    """
    if not isinstance(document, Mapping):
        raise ValueError("approval document must be an object")
    if document.get("schema_version") != "hybrid-ndr-evidence-export/v1":
        raise ValueError("approval document has an unsupported schema version")
    if str(document.get("export_id", "")) != export_id:
        raise ValueError("approval document does not match the evidence export")
    evidence = document.get("evidence")
    if not isinstance(evidence, list):
        raise ValueError("approval document must contain an evidence list")
    documented = {
        str(item.get("event_id", ""))
        for item in evidence
        if isinstance(item, Mapping) and item.get("event_id")
    }
    requested = set(evidence_ids)
    if documented != requested or len(evidence) != len(requested):
        raise ValueError("approval document must contain exactly the requested evidence identifiers")


class LocalStore:
    """Transactional local product state; every read takes an explicit tenant ID.

    The SQLite connection is shared across the WSGI worker and the detection
    service. Writes and reads are serialized by the store-wide RLock below; WAL
    mode plus a busy timeout make that serialization safe under concurrent
    threads, and `synchronous=NORMAL` keeps checkpoint stalls off the request
    path. The demo/profile stores never serve multi-process traffic, so a
    single in-process connection is sufficient.
    """

    def __init__(self, database: str | Path = ":memory:") -> None:
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database, check_same_thread=False, timeout=10.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA busy_timeout = 10000")
        self._lock = threading.RLock()
        self._migrate()
        self.audit = AuditLog(self.connection)

    def _migrate(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS response_records (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, kind, record_id)
            );
            CREATE INDEX IF NOT EXISTS response_records_work
                ON response_records (tenant_id, deployment_id, kind, state, updated_at);
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                event_time TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_tenant_time
                ON events (tenant_id, deployment_id, event_time DESC);
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                tenant_id UNINDEXED,
                deployment_id UNINDEXED,
                payload,
                tokenize = 'unicode61'
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS alerts_tenant_created
                ON alerts (tenant_id, deployment_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                status TEXT NOT NULL,
                response_json TEXT,
                error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
            );
            CREATE INDEX IF NOT EXISTS investigations_tenant_created
                ON investigations (tenant_id, deployment_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS model_transmissions (
                transmission_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                investigation_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                retention_mode TEXT NOT NULL,
                region TEXT NOT NULL,
                fields_included_json TEXT NOT NULL,
                fields_removed_json TEXT NOT NULL,
                fields_tokenized_json TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                response_hash TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                result TEXT NOT NULL,
                error_code TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(investigation_id)
            );
            CREATE INDEX IF NOT EXISTS transmissions_tenant_created
                ON model_transmissions (tenant_id, deployment_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                assignee TEXT NOT NULL,
                alert_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_comments (
                comment_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS sensors (
                sensor_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                sensor_type TEXT NOT NULL,
                status TEXT NOT NULL,
                events_per_second REAL NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_policies (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                level TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                region TEXT NOT NULL,
                retention_mode TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id)
            );
            CREATE TABLE IF NOT EXISTS entity_baselines (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                baseline_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, entity_id)
            );
            CREATE TABLE IF NOT EXISTS detection_rules (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, rule_id)
            );
            CREATE TABLE IF NOT EXISTS detection_suppressions (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                suppression_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, suppression_id)
            );
            CREATE TABLE IF NOT EXISTS integrations (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                integration_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                secret_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, integration_id)
            );
            CREATE TABLE IF NOT EXISTS system_settings (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id)
            );
            CREATE TABLE IF NOT EXISTS evidence_exports (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                export_id TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                export_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, export_id)
            );
            CREATE TABLE IF NOT EXISTS support_bundles (
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                bundle_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, deployment_id, bundle_id)
            );
            """
        )
        # Keep the FTS index in sync with pre-existing rows (upgrades) and any
        # rows inserted outside the store API.
        self.connection.execute(
            """INSERT OR IGNORE INTO events_fts (rowid, tenant_id, deployment_id, payload)
               SELECT rowid, tenant_id, deployment_id, payload_json FROM events"""
        )
        self.connection.commit()

    def insert_event(self, event: NormalizedEvent | Mapping[str, Any]) -> dict[str, Any]:
        item = event if isinstance(event, NormalizedEvent) else NormalizedEvent.from_dict(event)
        payload = item.to_dict()
        with self._lock:
            self.connection.execute(
                """INSERT OR IGNORE INTO events
                   (event_id, tenant_id, deployment_id, event_time, event_type, source, src_ip, dst_ip, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    item.event_id,
                    item.tenant_id,
                    item.deployment_id,
                    item.event_time,
                    item.event_type,
                    item.source,
                    item.src_ip,
                    item.dst_ip,
                    canonical_json(payload),
                ),
            )
            rowid = self.connection.execute(
                "SELECT rowid FROM events WHERE event_id = ?", (item.event_id,)
            ).fetchone()
            if rowid is not None:
                self.connection.execute(
                    """INSERT OR IGNORE INTO events_fts (rowid, tenant_id, deployment_id, payload)
                       VALUES (?, ?, ?, ?)""",
                    (int(rowid[0]), item.tenant_id, item.deployment_id, canonical_json(payload)),
                )
            self.connection.commit()
        return payload

    def insert_events(self, events: Iterable[NormalizedEvent | Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [self.insert_event(event) for event in events]

    def search_events(
        self,
        tenant_id: str,
        *,
        deployment_id: str | None = None,
        event_type: str | None = None,
        entity_id: str | None = None,
        source: str | None = None,
        query_text: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        protocol: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        sensor_id: str | None = None,
        event_id: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT payload_json FROM events WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        for clause, value in (
            ("deployment_id = ?", deployment_id),
            ("event_type = ?", event_type),
            ("source = ?", source),
        ):
            if value:
                # Clause texts are module-local literals; values are always
                # bound parameters, never interpolated.
                sql += " AND " + clause
                params.append(value)
        if entity_id:
            sql += " AND (src_ip = ? OR dst_ip = ?)"
            params.extend([entity_id, entity_id])
        for clause, value in (
            ("event_time >= ?", start_time), ("event_time <= ?", end_time),
            ("src_ip = ?", src_ip), ("dst_ip = ?", dst_ip), ("event_id = ?", event_id),
        ):
            if value:
                sql += f" AND {clause}"
                params.append(value)
        if query_text:
            tokens = [token for token in re.split(r"[^A-Za-z0-9]+", query_text) if token][:20]
            if tokens:
                # Indexed payload search through the FTS5 mirror table instead
                # of a full-table LIKE scan over payload_json.
                fts_query = " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)
                sql += """ AND EXISTS (
                    SELECT 1 FROM events_fts
                    WHERE events_fts.rowid = events.rowid
                      AND events_fts.tenant_id = events.tenant_id
                      AND events_fts MATCH ?
                )"""
                params.append(fts_query)
        if protocol:
            sql += " AND LOWER(json_extract(payload_json, '$.protocol')) = ?"
            params.append(protocol.lower())
        if sensor_id:
            sql += " AND json_extract(payload_json, '$.sensor_id') = ?"
            params.append(sensor_id)
        sql += " ORDER BY event_time DESC LIMIT ? OFFSET ?"
        params.append(max(1, min(int(limit), 1000)))
        params.append(max(0, min(int(offset), 100_000)))
        return [_row_json(row) for row in self.connection.execute(sql, params).fetchall()]

    def get_events(
        self, tenant_id: str, evidence_ids: Iterable[str], *, deployment_id: str | None = None
    ) -> list[dict[str, Any]]:
        ids = list(dict.fromkeys(evidence_ids))[:100]
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        sql = f"SELECT payload_json FROM events WHERE tenant_id = ? AND event_id IN ({placeholders})"
        params: list[Any] = [tenant_id, *ids]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        rows = self.connection.execute(sql, params).fetchall()
        by_id = {json.loads(row["payload_json"])["event_id"]: json.loads(row["payload_json"]) for row in rows}
        return [by_id[item] for item in ids if item in by_id]

    def save_alert(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        *,
        alert_id: str | None = None,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        alert = Alert(
            alert_id=alert_id or str(uuid.uuid4()),
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            created_at=created_at or utc_now(),
            detector_id=detection.detector_id,
            title=detection.title,
            severity=detection.severity,
            status="open",
            entity_type=detection.entity_type,
            entity_id=detection.entity_id,
            score=detection.score,
            evidence_ids=detection.evidence_ids,
            baseline=detection.baseline_values,
            features=detection.feature_values,
        )
        return self.put_alert(alert)

    def put_alert(self, alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
        item = alert if isinstance(alert, Alert) else Alert.from_dict(alert)
        payload = item.to_dict()
        with self._lock:
            self.connection.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, tenant_id, deployment_id, created_at, severity, status, entity_id, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    item.alert_id,
                    item.tenant_id,
                    item.deployment_id,
                    item.created_at,
                    item.severity,
                    item.status,
                    item.entity_id,
                    canonical_json(payload),
                ),
            )
            self.connection.commit()
        return payload

    def list_alerts(
        self,
        tenant_id: str,
        *,
        deployment_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT payload_json FROM alerts WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        for clause, value in (("deployment_id = ?", deployment_id), ("status = ?", status), ("severity = ?", severity)):
            if value:
                sql += f" AND {clause}"
                params.append(value)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        return [_row_json(row) for row in self.connection.execute(sql, params).fetchall()]

    def get_alert(
        self, tenant_id: str, alert_id: str, *, deployment_id: str | None = None
    ) -> dict[str, Any]:
        sql = "SELECT payload_json FROM alerts WHERE tenant_id = ? AND alert_id = ?"
        params: list[Any] = [tenant_id, alert_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        row = self.connection.execute(sql, params).fetchone()
        if not row:
            raise NotFoundError("alert not found")
        return _row_json(row)

    def update_alert(
        self,
        tenant_id: str,
        alert_id: str,
        changes: Mapping[str, Any],
        *,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        alert = self.get_alert(tenant_id, alert_id, deployment_id=deployment_id)
        allowed = {"status", "severity"}
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"unsupported alert fields: {sorted(unknown)}")
        alert.update(changes)
        validated = Alert.from_dict(alert)
        return self.put_alert(validated)

    def create_investigation(
        self, tenant_id: str, deployment_id: str, alert_id: str, *, investigation_id: str | None = None
    ) -> dict[str, Any]:
        now = utc_now()
        record = {
            "investigation_id": investigation_id or str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "alert_id": alert_id,
            "status": "running",
            "assessment": None,
            "error_code": None,
            "created_at": now,
            "updated_at": now,
        }
        # The alert-existence check and the insert run under one lock so a
        # concurrently removed alert cannot leave an orphaned investigation.
        with self._lock:
            exists = self.connection.execute(
                "SELECT 1 FROM alerts WHERE tenant_id = ? AND deployment_id = ? AND alert_id = ?",
                (tenant_id, deployment_id, alert_id),
            ).fetchone()
            if not exists:
                raise NotFoundError("alert not found")
            self.connection.execute(
                """INSERT INTO investigations
                   (investigation_id, tenant_id, deployment_id, alert_id, status, response_json, error_code, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
                (record["investigation_id"], tenant_id, deployment_id, alert_id, "running", now, now),
            )
            self.connection.commit()
        return record

    def finish_investigation(
        self,
        tenant_id: str,
        investigation_id: str,
        *,
        status: str,
        assessment: Mapping[str, Any] | None = None,
        error_code: str | None = None,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        if status not in {"completed", "failed", "unavailable", "rejected"}:
            raise ValueError("invalid terminal investigation status")
        sql = """UPDATE investigations SET status = ?, response_json = ?, error_code = ?, updated_at = ?
               WHERE tenant_id = ? AND investigation_id = ?"""
        params: list[Any] = [
            status, canonical_json(assessment) if assessment else None, error_code, utc_now(), tenant_id, investigation_id,
        ]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        cursor = self.connection.execute(
            sql, params,
        )
        if cursor.rowcount != 1:
            raise NotFoundError("investigation not found")
        self.connection.commit()
        return self.get_investigation(tenant_id, investigation_id, deployment_id=deployment_id)

    def get_investigation(
        self, tenant_id: str, investigation_id: str, *, deployment_id: str | None = None
    ) -> dict[str, Any]:
        sql = "SELECT * FROM investigations WHERE tenant_id = ? AND investigation_id = ?"
        params: list[Any] = [tenant_id, investigation_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        row = self.connection.execute(sql, params).fetchone()
        if not row:
            raise NotFoundError("investigation not found")
        return self._investigation_row(row)

    def list_investigations(
        self, tenant_id: str, *, deployment_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM investigations WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        return [self._investigation_row(row) for row in self.connection.execute(sql, params).fetchall()]

    @staticmethod
    def _investigation_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "investigation_id": row["investigation_id"],
            "tenant_id": row["tenant_id"],
            "deployment_id": row["deployment_id"],
            "alert_id": row["alert_id"],
            "status": row["status"],
            "assessment": json.loads(row["response_json"]) if row["response_json"] else None,
            "error_code": row["error_code"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def save_transmission(self, record: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "request_id",
            "investigation_id",
            "alert_id",
            "tenant_id",
            "deployment_id",
            "actor_id",
            "provider",
            "model",
            "retention_mode",
            "region",
            "fields_included",
            "fields_removed",
            "fields_tokenized",
            "prompt_hash",
            "response_hash",
            "input_tokens",
            "output_tokens",
            "latency_ms",
            "result",
            "payload",
        }
        missing = required - set(record)
        if missing:
            raise ValueError(f"missing transmission fields: {sorted(missing)}")
        item = dict(record)
        item.setdefault("transmission_id", str(uuid.uuid4()))
        item.setdefault("created_at", utc_now())
        item.setdefault("error_code", None)
        self.connection.execute(
            """INSERT INTO model_transmissions (
                   transmission_id, request_id, investigation_id, alert_id, tenant_id, deployment_id,
                   actor_id, provider, model, retention_mode, region, fields_included_json,
                   fields_removed_json, fields_tokenized_json, prompt_hash, response_hash,
                   input_tokens, output_tokens, latency_ms, result, error_code, payload_json, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                item["transmission_id"], item["request_id"], item["investigation_id"], item["alert_id"],
                item["tenant_id"], item["deployment_id"], item["actor_id"], item["provider"], item["model"],
                item["retention_mode"], item["region"], canonical_json(item["fields_included"]),
                canonical_json(item["fields_removed"]), canonical_json(item["fields_tokenized"]),
                item["prompt_hash"], item["response_hash"], int(item["input_tokens"]), int(item["output_tokens"]),
                int(item["latency_ms"]), item["result"], item["error_code"], canonical_json(item["payload"]), item["created_at"],
            ),
        )
        self.connection.commit()
        return item

    def get_transmission(
        self, tenant_id: str, investigation_id: str, *, deployment_id: str | None = None
    ) -> dict[str, Any]:
        sql = """SELECT * FROM model_transmissions
               WHERE tenant_id = ? AND investigation_id = ?"""
        params: list[Any] = [tenant_id, investigation_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        sql += " ORDER BY created_at DESC LIMIT 1"
        row = self.connection.execute(sql, params).fetchone()
        if not row:
            raise NotFoundError("transmission not found")
        return self._transmission_row(row)

    def list_transmissions(self, tenant_id: str, *, deployment_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM model_transmissions WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        return [self._transmission_row(row) for row in self.connection.execute(sql, params).fetchall()]

    @staticmethod
    def _transmission_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "transmission_id": row["transmission_id"],
            "request_id": row["request_id"],
            "investigation_id": row["investigation_id"],
            "alert_id": row["alert_id"],
            "tenant_id": row["tenant_id"],
            "deployment_id": row["deployment_id"],
            "actor_id": row["actor_id"],
            "provider": row["provider"],
            "model": row["model"],
            "retention_mode": row["retention_mode"],
            "region": row["region"],
            "fields_included": json.loads(row["fields_included_json"]),
            "fields_removed": json.loads(row["fields_removed_json"]),
            "fields_tokenized": json.loads(row["fields_tokenized_json"]),
            "prompt_hash": row["prompt_hash"],
            "response_hash": row["response_hash"],
            "input_tokens": row["input_tokens"],
            "output_tokens": row["output_tokens"],
            "latency_ms": row["latency_ms"],
            "result": row["result"],
            "error_code": row["error_code"],
            "payload": json.loads(row["payload_json"]),
            "created_at": row["created_at"],
        }

    def create_case(self, tenant_id: str, deployment_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        title = str(value.get("title", "")).strip()
        if not title:
            raise ValueError("case title is required")
        now = utc_now()
        item = {
            "case_id": str(value.get("case_id") or uuid.uuid4()),
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "title": title[:200],
            "status": str(value.get("status", "open")),
            "priority": str(value.get("priority", "medium")),
            "assignee": str(value.get("assignee", ""))[:200],
            "alert_ids": list(value.get("alert_ids", [])),
            "created_at": now,
            "updated_at": now,
        }
        if item["status"] not in {"open", "in_progress", "resolved", "closed"}:
            raise ValueError("invalid case status")
        if item["priority"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid case priority")
        self.connection.execute(
            """INSERT INTO cases
               (case_id, tenant_id, deployment_id, title, status, priority, assignee, alert_ids_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (item["case_id"], tenant_id, deployment_id, item["title"], item["status"], item["priority"], item["assignee"], canonical_json(item["alert_ids"]), now, now),
        )
        self.connection.commit()
        return item

    def list_cases(self, tenant_id: str, deployment_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM cases WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        sql += " ORDER BY updated_at DESC"
        return [self._case_row(row) for row in self.connection.execute(sql, params).fetchall()]

    def get_case(self, tenant_id: str, case_id: str, *, deployment_id: str | None = None) -> dict[str, Any]:
        sql = "SELECT * FROM cases WHERE tenant_id = ? AND case_id = ?"
        params: list[Any] = [tenant_id, case_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        row = self.connection.execute(sql, params).fetchone()
        if not row:
            raise NotFoundError("case not found")
        return self._case_row(row)

    def update_case(
        self,
        tenant_id: str,
        case_id: str,
        changes: Mapping[str, Any],
        *,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        allowed = {"title", "status", "priority", "assignee", "alert_ids"}
        if set(changes) - allowed:
            raise ValueError("unsupported case fields")
        # The read and the write share one lock so concurrent updates cannot
        # silently lose each other's changes (lost-update).
        with self._lock:
            item = self.get_case(tenant_id, case_id, deployment_id=deployment_id)
            item.update(changes)
            if item["status"] not in {"open", "in_progress", "resolved", "closed"}:
                raise ValueError("invalid case status")
            if item["priority"] not in {"low", "medium", "high", "critical"}:
                raise ValueError("invalid case priority")
            item["updated_at"] = utc_now()
            cursor = self.connection.execute(
                """UPDATE cases SET title = ?, status = ?, priority = ?, assignee = ?, alert_ids_json = ?, updated_at = ?
                   WHERE tenant_id = ? AND case_id = ?""",
                (item["title"], item["status"], item["priority"], item["assignee"], canonical_json(item["alert_ids"]), item["updated_at"], tenant_id, case_id),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("case not found")
            self.connection.commit()
        return item

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"], "tenant_id": row["tenant_id"], "deployment_id": row["deployment_id"],
            "title": row["title"], "status": row["status"], "priority": row["priority"], "assignee": row["assignee"],
            "alert_ids": json.loads(row["alert_ids_json"]), "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def add_case_comment(
        self,
        tenant_id: str,
        case_id: str,
        actor_id: str,
        body: str,
        *,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        self.get_case(tenant_id, case_id, deployment_id=deployment_id)
        body = body.strip()
        if not body or len(body) > 5000:
            raise ValueError("comment must contain 1-5000 characters")
        item = {"comment_id": str(uuid.uuid4()), "case_id": case_id, "tenant_id": tenant_id, "actor_id": actor_id, "body": body, "created_at": utc_now()}
        self.connection.execute(
            "INSERT INTO case_comments (comment_id, case_id, tenant_id, actor_id, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (item["comment_id"], case_id, tenant_id, actor_id, body, item["created_at"]),
        )
        self.connection.commit()
        return item

    def list_comments(
        self, tenant_id: str, case_id: str, *, deployment_id: str | None = None
    ) -> list[dict[str, Any]]:
        self.get_case(tenant_id, case_id, deployment_id=deployment_id)
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM case_comments WHERE tenant_id = ? AND case_id = ? ORDER BY created_at", (tenant_id, case_id)
        ).fetchall()]

    def upsert_sensor(self, value: Mapping[str, Any]) -> dict[str, Any]:
        item = {
            "sensor_id": str(value["sensor_id"]), "tenant_id": str(value["tenant_id"]),
            "deployment_id": str(value["deployment_id"]), "sensor_type": str(value["sensor_type"]),
            "status": str(value.get("status", "online")), "events_per_second": float(value.get("events_per_second", 0)),
            "last_seen": str(value.get("last_seen", utc_now())),
        }
        self.connection.execute(
            """INSERT OR REPLACE INTO sensors
               (sensor_id, tenant_id, deployment_id, sensor_type, status, events_per_second, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            tuple(item.values()),
        )
        self.connection.commit()
        return item

    def list_sensors(self, tenant_id: str, deployment_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM sensors WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if deployment_id:
            sql += " AND deployment_id = ?"
            params.append(deployment_id)
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    def set_policy(self, tenant_id: str, deployment_id: str, changes: Mapping[str, Any]) -> dict[str, Any]:
        current = self.get_policy(tenant_id, deployment_id)
        allowed = {"policy_id", "level", "provider", "model", "region", "retention_mode", "enabled"}
        if set(changes) - allowed:
            raise ValueError("unsupported policy fields")
        current.update(changes)
        if current["level"] not in {"strict", "balanced", "investigative", "disabled"}:
            raise ValueError("invalid policy level")
        if current["retention_mode"] != "zero":
            raise ValueError("MVP permits only zero-retention model policies")
        current["enabled"] = bool(current["enabled"])
        current["updated_at"] = utc_now()
        self.connection.execute(
            """INSERT OR REPLACE INTO model_policies
               (tenant_id, deployment_id, policy_id, level, provider, model, region, retention_mode, enabled, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, deployment_id, current["policy_id"], current["level"], current["provider"], current["model"], current["region"], current["retention_mode"], int(current["enabled"]), current["updated_at"]),
        )
        self.connection.commit()
        return current

    def get_policy(self, tenant_id: str, deployment_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM model_policies WHERE tenant_id = ? AND deployment_id = ?", (tenant_id, deployment_id)
        ).fetchone()
        if not row:
            return {
                "tenant_id": tenant_id, "deployment_id": deployment_id, "policy_id": "policy-v1",
                "level": "balanced", "provider": "demo-zero-retention", "model": "evidence-assessor-v1",
                "region": "us", "retention_mode": "zero", "enabled": True, "updated_at": utc_now(),
            }
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        return item

    def list_detection_rules(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        defaults = {item["rule_id"]: item for item in default_detection_rules(tenant_id, deployment_id)}
        rows = self.connection.execute(
            "SELECT payload_json FROM detection_rules WHERE tenant_id = ? AND deployment_id = ?",
            (tenant_id, deployment_id),
        ).fetchall()
        for row in rows:
            item = _row_json(row)
            defaults[item["rule_id"]] = item
        return sorted(defaults.values(), key=lambda item: (item["name"].lower(), item["rule_id"]))

    def get_detection_rule(self, tenant_id: str, deployment_id: str, rule_id: str) -> dict[str, Any]:
        for item in self.list_detection_rules(tenant_id, deployment_id):
            if item["rule_id"] == rule_id:
                return item
        raise NotFoundError("detection rule not found")

    def create_detection_rule(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        proposed_id = str(value.get("rule_id", ""))
        # The duplicate check and the insert share one lock, so a concurrent
        # create of the same rule_id cannot slip between check and insert; the
        # INSERT OR IGNORE rowcount is the atomic backstop.
        with self._lock:
            if proposed_id:
                existing = self.connection.execute(
                    "SELECT 1 FROM detection_rules WHERE tenant_id = ? AND deployment_id = ? AND rule_id = ?",
                    (tenant_id, deployment_id, proposed_id),
                ).fetchone()
                if existing:
                    raise ValueError("detection rule identifier already exists")
            item = normalize_detection_rule(tenant_id, deployment_id, value, actor_id=actor_id)
            cursor = self.connection.execute(
                """INSERT OR IGNORE INTO detection_rules (tenant_id, deployment_id, rule_id, payload_json, updated_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (tenant_id, deployment_id, item["rule_id"], canonical_json(item), item["updated_at"]),
            )
            if cursor.rowcount != 1:
                raise ValueError("detection rule identifier already exists")
            self.connection.commit()
        return item

    def update_detection_rule(
        self, tenant_id: str, deployment_id: str, rule_id: str, changes: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        if "rule_id" in changes and changes["rule_id"] != rule_id:
            raise ValueError("rule_id cannot be changed")
        existing = self.get_detection_rule(tenant_id, deployment_id, rule_id)
        item = normalize_detection_rule(
            tenant_id, deployment_id, {**changes, "rule_id": rule_id}, existing=existing, actor_id=actor_id
        )
        with self._lock:
            self.connection.execute(
                """INSERT OR REPLACE INTO detection_rules
                   (tenant_id, deployment_id, rule_id, payload_json, updated_at) VALUES (?, ?, ?, ?, ?)""",
                (tenant_id, deployment_id, rule_id, canonical_json(item), item["updated_at"]),
            )
            self.connection.commit()
        return item

    def delete_detection_rule(self, tenant_id: str, deployment_id: str, rule_id: str) -> dict[str, Any]:
        item = self.get_detection_rule(tenant_id, deployment_id, rule_id)
        if item.get("builtin"):
            raise ValueError("built-in detection rules cannot be deleted; disable them instead")
        cursor = self.connection.execute(
            "DELETE FROM detection_rules WHERE tenant_id = ? AND deployment_id = ? AND rule_id = ?",
            (tenant_id, deployment_id, rule_id),
        )
        if cursor.rowcount != 1:
            raise NotFoundError("detection rule not found")
        self.connection.commit()
        return item

    def list_suppressions(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload_json FROM detection_suppressions WHERE tenant_id = ? AND deployment_id = ? ORDER BY updated_at DESC",
            (tenant_id, deployment_id),
        ).fetchall()
        return [_row_json(row) for row in rows]

    def get_suppression(self, tenant_id: str, deployment_id: str, suppression_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM detection_suppressions WHERE tenant_id = ? AND deployment_id = ? AND suppression_id = ?",
            (tenant_id, deployment_id, suppression_id),
        ).fetchone()
        if not row:
            raise NotFoundError("suppression not found")
        return _row_json(row)

    def create_suppression(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        item = normalize_suppression(tenant_id, deployment_id, value, actor_id=actor_id)
        with self._lock:
            self.connection.execute(
                "INSERT INTO detection_suppressions (tenant_id, deployment_id, suppression_id, payload_json, updated_at) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, deployment_id, item["suppression_id"], canonical_json(item), item["updated_at"]),
            )
            self.connection.commit()
        return item

    def update_suppression(
        self, tenant_id: str, deployment_id: str, suppression_id: str, changes: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        if "suppression_id" in changes and changes["suppression_id"] != suppression_id:
            raise ValueError("suppression_id cannot be changed")
        existing = self.get_suppression(tenant_id, deployment_id, suppression_id)
        item = normalize_suppression(
            tenant_id, deployment_id, {**changes, "suppression_id": suppression_id},
            existing=existing, actor_id=actor_id,
        )
        self.connection.execute(
            "UPDATE detection_suppressions SET payload_json = ?, updated_at = ? WHERE tenant_id = ? AND deployment_id = ? AND suppression_id = ?",
            (canonical_json(item), item["updated_at"], tenant_id, deployment_id, suppression_id),
        )
        self.connection.commit()
        return item

    def delete_suppression(self, tenant_id: str, deployment_id: str, suppression_id: str) -> dict[str, Any]:
        item = self.get_suppression(tenant_id, deployment_id, suppression_id)
        self.connection.execute(
            "DELETE FROM detection_suppressions WHERE tenant_id = ? AND deployment_id = ? AND suppression_id = ?",
            (tenant_id, deployment_id, suppression_id),
        )
        self.connection.commit()
        return item

    def is_detection_suppressed(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent | Mapping[str, Any]],
        *,
        at: datetime | None = None,
    ) -> bool:
        checked_at = at or datetime.now(timezone.utc)
        rows = [item.to_dict() if isinstance(item, NormalizedEvent) else dict(item) for item in evidence]
        return any(
            suppression_matches(item, detection.detector_id, detection.entity_id, rows, at=checked_at)
            for item in self.list_suppressions(tenant_id, deployment_id)
        )

    def _integration_record(
        self, tenant_id: str, deployment_id: str, integration_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.connection.execute(
            "SELECT payload_json, secret_json FROM integrations WHERE tenant_id = ? AND deployment_id = ? AND integration_id = ?",
            (tenant_id, deployment_id, integration_id),
        ).fetchone()
        if not row:
            raise NotFoundError("integration not found")
        return json.loads(row["payload_json"]), json.loads(row["secret_json"])

    def list_integrations(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload_json, secret_json FROM integrations WHERE tenant_id = ? AND deployment_id = ? ORDER BY updated_at DESC",
            (tenant_id, deployment_id),
        ).fetchall()
        return [public_integration(json.loads(row["payload_json"]), json.loads(row["secret_json"])) for row in rows]

    def get_integration(self, tenant_id: str, deployment_id: str, integration_id: str) -> dict[str, Any]:
        item, secret = self._integration_record(tenant_id, deployment_id, integration_id)
        return public_integration(item, secret)

    def create_integration(self, tenant_id: str, deployment_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        item, secret = normalize_integration(tenant_id, deployment_id, value)
        with self._lock:
            self.connection.execute(
                """INSERT INTO integrations
                   (tenant_id, deployment_id, integration_id, payload_json, secret_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (tenant_id, deployment_id, item["integration_id"], canonical_json(item), canonical_json(secret), item["updated_at"]),
            )
            self.connection.commit()
        return public_integration(item, secret)

    def update_integration(
        self, tenant_id: str, deployment_id: str, integration_id: str, changes: Mapping[str, Any]
    ) -> dict[str, Any]:
        if "integration_id" in changes and changes["integration_id"] != integration_id:
            raise ValueError("integration_id cannot be changed")
        existing, existing_secret = self._integration_record(tenant_id, deployment_id, integration_id)
        item, secret = normalize_integration(
            tenant_id, deployment_id, {**changes, "integration_id": integration_id},
            existing=existing, existing_secret=existing_secret,
        )
        self.connection.execute(
            """UPDATE integrations SET payload_json = ?, secret_json = ?, updated_at = ?
               WHERE tenant_id = ? AND deployment_id = ? AND integration_id = ?""",
            (canonical_json(item), canonical_json(secret), item["updated_at"], tenant_id, deployment_id, integration_id),
        )
        self.connection.commit()
        return public_integration(item, secret)

    def delete_integration(self, tenant_id: str, deployment_id: str, integration_id: str) -> dict[str, Any]:
        item = self.get_integration(tenant_id, deployment_id, integration_id)
        self.connection.execute(
            "DELETE FROM integrations WHERE tenant_id = ? AND deployment_id = ? AND integration_id = ?",
            (tenant_id, deployment_id, integration_id),
        )
        self.connection.commit()
        return item

    def get_system_settings(self, tenant_id: str, deployment_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT settings_json FROM system_settings WHERE tenant_id = ? AND deployment_id = ?",
            (tenant_id, deployment_id),
        ).fetchone()
        return normalize_system_settings(
            tenant_id, deployment_id, {}, current=json.loads(row["settings_json"]) if row else None
        )

    def update_system_settings(
        self, tenant_id: str, deployment_id: str, changes: Mapping[str, Any]
    ) -> dict[str, Any]:
        current = self.get_system_settings(tenant_id, deployment_id)
        item = normalize_system_settings(tenant_id, deployment_id, changes, current=current)
        self.connection.execute(
            """INSERT OR REPLACE INTO system_settings
               (tenant_id, deployment_id, settings_json, updated_at) VALUES (?, ?, ?, ?)""",
            (tenant_id, deployment_id, canonical_json(item), item["updated_at"]),
        )
        self.connection.commit()
        return item

    def create_evidence_export(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, requested_by: str
    ) -> dict[str, Any]:
        allowed = {"alert_id", "investigation_id", "evidence_ids", "reason", "format"}
        if set(value) - allowed:
            raise ValueError("unsupported evidence export fields")
        evidence_ids = value.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) > 100:
            raise ValueError("evidence_ids must contain 1-100 event identifiers")
        if not all(isinstance(item, str) and item.strip() for item in evidence_ids):
            raise ValueError("evidence_ids contains an invalid identifier")
        reason = str(value.get("reason", "")).strip()
        if not 10 <= len(reason) <= 500:
            raise ValueError("reason must contain 10-500 characters")
        if value.get("format", "json") != "json":
            raise ValueError("the MVP evidence export format is json")
        now = utc_now()
        item = {
            "export_id": str(uuid.uuid4()), "tenant_id": tenant_id, "deployment_id": deployment_id,
            "alert_id": str(value.get("alert_id", "")), "investigation_id": str(value.get("investigation_id", "")),
            "evidence_ids": list(dict.fromkeys(evidence_ids)), "reason": reason, "format": "json",
            "status": "pending_approval", "requested_by": requested_by, "approved_by": None,
            "approval_justification": None, "sha256": None, "size_bytes": None,
            "download_count": 0, "last_downloaded_at": None, "created_at": now, "updated_at": now,
        }
        self.connection.execute(
            """INSERT INTO evidence_exports
               (tenant_id, deployment_id, export_id, status, payload_json, export_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, NULL, ?, ?)""",
            (tenant_id, deployment_id, item["export_id"], item["status"], canonical_json(item), now, now),
        )
        self.connection.commit()
        return item

    def list_evidence_exports(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload_json FROM evidence_exports WHERE tenant_id = ? AND deployment_id = ? ORDER BY created_at DESC",
            (tenant_id, deployment_id),
        ).fetchall()
        return [_row_json(row) for row in rows]

    def get_evidence_export(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM evidence_exports WHERE tenant_id = ? AND deployment_id = ? AND export_id = ?",
            (tenant_id, deployment_id, export_id),
        ).fetchone()
        if not row:
            raise NotFoundError("evidence export not found")
        return _row_json(row)

    def approve_evidence_export(
        self,
        tenant_id: str,
        deployment_id: str,
        export_id: str,
        *,
        approved_by: str,
        justification: str,
        document: Mapping[str, Any],
    ) -> dict[str, Any]:
        justification = justification.strip()
        if not 10 <= len(justification) <= 500:
            raise ValueError("approval justification must contain 10-500 characters")
        # The status check and the transition share one lock, and the UPDATE is
        # additionally conditional on status='pending_approval', so two
        # concurrent approvals cannot both pass the check and both write.
        with self._lock:
            row = self.connection.execute(
                "SELECT payload_json FROM evidence_exports "
                "WHERE tenant_id = ? AND deployment_id = ? AND export_id = ?",
                (tenant_id, deployment_id, export_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("evidence export not found")
            item = _row_json(row)
            if item["status"] != "pending_approval":
                raise ValueError("only pending evidence exports can be approved")
            validate_export_document(document, export_id, item["evidence_ids"])
            encoded = canonical_json(dict(document)).encode("utf-8")
            now = utc_now()
            item.update({
                "status": "approved", "approved_by": approved_by, "approval_justification": justification,
                "sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded), "updated_at": now,
            })
            cursor = self.connection.execute(
                """UPDATE evidence_exports SET status = ?, payload_json = ?, export_json = ?, updated_at = ?
                   WHERE tenant_id = ? AND deployment_id = ? AND export_id = ?
                     AND status = 'pending_approval'""",
                ("approved", canonical_json(item), encoded.decode("utf-8"), now,
                 tenant_id, deployment_id, export_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("only pending evidence exports can be approved")
            self.connection.commit()
        return item

    def get_evidence_export_document(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT status, export_json FROM evidence_exports WHERE tenant_id = ? AND deployment_id = ? AND export_id = ?",
            (tenant_id, deployment_id, export_id),
        ).fetchone()
        if not row:
            raise NotFoundError("evidence export not found")
        if row["status"] != "approved" or not row["export_json"]:
            raise ValueError("evidence export is not approved")
        return json.loads(row["export_json"])

    def mark_evidence_export_downloaded(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        item = self.get_evidence_export(tenant_id, deployment_id, export_id)
        if item["status"] != "approved":
            raise ValueError("evidence export is not approved")
        item["download_count"] = int(item.get("download_count", 0)) + 1
        item["last_downloaded_at"] = utc_now()
        item["updated_at"] = item["last_downloaded_at"]
        self.connection.execute(
            "UPDATE evidence_exports SET payload_json = ?, updated_at = ? WHERE tenant_id = ? AND deployment_id = ? AND export_id = ?",
            (canonical_json(item), item["updated_at"], tenant_id, deployment_id, export_id),
        )
        self.connection.commit()
        return item

    def create_support_bundle(
        self,
        tenant_id: str,
        deployment_id: str,
        document: Mapping[str, Any],
        *,
        requested_by: str,
        expires_at: str,
        options: Mapping[str, Any],
    ) -> dict[str, Any]:
        encoded = canonical_json(dict(document)).encode("utf-8")
        now = utc_now()
        item = {
            "bundle_id": str(uuid.uuid4()), "tenant_id": tenant_id, "deployment_id": deployment_id,
            "status": "ready", "requested_by": requested_by, "options": dict(options),
            "contains_secrets": False, "contains_event_content": False, "sha256": hashlib.sha256(encoded).hexdigest(),
            "size_bytes": len(encoded), "expires_at": expires_at, "download_count": 0,
            "last_downloaded_at": None, "created_at": now,
        }
        self.connection.execute(
            """INSERT INTO support_bundles
               (tenant_id, deployment_id, bundle_id, payload_json, bundle_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (tenant_id, deployment_id, item["bundle_id"], canonical_json(item), encoded.decode("utf-8"), now),
        )
        self.connection.commit()
        return item

    def list_support_bundles(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT payload_json FROM support_bundles WHERE tenant_id = ? AND deployment_id = ? ORDER BY created_at DESC",
            (tenant_id, deployment_id),
        ).fetchall()
        return [_row_json(row) for row in rows]

    def get_support_bundle(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT payload_json FROM support_bundles WHERE tenant_id = ? AND deployment_id = ? AND bundle_id = ?",
            (tenant_id, deployment_id, bundle_id),
        ).fetchone()
        if not row:
            raise NotFoundError("support bundle not found")
        return _row_json(row)

    def get_support_bundle_document(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT bundle_json FROM support_bundles WHERE tenant_id = ? AND deployment_id = ? AND bundle_id = ?",
            (tenant_id, deployment_id, bundle_id),
        ).fetchone()
        if not row:
            raise NotFoundError("support bundle not found")
        return json.loads(row["bundle_json"])

    def mark_support_bundle_downloaded(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        item = self.get_support_bundle(tenant_id, deployment_id, bundle_id)
        item["download_count"] = int(item.get("download_count", 0)) + 1
        item["last_downloaded_at"] = utc_now()
        self.connection.execute(
            "UPDATE support_bundles SET payload_json = ? WHERE tenant_id = ? AND deployment_id = ? AND bundle_id = ?",
            (canonical_json(item), tenant_id, deployment_id, bundle_id),
        )
        self.connection.commit()
        return item

    def set_baseline(self, tenant_id: str, deployment_id: str, entity_id: str, baseline: Mapping[str, Any]) -> dict[str, Any]:
        self.connection.execute(
            """INSERT OR REPLACE INTO entity_baselines (tenant_id, deployment_id, entity_id, baseline_json, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (tenant_id, deployment_id, entity_id, canonical_json(dict(baseline)), utc_now()),
        )
        self.connection.commit()
        return dict(baseline)

    def get_baseline(self, tenant_id: str, deployment_id: str, entity_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            """SELECT baseline_json, updated_at FROM entity_baselines
               WHERE tenant_id = ? AND deployment_id = ? AND entity_id = ?""",
            (tenant_id, deployment_id, entity_id),
        ).fetchone()
        if not row:
            return {"entity_id": entity_id, "status": "learning", "updated_at": None}
        return {"entity_id": entity_id, **json.loads(row["baseline_json"]), "updated_at": row["updated_at"]}

    def reset_demo(self, tenant_id: str = "demo-tenant", deployment_id: str = "demo-deployment") -> dict[str, int]:
        """Replace only the named demo tenant; never clear unrelated customer data."""
        with self._lock:
            for table in (
                "model_transmissions", "investigations", "case_comments", "cases", "alerts", "events",
                "sensors", "model_policies", "entity_baselines", "detection_rules", "detection_suppressions",
                "integrations", "system_settings", "evidence_exports", "support_bundles",
            ):
                self.connection.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))
            # Audit rows are intentionally immutable and are not reset.
            self.connection.commit()
        # Demo seed times are anchored to "now" so the demo never appears stale.
        now = datetime.now(timezone.utc)
        base = now - timedelta(minutes=6)
        events: list[NormalizedEvent] = []
        for index in range(56):
            events.append(
                NormalizedEvent(
                    tenant_id=tenant_id, deployment_id=deployment_id, event_id=f"demo-scan-{index:03d}",
                    event_time=(base + timedelta(milliseconds=index * 500)).isoformat().replace("+00:00", "Z"),
                    source="zeek", event_type="network.connection", sensor_id="sensor-zeek-01",
                    src_ip="10.0.4.21", src_port=51000 + index, dst_ip="203.0.113.40", dst_port=1000 + index,
                    protocol="tcp", bytes_out=512, bytes_in=64, details={"service": "-"},
                )
            )
        dns_event = NormalizedEvent(
            tenant_id=tenant_id, deployment_id=deployment_id, event_id="demo-dns-001",
            event_time=(base + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            source="zeek", event_type="network.dns", sensor_id="sensor-zeek-01", src_ip="10.0.4.32",
            dst_ip="8.8.8.8", dst_port=53, protocol="udp", details={"query": "service.example.com", "query_type": "A"},
        )
        suricata_event = NormalizedEvent(
            tenant_id=tenant_id, deployment_id=deployment_id, event_id="demo-suricata-001",
            event_time=(base + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
            source="suricata", event_type="network.alert", sensor_id="sensor-suricata-01", src_ip="10.0.4.55",
            dst_ip="198.51.100.10", dst_port=443, protocol="tcp",
            community_id="1:AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            details={"signature": "ET MALWARE Suspicious TLS connection", "severity": 2, "category": "Malware Command and Control"},
        )
        self.insert_events([*events, dns_event, suricata_event])
        from hybrid_ndr_contracts import DetectionResult

        scan = DetectionResult(
            detector_id="port-scan-v1", entity_type="host", entity_id="10.0.4.21", severity="high", score=0.91,
            evidence_ids=tuple(item.event_id for item in events[:20]),
            feature_values={"unique_destination_ports": 56.0}, baseline_values={"port_threshold_60s": 50.0},
            title="Potential port scan across 56 destination ports",
        )
        self.save_alert(
            tenant_id, deployment_id, scan, alert_id="demo-alert-port-scan",
            created_at=(now - timedelta(minutes=4)).isoformat().replace("+00:00", "Z"),
        )
        suricata = DetectionResult(
            detector_id="suricata-conversion-v1", entity_type="host", entity_id="10.0.4.55", severity="high", score=0.85,
            evidence_ids=("demo-suricata-001",), feature_values={"suricata_severity": 2.0}, baseline_values={},
            title="ET MALWARE Suspicious TLS connection",
        )
        self.save_alert(
            tenant_id, deployment_id, suricata, alert_id="demo-alert-suricata",
            created_at=(now - timedelta(minutes=3)).isoformat().replace("+00:00", "Z"),
        )
        last_seen = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        self.upsert_sensor({"sensor_id": "sensor-zeek-01", "tenant_id": tenant_id, "deployment_id": deployment_id, "sensor_type": "zeek", "status": "online", "events_per_second": 1842.4, "last_seen": last_seen})
        self.upsert_sensor({"sensor_id": "sensor-suricata-01", "tenant_id": tenant_id, "deployment_id": deployment_id, "sensor_type": "suricata", "status": "online", "events_per_second": 920.1, "last_seen": last_seen})
        self.set_policy(tenant_id, deployment_id, {})
        self.set_baseline(tenant_id, deployment_id, "10.0.4.21", {"dns_median": 14, "dns_p99": 24, "traffic_p99": 1000000, "known_destinations": ["203.0.113.40"]})
        return {"events": len(events) + 2, "alerts": 2, "sensors": 2}

    def close(self) -> None:
        self.connection.close()
