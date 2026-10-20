from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import importlib
import ipaddress
import json
import re
import statistics
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Iterable, Iterator, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from hybrid_ndr_audit import AuditIntegrityError
from hybrid_ndr_contracts import Alert, DetectionResult, NormalizedEvent, canonical_json, utc_now

from .local import NotFoundError
from .ports import Readiness
from .production_administration import PostgresAdministrationMixin
from .tls import verified_opener


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_METADATA_KEY = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _elapsed(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _safe_error(exc: BaseException) -> str:
    if isinstance(exc, ModuleNotFoundError):
        return "database driver is not installed"
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, (TimeoutError, URLError, OSError)):
        return "connection failed"
    return "backend operation failed"


def _iso(value: Any) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


def _json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def _percentile(values: Iterable[float], quantile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.999999)))
    return ordered[index]


class PostgresAuditLog:
    """Append-only, per-deployment hash chain persisted in PostgreSQL."""

    def __init__(self, store: "PostgresMetadataAdapter") -> None:
        self.store = store
        self._lock = threading.RLock()

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
        self.store._scope(tenant_id, deployment_id)
        if actor_type not in {"human", "service", "system"}:
            raise ValueError("actor_type must be human, service, or system")
        if result not in {"success", "failure", "denied"}:
            raise ValueError("result must be success, failure, or denied")
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
            "created_at": created_at or utc_now(),
            "metadata": dict(metadata or {}),
        }
        table = self.store._table("audit_events")
        lock_key = canonical_json([tenant_id, deployment_id])
        with self._lock, self.store._transaction() as cursor:
            # The advisory lock also serializes the first record, for which no
            # prior row exists to lock with SELECT ... FOR UPDATE.
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,))
            cursor.execute(
                f"SELECT record_hash FROM {table} WHERE tenant_id = %s AND deployment_id = %s "
                "ORDER BY sequence DESC LIMIT 1",
                (tenant_id, deployment_id),
            )
            previous = cursor.fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            record_hash = hashlib.sha256(
                (previous_hash + canonical_json(record)).encode("utf-8")
            ).hexdigest()
            cursor.execute(
                f"""INSERT INTO {table} (
                       audit_id, tenant_id, deployment_id, actor_id, actor_type, action,
                       resource_type, resource_id, request_id, result, created_at,
                       metadata_json, previous_hash, record_hash
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    record["audit_id"], tenant_id, deployment_id, actor_id, actor_type, action,
                    resource_type, resource_id, record["request_id"], result, record["created_at"],
                    canonical_json(record["metadata"]), previous_hash, record_hash,
                ),
            )
        return {**record, "previous_hash": previous_hash, "record_hash": record_hash}

    def list(self, tenant_id: str, deployment_id: str | None = None, *, limit: int = 200) -> list[dict[str, Any]]:
        self.store._scope(tenant_id, deployment_id)
        rows = self.store._all(
            f"SELECT * FROM {self.store._table('audit_events')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY sequence DESC LIMIT %s",
            (tenant_id, deployment_id, max(1, min(int(limit), 1000))),
        )
        return [self._row(row) for row in rows]

    def verify(self, tenant_id: str, deployment_id: str) -> bool:
        self.store._scope(tenant_id, deployment_id)
        rows = self.store._all(
            f"SELECT * FROM {self.store._table('audit_events')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY sequence ASC",
            (tenant_id, deployment_id),
        )
        previous_hash = "0" * 64
        for source in rows:
            record = self._row(source)
            payload = {
                key: record[key]
                for key in (
                    "audit_id", "tenant_id", "deployment_id", "actor_id", "actor_type",
                    "action", "resource_type", "resource_id", "request_id", "result",
                    "created_at", "metadata",
                )
            }
            expected = hashlib.sha256((previous_hash + canonical_json(payload)).encode("utf-8")).hexdigest()
            if record["previous_hash"] != previous_hash or record["record_hash"] != expected:
                raise AuditIntegrityError(f"audit chain failed at {record['audit_id']}")
            previous_hash = record["record_hash"]
        return True

    @staticmethod
    def _row(row: Mapping[str, Any]) -> dict[str, Any]:
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
            "created_at": _iso(row["created_at"]),
            "metadata": dict(_json_value(row["metadata_json"], {})),
            "previous_hash": row["previous_hash"],
            "record_hash": row["record_hash"],
        }

    def close(self) -> None:
        return None


class PostgresMetadataAdapter(PostgresAdministrationMixin):
    """Durable operational state adapter for the ``local_state`` schema."""

    backend = "postgresql"
    supports_product_io = True

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "local_state",
        timeout_seconds: float = 3.0,
        driver_loader: Callable[[str], Any] = importlib.import_module,
    ) -> None:
        if not _IDENTIFIER.fullmatch(schema):
            raise ValueError("PostgreSQL schema contains invalid characters")
        self.dsn = dsn
        self.schema = schema
        self.timeout_seconds = timeout_seconds
        self._driver_loader = driver_loader
        self.audit = PostgresAuditLog(self)

    def _table(self, table: str) -> str:
        if not _IDENTIFIER.fullmatch(table):
            raise ValueError("invalid PostgreSQL table")
        return f'"{self.schema}"."{table}"'

    @staticmethod
    def _scope(tenant_id: str, deployment_id: str | None) -> None:
        if not tenant_id or not deployment_id:
            raise ValueError("tenant_id and deployment_id are required")

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        psycopg = self._driver_loader("psycopg")
        with psycopg.connect(self.dsn, connect_timeout=max(1, int(self.timeout_seconds))) as connection:
            with connection.cursor() as cursor:
                yield cursor

    @staticmethod
    def _mapping(cursor: Any, row: Any) -> dict[str, Any]:
        columns = [column.name if hasattr(column, "name") else column[0] for column in cursor.description]
        return dict(zip(columns, row, strict=True))

    def _all(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._transaction() as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._mapping(cursor, row) for row in rows]

    def _one(self, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._transaction() as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
            return self._mapping(cursor, row) if row is not None else None

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> int:
        with self._transaction() as cursor:
            cursor.execute(query, params)
            return int(cursor.rowcount)

    def readiness(self) -> Readiness:
        started = time.monotonic()
        try:
            with self._transaction() as cursor:
                cursor.execute("SELECT to_regnamespace(%s)", (self.schema,))
                row = cursor.fetchone()
                if not row or row[0] is None:
                    return Readiness(self.backend, False, "schema", "required schema is missing", _elapsed(started))
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return Readiness(self.backend, True, "schema", "connection and schema verified", _elapsed(started))
        except Exception as exc:
            return Readiness(self.backend, False, "schema", _safe_error(exc), _elapsed(started))

    def _migration_statements(self) -> tuple[tuple[int, str, list[str]], ...]:
        """Versioned additive migrations applied by ensure_detection_schema.

        Version 1 is the base product state applied by the PostgreSQL init
        scripts (infra/postgres/001-product-state.sql); versions 2+ are applied
        in code so upgraded volumes converge without a container re-init.
        """
        return (
            (2, "detection checkpoints, alert keys, and alert evidence", [
                f"""CREATE TABLE IF NOT EXISTS {self._table('detection_checkpoints')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    job_name text NOT NULL,
                    completed_at timestamptz NOT NULL,
                    updated_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (tenant_id, deployment_id, job_name)
                )""",
                f"""CREATE TABLE IF NOT EXISTS {self._table('detection_alert_keys')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{{64}}$'),
                    alert_id text NOT NULL,
                    created_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, fingerprint),
                    FOREIGN KEY (tenant_id, deployment_id, alert_id)
                      REFERENCES {self._table('alerts')}(tenant_id, deployment_id, alert_id)
                      DEFERRABLE INITIALLY DEFERRED
                )""",
                f"""CREATE TABLE IF NOT EXISTS {self._table('alert_evidence')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    alert_id text NOT NULL,
                    event_id text NOT NULL,
                    event_time timestamptz NOT NULL,
                    event_type text NOT NULL,
                    source text NOT NULL,
                    community_id text NOT NULL,
                    raw_reference text NOT NULL,
                    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
                    PRIMARY KEY (tenant_id, deployment_id, alert_id, event_id),
                    FOREIGN KEY (tenant_id, deployment_id, alert_id)
                      REFERENCES {self._table('alerts')}(tenant_id, deployment_id, alert_id)
                )""",
                f"CREATE INDEX IF NOT EXISTS alert_evidence_event_id "
                f"ON {self._table('alert_evidence')} (tenant_id, deployment_id, event_id)",
            ]),
            (3, "admin tables (rules, suppressions, integrations, settings, exports, bundles)", [
                f"""CREATE TABLE IF NOT EXISTS {self._table('detection_rules')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    rule_id text NOT NULL,
                    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
                    updated_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, rule_id)
                )""",
                f"""CREATE TABLE IF NOT EXISTS {self._table('detection_suppressions')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    suppression_id text NOT NULL,
                    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
                    updated_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, suppression_id)
                )""",
                f"CREATE INDEX IF NOT EXISTS detection_suppressions_updated "
                f"ON {self._table('detection_suppressions')} (tenant_id, deployment_id, updated_at DESC)",
                f"""CREATE TABLE IF NOT EXISTS {self._table('integrations')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    integration_id text NOT NULL,
                    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
                    secret_json jsonb NOT NULL CHECK (jsonb_typeof(secret_json) = 'object'),
                    updated_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, integration_id)
                )""",
                f"""CREATE TABLE IF NOT EXISTS {self._table('system_settings')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    settings_json jsonb NOT NULL CHECK (jsonb_typeof(settings_json) = 'object'),
                    updated_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id)
                )""",
                f"""CREATE TABLE IF NOT EXISTS {self._table('evidence_exports')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    export_id text NOT NULL,
                    status text NOT NULL CHECK (status IN ('pending_approval', 'approved', 'rejected')),
                    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
                    export_json jsonb CHECK (export_json IS NULL OR jsonb_typeof(export_json) = 'object'),
                    created_at timestamptz NOT NULL,
                    updated_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, export_id)
                )""",
                f"CREATE INDEX IF NOT EXISTS evidence_exports_created "
                f"ON {self._table('evidence_exports')} (tenant_id, deployment_id, created_at DESC)",
                f"""CREATE TABLE IF NOT EXISTS {self._table('support_bundles')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    bundle_id text NOT NULL,
                    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
                    bundle_json jsonb NOT NULL CHECK (jsonb_typeof(bundle_json) = 'object'),
                    created_at timestamptz NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, bundle_id)
                )""",
                f"CREATE INDEX IF NOT EXISTS support_bundles_created "
                f"ON {self._table('support_bundles')} (tenant_id, deployment_id, created_at DESC)",
            ]),
            (4, "defer alert fingerprint foreign key until transaction commit", [
                f"ALTER TABLE {self._table('detection_alert_keys')} "
                "ALTER CONSTRAINT detection_alert_keys_tenant_id_deployment_id_alert_id_fkey "
                "DEFERRABLE INITIALLY DEFERRED",
            ]),
            (5, "customer-local response workflow and journal", [
                f"""CREATE TABLE IF NOT EXISTS {self._table('response_records')} (
                    tenant_id text NOT NULL,
                    deployment_id text NOT NULL,
                    kind text NOT NULL,
                    record_id text NOT NULL,
                    state text NOT NULL,
                    updated_at text NOT NULL,
                    payload_json text NOT NULL,
                    PRIMARY KEY (tenant_id, deployment_id, kind, record_id)
                )""",
                f"CREATE INDEX IF NOT EXISTS response_records_work ON {self._table('response_records')} "
                "(tenant_id, deployment_id, kind, state, updated_at)",
            ]),
        )

    def ensure_detection_schema(self) -> None:
        """Apply versioned additive migrations; safe to call on every startup.

        Volumes created by the init scripts already record version 1. Volumes
        that predate versioning have no migrations table; the base product
        state is assumed present, so version 1 is recorded without re-running
        the base DDL and only the additive migrations run.
        """
        with self._transaction() as cursor:
            # API and detection processes may start together on an upgraded volume.
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended('aegis-schema-migrations', 0))")
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {self._table('schema_migrations')} (
                    version bigint PRIMARY KEY,
                    description text NOT NULL,
                    applied_at timestamptz NOT NULL DEFAULT now()
                )"""
            )
            cursor.execute(f"SELECT COALESCE(MAX(version), 0) FROM {self._table('schema_migrations')}")
            row = cursor.fetchone()
            current = int(row[0] if row is not None else 0)
            if current == 0:
                cursor.execute(
                    f"INSERT INTO {self._table('schema_migrations')} (version, description) "
                    "VALUES (1, 'base product state (init scripts)') "
                    "ON CONFLICT (version) DO NOTHING"
                )
                current = 1
            for version, description, statements in self._migration_statements():
                if version <= current:
                    continue
                for statement in statements:
                    cursor.execute(statement)
                cursor.execute(
                    f"INSERT INTO {self._table('schema_migrations')} (version, description) "
                    "VALUES (%s, %s) ON CONFLICT (version) DO NOTHING",
                    (version, description),
                )

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
            alert_id=alert_id or str(uuid.uuid4()), tenant_id=tenant_id, deployment_id=deployment_id,
            created_at=created_at or utc_now(), detector_id=detection.detector_id, title=detection.title,
            severity=detection.severity, status="open", entity_type=detection.entity_type,
            entity_id=detection.entity_id, score=detection.score, evidence_ids=detection.evidence_ids,
            baseline=detection.baseline_values, features=detection.feature_values,
        )
        return self.put_alert(alert)

    def put_alert(self, alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
        with self._transaction() as cursor:
            return self._put_alert_on(cursor, alert)

    def _put_alert_on(self, cursor: Any, alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
        item = alert if isinstance(alert, Alert) else Alert.from_dict(alert)
        payload = item.to_dict()
        cursor.execute(
            f"""INSERT INTO {self._table('alerts')}
                (alert_id, tenant_id, deployment_id, created_at, severity, status, entity_id, payload_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO UPDATE SET
                  created_at = EXCLUDED.created_at, severity = EXCLUDED.severity,
                  status = EXCLUDED.status, entity_id = EXCLUDED.entity_id,
                  payload_json = EXCLUDED.payload_json
                WHERE alerts.tenant_id = EXCLUDED.tenant_id
                  AND alerts.deployment_id = EXCLUDED.deployment_id""",
            (item.alert_id, item.tenant_id, item.deployment_id, item.created_at, item.severity,
             item.status, item.entity_id, canonical_json(payload)),
        )
        if cursor.rowcount != 1:
            raise ValueError("alert identifier belongs to another deployment")
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
        self._scope(tenant_id, deployment_id)
        sql = f"SELECT payload_json FROM {self._table('alerts')} WHERE tenant_id = %s AND deployment_id = %s"
        params: list[Any] = [tenant_id, deployment_id]
        if status:
            sql += " AND status = %s"
            params.append(status)
        if severity:
            sql += " AND severity = %s"
            params.append(severity)
        sql += " ORDER BY created_at DESC LIMIT %s"
        params.append(max(1, min(int(limit), 500)))
        return [dict(_json_value(row["payload_json"], {})) for row in self._all(sql, tuple(params))]

    def get_alert(self, tenant_id: str, alert_id: str, *, deployment_id: str | None = None) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT payload_json FROM {self._table('alerts')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND alert_id = %s",
            (tenant_id, deployment_id, alert_id),
        )
        if not row:
            raise NotFoundError("alert not found")
        return dict(_json_value(row["payload_json"], {}))

    def update_alert(
        self,
        tenant_id: str,
        alert_id: str,
        changes: Mapping[str, Any],
        *,
        deployment_id: str | None = None,
    ) -> dict[str, Any]:
        unknown = set(changes) - {"status", "severity"}
        if unknown:
            raise ValueError(f"unsupported alert fields: {sorted(unknown)}")
        # Read and write must share one transaction: a separate read then a
        # separate write would let a concurrent change be silently overwritten.
        with self._transaction() as cursor:
            cursor.execute(
                f"SELECT payload_json FROM {self._table('alerts')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND alert_id = %s",
                (tenant_id, deployment_id, alert_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise NotFoundError("alert not found")
            alert = dict(_json_value(self._mapping(cursor, row)["payload_json"], {}))
            alert.update(changes)
            return self._put_alert_on(cursor, Alert.from_dict(alert))

    def create_investigation(
        self, tenant_id: str, deployment_id: str, alert_id: str, *, investigation_id: str | None = None
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        now = utc_now()
        item = {
            "investigation_id": investigation_id or str(uuid.uuid4()), "tenant_id": tenant_id,
            "deployment_id": deployment_id, "alert_id": alert_id, "status": "running",
            "assessment": None, "error_code": None, "created_at": now, "updated_at": now,
        }
        # The alert-existence check and the insert run in one transaction with
        # a row lock, so a concurrently deleted alert cannot leave an orphan.
        with self._transaction() as cursor:
            cursor.execute(
                f"SELECT 1 FROM {self._table('alerts')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND alert_id = %s FOR SHARE",
                (tenant_id, deployment_id, alert_id),
            )
            if cursor.fetchone() is None:
                raise NotFoundError("alert not found")
            cursor.execute(
                f"""INSERT INTO {self._table('investigations')}
                    (investigation_id, tenant_id, deployment_id, alert_id, status,
                     response_json, error_code, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, 'running', NULL, NULL, %s, %s)""",
                (item["investigation_id"], tenant_id, deployment_id, alert_id, now, now),
            )
        return item

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
        self._scope(tenant_id, deployment_id)
        if status not in {"completed", "failed", "unavailable", "rejected"}:
            raise ValueError("invalid terminal investigation status")
        with self._transaction() as cursor:
            cursor.execute(
                f"""UPDATE {self._table('investigations')}
                    SET status = %s, response_json = %s, error_code = %s, updated_at = %s
                    WHERE tenant_id = %s AND deployment_id = %s AND investigation_id = %s""",
                (status, canonical_json(assessment) if assessment else None, error_code, utc_now(),
                 tenant_id, deployment_id, investigation_id),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("investigation not found")
            cursor.execute(
                f"SELECT * FROM {self._table('investigations')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND investigation_id = %s",
                (tenant_id, deployment_id, investigation_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise NotFoundError("investigation not found")
            return self._investigation_row(self._mapping(cursor, row))

    def get_investigation(
        self, tenant_id: str, investigation_id: str, *, deployment_id: str | None = None
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT * FROM {self._table('investigations')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND investigation_id = %s",
            (tenant_id, deployment_id, investigation_id),
        )
        if not row:
            raise NotFoundError("investigation not found")
        return self._investigation_row(row)

    def list_investigations(
        self, tenant_id: str, *, deployment_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT * FROM {self._table('investigations')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY created_at DESC LIMIT %s",
            (tenant_id, deployment_id, max(1, min(int(limit), 500))),
        )
        return [self._investigation_row(row) for row in rows]

    @staticmethod
    def _investigation_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "investigation_id": row["investigation_id"], "tenant_id": row["tenant_id"],
            "deployment_id": row["deployment_id"], "alert_id": row["alert_id"], "status": row["status"],
            "assessment": _json_value(row["response_json"], None), "error_code": row["error_code"],
            "created_at": _iso(row["created_at"]), "updated_at": _iso(row["updated_at"]),
        }

    def save_transmission(self, record: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "request_id", "investigation_id", "alert_id", "tenant_id", "deployment_id", "actor_id",
            "provider", "model", "retention_mode", "region", "fields_included", "fields_removed",
            "fields_tokenized", "prompt_hash", "response_hash", "input_tokens", "output_tokens",
            "latency_ms", "result", "payload",
        }
        missing = required - set(record)
        if missing:
            raise ValueError(f"missing transmission fields: {sorted(missing)}")
        item = dict(record)
        self._scope(str(item["tenant_id"]), str(item["deployment_id"]))
        item.setdefault("transmission_id", str(uuid.uuid4()))
        item.setdefault("created_at", utc_now())
        item.setdefault("error_code", None)
        self._execute(
            f"""INSERT INTO {self._table('model_transmissions')} (
              transmission_id, request_id, investigation_id, alert_id, tenant_id, deployment_id,
              actor_id, provider, model, retention_mode, region, fields_included_json,
              fields_removed_json, fields_tokenized_json, prompt_hash, response_hash,
              input_tokens, output_tokens, latency_ms, result, error_code, payload_json, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s, %s, %s, %s)""",
            (
                item["transmission_id"], item["request_id"], item["investigation_id"], item["alert_id"],
                item["tenant_id"], item["deployment_id"], item["actor_id"], item["provider"], item["model"],
                item["retention_mode"], item["region"], canonical_json(item["fields_included"]),
                canonical_json(item["fields_removed"]), canonical_json(item["fields_tokenized"]),
                item["prompt_hash"], item["response_hash"], int(item["input_tokens"]), int(item["output_tokens"]),
                int(item["latency_ms"]), item["result"], item["error_code"], canonical_json(item["payload"]),
                item["created_at"],
            ),
        )
        return item

    def get_transmission(
        self, tenant_id: str, investigation_id: str, *, deployment_id: str | None = None
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT * FROM {self._table('model_transmissions')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND investigation_id = %s "
            "ORDER BY created_at DESC LIMIT 1",
            (tenant_id, deployment_id, investigation_id),
        )
        if not row:
            raise NotFoundError("transmission not found")
        return self._transmission_row(row)

    def list_transmissions(
        self, tenant_id: str, *, deployment_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT * FROM {self._table('model_transmissions')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY created_at DESC LIMIT %s",
            (tenant_id, deployment_id, max(1, min(int(limit), 500))),
        )
        return [self._transmission_row(row) for row in rows]

    @staticmethod
    def _transmission_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "transmission_id": row["transmission_id"], "request_id": row["request_id"],
            "investigation_id": row["investigation_id"], "alert_id": row["alert_id"],
            "tenant_id": row["tenant_id"], "deployment_id": row["deployment_id"], "actor_id": row["actor_id"],
            "provider": row["provider"], "model": row["model"], "retention_mode": row["retention_mode"],
            "region": row["region"], "fields_included": list(_json_value(row["fields_included_json"], [])),
            "fields_removed": list(_json_value(row["fields_removed_json"], [])),
            "fields_tokenized": list(_json_value(row["fields_tokenized_json"], [])),
            "prompt_hash": row["prompt_hash"], "response_hash": row["response_hash"],
            "input_tokens": row["input_tokens"], "output_tokens": row["output_tokens"],
            "latency_ms": row["latency_ms"], "result": row["result"], "error_code": row["error_code"],
            "payload": dict(_json_value(row["payload_json"], {})), "created_at": _iso(row["created_at"]),
        }

    def create_case(self, tenant_id: str, deployment_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        title = str(value.get("title", "")).strip()
        if not title:
            raise ValueError("case title is required")
        now = utc_now()
        item = {
            "case_id": str(value.get("case_id") or uuid.uuid4()), "tenant_id": tenant_id,
            "deployment_id": deployment_id, "title": title[:200], "status": str(value.get("status", "open")),
            "priority": str(value.get("priority", "medium")), "assignee": str(value.get("assignee", ""))[:200],
            "alert_ids": list(value.get("alert_ids", [])), "created_at": now, "updated_at": now,
        }
        self._validate_case(item)
        self._execute(
            f"""INSERT INTO {self._table('cases')}
              (case_id, tenant_id, deployment_id, title, status, priority, assignee,
               alert_ids_json, created_at, updated_at)
              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (item["case_id"], tenant_id, deployment_id, item["title"], item["status"], item["priority"],
             item["assignee"], canonical_json(item["alert_ids"]), now, now),
        )
        return item

    @staticmethod
    def _validate_case(item: Mapping[str, Any]) -> None:
        if item["status"] not in {"open", "in_progress", "resolved", "closed"}:
            raise ValueError("invalid case status")
        if item["priority"] not in {"low", "medium", "high", "critical"}:
            raise ValueError("invalid case priority")

    def list_cases(self, tenant_id: str, deployment_id: str | None = None) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT * FROM {self._table('cases')} WHERE tenant_id = %s AND deployment_id = %s "
            "ORDER BY updated_at DESC",
            (tenant_id, deployment_id),
        )
        return [self._case_row(row) for row in rows]

    def get_case(self, tenant_id: str, case_id: str, *, deployment_id: str | None = None) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT * FROM {self._table('cases')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND case_id = %s",
            (tenant_id, deployment_id, case_id),
        )
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
        # Single transaction: the read and write share one connection so a
        # concurrent update cannot be silently lost between them.
        with self._transaction() as cursor:
            cursor.execute(
                f"SELECT * FROM {self._table('cases')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND case_id = %s",
                (tenant_id, deployment_id, case_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise NotFoundError("case not found")
            item = self._case_row(self._mapping(cursor, row))
            item.update(changes)
            self._validate_case(item)
            item["updated_at"] = utc_now()
            cursor.execute(
                f"""UPDATE {self._table('cases')}
                    SET title = %s, status = %s, priority = %s, assignee = %s,
                        alert_ids_json = %s, updated_at = %s
                    WHERE tenant_id = %s AND deployment_id = %s AND case_id = %s""",
                (item["title"], item["status"], item["priority"], item["assignee"],
                 canonical_json(item["alert_ids"]), item["updated_at"], tenant_id, deployment_id, case_id),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("case not found")
        return item

    @staticmethod
    def _case_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "case_id": row["case_id"], "tenant_id": row["tenant_id"], "deployment_id": row["deployment_id"],
            "title": row["title"], "status": row["status"], "priority": row["priority"],
            "assignee": row["assignee"], "alert_ids": list(_json_value(row["alert_ids_json"], [])),
            "created_at": _iso(row["created_at"]), "updated_at": _iso(row["updated_at"]),
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
        item = {
            "comment_id": str(uuid.uuid4()), "case_id": case_id, "tenant_id": tenant_id,
            "actor_id": actor_id, "body": body, "created_at": utc_now(),
        }
        self._execute(
            f"INSERT INTO {self._table('case_comments')} "
            "(comment_id, case_id, tenant_id, actor_id, body, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (item["comment_id"], case_id, tenant_id, actor_id, body, item["created_at"]),
        )
        return item

    def list_comments(
        self, tenant_id: str, case_id: str, *, deployment_id: str | None = None
    ) -> list[dict[str, Any]]:
        self.get_case(tenant_id, case_id, deployment_id=deployment_id)
        rows = self._all(
            f"SELECT cc.* FROM {self._table('case_comments')} cc "
            f"JOIN {self._table('cases')} c ON c.tenant_id = cc.tenant_id AND c.case_id = cc.case_id "
            "WHERE cc.tenant_id = %s AND c.deployment_id = %s AND cc.case_id = %s ORDER BY cc.created_at",
            (tenant_id, deployment_id, case_id),
        )
        return [{**row, "created_at": _iso(row["created_at"])} for row in rows]

    def upsert_sensor(self, value: Mapping[str, Any]) -> dict[str, Any]:
        item = {
            "sensor_id": str(value["sensor_id"]), "tenant_id": str(value["tenant_id"]),
            "deployment_id": str(value["deployment_id"]), "sensor_type": str(value["sensor_type"]),
            "status": str(value.get("status", "online")),
            "events_per_second": float(value.get("events_per_second", 0)),
            "last_seen": str(value.get("last_seen", utc_now())),
        }
        self._scope(item["tenant_id"], item["deployment_id"])
        affected = self._execute(
            f"""INSERT INTO {self._table('sensors')}
                (sensor_id, tenant_id, deployment_id, sensor_type, status, events_per_second, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (sensor_id) DO UPDATE SET sensor_type = EXCLUDED.sensor_type,
                  status = EXCLUDED.status, events_per_second = EXCLUDED.events_per_second,
                  last_seen = EXCLUDED.last_seen
                WHERE sensors.tenant_id = EXCLUDED.tenant_id
                  AND sensors.deployment_id = EXCLUDED.deployment_id""",
            tuple(item.values()),
        )
        if affected != 1:
            raise ValueError("sensor identifier belongs to another deployment")
        return item

    def list_sensors(self, tenant_id: str, deployment_id: str | None = None) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT * FROM {self._table('sensors')} WHERE tenant_id = %s AND deployment_id = %s",
            (tenant_id, deployment_id),
        )
        return [{**row, "last_seen": _iso(row["last_seen"])} for row in rows]

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
        self._execute(
            f"""INSERT INTO {self._table('model_policies')}
              (tenant_id, deployment_id, policy_id, level, provider, model, region,
               retention_mode, enabled, updated_at)
              VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
              ON CONFLICT (tenant_id, deployment_id) DO UPDATE SET
                policy_id = EXCLUDED.policy_id, level = EXCLUDED.level, provider = EXCLUDED.provider,
                model = EXCLUDED.model, region = EXCLUDED.region,
                retention_mode = EXCLUDED.retention_mode, enabled = EXCLUDED.enabled,
                updated_at = EXCLUDED.updated_at""",
            (tenant_id, deployment_id, current["policy_id"], current["level"], current["provider"],
             current["model"], current["region"], current["retention_mode"], current["enabled"],
             current["updated_at"]),
        )
        return current

    def get_policy(self, tenant_id: str, deployment_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT * FROM {self._table('model_policies')} WHERE tenant_id = %s AND deployment_id = %s",
            (tenant_id, deployment_id),
        )
        if not row:
            return {
                "tenant_id": tenant_id, "deployment_id": deployment_id, "policy_id": "policy-v1",
                "level": "balanced", "provider": "demo-zero-retention", "model": "evidence-assessor-v1",
                "region": "us", "retention_mode": "zero", "enabled": True, "updated_at": utc_now(),
            }
        return {**row, "enabled": bool(row["enabled"]), "updated_at": _iso(row["updated_at"])}

    def set_baseline(
        self, tenant_id: str, deployment_id: str, entity_id: str, baseline: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        self._execute(
            f"""INSERT INTO {self._table('entity_baselines')}
              (tenant_id, deployment_id, entity_id, baseline_json, updated_at)
              VALUES (%s, %s, %s, %s, %s)
              ON CONFLICT (tenant_id, deployment_id, entity_id) DO UPDATE SET
                baseline_json = EXCLUDED.baseline_json, updated_at = EXCLUDED.updated_at""",
            (tenant_id, deployment_id, entity_id, canonical_json(dict(baseline)), utc_now()),
        )
        return dict(baseline)

    def get_baseline(self, tenant_id: str, deployment_id: str, entity_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT baseline_json, updated_at FROM {self._table('entity_baselines')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND entity_id = %s",
            (tenant_id, deployment_id, entity_id),
        )
        if not row:
            return {"entity_id": entity_id, "status": "learning", "updated_at": None}
        return {
            "entity_id": entity_id, **dict(_json_value(row["baseline_json"], {})),
            "updated_at": _iso(row["updated_at"]),
        }

    def list_detection_baselines(self, tenant_id: str, deployment_id: str) -> dict[str, dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT entity_id, baseline_json FROM {self._table('entity_baselines')} "
            "WHERE tenant_id = %s AND deployment_id = %s",
            (tenant_id, deployment_id),
        )
        return {row["entity_id"]: dict(_json_value(row["baseline_json"], {})) for row in rows}

    def get_detection_checkpoint(self, tenant_id: str, deployment_id: str, job_name: str) -> str | None:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT completed_at FROM {self._table('detection_checkpoints')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND job_name = %s",
            (tenant_id, deployment_id, job_name),
        )
        return _iso(row["completed_at"]) if row else None

    def set_detection_checkpoint(
        self, tenant_id: str, deployment_id: str, job_name: str, completed_at: dt.datetime
    ) -> None:
        self._scope(tenant_id, deployment_id)
        self._execute(
            f"""INSERT INTO {self._table('detection_checkpoints')}
                (tenant_id, deployment_id, job_name, completed_at, updated_at)
                VALUES (%s, %s, %s, %s, now())
                ON CONFLICT (tenant_id, deployment_id, job_name) DO UPDATE SET
                  completed_at = EXCLUDED.completed_at, updated_at = now()""",
            (tenant_id, deployment_id, job_name, completed_at),
        )

    def save_detected_alert(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent | Mapping[str, Any]],
        *,
        fingerprint: str,
        alert_id: str,
        created_at: str,
    ) -> tuple[bool, dict[str, Any]]:
        """Atomically persist one idempotent alert and its local evidence snapshots."""

        self._scope(tenant_id, deployment_id)
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("detection fingerprint must be a lowercase SHA-256 digest")
        items = [item if isinstance(item, NormalizedEvent) else NormalizedEvent.from_dict(item) for item in evidence]
        by_id = {item.event_id: item for item in items}
        if tuple(by_id) != tuple(dict.fromkeys(detection.evidence_ids)):
            if set(by_id) != set(detection.evidence_ids):
                raise ValueError("persisted alert evidence does not match the detection result")
        if any(item.tenant_id != tenant_id or item.deployment_id != deployment_id for item in items):
            raise ValueError("alert evidence belongs to another tenant or deployment")
        alert = Alert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            created_at=created_at,
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
        payload = alert.to_dict()
        with self._transaction() as cursor:
            # The FK is deferred until commit so this claim and its parent alert
            # can be created atomically. The fingerprint is the idempotency guard.
            # Insert it first
            # and treat its rowcount as authoritative: if a concurrent call
            # already registered this fingerprint (with the same deterministic
            # alert_id, or a different one), this call must NOT insert its own
            # alert row, or a duplicate alert would escape the guard.
            cursor.execute(
                f"""INSERT INTO {self._table('detection_alert_keys')}
                    (tenant_id, deployment_id, fingerprint, alert_id, created_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, deployment_id, fingerprint) DO NOTHING""",
                (tenant_id, deployment_id, fingerprint, alert_id, created_at),
            )
            created = cursor.rowcount == 1
            cursor.execute(
                f"SELECT alert_id FROM {self._table('detection_alert_keys')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND fingerprint = %s",
                (tenant_id, deployment_id, fingerprint),
            )
            mapped_row = cursor.fetchone()
            if mapped_row is None:
                raise ValueError("detection fingerprint mapping disappeared")
            mapped_alert_id = str(mapped_row[0])
            if mapped_alert_id != alert_id:
                # A concurrent call registered this fingerprint under another
                # deterministic identifier; the mapping wins and this call must
                # not create a duplicate alert or orphan evidence rows.
                created = False
                alert_id = mapped_alert_id
            if created:
                cursor.execute(
                    f"""INSERT INTO {self._table('alerts')}
                        (alert_id, tenant_id, deployment_id, created_at, severity, status, entity_id, payload_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (alert_id) DO NOTHING""",
                    (
                        alert.alert_id, alert.tenant_id, alert.deployment_id, alert.created_at,
                        alert.severity, alert.status, alert.entity_id, canonical_json(payload),
                    ),
                )
                if cursor.rowcount == 0:
                    # The deterministic identifier already exists under another
                    # fingerprint (should not happen); treat as a duplicate.
                    created = False
            if created:
                # Preserve detector provenance separately from analyst-editable
                # severity/status. Legacy alerts without this record require approval.
                origin = {"sha256": hashlib.sha256(canonical_json({key: payload[key] for key in
                          ("detector_id", "severity", "entity_type", "entity_id", "evidence_ids", "created_at",
                           "features", "baseline")}).encode("utf-8")).hexdigest()}
                cursor.execute(
                    f"INSERT INTO {self._table('response_records')} "
                    "(tenant_id,deployment_id,kind,record_id,state,updated_at,payload_json) "
                    "VALUES (%s,%s,'detector_origin',%s,'',%s,%s) "
                    "ON CONFLICT (tenant_id,deployment_id,kind,record_id) DO NOTHING",
                    (tenant_id, deployment_id, alert_id, utc_now(), canonical_json(origin)),
                )
            for item in items:
                cursor.execute(
                    f"""INSERT INTO {self._table('alert_evidence')}
                        (tenant_id, deployment_id, alert_id, event_id, event_time, event_type,
                         source, community_id, raw_reference, snapshot_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, deployment_id, alert_id, event_id) DO NOTHING""",
                    (
                        tenant_id, deployment_id, alert_id, item.event_id, item.event_time,
                        item.event_type, item.source, item.community_id, item.raw_reference,
                        canonical_json(item.to_dict()),
                    ),
                )
            if not created:
                cursor.execute(
                    f"SELECT payload_json FROM {self._table('alerts')} "
                    "WHERE tenant_id = %s AND deployment_id = %s AND alert_id = %s",
                    (tenant_id, deployment_id, alert_id),
                )
                row = cursor.fetchone()
                if row is None:
                    raise ValueError("deterministic alert identifier belongs to another deployment")
                payload = dict(_json_value(self._mapping(cursor, row)["payload_json"], {}))
        return created, payload

    def close(self) -> None:
        return None


class ClickHouseEventAdapter:
    """HTTP adapter for normalized telemetry in ClickHouse."""

    backend = "clickhouse"
    supports_product_io = True

    def __init__(
        self,
        endpoint: str,
        *,
        database: str = "hybrid_ndr",
        user: str = "",
        password: str = "",
        timeout_seconds: float = 3.0,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
    ) -> None:
        if not _IDENTIFIER.fullmatch(database):
            raise ValueError("ClickHouse database contains invalid characters")
        self.endpoint = endpoint.rstrip("/")
        self.database = database
        self.user = user
        self.password = password
        self.timeout_seconds = timeout_seconds
        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)
        self._search_schema_ensured = False

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    def _ensure_search_schema(self) -> None:
        """Idempotently converge upgraded tables to the current schema.

        Adds the token-search column/index and converts the IP columns from
        IPv6 to String so missing addresses are stored as empty strings (the
        NormalizedEvent contract) instead of the unspecified address "::" —
        which otherwise creates phantom source entities for detection and
        wastes redaction token slots. IPv6 columns must drop their bloom
        indexes before the type change, so the sequence is explicit.
        """
        if self._search_schema_ensured:
            return
        self._search_schema_ensured = True
        self._request(
            f"ALTER TABLE {self.database}.network_events "
            "ADD COLUMN IF NOT EXISTS search_text String, "
            "ADD INDEX IF NOT EXISTS search_text_tokenbf search_text "
            "TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4"
        )
        self._request(
            f"ALTER TABLE {self.database}.network_events "
            "DROP INDEX IF EXISTS source_ip_bloom, "
            "DROP INDEX IF EXISTS destination_ip_bloom, "
            "MODIFY COLUMN src_ip String, MODIFY COLUMN dst_ip String, "
            "ADD INDEX IF NOT EXISTS source_ip_bloom src_ip TYPE bloom_filter(0.01) GRANULARITY 4, "
            "ADD INDEX IF NOT EXISTS destination_ip_bloom dst_ip TYPE bloom_filter(0.01) GRANULARITY 4"
        )

    @staticmethod
    def _search_text(item: NormalizedEvent) -> str:
        """Lowercased, bounded token stream indexed for payload search.

        The index covers the structured event fields AND every string value in
        the details dict (DNS queries, HTTP URLs, TLS server names, ...). That
        is the intended full-text search feature, but it means anything that
        reaches the details dict becomes token-searchable: the model-request
        redaction pipeline scrubs details before external calls, and direct
        event storage is expected to carry only normalized, non-secret event
        content from the sensor pipeline.
        """
        parts = [
            item.source, item.event_type, item.sensor_id, item.community_id, item.protocol,
            item.raw_reference, item.event_id, item.src_ip, item.dst_ip,
        ]
        details = item.details if isinstance(item.details, dict) else {}
        for key, value in details.items():
            parts.append(str(key))
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                parts.append(str(value))
            elif isinstance(value, list):
                parts.extend(str(entry) for entry in value if isinstance(entry, (str, int, float)))
        return " ".join(part for part in parts if part)[:16_384].lower()

    @staticmethod
    def _uuid(value: str, field: str) -> str:
        try:
            return str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"{field} must be a UUID for production event storage") from exc

    @staticmethod
    def _ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("entity_id must be an IP address for an event timeline") from exc

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "hybrid-ndr-local-api/1"}
        if self.user:
            encoded = base64.b64encode(f"{self.user}:{self.password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        return headers

    def _request(self, query: str, *, body: bytes | None = None) -> bytes:
        params = {"database": self.database, "date_time_input_format": "best_effort"}
        request_body = body if body is not None else query.encode("utf-8")
        request = Request(
            f"{self.endpoint}/?{urlencode(params)}", data=request_body, method="POST",
            headers={**self._headers(), "Content-Type": "text/plain; charset=utf-8"},
        )
        response = self._opener(request, timeout=self.timeout_seconds)
        return response.read()

    def readiness(self) -> Readiness:
        started = time.monotonic()
        query = f"SELECT count() FROM system.databases WHERE name = {self._quote(self.database)} FORMAT TabSeparated"
        try:
            body = self._request(query).decode("ascii", "strict").strip()
            ready = body == "1"
            return Readiness(
                self.backend, ready, "database", "database verified" if ready else "required database is missing",
                _elapsed(started),
            )
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError) as exc:
            return Readiness(self.backend, False, "database", _safe_error(exc), _elapsed(started))

    def insert_event(self, event: NormalizedEvent | Mapping[str, Any]) -> dict[str, Any]:
        return self.insert_events([event])[0]

    def insert_events(self, events: Iterable[NormalizedEvent | Mapping[str, Any]]) -> list[dict[str, Any]]:
        items = [event if isinstance(event, NormalizedEvent) else NormalizedEvent.from_dict(event) for event in events]
        if not items:
            return []
        self._ensure_search_schema()
        rows: list[str] = []
        payloads: list[dict[str, Any]] = []
        for item in items:
            payload = item.to_dict()
            details = payload.get("details", {})
            # Stored events use canonical JSON normalization (sorted keys,
            # compact separators, ensure_ascii): the round-trip through
            # _event_row is deterministic, and any non-normalized Unicode in
            # the original event is normalized at write time by design.
            row = {
                "tenant_id": self._uuid(item.tenant_id, "tenant_id"),
                "deployment_id": self._uuid(item.deployment_id, "deployment_id"),
                "event_id": self._uuid(item.event_id, "event_id"),
                "event_time": item.event_time,
                "ingested_at": item.ingested_at,
                "source": item.source,
                "event_type": item.event_type,
                "sensor_id": item.sensor_id,
                "community_id": item.community_id,
                "src_ip": item.src_ip or "",
                "src_port": item.src_port,
                "dst_ip": item.dst_ip or "",
                "dst_port": item.dst_port,
                "protocol": item.protocol,
                "duration_ms": item.duration_ms,
                "bytes_out": item.bytes_out,
                "bytes_in": item.bytes_in,
                "severity": int(details.get("severity", 0)),
                "signature": str(details.get("signature", "")),
                "raw_reference": item.raw_reference,
                "raw_event": canonical_json(payload),
                "search_text": self._search_text(item),
            }
            rows.append(canonical_json(row))
            payloads.append(payload)
        query = f"INSERT INTO {self.database}.network_events FORMAT JSONEachRow\n"
        self._request(query, body=(query + "\n".join(rows) + "\n").encode("utf-8"))
        return payloads

    def _select(self, where: str, limit: int, params: str = "", *, offset: int = 0) -> list[dict[str, Any]]:
        query = f"""SELECT
          toString(tenant_id) AS tenant_id_text,
          toString(deployment_id) AS deployment_id_text,
          toString(event_id) AS event_id_text,
          concat(replaceOne(toString(event_time), ' ', 'T'), 'Z') AS event_time_text,
          concat(replaceOne(toString(ingested_at), ' ', 'T'), 'Z') AS ingested_at_text,
          source, event_type, sensor_id, community_id, toString(src_ip) AS src_ip_text,
          src_port, toString(dst_ip) AS dst_ip_text, dst_port, protocol, duration_ms,
          bytes_out, bytes_in, severity, signature, raw_reference, raw_event
        FROM {self.database}.network_events
        WHERE {where} {params}
        ORDER BY event_time DESC LIMIT {max(1, min(int(limit), 1000))}
        OFFSET {max(0, min(int(offset), 100_000))}
        FORMAT JSONEachRow"""
        body = self._request(query).decode("utf-8")
        return [self._event_row(json.loads(line)) for line in body.splitlines() if line.strip()]

    @staticmethod
    def _event_row(row: Mapping[str, Any]) -> dict[str, Any]:
        details: dict[str, Any] = {}
        try:
            raw = json.loads(str(row.get("raw_event", "")))
            if isinstance(raw, dict):
                if raw.get("event_id") == row.get("event_id_text"):
                    details = dict(raw.get("details", {}))
                elif row.get("source") == "zeek":
                    for source_name, target_name in (
                        ("query", "query"), ("qtype_name", "query_type"),
                        ("service", "service"), ("server_name", "server_name"),
                    ):
                        if source_name in raw:
                            details[target_name] = raw[source_name]
            # A non-dict raw_event (JSON array/scalar) yields empty details by
            # design; detail extraction is best-effort and never crashes the
            # row mapping.
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        if row.get("signature"):
            details.setdefault("signature", row["signature"])
        if int(row.get("severity", 0)):
            details.setdefault("severity", int(row["severity"]))
        def display_ip(value: Any) -> str:
            try:
                parsed = ipaddress.ip_address(str(value))
                if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
                    return str(parsed.ipv4_mapped)
                return str(parsed)
            except ValueError:
                return str(value or "")

        return {
            "tenant_id": row["tenant_id_text"], "deployment_id": row["deployment_id_text"],
            "event_id": row["event_id_text"], "event_time": row["event_time_text"],
            "ingested_at": row["ingested_at_text"], "source": row["source"],
            "event_type": row["event_type"], "sensor_id": row["sensor_id"],
            "community_id": row.get("community_id", ""), "src_ip": display_ip(row.get("src_ip_text", "")),
            "src_port": int(row.get("src_port", 0)), "dst_ip": display_ip(row.get("dst_ip_text", "")),
            "dst_port": int(row.get("dst_port", 0)), "protocol": row.get("protocol", ""),
            "duration_ms": int(row.get("duration_ms", 0)), "bytes_out": int(row.get("bytes_out", 0)),
            "bytes_in": int(row.get("bytes_in", 0)), "raw_reference": row.get("raw_reference", ""),
            "details": details,
        }

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
        tenant = self._uuid(tenant_id, "tenant_id")
        self._ensure_search_schema()
        clauses = [f"tenant_id = toUUID({self._quote(tenant)})"]
        if deployment_id:
            clauses.append(
                f"deployment_id = toUUID({self._quote(self._uuid(deployment_id, 'deployment_id'))})"
            )
        if event_type:
            clauses.append(f"event_type = {self._quote(event_type)}")
        if source:
            clauses.append(f"source = {self._quote(source)}")
        if entity_id:
            entity = self._ip(entity_id)
            clauses.append(f"(src_ip = {self._quote(entity)} OR dst_ip = {self._quote(entity)})")
        if query_text:
            # Tokenized search over the indexed search_text column. The
            # tokenbf_v1 index accelerates multiSearchAnyCaseInsensitive, so
            # payload search does not scan every raw_event blob.
            tokens = [token for token in re.split(r"[^A-Za-z0-9]+", query_text) if token][:20]
            if tokens:
                token_list = ", ".join(self._quote(token) for token in tokens)
                clauses.append(f"multiSearchAnyCaseInsensitive(search_text, [{token_list}]) > 0")
        if start_time:
            clauses.append(f"event_time >= parseDateTime64BestEffort({self._quote(start_time)})")
        if end_time:
            clauses.append(f"event_time <= parseDateTime64BestEffort({self._quote(end_time)})")
        if protocol:
            clauses.append(f"lower(protocol) = lower({self._quote(protocol)})")
        if src_ip:
            clauses.append(f"src_ip = {self._quote(self._ip(src_ip))}")
        if dst_ip:
            clauses.append(f"dst_ip = {self._quote(self._ip(dst_ip))}")
        if sensor_id:
            clauses.append(f"sensor_id = {self._quote(sensor_id)}")
        if event_id:
            clauses.append(f"event_id = toUUID({self._quote(self._uuid(event_id, 'event_id'))})")
        return self._select(" AND ".join(clauses), limit, offset=offset)

    def get_events(
        self,
        tenant_id: str,
        evidence_ids: Iterable[str],
        *,
        deployment_id: str | None = None,
    ) -> list[dict[str, Any]]:
        tenant = self._uuid(tenant_id, "tenant_id")
        ids = [self._uuid(item, "event_id") for item in dict.fromkeys(evidence_ids)][:100]
        if not ids:
            return []
        self._ensure_search_schema()
        id_list = ",".join(f"toUUID({self._quote(item)})" for item in ids)
        where = f"tenant_id = toUUID({self._quote(tenant)}) AND event_id IN ({id_list})"
        if deployment_id:
            where += f" AND deployment_id = toUUID({self._quote(self._uuid(deployment_id, 'deployment_id'))})"
        rows = self._select(where, len(ids))
        by_id = {item["event_id"]: item for item in rows}
        return [by_id[item] for item in ids if item in by_id]

    def get_baseline(self, tenant_id: str, deployment_id: str, entity_id: str) -> dict[str, Any]:
        tenant = self._uuid(tenant_id, "tenant_id")
        deployment = self._uuid(deployment_id, "deployment_id")
        entity = self._ip(entity_id)
        self._ensure_search_schema()
        query = f"""SELECT
          count() AS event_count,
          countIf(positionCaseInsensitive(event_type, 'dns') > 0) AS dns_events,
          quantileExact(0.5)(bytes_out + bytes_in) AS traffic_median,
          quantileExact(0.99)(bytes_out + bytes_in) AS traffic_p99,
          if(count() = 0, NULL, concat(replaceOne(toString(max(ingested_at)), ' ', 'T'), 'Z')) AS updated_at
        FROM {self.database}.network_events
        WHERE tenant_id = toUUID({self._quote(tenant)})
          AND deployment_id = toUUID({self._quote(deployment)})
          AND (src_ip = {self._quote(entity)} OR dst_ip = {self._quote(entity)})
        FORMAT JSONEachRow"""
        lines = self._request(query).decode("utf-8").splitlines()
        row = json.loads(lines[0]) if lines else {}
        count = int(row.get("event_count", 0))
        return {
            "entity_id": entity_id, "status": "established" if count >= 20 else "learning",
            "event_count": count, "dns_events": int(row.get("dns_events", 0)),
            "traffic_median": float(row.get("traffic_median", 0)),
            "traffic_p99": float(row.get("traffic_p99", 0)), "updated_at": row.get("updated_at"),
        }

    def events_ingested_between(
        self,
        tenant_id: str,
        deployment_id: str,
        start: dt.datetime,
        end: dt.datetime,
        *,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        tenant = self._uuid(tenant_id, "tenant_id")
        deployment = self._uuid(deployment_id, "deployment_id")
        start_text = _iso(start)
        end_text = _iso(end)
        self._ensure_search_schema()
        query = f"""SELECT
          toString(tenant_id) AS tenant_id_text,
          toString(deployment_id) AS deployment_id_text,
          toString(event_id) AS event_id_text,
          concat(replaceOne(toString(event_time), ' ', 'T'), 'Z') AS event_time_text,
          concat(replaceOne(toString(ingested_at), ' ', 'T'), 'Z') AS ingested_at_text,
          source, event_type, sensor_id, community_id, toString(src_ip) AS src_ip_text,
          src_port, toString(dst_ip) AS dst_ip_text, dst_port, protocol, duration_ms,
          bytes_out, bytes_in, severity, signature, raw_reference, raw_event
        FROM {self.database}.network_events
        WHERE tenant_id = toUUID({self._quote(tenant)})
          AND deployment_id = toUUID({self._quote(deployment)})
          AND ingested_at >= parseDateTime64BestEffort({self._quote(start_text)})
          AND ingested_at <= parseDateTime64BestEffort({self._quote(end_text)})
        ORDER BY ingested_at DESC, event_id DESC
        LIMIT {max(1, min(int(limit), 50_000))}
        FORMAT JSONEachRow"""
        body = self._request(query).decode("utf-8")
        return [self._event_row(json.loads(line)) for line in body.splitlines() if line.strip()]

    def calculate_detection_baselines(
        self,
        tenant_id: str,
        deployment_id: str,
        start: dt.datetime,
        end: dt.datetime,
    ) -> dict[str, dict[str, Any]]:
        tenant = self._uuid(tenant_id, "tenant_id")
        deployment = self._uuid(deployment_id, "deployment_id")
        self._ensure_search_schema()
        scope = f"""tenant_id = toUUID({self._quote(tenant)})
          AND deployment_id = toUUID({self._quote(deployment)})
          AND event_time >= parseDateTime64BestEffort({self._quote(_iso(start))})
          AND event_time < parseDateTime64BestEffort({self._quote(_iso(end))})
          AND src_ip != ''"""
        bucket_query = f"""SELECT
          toString(src_ip) AS entity_id,
          toString(toStartOfMinute(event_time)) AS minute,
          countIf(positionCaseInsensitive(event_type, 'dns') > 0) AS dns_queries,
          sum(bytes_out) AS traffic_bytes
        FROM {self.database}.network_events
        WHERE {scope}
        GROUP BY src_ip, minute
        ORDER BY entity_id, minute
        FORMAT JSONEachRow"""
        destination_query = f"""SELECT
          toString(src_ip) AS entity_id,
          groupUniqArray(256)(toString(dst_ip)) AS known_destinations,
          groupUniqArrayIf(64)(toString(dst_ip), positionCaseInsensitive(event_type, 'dns') > 0)
            AS known_dns_destinations
        FROM {self.database}.network_events
        WHERE {scope}
        GROUP BY src_ip
        FORMAT JSONEachRow"""
        buckets: dict[str, list[dict[str, Any]]] = {}
        for line in self._request(bucket_query).decode("utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                buckets.setdefault(row["entity_id"], []).append(row)
        destinations = {
            row["entity_id"]: row
            for line in self._request(destination_query).decode("utf-8").splitlines()
            if line.strip()
            for row in (json.loads(line),)
        }
        result: dict[str, dict[str, Any]] = {}
        for entity_id, rows in buckets.items():
            dns_counts = [float(row.get("dns_queries", 0)) for row in rows]
            traffic = [float(row.get("traffic_bytes", 0)) for row in rows]
            median = float(statistics.median(dns_counts)) if dns_counts else 0.0
            deviations = [abs(value - median) for value in dns_counts]
            known = destinations.get(entity_id, {})
            result[entity_id] = {
                "dns_median": median,
                "dns_mad": float(statistics.median(deviations)) if deviations else 0.0,
                "dns_p99": _percentile(dns_counts, 0.99),
                "traffic_p99": _percentile(traffic, 0.99),
                "known_destinations": sorted(set(known.get("known_destinations", ())))[:256],
                "known_dns_destinations": sorted(set(known.get("known_dns_destinations", ())))[:64],
                "sample_windows": len(rows),
            }
        peer_dns_p99 = _percentile((item["dns_p99"] for item in result.values()), 0.99)
        peer_traffic_p99 = _percentile((item["traffic_p99"] for item in result.values()), 0.99)
        for baseline in result.values():
            baseline["peer_dns_p99"] = peer_dns_p99
            baseline["peer_traffic_p99"] = peer_traffic_p99
        return result

    def close(self) -> None:
        return None


class MinIOEvidenceAdapter:
    """Minimal SigV4 S3 client for tenant/deployment-scoped immutable evidence."""

    backend = "minio"
    supports_product_io = True
    maximum_object_bytes = 100 * 1024 * 1024

    def __init__(
        self,
        endpoint: str,
        *,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
        timeout_seconds: float = 3.0,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
        utcnow: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise ValueError("invalid MinIO endpoint")
        if not bucket or "/" in bucket:
            raise ValueError("invalid MinIO bucket")
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.timeout_seconds = timeout_seconds
        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)
        self._utcnow = utcnow

    @staticmethod
    def _segment(value: str, field: str) -> str:
        value = str(value)
        if not value or len(value) > 256 or any(ord(character) < 32 for character in value):
            raise ValueError(f"invalid {field}")
        return quote(value, safe="-_.~")

    def _object_key(self, tenant_id: str, deployment_id: str, object_id: str) -> str:
        return "/".join((
            self._segment(tenant_id, "tenant_id"), self._segment(deployment_id, "deployment_id"),
            self._segment(object_id, "object_id"),
        ))

    def _signature_key(self, date_stamp: str) -> bytes:
        date_key = hmac.new(("AWS4" + self.secret_key).encode(), date_stamp.encode("ascii"), hashlib.sha256).digest()
        region_key = hmac.new(date_key, self.region.encode(), hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
        return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()

    def _signed_request(
        self,
        method: str,
        *,
        key: str | None = None,
        payload: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> Request:
        parsed = urlparse(self.endpoint)
        timestamp = self._utcnow().astimezone(dt.timezone.utc)
        amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = timestamp.strftime("%Y%m%d")
        path = f"/{quote(self.bucket, safe='-_.~')}"
        if key is not None:
            path += "/" + key
        payload_hash = hashlib.sha256(payload).hexdigest()
        signed = {
            "host": parsed.netloc,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
            **{name.lower(): " ".join(str(value).strip().split()) for name, value in (headers or {}).items()},
        }
        names = ";".join(sorted(signed))
        canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
        canonical_request = "\n".join((method, path, "", canonical_headers, names, payload_hash))
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ))
        signature = hmac.new(self._signature_key(date_stamp), string_to_sign.encode(), hashlib.sha256).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={names}, Signature={signature}"
        )
        request_headers = {name.title(): value for name, value in signed.items()}
        request_headers["Authorization"] = authorization
        request_headers["User-Agent"] = "hybrid-ndr-local-api/1"
        return Request(
            f"{self.endpoint}{path}", data=payload if method in {"PUT", "POST"} else None,
            method=method, headers=request_headers,
        )

    def readiness(self) -> Readiness:
        started = time.monotonic()
        try:
            health = self._opener(
                Request(f"{self.endpoint}/minio/health/ready", headers={"User-Agent": "hybrid-ndr-local-api/1"}),
                timeout=self.timeout_seconds,
            )
            if getattr(health, "status", 200) != 200:
                return Readiness(self.backend, False, "bucket", "service is not ready", _elapsed(started))
            response = self._opener(self._signed_request("HEAD"), timeout=self.timeout_seconds)
            ready = getattr(response, "status", 200) in {200, 204}
            return Readiness(
                self.backend, ready, "bucket", "service and bucket verified" if ready else "required bucket is missing",
                _elapsed(started),
            )
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return Readiness(self.backend, False, "bucket", _safe_error(exc), _elapsed(started))

    def put(
        self,
        tenant_id: str,
        deployment_id: str,
        object_id: str,
        data: bytes | bytearray | memoryview | str,
        *,
        content_type: str = "application/octet-stream",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        body = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if len(body) > self.maximum_object_bytes:
            raise ValueError("evidence object exceeds the 100 MiB limit")
        if "\n" in content_type or "\r" in content_type:
            raise ValueError("invalid content_type")
        key = self._object_key(tenant_id, deployment_id, object_id)
        digest = hashlib.sha256(body).hexdigest()
        object_metadata = {
            "tenant-id": tenant_id, "deployment-id": deployment_id, "object-id": object_id,
            "sha256": digest,
        }
        for name, value in (metadata or {}).items():
            normalized = str(name).strip().lower().replace("_", "-")
            if not _METADATA_KEY.fullmatch(normalized):
                raise ValueError("invalid evidence metadata key")
            if normalized in {"tenant-id", "deployment-id", "object-id", "sha256"}:
                raise ValueError("evidence metadata key is reserved")
            text = str(value)
            if len(text) > 1024 or "\r" in text or "\n" in text:
                raise ValueError("invalid evidence metadata value")
            object_metadata[normalized] = text
        headers = {
            "content-type": content_type,
            "if-none-match": "*",
            **{f"x-amz-meta-{key}": value for key, value in object_metadata.items()},
        }
        try:
            response = self._opener(
                self._signed_request("PUT", key=key, payload=body, headers=headers), timeout=self.timeout_seconds
            )
            response_headers = getattr(response, "headers", {})
            etag = str(response_headers.get("ETag", "")).strip('"') if response_headers else ""
        except HTTPError as exc:
            if exc.code in {409, 412}:
                raise FileExistsError("evidence object already exists") from exc
            raise OSError(f"evidence write failed with HTTP {exc.code}") from exc
        return {
            "tenant_id": tenant_id, "deployment_id": deployment_id, "object_id": object_id,
            "bucket": self.bucket, "key": key, "content_type": content_type, "size": len(body),
            "sha256": digest, "etag": etag, "metadata": object_metadata,
        }

    def get(self, tenant_id: str, deployment_id: str, object_id: str) -> dict[str, Any]:
        key = self._object_key(tenant_id, deployment_id, object_id)
        try:
            response = self._opener(self._signed_request("GET", key=key), timeout=self.timeout_seconds)
            body = response.read(self.maximum_object_bytes + 1)
            if len(body) > self.maximum_object_bytes:
                raise ValueError("evidence object exceeds the 100 MiB limit")
            source_headers = getattr(response, "headers", {})
            headers = {str(name).lower(): str(value) for name, value in source_headers.items()} if source_headers else {}
        except HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError("evidence object not found") from exc
            raise OSError(f"evidence read failed with HTTP {exc.code}") from exc
        metadata = {
            name.removeprefix("x-amz-meta-"): value
            for name, value in headers.items() if name.startswith("x-amz-meta-")
        }
        if metadata.get("tenant-id", tenant_id) != tenant_id or metadata.get("deployment-id", deployment_id) != deployment_id:
            raise NotFoundError("evidence object not found")
        digest = hashlib.sha256(body).hexdigest()
        expected = metadata.get("sha256")
        if expected and not hmac.compare_digest(expected, digest):
            raise ValueError("evidence object integrity check failed")
        return {
            "tenant_id": tenant_id, "deployment_id": deployment_id, "object_id": object_id,
            "bucket": self.bucket, "key": key, "content_type": headers.get("content-type", "application/octet-stream"),
            "size": len(body), "sha256": digest, "etag": headers.get("etag", "").strip('"'),
            "metadata": metadata, "data": body,
        }


class ProductionStore:
    """LocalStore-compatible facade across the three production backends."""

    backend = "production"

    def __init__(self, metadata: PostgresMetadataAdapter, events: ClickHouseEventAdapter, evidence: MinIOEvidenceAdapter) -> None:
        self.metadata = metadata
        self.events = events
        self.evidence = evidence
        self.audit = metadata.audit

    def __getattr__(self, name: str) -> Any:
        return getattr(self.metadata, name)

    def insert_event(self, event: NormalizedEvent | Mapping[str, Any]) -> dict[str, Any]:
        return self.events.insert_event(event)

    def insert_events(self, events: Iterable[NormalizedEvent | Mapping[str, Any]]) -> list[dict[str, Any]]:
        return self.events.insert_events(events)

    def search_events(self, tenant_id: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self.events.search_events(tenant_id, **kwargs)

    def get_events(self, tenant_id: str, evidence_ids: Iterable[str], **kwargs: Any) -> list[dict[str, Any]]:
        return self.events.get_events(tenant_id, evidence_ids, **kwargs)

    def get_baseline(self, tenant_id: str, deployment_id: str, entity_id: str) -> dict[str, Any]:
        # The runtime baseline is calculated over resident telemetry. Explicit
        # detector configuration remains durable in PostgreSQL via set_baseline.
        computed = self.events.get_baseline(tenant_id, deployment_id, entity_id)
        configured = self.metadata.get_baseline(tenant_id, deployment_id, entity_id)
        if configured.get("updated_at"):
            computed["configured"] = {
                key: value for key, value in configured.items() if key not in {"entity_id", "updated_at", "status"}
            }
            computed["configuration_updated_at"] = configured["updated_at"]
        return computed

    def put_evidence(self, tenant_id: str, deployment_id: str, object_id: str, data: Any, **kwargs: Any) -> dict[str, Any]:
        return self.evidence.put(tenant_id, deployment_id, object_id, data, **kwargs)

    def get_evidence(self, tenant_id: str, deployment_id: str, object_id: str) -> dict[str, Any]:
        return self.evidence.get(tenant_id, deployment_id, object_id)

    def readiness(self) -> Readiness:
        started = time.monotonic()
        checks = (self.metadata.readiness(), self.events.readiness(), self.evidence.readiness())
        ready = all(check.ready for check in checks)
        return Readiness(self.backend, ready, "product_store", "all backends verified" if ready else "backend unavailable", _elapsed(started))

    def reset_demo(self, *_args: Any, **_kwargs: Any) -> dict[str, int]:
        raise ValueError("demo reset is disabled for production persistence")

    def close(self) -> None:
        self.metadata.close()
        self.events.close()
