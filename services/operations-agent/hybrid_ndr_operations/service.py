from __future__ import annotations

import base64
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from hybrid_ndr_observability import exception as log_exception, warning as log_warning


_CLICKHOUSE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")
_METRIC_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SENSOR_TYPES = frozenset({"suricata", "zeek"})
_SENSOR_STATUSES = frozenset({"online", "offline", "degraded", "error", "stale"})
_DETECTION_JOBS = (
    "fast-10s",
    "behavior-1m",
    "tunneling-5m",
    "baseline-hourly",
    "model-retraining-daily",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _bounded_int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(env.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _endpoint(value: str, name: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid HTTP URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{name} must be an internal HTTP(S) URL without credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError(f"{name} must be an origin without a path, query, or fragment")
    return value.rstrip("/")


@dataclass(frozen=True)
class OperationsConfig:
    postgres_url: str
    clickhouse_url: str
    clickhouse_database: str
    clickhouse_user: str
    clickhouse_password: str
    minio_url: str
    migration_file: Path
    ca_file: str = ""
    poll_seconds: int = 15
    retention_interval_seconds: int = 86_400
    health_snapshot_interval_seconds: int = 3_600
    clickhouse_event_retention_days: int = 30
    postgres_event_retention_days: int = 30
    operational_history_retention_days: int = 90
    minio_raw_retention_days: int = 30
    minio_case_retention_days: int = 365
    minio_export_retention_days: int = 30

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> "OperationsConfig":
        database = environ.get("CLICKHOUSE_DATABASE", "hybrid_ndr").strip()
        if not _CLICKHOUSE_IDENTIFIER.fullmatch(database):
            raise ValueError("CLICKHOUSE_DATABASE is not a valid identifier")
        postgres_url = environ.get("POSTGRES_URL", "").strip()
        clickhouse_user = environ.get("CLICKHOUSE_USER", "").strip()
        clickhouse_password = environ.get("CLICKHOUSE_PASSWORD", "").strip()
        if not postgres_url or not clickhouse_user or not clickhouse_password:
            raise ValueError("POSTGRES_URL, CLICKHOUSE_USER, and CLICKHOUSE_PASSWORD are required")
        ca_file = environ.get("PERSISTENCE_CA_FILE", "").strip()
        if ca_file:
            from hybrid_ndr_storage.tls import postgres_dsn_with_tls

            postgres_url = postgres_dsn_with_tls(postgres_url, ca_file)
        return cls(
            postgres_url=postgres_url,
            clickhouse_url=_endpoint(
                environ.get("CLICKHOUSE_URL", "http://clickhouse:8123").strip(), "CLICKHOUSE_URL"
            ),
            clickhouse_database=database,
            clickhouse_user=clickhouse_user,
            clickhouse_password=clickhouse_password,
            minio_url=_endpoint(environ.get("MINIO_ENDPOINT", "http://minio:9000").strip(), "MINIO_ENDPOINT"),
            ca_file=ca_file,
            migration_file=Path(environ.get(
                "OPERATIONS_MIGRATION_FILE", "/opt/hybrid-ndr/003-operational-retention.sql"
            )),
            poll_seconds=_bounded_int(environ, "OPERATIONS_POLL_SECONDS", 15, 5, 300),
            retention_interval_seconds=_bounded_int(
                environ, "RETENTION_INTERVAL_SECONDS", 86_400, 3_600, 604_800
            ),
            health_snapshot_interval_seconds=_bounded_int(
                environ, "OPERATIONS_HEALTH_SNAPSHOT_SECONDS", 3_600, 300, 86_400
            ),
            clickhouse_event_retention_days=_bounded_int(
                environ, "CLICKHOUSE_EVENT_RETENTION_DAYS", 30, 1, 3650
            ),
            postgres_event_retention_days=_bounded_int(
                environ, "POSTGRES_EVENT_RETENTION_DAYS", 30, 1, 3650
            ),
            operational_history_retention_days=_bounded_int(
                environ, "OPERATIONAL_HISTORY_RETENTION_DAYS", 90, 1, 3650
            ),
            minio_raw_retention_days=_bounded_int(environ, "MINIO_RAW_RETENTION_DAYS", 30, 1, 3650),
            minio_case_retention_days=_bounded_int(environ, "MINIO_CASE_RETENTION_DAYS", 365, 1, 3650),
            minio_export_retention_days=_bounded_int(environ, "MINIO_EXPORT_RETENTION_DAYS", 30, 1, 3650),
        )


class PostgresOperations:
    def __init__(self, dsn: str, *, connect: Callable[..., Any] | None = None) -> None:
        self.dsn = dsn
        if connect is None:
            import psycopg
            connect = psycopg.connect
        self._connect = connect

    def migrate(self, path: Path) -> None:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256_000:
            raise RuntimeError("operational migration file is unavailable")
        sql = path.read_text(encoding="utf-8").replace("\\set ON_ERROR_STOP on", "", 1)
        with self._connect(self.dsn, connect_timeout=5) as connection:
            connection.execute(sql)

    def metrics(self, now: datetime) -> dict[str, Any]:
        with self._connect(self.dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """SELECT sensor_type, status, count(*)::bigint,
                              COALESCE(sum(events_per_second), 0)::double precision,
                              EXTRACT(epoch FROM (%s::timestamptz - max(last_seen)))::double precision
                       FROM local_state.sensors
                       GROUP BY sensor_type, status""",
                    (now,),
                )
                sensors = [
                    {
                        "sensor_type": str(row[0]),
                        "status": str(row[1]),
                        "count": int(row[2]),
                        "events_per_second": float(row[3]),
                        "last_seen_age_seconds": max(0.0, float(row[4])),
                    }
                    for row in cursor.fetchall()
                ]
                cursor.execute(
                    """SELECT job_name,
                              EXTRACT(epoch FROM (%s::timestamptz - completed_at))::double precision
                       FROM local_state.detection_checkpoints""",
                    (now,),
                )
                detection_jobs = {
                    str(row[0]): max(0.0, float(row[1])) for row in cursor.fetchall()
                }
                cursor.execute("SELECT pg_database_size(current_database())")
                database_bytes = int(cursor.fetchone()[0])
                cursor.execute(
                    """SELECT status, last_completed_at, rows_affected, detail_code
                       FROM local_state.operational_jobs WHERE job_name = 'retention-daily'"""
                )
                row = cursor.fetchone()
                retention = None if row is None else {
                    "status": str(row[0]),
                    "last_completed_at": row[1],
                    "rows_affected": int(row[2]),
                    "detail_code": str(row[3]),
                }
        return {
            "sensors": sensors,
            "detection_jobs": detection_jobs,
            "database_bytes": database_bytes,
            "retention": retention,
        }

    def retention_due(self, now: datetime, interval_seconds: int) -> bool:
        with self._connect(self.dsn, connect_timeout=5) as connection:
            row = connection.execute(
                """SELECT last_completed_at FROM local_state.operational_jobs
                   WHERE job_name = 'retention-daily' AND status = 'succeeded'"""
            ).fetchone()
        return row is None or row[0] is None or now >= row[0] + timedelta(seconds=interval_seconds)

    def start_job(self, now: datetime) -> None:
        with self._connect(self.dsn, connect_timeout=5) as connection:
            connection.execute(
                """INSERT INTO local_state.operational_jobs
                     (job_name, status, last_started_at, last_completed_at, rows_affected, detail_code)
                   VALUES ('retention-daily', 'running', %s, NULL, 0, 'started')
                   ON CONFLICT (job_name) DO UPDATE SET
                     status = 'running', last_started_at = EXCLUDED.last_started_at,
                     rows_affected = 0, detail_code = 'started', updated_at = now()""",
                (now,),
            )

    def apply_retention(self, config: OperationsConfig, now: datetime) -> int:
        with self._connect(self.dsn, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext('hybrid-ndr-retention-daily'))")
                cursor.execute(
                    "DELETE FROM local_state.events WHERE event_time < %s::timestamptz - (%s * interval '1 day')",
                    (now, config.postgres_event_retention_days),
                )
                events_deleted = max(0, int(cursor.rowcount))
                cursor.execute(
                    "DELETE FROM local_state.operational_health_snapshots "
                    "WHERE collected_at < %s::timestamptz - (%s * interval '1 day')",
                    (now, config.operational_history_retention_days),
                )
                history_deleted = max(0, int(cursor.rowcount))
                cursor.execute(
                    """INSERT INTO local_state.retention_settings
                         (singleton, clickhouse_event_days, postgres_event_days,
                          minio_raw_days, minio_case_days, minio_export_days, updated_at)
                       VALUES (true, %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (singleton) DO UPDATE SET
                         clickhouse_event_days = EXCLUDED.clickhouse_event_days,
                         postgres_event_days = EXCLUDED.postgres_event_days,
                         minio_raw_days = EXCLUDED.minio_raw_days,
                         minio_case_days = EXCLUDED.minio_case_days,
                         minio_export_days = EXCLUDED.minio_export_days,
                         updated_at = EXCLUDED.updated_at""",
                    (
                        config.clickhouse_event_retention_days,
                        config.postgres_event_retention_days,
                        config.minio_raw_retention_days,
                        config.minio_case_retention_days,
                        config.minio_export_retention_days,
                        now,
                    ),
                )
        return events_deleted + history_deleted

    def finish_job(self, now: datetime, *, succeeded: bool, rows_affected: int, detail_code: str) -> None:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_]{1,63}", detail_code):
            detail_code = "internal_error"
        with self._connect(self.dsn, connect_timeout=5) as connection:
            connection.execute(
                """UPDATE local_state.operational_jobs SET
                     status = %s, last_completed_at = %s, rows_affected = %s,
                     detail_code = %s, updated_at = now()
                   WHERE job_name = 'retention-daily'""",
                ("succeeded" if succeeded else "failed", now, max(0, rows_affected), detail_code),
            )

    def save_health(self, now: datetime, evidence: Mapping[str, Any]) -> None:
        encoded = json.dumps(evidence, separators=(",", ":"), sort_keys=True)
        if len(encoded) > 64_000:
            raise RuntimeError("operational health evidence is too large")
        with self._connect(self.dsn, connect_timeout=5) as connection:
            connection.execute(
                """INSERT INTO local_state.operational_health_snapshots
                     (collected_at, status, evidence_json) VALUES (%s, %s, %s::jsonb)""",
                (now, evidence["status"], encoded),
            )


class ClickHouseOperations:
    def __init__(
        self,
        endpoint: str,
        database: str,
        user: str,
        password: str,
        *,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
    ) -> None:
        if not _CLICKHOUSE_IDENTIFIER.fullmatch(database):
            raise ValueError("ClickHouse database is not a valid identifier")
        self.endpoint = endpoint.rstrip("/")
        self.database = database
        self.user = user
        self.password = password
        from hybrid_ndr_storage.tls import verified_opener

        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)

    def _request(self, query: str) -> bytes:
        authorization = base64.b64encode(f"{self.user}:{self.password}".encode()).decode("ascii")
        request = Request(
            self.endpoint + "/",
            data=query.encode("utf-8"),
            method="POST",
            headers={
                "Authorization": "Basic " + authorization,
                "Content-Type": "text/plain; charset=utf-8",
                "User-Agent": "hybrid-ndr-operations/1",
            },
        )
        response = self._opener(request, timeout=5)
        body = response.read(1_000_001)
        if len(body) > 1_000_000:
            raise RuntimeError("ClickHouse operational response is too large")
        return body

    def apply_retention(self, days: int) -> None:
        if not 1 <= int(days) <= 3650:
            raise ValueError("ClickHouse retention must be between 1 and 3650 days")
        self._request(
            f"ALTER TABLE {self.database}.network_events "
            # event_time is DateTime64; ClickHouse TTL expressions must resolve
            # to DateTime/Date, so normalize before adding the interval.
            f"MODIFY TTL toDateTime(event_time) + toIntervalDay({int(days)}) DELETE"
        )

    def metrics(self, now: datetime) -> dict[str, Any]:
        parts = json.loads(self._request(
            "SELECT sum(rows) AS rows, sum(bytes_on_disk) AS bytes, count() AS parts "
            "FROM system.parts "
            f"WHERE active AND database = '{self.database}' AND table = 'network_events' FORMAT JSON"
        ))
        part_row = (parts.get("data") or [{}])[0]
        lag = json.loads(self._request(
            "SELECT source, greatest(0, dateDiff('second', max(ingested_at), now())) AS lag "
            f"FROM {self.database}.network_events GROUP BY source FORMAT JSON"
        ))
        activity = json.loads(self._request(
            "SELECT metric, value FROM system.metrics "
            "WHERE metric IN ('Query', 'Merge') FORMAT JSON"
        ))
        lags = {
            str(item.get("source")): max(0.0, float(item.get("lag", 0)))
            for item in lag.get("data", [])
            if str(item.get("source")) in {"suricata", "zeek"}
        }
        active = {str(item.get("metric")): float(item.get("value", 0)) for item in activity.get("data", [])}
        return {
            "rows": int(part_row.get("rows") or 0),
            "bytes": int(part_row.get("bytes") or 0),
            "parts": int(part_row.get("parts") or 0),
            "ingestion_lag": lags,
            "active_queries": active.get("Query", 0.0),
            "active_merges": active.get("Merge", 0.0),
            "checked_at": _timestamp(now),
        }


class OperationsBackend(Protocol):
    def postgres_metrics(self, now: datetime) -> Mapping[str, Any]: ...
    def clickhouse_metrics(self, now: datetime) -> Mapping[str, Any]: ...
    def minio_ready(self) -> bool: ...
    def retention_due(self, now: datetime, interval_seconds: int) -> bool: ...
    def run_retention(self, config: OperationsConfig, now: datetime) -> int: ...
    def save_health(self, now: datetime, evidence: Mapping[str, Any]) -> None: ...


class LocalOperationsBackend:
    def __init__(
        self,
        postgres: PostgresOperations,
        clickhouse: ClickHouseOperations,
        minio_url: str,
        *,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.postgres = postgres
        self.clickhouse = clickhouse
        self.minio_url = minio_url.rstrip("/")
        from hybrid_ndr_storage.tls import verified_opener

        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)

    def postgres_metrics(self, now: datetime) -> Mapping[str, Any]:
        return self.postgres.metrics(now)

    def clickhouse_metrics(self, now: datetime) -> Mapping[str, Any]:
        return self.clickhouse.metrics(now)

    def minio_ready(self) -> bool:
        response = self._opener(Request(self.minio_url + "/minio/health/ready"), timeout=3)
        return getattr(response, "status", 200) == 200

    def retention_due(self, now: datetime, interval_seconds: int) -> bool:
        return self.postgres.retention_due(now, interval_seconds)

    def run_retention(self, config: OperationsConfig, now: datetime) -> int:
        self.postgres.start_job(now)
        try:
            self.clickhouse.apply_retention(config.clickhouse_event_retention_days)
            affected = self.postgres.apply_retention(config, now)
            self.postgres.finish_job(now, succeeded=True, rows_affected=affected, detail_code="completed")
            return affected
        except Exception as exc:
            self.postgres.finish_job(
                now,
                succeeded=False,
                rows_affected=0,
                detail_code=("clickhouse_unavailable" if isinstance(exc, (HTTPError, URLError, TimeoutError, OSError)) else "retention_failed"),
            )
            log_exception("operations.retention.failed", exc)
            raise

    def save_health(self, now: datetime, evidence: Mapping[str, Any]) -> None:
        self.postgres.save_health(now, evidence)


class OperationsAgent:
    def __init__(self, config: OperationsConfig, backend: OperationsBackend) -> None:
        self.config = config
        self.backend = backend
        self.last_snapshot_at: datetime | None = None
        self.snapshot: dict[str, Any] = {
            "status": "degraded",
            "service": "operations-agent",
            "checked_at": None,
            "components": {},
            "schedules": {},
            "telemetry_boundary": {
                "scope": "customer-local-only",
                "external_exporters": 0,
                "customer_content_included": False,
            },
        }
        self.metrics: dict[str, Any] = {}

    def poll(self, now: datetime | None = None) -> dict[str, Any]:
        observed_at = (now or utc_now()).astimezone(timezone.utc)
        failures: set[str] = set()
        try:
            postgres = dict(self.backend.postgres_metrics(observed_at))
        except Exception as exc:
            postgres = {"sensors": [], "detection_jobs": {}, "database_bytes": 0, "retention": None}
            failures.add("postgres")
            log_exception("operations.poll.postgres_failed", exc)
        try:
            clickhouse = dict(self.backend.clickhouse_metrics(observed_at))
        except Exception as exc:
            clickhouse = {
                "rows": 0, "bytes": 0, "parts": 0, "ingestion_lag": {},
                "active_queries": 0, "active_merges": 0,
            }
            failures.add("clickhouse")
            log_exception("operations.poll.clickhouse_failed", exc)
        try:
            if not self.backend.minio_ready():
                failures.add("minio")
        except Exception:
            failures.add("minio")

        retention_ran = False
        retention_failed = False
        retention_rows = 0
        try:
            if not failures.intersection({"postgres", "clickhouse"}) and self.backend.retention_due(
                observed_at, self.config.retention_interval_seconds
            ):
                retention_rows = self.backend.run_retention(self.config, observed_at)
                retention_ran = True
        except Exception:
            failures.add("retention")
            retention_failed = True

        reported_jobs = postgres.get("detection_jobs", {})
        jobs: dict[str, dict[str, Any]] = {}
        for name in _DETECTION_JOBS:
            raw_age = reported_jobs.get(name) if isinstance(reported_jobs, Mapping) else None
            if raw_age is None or not math.isfinite(float(raw_age)):
                jobs[name] = {"age_seconds": None, "fresh": False}
                continue
            age = max(0.0, float(raw_age))
            jobs[name] = {"age_seconds": round(age, 3), "fresh": self._job_fresh(name, age)}
        if any(not item["fresh"] for item in jobs.values()):
            failures.add("detection_schedule")
        retention = postgres.get("retention")
        retention_status = (
            "failed" if retention_failed else "succeeded" if retention_ran else str(retention.get("status"))
            if isinstance(retention, Mapping) else "pending"
        )
        if retention_status == "failed":
            failures.add("retention")

        sensor_evidence: list[dict[str, Any]] = []
        for sensor in postgres.get("sensors", []):
            sensor_type = str(sensor.get("sensor_type", ""))
            status = str(sensor.get("status", ""))
            if sensor_type not in _SENSOR_TYPES or status not in _SENSOR_STATUSES:
                continue
            sensor_evidence.append({
                "sensor_type": sensor_type,
                "status": status,
                "count": max(0, int(sensor.get("count", 0))),
                "events_per_second": round(max(0.0, _finite(sensor.get("events_per_second", 0))), 3),
                "last_seen_age_seconds": round(
                    max(0.0, _finite(sensor.get("last_seen_age_seconds", 0))), 3
                ),
            })
        sensor_evidence.sort(key=lambda item: (item["sensor_type"], item["status"]))
        ingestion_lag: dict[str, float] = {}
        raw_lag = clickhouse.get("ingestion_lag", {})
        if isinstance(raw_lag, Mapping):
            for source in ("suricata", "zeek"):
                if source in raw_lag:
                    ingestion_lag[source] = round(max(0.0, _finite(raw_lag[source])), 3)

        self.metrics = {
            "postgres": postgres,
            "clickhouse": clickhouse,
            "dependency_up": {name: 0 if name in failures else 1 for name in ("postgres", "clickhouse", "minio")},
            "retention_rows": retention_rows if retention_ran else int(retention.get("rows_affected", 0))
            if isinstance(retention, Mapping) else 0,
            "retention_status": retention_status,
        }
        self.snapshot = {
            "status": "degraded" if failures else "healthy",
            "service": "operations-agent",
            "checked_at": _timestamp(observed_at),
            "components": {
                name: {"ready": name not in failures}
                for name in ("postgres", "clickhouse", "minio")
            },            "schedules": {
                "detection": jobs,
                "retention": {
                    "status": retention_status,
                    "ran_this_poll": retention_ran,
                },
            },
            "ingestion": {
                "source_lag_seconds": ingestion_lag,
            },
            "sensors": sensor_evidence,
            "storage": {
                "postgres_database_bytes": max(0, int(postgres.get("database_bytes", 0))),
                "clickhouse_event_rows": max(0, int(clickhouse.get("rows", 0))),
                "clickhouse_event_bytes": max(0, int(clickhouse.get("bytes", 0))),
                "clickhouse_active_parts": max(0, int(clickhouse.get("parts", 0))),
            },
            "clickhouse": {
                "active_queries": max(0.0, _finite(clickhouse.get("active_queries", 0))),
                "active_merges": max(0.0, _finite(clickhouse.get("active_merges", 0))),
            },
            "retention": {
                "clickhouse_event_days": self.config.clickhouse_event_retention_days,
                "postgres_event_days": self.config.postgres_event_retention_days,
                "minio_raw_days": self.config.minio_raw_retention_days,
                "minio_case_days": self.config.minio_case_retention_days,
                "minio_export_days": self.config.minio_export_retention_days,
            },
            "telemetry_boundary": {
                "scope": "customer-local-only",
                "external_exporters": 0,
                "customer_content_included": False,
            },
        }
        if (
            self.last_snapshot_at is None
            or observed_at >= self.last_snapshot_at + timedelta(seconds=self.config.health_snapshot_interval_seconds)
        ):
            try:
                self.backend.save_health(observed_at, self.snapshot)
                self.last_snapshot_at = observed_at
            except Exception:
                self.snapshot["status"] = "degraded"
                self.snapshot["components"]["postgres"] = {"ready": False}
                self.metrics["dependency_up"]["postgres"] = 0
        if failures:
            log_warning(
                "operations.poll.degraded",
                components=",".join(sorted(failures)),
            )
        return self.snapshot

    def _job_fresh(self, name: str, age: float) -> bool:
        limit = 7_200 if name == "baseline-hourly" else 172_800 if name == "model-retraining-daily" else 900
        return age <= limit


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def _finite(value: Any) -> float:
    number = float(value)
    return number if math.isfinite(number) else 0.0


def render_prometheus(agent: OperationsAgent) -> str:
    data = agent.metrics
    lines = [
        "# HELP hybrid_ndr_operations_up Customer-local operations agent health.",
        "# TYPE hybrid_ndr_operations_up gauge",
        f"hybrid_ndr_operations_up {1 if agent.snapshot.get('status') == 'healthy' else 0}",
        "# HELP hybrid_ndr_telemetry_external_exporters Configured external telemetry exporters.",
        "# TYPE hybrid_ndr_telemetry_external_exporters gauge",
        "hybrid_ndr_telemetry_external_exporters 0",
    ]
    for dependency, ready in sorted(data.get("dependency_up", {}).items()):
        lines.append(f'hybrid_ndr_dependency_up{{dependency="{_label(dependency)}"}} {int(ready)}')
    postgres = data.get("postgres", {})
    lines.append(f"hybrid_ndr_postgres_database_bytes {_finite(postgres.get('database_bytes', 0))}")
    for sensor in postgres.get("sensors", []):
        sensor_type = str(sensor.get("sensor_type", "unknown"))
        status = str(sensor.get("status", "unknown"))
        if sensor_type not in _SENSOR_TYPES or status not in _SENSOR_STATUSES:
            continue
        labels = f'sensor_type="{_label(sensor_type)}",status="{_label(status)}"'
        lines.append(f"hybrid_ndr_sensors{{{labels}}} {_finite(sensor.get('count', 0))}")
        lines.append(
            f'hybrid_ndr_sensor_events_per_second{{sensor_type="{_label(sensor_type)}"}} '
            f"{_finite(sensor.get('events_per_second', 0))}"
        )
        lines.append(
            f'hybrid_ndr_sensor_last_seen_age_seconds{{sensor_type="{_label(sensor_type)}"}} '
            f"{_finite(sensor.get('last_seen_age_seconds', 0))}"
        )
    for job, age in postgres.get("detection_jobs", {}).items():
        if _METRIC_LABEL.fullmatch(str(job)):
            lines.append(f'hybrid_ndr_detection_job_age_seconds{{job="{_label(str(job))}"}} {_finite(age)}')
    schedule_evidence = agent.snapshot.get("schedules", {}).get("detection", {})
    for job in _DETECTION_JOBS:
        evidence = schedule_evidence.get(job, {}) if isinstance(schedule_evidence, Mapping) else {}
        lines.append(
            f'hybrid_ndr_detection_job_fresh{{job="{job}"}} '
            f"{1 if evidence.get('fresh') is True else 0}"
        )
    clickhouse = data.get("clickhouse", {})
    for field, metric in (
        ("rows", "hybrid_ndr_clickhouse_event_rows"),
        ("bytes", "hybrid_ndr_clickhouse_table_bytes"),
        ("parts", "hybrid_ndr_clickhouse_active_parts"),
        ("active_queries", "hybrid_ndr_clickhouse_active_queries"),
        ("active_merges", "hybrid_ndr_clickhouse_active_merges"),
    ):
        lines.append(f"{metric} {_finite(clickhouse.get(field, 0))}")
    for source, lag in clickhouse.get("ingestion_lag", {}).items():
        if source in {"suricata", "zeek"}:
            lines.append(f'hybrid_ndr_ingestion_lag_seconds{{source="{source}"}} {_finite(lag)}')
    lines.extend([
        f"hybrid_ndr_retention_rows_deleted {_finite(data.get('retention_rows', 0))}",
        f"hybrid_ndr_retention_job_success {1 if data.get('retention_status') == 'succeeded' else 0}",
        f"hybrid_ndr_retention_policy_days{{backend=\"clickhouse\"}} {agent.config.clickhouse_event_retention_days}",
        f"hybrid_ndr_retention_policy_days{{backend=\"postgresql\"}} {agent.config.postgres_event_retention_days}",
        f"hybrid_ndr_retention_policy_days{{backend=\"minio-raw\"}} {agent.config.minio_raw_retention_days}",
        f"hybrid_ndr_retention_policy_days{{backend=\"minio-case\"}} {agent.config.minio_case_retention_days}",
        f"hybrid_ndr_retention_policy_days{{backend=\"minio-export\"}} {agent.config.minio_export_retention_days}",
    ])
    return "\n".join(lines) + "\n"
