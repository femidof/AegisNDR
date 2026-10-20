from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import MagicMock
from datetime import datetime, timezone
from pathlib import Path

import support  # noqa: F401
from hybrid_ndr_observability import Telemetry, sanitize_route, validate_collector_endpoint
from hybrid_ndr_operations import ClickHouseOperations, OperationsAgent, OperationsConfig, PostgresOperations, render_prometheus


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
EXPECTED_JOBS = {
    "fast-10s": 5,
    "behavior-1m": 20,
    "tunneling-5m": 120,
    "baseline-hourly": 1800,
    "model-retraining-daily": 43_200,
}


def operations_config(**overrides: object) -> OperationsConfig:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "deployment_id": "deployment-a",
        "postgres_url": "postgresql://ndr:secret@postgres:5432/hybrid_ndr",
        "clickhouse_url": "http://clickhouse:8123",
        "clickhouse_database": "hybrid_ndr",
        "clickhouse_user": "ndr",
        "clickhouse_password": "secret",
        "minio_url": "http://minio:9000",
        "migration_file": Path("/tmp/003-operational-retention.sql"),
    }
    values.update(overrides)
    return OperationsConfig(**values)  # type: ignore[arg-type]


class MemoryOperationsBackend:
    def __init__(self) -> None:
        self.due = True
        self.fail_retention = False
        self.saved: list[dict[str, object]] = []
        self.retention_runs = 0
        self.postgres = {
            "sensors": [
                {
                    "sensor_id": "customer-secret-sensor-id",
                    "sensor_type": "suricata",
                    "status": "online",
                    "count": 2,
                    "events_per_second": 120.5,
                    "last_seen_age_seconds": 4,
                },
                {
                    "sensor_type": "customer-defined-secret",
                    "status": "online",
                    "count": 1,
                    "events_per_second": 1,
                    "last_seen_age_seconds": 1,
                },
            ],
            "detection_jobs": dict(EXPECTED_JOBS),
            "database_bytes": 4096,
            "retention": {
                "status": "succeeded",
                "rows_affected": 3,
                "detail_code": "completed",
            },
        }
        self.clickhouse = {
            "rows": 42,
            "bytes": 8192,
            "parts": 3,
            "ingestion_lag": {
                "suricata": 3,
                "zeek": 7,
                "customer-secret-source": 999,
            },
            "active_queries": 2,
            "active_merges": 1,
        }

    def postgres_metrics(self, _now: datetime):
        return self.postgres

    def clickhouse_metrics(self, _now: datetime):
        return self.clickhouse

    def minio_ready(self) -> bool:
        return True

    def retention_due(self, _now: datetime, _interval_seconds: int) -> bool:
        return self.due

    def run_retention(self, _config: OperationsConfig, _now: datetime) -> int:
        self.retention_runs += 1
        if self.fail_retention:
            raise RuntimeError("simulated")
        return 8

    def save_health(self, _now: datetime, evidence):
        self.saved.append(json.loads(json.dumps(evidence)))


class CollectorBoundaryTests(unittest.TestCase):
    def test_otlp_endpoint_is_locked_to_customer_local_collector(self) -> None:
        self.assertEqual(
            validate_collector_endpoint("http://otel-collector:4318"),
            "http://otel-collector:4318",
        )
        for endpoint in (
            "https://otel-collector:4318",
            "http://telemetry.vendor.example:4318",
            "http://otel-collector:4318/v1/traces",
            "http://user:password@otel-collector:4318",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_collector_endpoint(endpoint)

    def test_wsgi_metrics_contain_only_bounded_operational_attributes(self) -> None:
        telemetry = Telemetry("local-api", {"OTEL_SDK_DISABLED": "true"})
        recorded: list[tuple[float, dict[str, object]]] = []

        class Recorder:
            def add(self, amount, attributes):
                recorded.append((float(amount), dict(attributes)))

            def record(self, amount, attributes):
                recorded.append((float(amount), dict(attributes)))

        telemetry._request_count = Recorder()  # type: ignore[attr-defined]
        telemetry._request_duration = Recorder()  # type: ignore[attr-defined]

        def application(_environ, start_response):
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b"{}"]

        observed = telemetry.wrap_wsgi(application)
        observed(
            {
                "REQUEST_METHOD": "GET",
                "PATH_INFO": "/v1/events/customer-event-123",
                "QUERY_STRING": "tenant_id=customer-secret",
                "HTTP_AUTHORIZATION": "Bearer customer-secret-token",
            },
            lambda _status, _headers: None,
        )
        self.assertEqual(sanitize_route("/v1/events/customer-event-123"), "/v1/events/:id")
        encoded = json.dumps(recorded, sort_keys=True)
        self.assertIn('"http.route": "/v1/events/:id"', encoded)
        self.assertNotIn("customer-event-123", encoded)
        self.assertNotIn("customer-secret", encoded)
        self.assertNotIn("authorization", encoded.lower())


class OperationsAgentTests(unittest.TestCase):
    def test_health_evidence_and_metrics_are_aggregated_and_content_free(self) -> None:
        backend = MemoryOperationsBackend()
        agent = OperationsAgent(operations_config(), backend)
        snapshot = agent.poll(NOW)

        self.assertEqual(snapshot["status"], "healthy")
        self.assertEqual(snapshot["telemetry_boundary"], {
            "scope": "customer-local-only",
            "external_exporters": 0,
            "customer_content_included": False,
        })
        self.assertEqual(snapshot["storage"]["clickhouse_event_bytes"], 8192)
        self.assertEqual(snapshot["sensors"], [{
            "sensor_type": "suricata",
            "status": "online",
            "count": 2,
            "events_per_second": 120.5,
            "last_seen_age_seconds": 4.0,
        }])
        self.assertEqual(snapshot["ingestion"]["source_lag_seconds"], {"suricata": 3.0, "zeek": 7.0})
        self.assertEqual(snapshot["schedules"]["retention"]["status"], "succeeded")
        self.assertEqual(backend.retention_runs, 1)
        self.assertEqual(len(backend.saved), 1)

        prometheus = render_prometheus(agent)
        for metric in (
            "hybrid_ndr_sensors",
            "hybrid_ndr_sensor_events_per_second",
            "hybrid_ndr_ingestion_lag_seconds",
            "hybrid_ndr_clickhouse_table_bytes",
            "hybrid_ndr_clickhouse_active_queries",
            "hybrid_ndr_postgres_database_bytes",
            "hybrid_ndr_retention_policy_days",
            "hybrid_ndr_telemetry_external_exporters 0",
        ):
            self.assertIn(metric, prometheus)

        exported = json.dumps({"support": backend.saved, "metrics": prometheus}, sort_keys=True)
        self.assertNotIn("customer-secret-sensor-id", exported)
        self.assertNotIn("customer-defined-secret", exported)
        self.assertNotIn("customer-secret-source", exported)
        for forbidden_key in ("tenant_id", "deployment_id", "event_id", "src_ip", "raw_reference"):
            self.assertNotIn(forbidden_key, exported)

    def test_missing_daily_checkpoint_is_explicitly_degraded(self) -> None:
        backend = MemoryOperationsBackend()
        backend.due = False
        del backend.postgres["detection_jobs"]["model-retraining-daily"]
        agent = OperationsAgent(operations_config(), backend)

        snapshot = agent.poll(NOW)
        self.assertEqual(snapshot["status"], "degraded")
        self.assertEqual(
            snapshot["schedules"]["detection"]["model-retraining-daily"],
            {"age_seconds": None, "fresh": False},
        )
        self.assertIn(
            'hybrid_ndr_detection_job_fresh{job="model-retraining-daily"} 0',
            render_prometheus(agent),
        )

    def test_retention_failure_is_visible_in_health_and_metrics(self) -> None:
        backend = MemoryOperationsBackend()
        backend.fail_retention = True
        agent = OperationsAgent(operations_config(), backend)

        snapshot = agent.poll(NOW)
        self.assertEqual(snapshot["status"], "degraded")
        self.assertEqual(snapshot["schedules"]["retention"]["status"], "failed")
        self.assertIn("hybrid_ndr_retention_job_success 0", render_prometheus(agent))


class ClickHouseOperationsTests(unittest.TestCase):
    class Response:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def read(self, _maximum: int) -> bytes:
            return self.body

    def test_retention_and_metrics_queries_are_bounded(self) -> None:
        requests = []
        responses = iter((
            b'{"data":[{"rows":"10","bytes":"2048","parts":"2"}]}',
            b'{"data":[{"source":"suricata","lag":"4"},{"source":"customer-name","lag":"999"}]}',
            b'{"data":[{"metric":"Query","value":"3"},{"metric":"Merge","value":"1"}]}',
        ))

        def opener(request, timeout):
            requests.append((request, timeout))
            return self.Response(next(responses))

        clickhouse = ClickHouseOperations(
            "http://clickhouse:8123", "hybrid_ndr", "ndr", "secret", opener=opener
        )
        metrics = clickhouse.metrics(NOW)
        self.assertEqual(metrics["ingestion_lag"], {"suricata": 4.0})
        self.assertEqual(metrics["bytes"], 2048)
        self.assertEqual(metrics["active_queries"], 3.0)
        self.assertTrue(all(timeout == 5 for _request, timeout in requests))
        self.assertTrue(all(request.full_url == "http://clickhouse:8123/" for request, _ in requests))

        retention_requests = []

        def retention_opener(request, timeout):
            retention_requests.append((request, timeout))
            return self.Response(b"")

        retention = ClickHouseOperations(
            "http://clickhouse:8123", "hybrid_ndr", "ndr", "secret", opener=retention_opener
        )
        retention.apply_retention(30)
        self.assertEqual(
            retention_requests[0][0].data.decode("utf-8"),
            "ALTER TABLE hybrid_ndr.network_events MODIFY TTL toDateTime(event_time) + toIntervalDay(30) DELETE",
        )
        with self.assertRaises(ValueError):
            retention.apply_retention(0)

    def test_invalid_database_identifier_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ClickHouseOperations("http://clickhouse:8123", "hybrid_ndr; DROP TABLE x", "ndr", "secret")


class PostgresOperationsScopeTests(unittest.TestCase):
    def test_metrics_bind_sensor_and_checkpoint_queries_to_installed_scope(self):
        connection = MagicMock()
        cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [
            [("zeek", "online", 1, 2.0, 3.0)], [("fast-10s", 5.0)]
        ]
        cursor.fetchone.side_effect = [(4096,), None]
        connect = MagicMock(return_value=connection)
        backend = PostgresOperations("postgresql://local", tenant_id="tenant-a", deployment_id="deployment-a", connect=connect)
        result = backend.metrics(NOW)
        self.assertEqual(result["detection_jobs"], {"fast-10s": 5.0})
        self.assertEqual(result["sensors"][0]["sensor_type"], "zeek")
        scoped = cursor.execute.call_args_list[:2]
        for call in scoped:
            self.assertIn("WHERE tenant_id = %s AND deployment_id = %s", call.args[0])
            self.assertEqual(call.args[1], (NOW, "tenant-a", "deployment-a"))

    def test_unscoped_monitoring_is_rejected(self):
        for tenant, deployment in (("", "deployment-a"), ("tenant-a", " ")):
            with self.assertRaises(ValueError):
                PostgresOperations("postgresql://local", tenant_id=tenant, deployment_id=deployment, connect=MagicMock())


class OperationsConfigurationTests(unittest.TestCase):
    def test_environment_requires_installed_tenant_and_deployment(self):
        environment = {"POSTGRES_URL": "postgresql://local", "CLICKHOUSE_USER": "ndr", "CLICKHOUSE_PASSWORD": "test"}
        for values in ({}, {"TENANT_ID": "tenant-a"}, {"DEPLOYMENT_ID": "deployment-a"}):
            with self.assertRaisesRegex(ValueError, "TENANT_ID and DEPLOYMENT_ID"):
                OperationsConfig.from_env({**environment, **values})

    def test_configuration_bounds_retention_and_internal_origins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            migration = Path(temporary) / "003.sql"
            migration.write_text("SELECT 1;\n", encoding="utf-8")
            environment = {
                "TENANT_ID": "tenant-a",
                "DEPLOYMENT_ID": "deployment-a",
                "POSTGRES_URL": "postgresql://ndr:secret@postgres:5432/hybrid_ndr",
                "CLICKHOUSE_USER": "ndr",
                "CLICKHOUSE_PASSWORD": "secret",
                "OPERATIONS_MIGRATION_FILE": str(migration),
                "CLICKHOUSE_EVENT_RETENTION_DAYS": "3651",
            }
            with self.assertRaises(ValueError):
                OperationsConfig.from_env(environment)
            environment["CLICKHOUSE_EVENT_RETENTION_DAYS"] = "30"
            # Verified HTTPS origins are valid (the internal-TLS overlay uses
            # them); embedded credentials or foreign schemes are not.
            environment["MINIO_ENDPOINT"] = "https://minio:9000"
            config = OperationsConfig.from_env(environment)
            self.assertEqual(config.minio_url, "https://minio:9000")
            environment["MINIO_ENDPOINT"] = "https://user:pass@minio:9000"
            with self.assertRaises(ValueError):
                OperationsConfig.from_env(environment)
            environment["MINIO_ENDPOINT"] = "ftp://minio:9000"
            with self.assertRaises(ValueError):
                OperationsConfig.from_env(environment)


class MetricsAuthenticationTests(unittest.TestCase):
    """The operations-agent /metrics endpoint is token-gated when configured."""

    def _authorized(self, token: str, header: str) -> bool:
        # Imported lazily so the entrypoint's sys.path setup is not required.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "operations_app",
            Path(__file__).resolve().parents[2] / "services/operations-agent/app.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.authorized_for_metrics(token, header)

    def test_metrics_require_bearer_token_when_configured(self) -> None:
        self.assertTrue(self._authorized("sekret", "Bearer sekret"))
        # The auth scheme is case-insensitive per RFC 7235.
        self.assertTrue(self._authorized("sekret", "bearer sekret"))
        self.assertFalse(self._authorized("sekret", "Bearer wrong"))
        self.assertFalse(self._authorized("sekret", ""))
        self.assertFalse(self._authorized("sekret", "Basic sekret"))

    def test_metrics_are_open_when_no_token_is_configured(self) -> None:
        self.assertTrue(self._authorized("", "Bearer anything"))
        self.assertTrue(self._authorized("", ""))


if __name__ == "__main__":
    unittest.main()
