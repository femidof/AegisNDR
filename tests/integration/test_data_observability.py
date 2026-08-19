from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ProductStateSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = (ROOT / "infra/postgres/001-product-state.sql").read_text()

    def test_all_product_state_tables_are_initialized(self) -> None:
        expected = {
            "events",
            "alerts",
            "alert_evidence",
            "detection_alert_keys",
            "detection_checkpoints",
            "investigations",
            "model_transmissions",
            "cases",
            "case_comments",
            "sensors",
            "model_policies",
            "entity_baselines",
            "audit_events",
        }
        tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS local_state\.([a-z_]+)", self.schema))
        self.assertTrue(expected.issubset(tables))

    def test_control_plane_metadata_tables_are_initialized(self) -> None:
        expected = {
            "enrollment_tokens", "deployments", "organizations", "software_releases",
            "control_audit", "idempotency_records", "gateway_usage",
        }
        tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS control_plane\.([a-z_]+)", self.schema))
        self.assertTrue(expected.issubset(tables))

    def test_audit_table_is_append_only(self) -> None:
        self.assertIn("audit_events_no_update", self.schema)
        self.assertIn("audit_events_no_delete", self.schema)
        self.assertIn("audit records are append-only", self.schema)


class EvidenceBucketTests(unittest.TestCase):
    def test_bucket_initialization_enforces_privacy_and_retention(self) -> None:
        script = (ROOT / "infra/minio/initialize-buckets.sh").read_text()
        self.assertIn("mc mb --ignore-existing --with-lock", script)
        self.assertIn("mc version enable", script)
        self.assertIn("mc anonymous set none", script)
        self.assertIn("mc retention set --default GOVERNANCE", script)


class ObservabilityProvisioningTests(unittest.TestCase):
    def test_prometheus_covers_required_components(self) -> None:
        config = (ROOT / "infra/prometheus/prometheus.yml").read_text()
        for target in (
            "vector:9598",
            "postgres-exporter:9187",
            "minio:9000",
            "local-api:8080/healthz",
            "operations-agent:9108/healthz",
            "otel-collector:8888",
            "clickhouse:9000",
        ):
            self.assertIn(target, config)
        self.assertNotIn("control-api", config)

    def test_dashboards_are_valid_and_have_stable_unique_uids(self) -> None:
        dashboard_paths = sorted((ROOT / "infra/grafana/dashboards").glob("*.json"))
        self.assertEqual(4, len(dashboard_paths))
        dashboards = [json.loads(path.read_text()) for path in dashboard_paths]
        self.assertEqual(len(dashboards), len({dashboard["uid"] for dashboard in dashboards}))
        self.assertEqual(
            {"Ingestion Pipeline", "Sensor Fleet", "Service Health", "Storage Capacity"},
            {dashboard["title"] for dashboard in dashboards},
        )
        self.assertTrue(all(dashboard["panels"] for dashboard in dashboards))

    def test_grafana_uses_provisioned_non_anonymous_datasources(self) -> None:
        datasource = (ROOT / "infra/grafana/provisioning/datasources/datasources.yml").read_text()
        self.assertIn("uid: prometheus", datasource)
        self.assertIn("uid: product-state", datasource)
        self.assertIn("user: $GRAFANA_POSTGRES_USER", datasource)
        self.assertIn("password: $GRAFANA_POSTGRES_PASSWORD", datasource)

    def test_otel_collector_has_no_debug_or_external_exporter(self) -> None:
        config = (ROOT / "infra/otel/collector.yml").read_text()
        self.assertIn("prometheus", config)
        self.assertIn("receivers:\n  otlp:", config)
        exporters_section = config.split("exporters:", 1)[1].split("service:", 1)[0]
        for forbidden in ("debug:", "otlp:", "otlphttp", "remote_write", "remote-write", "logging:"):
            self.assertNotIn(forbidden, exporters_section)
        self.assertIn("exporters: [prometheus]", config)


if __name__ == "__main__":
    unittest.main()
