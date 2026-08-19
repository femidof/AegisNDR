from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from hybrid_ndr_storage import PersistenceSettings, ProductionStore, build_persistence, build_store
from hybrid_ndr_storage.adapters import ClickHouseEventAdapter, MinIOEvidenceAdapter, PostgresMetadataAdapter

class _Response:
    def __init__(self, body: bytes = b"", status: int = 200):
        self.body = body
        self.status = status

    def read(self, _limit: int | None = None):
        return self.body


class _Cursor:
    def __init__(self):
        self.query_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query, _params=None):
        self.query_count += 1

    def fetchone(self):
        return ("local_state",) if self.query_count == 1 else (1,)


class _Connection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return _Cursor()


class _Psycopg:
    @staticmethod
    def connect(_dsn, **_kwargs):
        return _Connection()


class PersistenceAdapterTests(unittest.TestCase):
    def test_demo_profile_preserves_sqlite_and_filesystem_backends(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = PersistenceSettings(
                profile="demo",
                sqlite_path=str(Path(directory) / "demo.sqlite3"),
                evidence_path=str(Path(directory) / "evidence"),
            )
            adapters = build_persistence(settings)
            status = adapters.readiness()
            self.assertTrue(status["ready"], status)
            self.assertEqual(status["adapters"]["metadata"]["backend"], "sqlite")
            self.assertEqual(status["adapters"]["evidence"]["backend"], "filesystem")

    def test_production_profile_selects_explicit_external_ports(self):
        settings = PersistenceSettings.from_env({
            "PERSISTENCE_PROFILE": "production",
            "POSTGRES_URL": "postgresql://user:secret@postgres:5432/hybrid_ndr",
            "POSTGRES_SCHEMA": "local_state",
            "CLICKHOUSE_URL": "http://clickhouse:8123",
            "CLICKHOUSE_DATABASE": "hybrid_ndr",
            "CLICKHOUSE_USER": "hybrid_ndr",
            "CLICKHOUSE_PASSWORD": "secret",
            "MINIO_ENDPOINT": "http://minio:9000",
            "MINIO_BUCKET": "hybrid-ndr-evidence",
            "MINIO_ACCESS_KEY": "access",
            "MINIO_SECRET_KEY": "secret",
            "PERSISTENCE_READINESS_REQUIRED": "true",
        })
        adapters = build_persistence(settings)
        self.assertEqual(adapters.metadata.backend, "postgresql")
        self.assertEqual(adapters.events.backend, "clickhouse")
        self.assertEqual(adapters.evidence.backend, "minio")
        self.assertTrue(settings.readiness_required)
        self.assertEqual(
            adapters.readiness()["product_io"],
            {"metadata": True, "events": True, "evidence": True},
        )
        store = build_store(settings, adapters)
        self.assertIsInstance(store, ProductionStore)
        self.assertIs(store.metadata, adapters.metadata)
        self.assertIs(store.events, adapters.events)
        self.assertIs(store.evidence, adapters.evidence)

    def test_backend_readiness_checks_schema_database_and_bucket(self):
        postgres = PostgresMetadataAdapter(
            "postgresql://user:secret@postgres:5432/hybrid_ndr",
            driver_loader=lambda _name: _Psycopg,
        )
        clickhouse = ClickHouseEventAdapter(
            "http://clickhouse:8123", opener=lambda _request, timeout: _Response(b"1\n")
        )
        requests = []

        def minio_open(request, timeout):
            requests.append((request.get_method(), request.full_url, dict(request.header_items()), timeout))
            return _Response(status=200)

        minio = MinIOEvidenceAdapter(
            "http://minio:9000", bucket="hybrid-ndr-evidence", access_key="access", secret_key="secret",
            opener=minio_open,
        )
        self.assertTrue(postgres.readiness().ready)
        self.assertTrue(clickhouse.readiness().ready)
        self.assertTrue(minio.readiness().ready)
        self.assertEqual(requests[1][0], "HEAD")
        self.assertTrue(requests[1][1].endswith("/hybrid-ndr-evidence"))
        self.assertIn("Authorization", requests[1][2])

    def test_invalid_production_configuration_is_rejected_without_secret_echo(self):
        with self.assertRaises(ValueError) as failure:
            PersistenceSettings.from_env({"PERSISTENCE_PROFILE": "production", "POSTGRES_URL": "secret-value"})
        self.assertNotIn("secret-value", str(failure.exception))

    def test_ca_file_forces_verified_tls_on_internal_credential_hops(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_key = Path(directory) / "ca-key.pem"
            ca_file = Path(directory) / "internal-ca.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-new", "-sha256", "-days", "2", "-nodes",
                 "-keyout", str(ca_key), "-subj", "/CN=Hybrid NDR Internal TLS Test CA",
                 "-out", str(ca_file)],
                check=True, capture_output=True,
            )
            settings = PersistenceSettings.from_env({
                "PERSISTENCE_PROFILE": "production",
                "POSTGRES_URL": "postgresql://user:secret@postgres:5432/hybrid_ndr",
                "POSTGRES_SCHEMA": "local_state",
                "CLICKHOUSE_URL": "https://clickhouse:8443",
                "CLICKHOUSE_DATABASE": "hybrid_ndr",
                "CLICKHOUSE_USER": "hybrid_ndr",
                "CLICKHOUSE_PASSWORD": "secret",
                "MINIO_ENDPOINT": "https://minio:9000",
                "MINIO_BUCKET": "hybrid-ndr-evidence",
                "MINIO_ACCESS_KEY": "access",
                "MINIO_SECRET_KEY": "secret",
                "PERSISTENCE_CA_FILE": str(ca_file),
            })
            self.assertEqual(settings.ca_file, str(ca_file))
            adapters = build_persistence(settings)
            self.assertIn("sslmode=verify-full", adapters.metadata.dsn)
            self.assertIn(f"sslrootcert={ca_file}", adapters.metadata.dsn)
            self.assertTrue(adapters.events._opener is not None)
            self.assertTrue(adapters.evidence._opener is not None)

    def test_ca_file_requires_regular_non_symlink_file(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = PersistenceSettings.from_env({
                "PERSISTENCE_PROFILE": "production",
                "POSTGRES_URL": "postgresql://user:secret@postgres:5432/hybrid_ndr",
                "POSTGRES_SCHEMA": "local_state",
                "CLICKHOUSE_URL": "https://clickhouse:8443",
                "CLICKHOUSE_DATABASE": "hybrid_ndr",
                "CLICKHOUSE_USER": "hybrid_ndr",
                "CLICKHOUSE_PASSWORD": "secret",
                "MINIO_ENDPOINT": "https://minio:9000",
                "MINIO_BUCKET": "hybrid-ndr-evidence",
                "MINIO_ACCESS_KEY": "access",
                "MINIO_SECRET_KEY": "secret",
                "PERSISTENCE_CA_FILE": str(Path(directory) / "missing.pem"),
            })
            with self.assertRaises(ValueError):
                build_persistence(settings)


class _ScriptedCursor:
    def __init__(self, current_version: int) -> None:
        self.statements: list[str] = []
        self.parameters: list[tuple] = []
        self.current_version = current_version
        self._asked_version = False

    def execute(self, sql: str, params: tuple | None = None) -> None:
        self.statements.append(sql)
        if params is not None:
            self.parameters.append(tuple(params))
        if "COALESCE(MAX(version), 0)" in sql:
            self._asked_version = True

    def fetchone(self):
        if self._asked_version:
            return (self.current_version,)
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _ScriptedConnection:
    def __init__(self, cursor_instance: _ScriptedCursor) -> None:
        self.cursor_instance = cursor_instance

    def cursor(self):
        return self.cursor_instance

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _ScriptedPsycopg:
    def __init__(self, current_version: int) -> None:
        self.cursor_instance = _ScriptedCursor(current_version)

    def connect(self, _dsn, **_kwargs):
        return _ScriptedConnection(self.cursor_instance)

    def inspect(self) -> _ScriptedCursor:
        return self.cursor_instance


class SchemaMigrationTests(unittest.TestCase):
    """PostgresMetadataAdapter applies additive migrations deterministically."""

    def _adapter(self, current_version: int):
        from hybrid_ndr_storage.adapters import PostgresMetadataAdapter

        driver = _ScriptedPsycopg(current_version)
        adapter = PostgresMetadataAdapter(
            "postgresql://user:secret@postgres:5432/hybrid_ndr",
            schema="local_state",
            driver_loader=lambda _name: driver,
        )
        adapter._scripted_driver = driver  # type: ignore[attr-defined]
        return adapter

    def test_fresh_volume_records_base_then_applies_all_migrations(self) -> None:
        adapter = self._adapter(0)
        adapter.ensure_detection_schema()
        cursor = adapter._scripted_driver.inspect()
        statements = "\n".join(cursor.statements)
        self.assertIn("CREATE TABLE IF NOT EXISTS \"local_state\".\"schema_migrations\"", statements)
        self.assertIn("VALUES (1, 'base product state (init scripts)')", statements)
        for table in ("detection_checkpoints", "detection_alert_keys", "alert_evidence",
                      "detection_rules", "detection_suppressions", "integrations",
                      "system_settings", "evidence_exports", "support_bundles"):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS \"local_state\".\"{table}\"", statements)
        versions = [params[0] for params in cursor.parameters]
        self.assertEqual(versions, [2, 3])

    def test_partially_migrated_volume_applies_only_pending_versions(self) -> None:
        adapter = self._adapter(2)
        adapter.ensure_detection_schema()
        cursor = adapter._scripted_driver.inspect()
        statements = "\n".join(cursor.statements)
        self.assertNotIn("detection_checkpoints", statements)
        self.assertIn("\"detection_rules\"", statements)
        self.assertEqual([params[0] for params in cursor.parameters], [3])

    def test_current_volume_is_a_noop(self) -> None:
        adapter = self._adapter(3)
        adapter.ensure_detection_schema()
        cursor = adapter._scripted_driver.inspect()
        statements = "\n".join(cursor.statements)
        self.assertNotIn("CREATE TABLE IF NOT EXISTS \"local_state\".\"detection_checkpoints\"", statements)
        self.assertEqual(cursor.parameters, [])


if __name__ == "__main__":
    unittest.main()
