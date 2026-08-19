from __future__ import annotations

import random
import unittest
from dataclasses import replace
from pathlib import Path

import support  # noqa: F401
from hybrid_ndr_connector import Connector
from hybrid_ndr_gateway import ModelGateway, OfflineProvider
from hybrid_ndr_storage.adapters import ClickHouseEventAdapter

from test_deployment_connector import Client, DeploymentConnectorTests, Metrics
from test_detection import event as make_event


class ClickHouseEmptyIpTests(unittest.TestCase):
    """Item 42: missing addresses are stored as empty strings, never '::'."""

    def _adapter(self, queries: list[bytes]):
        class Response:
            def read(self, _limit=-1):
                return b""

        def opener(request, timeout):
            queries.append(request.data)
            return Response()

        return ClickHouseEventAdapter(
            "http://clickhouse:8123", user="u", password="p", opener=opener
        )

    def test_insert_events_stores_empty_ips_as_empty_strings(self):
        queries: list[bytes] = []
        adapter = self._adapter(queries)
        events = [
            make_event(1, tenant_id="11111111-1111-4111-8111-111111111111",
                       deployment_id="22222222-2222-4222-8222-222222222222",
                       event_id="33333333-3333-4333-8333-333333333333",
                       src_ip="", dst_ip=""),
            make_event(2, tenant_id="11111111-1111-4111-8111-111111111111",
                       deployment_id="22222222-2222-4222-8222-222222222222",
                       event_id="44444444-4444-4444-8444-444444444444",
                       src_ip="10.0.0.5", dst_ip="8.8.8.8"),
        ]
        adapter.insert_events(events)
        body = queries[-1].decode("utf-8")
        self.assertIn('"src_ip":""', body)
        self.assertIn('"dst_ip":""', body)
        self.assertNotIn('"::"', body)
        self.assertIn('"src_ip":"10.0.0.5"', body)

    def test_search_queries_compare_ip_columns_as_strings(self):
        queries: list[bytes] = []
        adapter = self._adapter(queries)
        adapter.search_events(
            "11111111-1111-4111-8111-111111111111", entity_id="10.0.0.5"
        )
        select = next(q for q in queries if q.startswith(b"SELECT")).decode("utf-8")
        self.assertIn("src_ip = '10.0.0.5'", select)
        self.assertNotIn("toIPv6", select)

    def test_schema_convergence_migrates_ipv6_columns_to_string(self):
        queries: list[bytes] = []
        adapter = self._adapter(queries)
        adapter.insert_events([make_event(
            1, tenant_id="11111111-1111-4111-8111-111111111111",
            deployment_id="22222222-2222-4222-8222-222222222222",
            event_id="33333333-3333-4333-8333-333333333333",
        )])
        alters = " ".join(q.decode("utf-8") for q in queries if q.startswith(b"ALTER"))
        self.assertIn("MODIFY COLUMN src_ip String", alters)
        self.assertIn("MODIFY COLUMN dst_ip String", alters)
        self.assertIn("DROP INDEX IF EXISTS source_ip_bloom", alters)


class EventRowRobustnessTests(unittest.TestCase):
    """Item 58: non-dict raw events never crash row mapping."""

    def test_non_dict_raw_event_yields_empty_details(self):
        row = {
            "tenant_id_text": "t", "deployment_id_text": "d", "event_id_text": "e-1",
            "event_time_text": "2026-08-05T05:35:00Z", "ingested_at_text": "2026-08-05T05:35:00Z",
            "source": "zeek", "event_type": "network.connection", "sensor_id": "s-1",
            "community_id": "", "src_ip_text": "10.0.0.5", "src_port": 1,
            "dst_ip_text": "8.8.8.8", "dst_port": 2, "protocol": "tcp", "duration_ms": 0,
            "bytes_out": 0, "bytes_in": 0, "raw_reference": "", "severity": 0, "signature": "",
            "raw_event": '[{"not": "an object"}]',
        }
        mapped = ClickHouseEventAdapter._event_row(row)
        self.assertEqual(mapped["details"], {})

    def test_invalid_json_raw_event_yields_empty_details(self):
        row = {
            "tenant_id_text": "t", "deployment_id_text": "d", "event_id_text": "e-1",
            "event_time_text": "2026-08-05T05:35:00Z", "ingested_at_text": "2026-08-05T05:35:00Z",
            "source": "suricata", "event_type": "network.alert", "sensor_id": "s-1",
            "community_id": "", "src_ip_text": "", "src_port": 0,
            "dst_ip_text": "", "dst_port": 0, "protocol": "", "duration_ms": 0,
            "bytes_out": 0, "bytes_in": 0, "raw_reference": "", "severity": 2, "signature": "alert",
            "raw_event": "not-json",
        }
        mapped = ClickHouseEventAdapter._event_row(row)
        self.assertEqual(mapped["details"], {"signature": "alert", "severity": 2})


class GatewaySigningKeyMinimumTests(unittest.TestCase):
    """Item 53: class and entrypoint agree on a 32-byte minimum."""

    def test_short_signing_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            ModelGateway(OfflineProvider(), signing_key=b"x" * 16)
        ModelGateway(OfflineProvider(), signing_key=b"x" * 32)


class ConnectorIdentityWriteDirTests(DeploymentConnectorTests):
    """Item 50: mutable identity material lands in the writable directory.

    The inherited harness tests run with identity_write_dir == identity_dir
    (legacy behavior); the write-dir tests below opt in explicitly.
    """

    def setUp(self) -> None:
        super().setUp()
        self.write_dir = Path(self.temp.name) / "identity-writable"

    def test_rotation_writes_to_writable_dir_and_keeps_key_in_identity_dir(self):
        self.write_dir.mkdir(mode=0o700)
        self.settings = replace(self.settings, identity_write_dir=self.write_dir)
        connector = Connector(
            self.settings, metrics=Metrics(), client_factory=lambda: Client(self.authority, self.issued),
            monotonic=lambda: 100.0, random_source=random.Random(5),
        )
        outcomes = connector.run_once()
        self.assertEqual(set(outcomes.values()), {"success"}, outcomes)
        # Rotated certificate, fingerprint, and enrollment metadata move to the
        # writable directory...
        self.assertEqual(
            (self.write_dir / "certificate-fingerprint").read_text().strip(),
            self.issued["certificate_fingerprint"],
        )
        self.assertTrue((self.write_dir / "deployment-cert.pem").is_file())
        self.assertTrue((self.write_dir / "enrollment.json").is_file())
        # ...while the installer-provisioned key is never copied there, so the
        # identity mount can stay read-only.
        self.assertFalse((self.write_dir / "deployment-key.pem").exists())
        self.assertTrue((self.identity / "deployment-key.pem").is_file())
        # A restarted connector reads the rotated material from the writable dir.
        restarted = Connector(
            self.settings, metrics=Metrics(), client_factory=lambda: Client(self.authority, self.issued),
            monotonic=lambda: 200.0,
        )
        self.assertEqual(restarted.identity["certificate_fingerprint"], self.issued["certificate_fingerprint"])

    def test_reads_fall_back_to_legacy_identity_dir_for_upgrades(self):
        # No writable-dir files yet: the connector must keep using the legacy
        # identity-directory material (upgraded volumes).
        self.write_dir.mkdir(mode=0o700)
        self.settings = replace(self.settings, identity_write_dir=self.write_dir)
        connector = Connector(
            self.settings, metrics=Metrics(), client_factory=lambda: Client(self.authority, self.issued),
            monotonic=lambda: 100.0,
        )
        self.assertEqual(connector.identity["tenant_id"], "tenant-1")
        self.assertEqual(
            connector.identity["certificate_fingerprint"],
            (self.identity / "certificate-fingerprint").read_text().strip(),
        )


if __name__ == "__main__":
    unittest.main()
