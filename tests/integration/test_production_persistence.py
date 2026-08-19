from __future__ import annotations

import os
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "audit",
    ROOT / "packages" / "storage",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_contracts import DetectionResult, NormalizedEvent, utc_now  # noqa: E402
from hybrid_ndr_storage import NotFoundError, PersistenceSettings, build_persistence, build_store  # noqa: E402


@unittest.skipUnless(
    os.environ.get("RUN_PRODUCTION_PERSISTENCE_TESTS") == "1",
    "set RUN_PRODUCTION_PERSISTENCE_TESTS=1 inside the customer Compose network",
)
class ProductionPersistenceIntegrationTests(unittest.TestCase):
    def test_core_product_flow_is_durable_and_scoped(self):
        settings = PersistenceSettings.from_env()
        self.assertEqual(settings.profile, "production")
        persistence = build_persistence(settings)
        store = build_store(settings, persistence)
        self.addCleanup(store.close)

        tenant_id = str(uuid.uuid4())
        deployment_id = str(uuid.uuid4())
        other_deployment = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        event = NormalizedEvent(
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            event_id=event_id,
            event_time=utc_now(),
            source="integration-test",
            event_type="network.connection",
            sensor_id="integration-sensor",
            src_ip="10.42.0.7",
            src_port=51000,
            dst_ip="198.51.100.7",
            dst_port=443,
            protocol="tcp",
            bytes_out=2048,
            bytes_in=512,
            details={"test_run": tenant_id},
        )
        store.insert_event(event)
        found = store.search_events(
            tenant_id, deployment_id=deployment_id, entity_id="10.42.0.7", limit=10
        )
        self.assertIn(event_id, {item["event_id"] for item in found})
        self.assertEqual(
            store.search_events(tenant_id, deployment_id=other_deployment, limit=10), []
        )

        detection = DetectionResult(
            detector_id="integration-detector", entity_type="host", entity_id="10.42.0.7",
            severity="high", score=0.9, evidence_ids=(event_id,),
            feature_values={"bytes": 2560.0}, baseline_values={"p99": 1000.0},
            title="Integration persistence alert",
        )
        alert = store.save_alert(tenant_id, deployment_id, detection)
        self.assertEqual(
            store.get_alert(tenant_id, alert["alert_id"], deployment_id=deployment_id)["alert_id"],
            alert["alert_id"],
        )
        with self.assertRaises(NotFoundError):
            store.get_alert(tenant_id, alert["alert_id"], deployment_id=other_deployment)

        investigation = store.create_investigation(
            tenant_id, deployment_id, alert["alert_id"]
        )
        finished = store.finish_investigation(
            tenant_id, investigation["investigation_id"], status="completed",
            assessment={"summary": "integration"}, deployment_id=deployment_id,
        )
        self.assertEqual(finished["status"], "completed")
        transmission = store.save_transmission({
            "request_id": str(uuid.uuid4()), "investigation_id": investigation["investigation_id"],
            "alert_id": alert["alert_id"], "tenant_id": tenant_id, "deployment_id": deployment_id,
            "actor_id": "integration-test", "provider": "integration", "model": "integration-v1",
            "retention_mode": "zero", "region": "local", "fields_included": ["observations"],
            "fields_removed": [], "fields_tokenized": ["src_ip"], "prompt_hash": "a" * 64,
            "response_hash": "b" * 64, "input_tokens": 10, "output_tokens": 5, "latency_ms": 1,
            "result": "success", "payload": {"redacted": True},
        })
        self.assertEqual(store.get_transmission(
            tenant_id, investigation["investigation_id"], deployment_id=deployment_id
        )["transmission_id"], transmission["transmission_id"])

        case = store.create_case(
            tenant_id, deployment_id,
            {"title": "Integration case", "alert_ids": [alert["alert_id"]]},
        )
        comment = store.add_case_comment(
            tenant_id, case["case_id"], "integration-test", "Persisted comment",
            deployment_id=deployment_id,
        )
        self.assertEqual(comment["body"], "Persisted comment")
        self.assertEqual(len(store.list_comments(
            tenant_id, case["case_id"], deployment_id=deployment_id
        )), 1)

        audit = store.audit.append(
            tenant_id=tenant_id, deployment_id=deployment_id, actor_id="integration-test",
            actor_type="service", action="persistence.verified", resource_type="deployment",
            resource_id=deployment_id,
        )
        self.assertTrue(audit["record_hash"])
        self.assertTrue(store.audit.verify(tenant_id, deployment_id))
        with self.assertRaises(Exception):
            store.metadata._execute(
                f"UPDATE {store.metadata._table('audit_events')} SET action = %s "
                "WHERE tenant_id = %s AND deployment_id = %s AND audit_id = %s",
                ("tampered", tenant_id, deployment_id, audit["audit_id"]),
            )

        evidence = store.put_evidence(
            tenant_id, deployment_id, "integration-evidence.json", b'{"verified":true}',
            content_type="application/json", metadata={"purpose": "integration"},
        )
        loaded = store.get_evidence(tenant_id, deployment_id, "integration-evidence.json")
        self.assertEqual(loaded["data"], b'{"verified":true}')
        self.assertEqual(loaded["sha256"], evidence["sha256"])
        self.assertEqual(loaded["metadata"]["purpose"], "integration")
        with self.assertRaises(FileExistsError):
            store.put_evidence(
                tenant_id, deployment_id, "integration-evidence.json", b"replacement"
            )

        baseline = store.get_baseline(tenant_id, deployment_id, "10.42.0.7")
        self.assertGreaterEqual(baseline["event_count"], 1)
        self.assertTrue(persistence.readiness()["ready"])


if __name__ == "__main__":
    unittest.main()
