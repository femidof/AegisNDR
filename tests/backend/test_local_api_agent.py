from __future__ import annotations

import unittest

import support
from hybrid_ndr_agent import InvestigationRuntime
from hybrid_ndr_auth import HeaderAuthenticator
from hybrid_ndr_gateway import ModelGateway, OfflineProvider
from hybrid_ndr_local_api import LocalAPI, create_application
from hybrid_ndr_storage import LocalStore


def demo_authenticator():
    # Explicit demo-only auth for unit tests; production defaults to JWT.
    return HeaderAuthenticator()


class LocalAPITests(unittest.TestCase):
    def setUp(self):
        self.store = LocalStore(":memory:")
        self.store.reset_demo()
        self.api = create_application(self.store, authenticator=demo_authenticator()).api
        self.headers = support.analyst_headers()

    def tearDown(self):
        self.store.close()

    def test_tenant_isolation_and_role_enforcement(self):
        other = support.analyst_headers("other-tenant", "other-deployment")
        result = self.api.handle("GET", "/api/v1/alerts/demo-alert-port-scan", headers=other)
        self.assertEqual(result.status, 404)
        other_site = support.analyst_headers("demo-tenant", "other-deployment")
        result = self.api.handle("GET", "/api/v1/alerts/demo-alert-port-scan", headers=other_site)
        self.assertEqual(result.status, 404)
        read_only = {**self.headers, "X-Role": "read-only"}
        result = self.api.handle("PATCH", "/api/v1/alerts/demo-alert-port-scan", headers=read_only, body={"status": "triaged"})
        self.assertEqual(result.status, 403)
        self.assertEqual(result.body["error"]["code"], "permission_denied")

    def test_investigation_transmission_is_visible_and_redacted(self):
        result = self.api.handle("POST", "/api/v1/alerts/demo-alert-port-scan/investigate", headers=self.headers)
        self.assertEqual(result.status, 201, result.body)
        self.assertEqual(result.body["status"], "completed")
        transmission = self.api.handle(
            "GET", f"/api/v1/investigations/{result.body['investigation_id']}/transmission", headers=self.headers
        )
        self.assertEqual(transmission.status, 200)
        self.assertEqual(transmission.body["retention_mode"], "zero")
        self.assertNotIn("10.0.4.21", str(transmission.body["payload"]))
        self.assertTrue(transmission.body["fields_tokenized"])
        self.assertTrue(self.store.audit.verify("demo-tenant", "demo-deployment"))

    def test_api_request_id_correlates_investigation_and_audit_records(self):
        captured = {}
        original = self.api.runtime.investigate

        def spy(**kwargs):
            captured.update(kwargs)
            return original(**kwargs)

        self.api.runtime.investigate = spy  # type: ignore[attr-defined]
        try:
            result = self.api.handle("POST", "/api/v1/alerts/demo-alert-port-scan/investigate", headers=self.headers)
        finally:
            self.api.runtime.investigate = original  # type: ignore[attr-defined]
        self.assertEqual(result.status, 201)
        # The API layer's correlation ID reaches the agent runtime...
        self.assertIsNotNone(captured.get("request_id"))
        # ...and the same identifier lands in the audit chain for the
        # investigation it created, so the request is traceable end to end.
        entries = self.store.audit.list("demo-tenant", "demo-deployment")
        created = next(entry for entry in entries if entry["action"] == "investigation.created")
        self.assertEqual(created["request_id"], captured["request_id"])

    def test_offline_model_failure_leaves_alert_open(self):
        runtime = InvestigationRuntime(
            self.store,
            ModelGateway(OfflineProvider(), signing_key=b"offline-gateway-signing-key-0123456789"),
            token_key=b"offline-redaction-token-key",
        )
        api = LocalAPI(self.store, runtime, authenticator=demo_authenticator())
        result = api.handle("POST", "/api/v1/alerts/demo-alert-suricata/investigate", headers=self.headers)
        self.assertEqual(result.status, 201)
        self.assertEqual(result.body["status"], "unavailable")
        self.assertEqual(self.store.get_alert("demo-tenant", "demo-alert-suricata")["status"], "open")
        ledger = self.store.get_transmission("demo-tenant", result.body["investigation_id"])
        self.assertEqual(ledger["result"], "failure")
        self.assertEqual(ledger["error_code"], "provider_unavailable")

    def test_cors_health_and_human_readable_errors(self):
        response = self.api.handle("OPTIONS", "/api/v1/alerts", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(response.status, 204)
        self.assertIn(("Access-Control-Allow-Origin", "http://localhost:5173"), response.headers)
        self.assertEqual(self.api.handle("GET", "/healthz").body["status"], "healthy")
        error = self.api.handle("GET", "/api/v1/alerts")
        self.assertEqual(error.status, 401)
        self.assertIn("required", error.body["error"]["message"].lower())

    def admin_headers(self):
        return {**self.headers, "X-Role": "security-admin", "X-Actor-ID": "admin-01"}

    def test_rule_tuning_and_suppressions_are_scoped_and_audited(self):
        admin = self.admin_headers()
        listed = self.api.handle("GET", "/api/v1/detection-rules", headers=admin)
        self.assertEqual(listed.status, 200)
        self.assertGreater(listed.body["count"], 0)

        created = self.api.handle(
            "POST", "/api/v1/detection-rules", headers=admin,
            body={"name": "Scanner policy", "detector_id": "port-scan-v1", "schedule": "fast-10s",
                  "description": "Tuned local detector", "enabled": True, "severity": "medium",
                  "thresholds": {"vertical_port_threshold": 40}},
        )
        self.assertEqual(created.status, 201, created.body)
        rule_id = created.body["rule_id"]
        updated = self.api.handle(
            "PATCH", f"/api/v1/detection-rules/{rule_id}", headers=admin,
            body={"enabled": False, "severity": "low"},
        )
        self.assertEqual(updated.status, 200)
        self.assertEqual(updated.body["severity"], "low")
        self.assertFalse(updated.body["enabled"])
        deleted = self.api.handle("DELETE", f"/api/v1/detection-rules/{rule_id}", headers=admin)
        self.assertEqual(deleted.status, 200)

        suppression = self.api.handle(
            "POST", "/api/v1/detection-suppressions", headers=admin,
            body={"name": "Approved scanner", "rule_id": "port-scan-v1",
                  "match": {"entity_id": "10.0.4.21"}, "reason": "authorized scanning", "enabled": True},
        )
        self.assertEqual(suppression.status, 201, suppression.body)
        suppression_id = suppression.body["suppression_id"]
        self.assertEqual(
            self.api.handle("GET", f"/api/v1/detection-suppressions/{suppression_id}", headers=admin).body["name"],
            "Approved scanner",
        )
        self.api.handle("DELETE", f"/api/v1/detection-suppressions/{suppression_id}", headers=admin)

        audit = self.store.audit.list("demo-tenant", "demo-deployment")
        actions = {entry["action"] for entry in audit}
        self.assertTrue({"rule.created", "rule.updated", "rule.deleted", "suppression.created", "suppression.deleted"} <= actions)
        self.assertTrue(self.store.audit.verify("demo-tenant", "demo-deployment"))

    def test_read_only_and_analyst_cannot_tune_rules_or_read_secrets(self):
        read_only = {**self.headers, "X-Role": "read-only"}
        result = self.api.handle("POST", "/api/v1/detection-rules", headers=read_only, body={"name": "x", "detector_id": "port-scan-v1"})
        self.assertEqual(result.status, 403)
        result = self.api.handle("POST", "/api/v1/detection-suppressions", headers=read_only, body={})
        self.assertEqual(result.status, 403)
        result = self.api.handle("GET", "/api/v1/integrations", headers=self.headers)
        self.assertEqual(result.status, 403)
        result = self.api.handle("POST", "/api/v1/integrations", headers=self.headers, body={})
        self.assertEqual(result.status, 403)

    def test_integrations_are_write_only_scoped_and_rotatable(self):
        admin = self.admin_headers()
        created = self.api.handle(
            "POST", "/api/v1/integrations", headers=admin,
            body={"name": "Primary SIEM", "kind": "generic_siem", "endpoint_url": "https://siem.example/api/events",
                  "format": "json", "auth_type": "bearer", "secret": "rotation-secret", "enabled": True,
                  "verify_tls": True, "event_types": ["alerts", "cases"], "minimum_severity": "medium",
                  "headers": {}},
        )
        self.assertEqual(created.status, 201, created.body)
        integration_id = created.body["integration_id"]
        self.assertNotIn("secret", created.body)
        self.assertTrue(created.body["secret_configured"])

        rotated = self.api.handle(
            "PATCH", f"/api/v1/integrations/{integration_id}", headers=admin,
            body={"secret": "new-secret"},
        )
        self.assertEqual(rotated.status, 200)
        self.assertTrue(rotated.body["secret_configured"])

        other = support.analyst_headers("other-tenant", "other-deployment")
        self.api.handle("GET", f"/api/v1/integrations/{integration_id}", headers={**other, "X-Role": "security-admin"})
        listed = self.api.handle("GET", "/api/v1/integrations", headers=admin)
        self.assertEqual(listed.status, 200)
        self.assertIn("forwarding_contract", listed.body)
        self.assertEqual(self.api.handle("GET", f"/api/v1/integrations/{integration_id}", headers=admin).body["integration_id"], integration_id)
        deleted = self.api.handle("DELETE", f"/api/v1/integrations/{integration_id}", headers=admin)
        self.assertEqual(deleted.status, 200)


if __name__ == "__main__":
    unittest.main()
