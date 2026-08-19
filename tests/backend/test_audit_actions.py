from __future__ import annotations

import unittest

import support
from hybrid_ndr_local_api import create_application
from hybrid_ndr_storage import LocalStore


class AuditActionTests(unittest.TestCase):
    """Every Local API action that writes an audit record must produce a scoped, chain-valid entry."""

    def setUp(self) -> None:
        self.store = LocalStore(":memory:")
        self.store.reset_demo()
        self.api = create_application(self.store).api
        self.analyst = support.analyst_headers()
        self.admin = {**self.analyst, "X-Role": "security-admin", "X-Actor-ID": "admin-01"}
        self.manager = {**self.analyst, "X-Role": "soc-manager", "X-Actor-ID": "manager-01"}
        self.auditor = {**self.analyst, "X-Role": "auditor", "X-Actor-ID": "auditor-01"}

    def tearDown(self) -> None:
        self.store.close()

    def actions(self) -> list[str]:
        return [entry["action"] for entry in self.store.audit.list("demo-tenant", "demo-deployment")]

    def assert_chain_valid(self) -> None:
        self.assertTrue(self.store.audit.verify("demo-tenant", "demo-deployment"))

    def test_session_authentication_is_audited(self) -> None:
        result = self.api.handle("POST", "/api/v1/session/audit", headers=self.analyst)
        self.assertEqual(result.status, 204, result.body)
        self.assertIn("authentication.succeeded", self.actions())
        self.assert_chain_valid()

    def test_alert_update_is_audited(self) -> None:
        result = self.api.handle(
            "PATCH", "/api/v1/alerts/demo-alert-port-scan", headers=self.analyst,
            body={"status": "triaged", "severity": "medium"},
        )
        self.assertEqual(result.status, 200, result.body)
        self.assertIn("alert.updated", self.actions())
        self.assert_chain_valid()

    def test_case_lifecycle_is_audited(self) -> None:
        created = self.api.handle(
            "POST", "/api/v1/cases", headers=self.analyst,
            body={"title": "Port scan incident", "priority": "high", "alert_ids": ["demo-alert-port-scan"]},
        )
        self.assertEqual(created.status, 201, created.body)
        case_id = created.body["case_id"]
        updated = self.api.handle(
            "PATCH", f"/api/v1/cases/{case_id}", headers=self.analyst, body={"status": "in_progress"}
        )
        self.assertEqual(updated.status, 200, updated.body)
        comment = self.api.handle(
            "POST", f"/api/v1/cases/{case_id}/comments", headers=self.analyst, body={"body": "Awaiting evidence review"}
        )
        self.assertEqual(comment.status, 201, comment.body)
        actions = self.actions()
        self.assertIn("case.created", actions)
        self.assertIn("case.updated", actions)
        self.assertIn("case.comment.created", actions)
        self.assert_chain_valid()

    def test_model_policy_update_is_audited(self) -> None:
        result = self.api.handle(
            "PATCH", "/api/v1/model-policy", headers=self.admin,
            body={"enabled": True, "level": "balanced", "retention_mode": "zero"},
        )
        self.assertEqual(result.status, 200, result.body)
        self.assertIn("model_policy.updated", self.actions())
        self.assert_chain_valid()

    def test_rule_suppression_integration_crud_is_audited(self) -> None:
        rule = self.api.handle(
            "POST", "/api/v1/detection-rules", headers=self.admin,
            body={"name": "Custom scanner", "detector_id": "port-scan-v1", "schedule": "fast-10s",
                  "severity": "medium", "enabled": True, "thresholds": {"vertical_port_threshold": 40}},
        )
        self.assertEqual(rule.status, 201, rule.body)
        rule_id = rule.body["rule_id"]
        self.api.handle("PATCH", f"/api/v1/detection-rules/{rule_id}", headers=self.admin, body={"enabled": False})
        self.api.handle("DELETE", f"/api/v1/detection-rules/{rule_id}", headers=self.admin)

        suppression = self.api.handle(
            "POST", "/api/v1/detection-suppressions", headers=self.admin,
            body={"name": "Approved scanner", "rule_id": "port-scan-v1",
                  "match": {"entity_id": "10.0.4.21"}, "reason": "authorized scanning activity", "enabled": True},
        )
        self.assertEqual(suppression.status, 201, suppression.body)
        suppression_id = suppression.body["suppression_id"]
        self.api.handle("PATCH", f"/api/v1/detection-suppressions/{suppression_id}", headers=self.admin, body={"enabled": False})
        self.api.handle("DELETE", f"/api/v1/detection-suppressions/{suppression_id}", headers=self.admin)

        integration = self.api.handle(
            "POST", "/api/v1/integrations", headers=self.admin,
            body={"name": "SIEM", "kind": "generic_siem", "endpoint_url": "https://siem.example/events",
                  "format": "json", "auth_type": "bearer", "secret": "s3cret", "enabled": True,
                  "minimum_severity": "medium", "verify_tls": True, "event_types": ["alerts"], "headers": {}},
        )
        self.assertEqual(integration.status, 201, integration.body)
        integration_id = integration.body["integration_id"]
        self.api.handle("PATCH", f"/api/v1/integrations/{integration_id}", headers=self.admin, body={"enabled": False})
        self.api.handle("DELETE", f"/api/v1/integrations/{integration_id}", headers=self.admin)

        actions = self.actions()
        self.assertIn("rule.created", actions)
        self.assertIn("rule.updated", actions)
        self.assertIn("rule.deleted", actions)
        self.assertIn("suppression.created", actions)
        self.assertIn("suppression.updated", actions)
        self.assertIn("suppression.deleted", actions)
        self.assertIn("integration.created", actions)
        self.assertIn("integration.updated", actions)
        self.assertIn("integration.deleted", actions)
        self.assert_chain_valid()

    def test_retention_and_settings_update_is_audited(self) -> None:
        settings = self.api.handle(
            "PATCH", "/api/v1/system/settings", headers=self.admin, body={"event_retention_days": 60}
        )
        self.assertEqual(settings.status, 200, settings.body)
        self.assertIn("retention.updated", self.actions())
        self.api.handle(
            "PATCH", "/api/v1/system/settings", headers=self.admin,
            body={"support_bundle_ttl_hours": 12},
        )
        self.assertIn("system_settings.updated", self.actions())
        self.assert_chain_valid()

    def test_evidence_export_approval_flow_is_audited(self) -> None:
        exported = self.api.handle(
            "POST", "/api/v1/evidence/exports", headers=self.analyst,
            body={"alert_id": "demo-alert-port-scan", "evidence_ids": ["demo-scan-000", "demo-scan-001"],
                  "reason": "authorized export for incident response", "format": "json"},
        )
        self.assertEqual(exported.status, 201, exported.body)
        export_id = exported.body["export_id"]
        self.assertIn("evidence_export.requested", self.actions())

        approved = self.api.handle(
            "POST", f"/api/v1/evidence/exports/{export_id}/approve", headers=self.manager,
            body={"approved": True, "justification": "reviewed and authorized by management"},
        )
        self.assertEqual(approved.status, 200, approved.body)
        actions = self.actions()
        self.assertIn("response.approved", actions)
        self.assertIn("evidence_export.approved", actions)

        downloaded = self.api.handle(
            "GET", f"/api/v1/evidence/exports/{export_id}/download", headers=self.manager
        )
        self.assertEqual(downloaded.status, 200, downloaded.body)
        self.assertIn("evidence_export.downloaded", self.actions())
        self.assert_chain_valid()

    def test_support_bundle_lifecycle_is_audited(self) -> None:
        created = self.api.handle(
            "POST", "/api/v1/support-bundles", headers=self.admin,
            body={"include_health": True, "include_configuration": True, "include_audit": True},
        )
        self.assertEqual(created.status, 201, created.body)
        bundle_id = created.body["bundle_id"]
        self.assertIn("support_bundle.created", self.actions())

        accessed = self.api.handle(
            "GET", f"/api/v1/support-bundles/{bundle_id}/download", headers=self.admin
        )
        self.assertEqual(accessed.status, 200, accessed.body)
        self.assertIn("support.accessed", self.actions())
        self.assert_chain_valid()

    def test_audit_read_is_role_enforced_and_chain_valid(self) -> None:
        self.api.handle("POST", "/api/v1/session/audit", headers=self.analyst)
        self.api.handle(
            "PATCH", "/api/v1/alerts/demo-alert-port-scan", headers=self.analyst, body={"status": "resolved"}
        )
        forbidden = self.api.handle("GET", "/api/v1/audit", headers=self.analyst)
        self.assertEqual(forbidden.status, 403)
        allowed = self.api.handle("GET", "/api/v1/audit", headers=self.auditor)
        self.assertEqual(allowed.status, 200)
        self.assertTrue(allowed.body["chain_valid"])
        actions = {entry["action"] for entry in allowed.body["items"]}
        self.assertIn("authentication.succeeded", actions)
        self.assertIn("alert.updated", actions)
        self.assert_chain_valid()

    def test_mutating_actions_are_scoped_to_the_signed_deployment(self) -> None:
        other = support.analyst_headers("other-tenant", "other-deployment")
        result = self.api.handle(
            "POST", "/api/v1/cases", headers=other,
            body={"title": "Cross-tenant case", "priority": "low", "alert_ids": []},
        )
        self.assertEqual(result.status, 201, result.body)
        self.assertNotIn("case.created", self.actions())
        self.assert_chain_valid()


if __name__ == "__main__":
    unittest.main()
