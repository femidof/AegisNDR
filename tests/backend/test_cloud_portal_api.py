from __future__ import annotations

import json
import unittest

import support  # noqa: F401
import test_identity
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hybrid_ndr_auth import AuthenticationError, StaticJWKSource
from hybrid_ndr_control_api import (
    ControlAPI,
    ControlStore,
    PortalAuthConfig,
    PortalJWTAuthenticator,
    PortalPrincipal,
)


ALL_PERMISSIONS = frozenset({
    "organizations:read", "organizations:manage", "users:read", "users:manage",
    "deployments:read", "deployments:manage", "entitlements:read", "entitlements:manage",
    "policy:read", "policy:manage", "usage:read", "updates:read", "updates:manage",
    "support:read", "support:manage", "audit:read",
})


def make_csr():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cloud-portal-test")]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


class TokenPortalAuthenticator:
    def authenticate(self, headers):
        token = headers.get("authorization", "").removeprefix("Bearer ")
        if token == "owner-a":
            return PortalPrincipal("tenant-a", "org-a", "owner-a", "organization_owner", ALL_PERMISSIONS)
        if token == "reader-a":
            return PortalPrincipal(
                "tenant-a", "org-a", "reader-a", "read_only",
                frozenset(permission for permission in ALL_PERMISSIONS if permission.endswith(":read")),
            )
        if token == "owner-b":
            return PortalPrincipal("tenant-b", "org-b", "owner-b", "organization_owner", ALL_PERMISSIONS)
        raise AuthenticationError(401, "authentication_required", "A valid test token is required.")


class CloudPortalAPITests(unittest.TestCase):
    def setUp(self):
        self.store = ControlStore(
            ":memory:",
            identity_configuration={
                "issuer": "https://identity.example/oidc",
                "jwks_uri": "https://identity.example/oidc/jwks",
                "dashboard_client_id": "local-dashboard",
                "dashboard_scopes": [
                    "openid", "profile", "urn:logto:scope:organizations",
                    "urn:logto:scope:organization_roles", "alerts:read",
                ],
            },
        )
        self.api = ControlAPI(self.store, portal_authenticator=TokenPortalAuthenticator())

    def tearDown(self):
        self.store.close()

    @staticmethod
    def portal_headers(token="owner-a"):
        return {"Authorization": f"Bearer {token}"}

    def create_and_exchange(self, token="owner-a", name="New York edge"):
        created = self.api.handle(
            "POST", "/v1/portal/deployments", headers=self.portal_headers(token),
            body={"name": name, "update_channel": "stable"},
        )
        self.assertEqual(created.status, 201, created.body)
        exchange = self.api.handle(
            "POST", "/v1/enrollment/exchange",
            headers={"Idempotency-Key": f"exchange-{token}-0001"},
            body={"enrollment_token": created.body["enrollment_token"], "csr": make_csr()},
        )
        self.assertEqual(exchange.status, 201, exchange.body)
        return created.body, exchange.body

    def test_authenticated_enrollment_returns_logto_identity_and_token_is_not_listed_again(self):
        created, enrollment = self.create_and_exchange()
        self.assertEqual(enrollment["identity"], {
            "issuer": "https://identity.example/oidc",
            "jwks_uri": "https://identity.example/oidc/jwks",
            "dashboard_client_id": "local-dashboard",
            "organization_id": "org-a",
            "dashboard_scopes": [
                "openid", "profile", "urn:logto:scope:organizations",
                "urn:logto:scope:organization_roles", "alerts:read",
            ],
        })
        self.assertNotIn("offline_access", enrollment["identity"]["dashboard_scopes"])
        listed = self.api.handle("GET", "/v1/portal/enrollments", headers=self.portal_headers())
        self.assertEqual(listed.status, 200, listed.body)
        self.assertEqual(listed.body["items"][0]["enrollment_id"], created["enrollment_id"])
        self.assertEqual(listed.body["items"][0]["status"], "used")
        self.assertNotIn("enrollment_token", json.dumps(listed.body))
        self.assertNotIn("token_hash", json.dumps(listed.body))

    def test_fleet_health_versions_sensors_usage_and_updates_are_metadata_only(self):
        _, enrollment = self.create_and_exchange()
        deployment_id = enrollment["deployment_id"]
        machine = {
            "X-Tenant-ID": enrollment["tenant_id"],
            "X-Deployment-ID": deployment_id,
            "X-Verified-Client-Certificate-Fingerprint": enrollment["certificate_fingerprint"],
        }
        heartbeat = self.api.handle(
            "POST", f"/v1/deployments/{deployment_id}/heartbeat",
            headers={**machine, "Idempotency-Key": "heartbeat-cloud-0001"},
            body={
                "software_version": "0.0.9",
                "sensor_health": {"suricata-01": "healthy", "zeek-01": "degraded"},
                "event_count": 4200,
                "storage_percent": 18.5,
                "update_status": "available",
                "error_codes": ["SENSOR_LAG_01"],
            },
        )
        self.assertEqual(heartbeat.status, 200, heartbeat.body)
        usage = self.api.handle(
            "POST", f"/v1/deployments/{deployment_id}/usage",
            headers={**machine, "Idempotency-Key": "usage-cloud-000001"},
            body={"events_processed": 4200, "protected_assets": 84, "model_requests": 7, "input_tokens": 900},
        )
        self.assertEqual(usage.status, 200, usage.body)

        detail = self.api.handle(
            "GET", f"/v1/portal/deployments/{deployment_id}", headers=self.portal_headers()
        )
        self.assertEqual(detail.status, 200, detail.body)
        self.assertEqual(detail.body["software"]["installed_version"], "0.0.9")
        self.assertTrue(detail.body["software"]["update_available"])
        self.assertEqual(detail.body["sensors"][0], {"sensor_id": "suricata-01", "status": "healthy"})
        self.assertEqual(detail.body["usage"]["events_processed"], 4200)
        serialized = json.dumps(detail.body).lower()
        for forbidden in ("raw_events", "evidence_ids", "packet_capture", "src_ip", "analyst_notes", "prompt", "response"):
            self.assertNotIn(forbidden, serialized)
        columns = {
            row["name"]
            for row in self.store.connection.execute("PRAGMA table_info(deployments)")
        }
        self.assertFalse(columns & {"events_json", "evidence_json", "prompts_json", "responses_json", "pcap"})

    def test_cross_organization_reads_and_read_only_mutations_fail_closed(self):
        _, deployment_a = self.create_and_exchange("owner-a", "Tenant A site")
        _, deployment_b = self.create_and_exchange("owner-b", "Tenant B site")
        list_a = self.api.handle("GET", "/v1/portal/deployments", headers=self.portal_headers("owner-a"))
        self.assertEqual([item["deployment_id"] for item in list_a.body["items"]], [deployment_a["deployment_id"]])
        cross_read = self.api.handle(
            "GET", f"/v1/portal/deployments/{deployment_b['deployment_id']}",
            headers=self.portal_headers("owner-a"),
        )
        self.assertEqual(cross_read.status, 404)
        denied = self.api.handle(
            "POST", "/v1/portal/deployments", headers=self.portal_headers("reader-a"),
            body={"name": "Forbidden site"},
        )
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.body["error"]["code"], "permission_denied")

    def test_entitlement_policy_support_and_channel_mutations_are_scoped_and_audited(self):
        _, enrollment = self.create_and_exchange()
        deployment_id = enrollment["deployment_id"]
        entitlements = self.api.handle(
            "PATCH", f"/v1/portal/deployments/{deployment_id}/entitlements",
            headers=self.portal_headers(), body={"ai_monthly_limit": 2500, "offline_grace_days": 21},
        )
        self.assertEqual(entitlements.status, 200, entitlements.body)
        self.assertEqual(entitlements.body["ai_monthly_limit"], 2500)
        policy = self.api.handle(
            "PATCH", f"/v1/portal/deployments/{deployment_id}/model-policy",
            headers=self.portal_headers(),
            body={
                "policy_id": "policy-v2", "level": "strict", "provider": "approved-provider",
                "model": "evidence-assessor-v2", "region": "us", "retention_mode": "zero", "enabled": True,
            },
        )
        self.assertEqual(policy.status, 200, policy.body)
        invalid_retention = self.api.handle(
            "PATCH", f"/v1/portal/deployments/{deployment_id}/model-policy",
            headers=self.portal_headers(), body={"retention_mode": "30-days"},
        )
        self.assertEqual(invalid_retention.status, 400)
        organization = self.api.handle(
            "PATCH", "/v1/portal/organization", headers=self.portal_headers(),
            body={
                "name": "Northstar Labs", "support_tier": "priority", "service_level": "24x7",
                "support_email": "security@northstar.example", "external_customer_ref": "CRM-1042",
            },
        )
        self.assertEqual(organization.status, 200, organization.body)
        channel = self.api.handle(
            "PATCH", f"/v1/portal/deployments/{deployment_id}/update-channel",
            headers=self.portal_headers(), body={"update_channel": "preview"},
        )
        self.assertEqual(channel.status, 200, channel.body)
        actions = {
            row["action"] for row in self.store.connection.execute(
                "SELECT action FROM control_audit WHERE tenant_id = 'tenant-a'"
            )
        }
        self.assertTrue({"enrollment.created", "deployment.entitlements.updated", "deployment.model-policy.updated", "organization.updated", "deployment.update-channel.updated"} <= actions)

    def test_customer_content_is_rejected_at_machine_and_portal_boundaries(self):
        _, enrollment = self.create_and_exchange()
        machine = {
            "X-Tenant-ID": enrollment["tenant_id"],
            "X-Deployment-ID": enrollment["deployment_id"],
            "X-Verified-Client-Certificate-Fingerprint": enrollment["certificate_fingerprint"],
            "Idempotency-Key": "heartbeat-forbidden-01",
        }
        nested = self.api.handle(
            "POST", f"/v1/deployments/{enrollment['deployment_id']}/heartbeat", headers=machine,
            body={"sensor_health": {"zeek": {"status": "healthy", "events": [{"src_ip": "10.0.0.1"}]}}},
        )
        self.assertEqual(nested.status, 400)
        self.assertEqual(nested.body["error"]["code"], "customer_content_forbidden")
        portal = self.api.handle(
            "PATCH", "/v1/portal/organization", headers=self.portal_headers(),
            body={"name": "Northstar", "evidence": {"id": "event-1"}},
        )
        self.assertEqual(portal.status, 400)
        self.assertEqual(portal.body["error"]["code"], "customer_content_forbidden")


class PortalJWTAuthenticationTests(unittest.TestCase):
    now = 1_800_000_000

    def setUp(self):
        self.config = PortalAuthConfig(
            mode="jwt",
            issuer="https://identity.example/oidc",
            audience="https://hybrid-ndr.cloud/api",
            jwks_url="https://identity.example/oidc/jwks",
            allowed_organization_ids=("org-a",),
        )
        self.authenticator = PortalJWTAuthenticator(
            self.config,
            StaticJWKSource([{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "identity-test-key",
                "n": test_identity.N, "e": test_identity.E,
            }]),
            wall_clock=lambda: self.now,
        )
        self.claims = {
            "iss": self.config.issuer, "aud": self.config.audience, "sub": "owner-a",
            "iat": self.now - 10, "exp": self.now + 300,
            "tenant_id": "tenant-a", "organization_id": "org-a", "organization_binding_id": "org-a",
            "roles": ["organization_owner"],
            "jti": "portal-token-001", "actor_type": "human", "session_id": "portal-session-001",
            "scope": "openid organizations:read deployments:read deployments:manage policy:read policy:manage",
        }

    def test_logto_organization_token_resolves_cloud_permissions(self):
        principal = self.authenticator.authenticate({"authorization": "Bearer " + test_identity.token(self.claims)})
        self.assertEqual(principal.tenant_id, "tenant-a")
        self.assertEqual(principal.organization_id, "org-a")
        self.assertIn("deployments:manage", principal.permissions)

    def test_binding_mismatch_and_deployment_agent_are_rejected(self):
        cases = [
            ({**self.claims, "organization_binding_id": "org-b"}, "organization_mismatch"),
            ({**self.claims, "roles": ["deployment_agent"]}, "human_role_required"),
            ({key: value for key, value in self.claims.items() if key != "session_id"}, "invalid_token_claims"),
            ({**self.claims, "actor_type": "machine"}, "invalid_token_type"),
        ]
        for claims, code in cases:
            with self.subTest(code=code), self.assertRaises(AuthenticationError) as failure:
                self.authenticator.authenticate({"authorization": "Bearer " + test_identity.token(claims)})
            self.assertEqual(failure.exception.code, code)


if __name__ == "__main__":
    unittest.main()
