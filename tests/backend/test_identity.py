from __future__ import annotations

import base64
import hashlib
import json
import unittest

import support  # noqa: F401
from hybrid_ndr_auth import (
    AuthConfig,
    AuthenticationError,
    JWKSClient,
    JWTAuthenticator,
    StaticJWKSource,
    build_authenticator,
)
from hybrid_ndr_local_api import create_application
from hybrid_ndr_storage import LocalStore


N = "vay09qOpvCF2yFAypOwHq-wyl2DhfW2wnY8HFAUpSwuBTApVT8pO9CyW9Y99bHaMG0fIjK7x7ndzydvdTPwhx0jThe4-sxdPo8F4zxNBK45sg0jsAn6YOYP4eGRGAzzd0INkpBx1FjevFQus0jQK3cJpxyRPQl6mA8zk8F_vnwdFK-2A5LgjgjtjOudrlyn07WU28Q3r85l6FgjUXYkEuDSex-PHHxez78vlwvV1JDO5DBf3eMRC9jQRcNFupMzusevBr8GEGu3mWxmWdtAEDci7fRlTJb2rCWXttkMFQBWBJB3Jim4pZ_ZdLBBFAO8KBKcq-v-TP7GvreMi9f-6sw"
E = "AQAB"
D = "KTSjba95eN72PKc7kVubgQyDoyJPal3RkDEZ0w4Z_e0mbjwSc46aX25ubzN4hn8sieKq3XFGKs21kGVc6tQdjHs0RLTQ1zxZt1QZKDdhIZLD3TOS3indbSVP7euu0BZBhAJ_cy2hfC2lshdCuLnIoIuTSkmHlH4WZ93z4Iqe9neQRBmS36LhUsBgycAL6oiuLcO8GPPGme1iVxSt8KndTyCshRi-1kYOZJefLsT1m_YU79sCWqMOTwBlcU0d7kZ99jdKBwCcGJPaUA4C0GgBD5fiOAI7I08M5x8c_AuTz6fmiasW6qeU-ZDioXSFFf4Ud8YAs-LgxabfeknsBh4KCQ"


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def token(claims: dict, header: dict | None = None) -> str:
    header = header or {"alg": "RS256", "typ": "JWT", "kid": "identity-test-key"}
    encoded_header = b64encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_claims = b64encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    modulus = int.from_bytes(b64decode(N), "big")
    private_exponent = int.from_bytes(b64decode(D), "big")
    key_bytes = (modulus.bit_length() + 7) // 8
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
    encoded_message = b"\x00\x01" + b"\xff" * (key_bytes - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus).to_bytes(key_bytes, "big")
    return f"{encoded_header}.{encoded_claims}.{b64encode(signature)}"


class IdentityTests(unittest.TestCase):
    now = 1_800_000_000

    def setUp(self):
        self.config = AuthConfig(
            mode="jwt",
            issuer="http://identity.example/oidc",
            audience="https://hybrid-ndr.local/api",
            jwks_url="http://identity.example/oidc/jwks",
            expected_tenant_id="demo-tenant",
            allowed_organization_ids=("org-ndr",),
            expected_deployment_id="demo-deployment",
            algorithms=("RS256",),
            require_role_claim=True,
        )
        self.authenticator = JWTAuthenticator(
            self.config,
            StaticJWKSource([{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "identity-test-key", "n": N, "e": E}]),
            wall_clock=lambda: self.now,
        )
        self.claims = {
            "iss": self.config.issuer,
            "aud": [self.config.audience],
            "sub": "analyst-01",
            "jti": "access-token-01",
            "iat": self.now - 10,
            "exp": self.now + 300,
            "organization_id": "org-ndr",
            "organization_binding_id": "org-ndr",
            "tenant_id": "demo-tenant",
            "deployment_ids": ["demo-deployment"],
            "roles": ["analyst"],
            "actor_type": "human",
            "session_id": "session-01",
            "scope": "openid alerts:read alerts:update investigations:read audit:read",
        }

    def headers(self, access_token: str | None = None) -> dict[str, str]:
        return {
            "authorization": "Bearer " + (access_token or token(self.claims)),
            "x-deployment-id": "demo-deployment",
        }

    def test_verified_token_resolves_signed_tenant_deployment_role_and_permissions(self):
        principal = self.authenticator.authenticate(self.headers())
        self.assertEqual(principal.tenant_id, "demo-tenant")
        self.assertEqual(principal.organization_id, "org-ndr")
        self.assertEqual(principal.deployment_id, "demo-deployment")
        self.assertEqual(principal.role, "analyst")
        self.assertIn("alerts:update", principal.permissions)
        # A signed scope still cannot exceed the local role ceiling.
        self.assertNotIn("audit:read", principal.permissions)

    def test_api_uses_bearer_identity_and_ignores_forged_actor_headers(self):
        store = LocalStore(":memory:")
        try:
            store.reset_demo()
            api = create_application(store, authenticator=self.authenticator).api
            response = api.handle(
                "GET", "/api/v1/alerts",
                headers={**self.headers(), "X-Actor-ID": "forged-admin", "X-Role": "organization-owner"},
            )
            self.assertEqual(response.status, 200, response.body)
            denied = api.handle("GET", "/api/v1/audit", headers=self.headers())
            self.assertEqual(denied.status, 403)
        finally:
            store.close()

    def test_tampering_wrong_issuer_audience_and_expiry_fail_closed(self):
        valid = token(self.claims)
        encoded_header, encoded_claims, encoded_signature = valid.split(".")
        changed_signature = bytearray(b64decode(encoded_signature))
        changed_signature[-1] ^= 1
        changed = f"{encoded_header}.{encoded_claims}.{b64encode(bytes(changed_signature))}"
        cases = [
            (changed, "invalid_token_signature"),
            (token({**self.claims, "iss": "http://attacker.example/oidc"}), "invalid_token_issuer"),
            (token({**self.claims, "aud": "https://other.example/api"}), "invalid_token_audience"),
            (token({**self.claims, "exp": self.now - 60}), "token_expired"),
        ]
        for access_token, expected_code in cases:
            with self.subTest(expected_code=expected_code), self.assertRaises(AuthenticationError) as failure:
                self.authenticator.authenticate(self.headers(access_token))
            self.assertEqual(failure.exception.code, expected_code)

    def test_cross_organization_and_cross_deployment_tokens_are_rejected(self):
        cases = [
            ({**self.claims, "organization_id": "org-other"}, "organization_mismatch"),
            ({**self.claims, "organization_binding_id": "org-other"}, "organization_mismatch"),
            ({**self.claims, "tenant_id": "other-tenant"}, "tenant_mismatch"),
            ({**self.claims, "deployment_ids": ["other-deployment"]}, "deployment_mismatch"),
            ({key: value for key, value in self.claims.items() if key != "roles"}, "role_claim_missing"),
        ]
        for claims, expected_code in cases:
            with self.subTest(expected_code=expected_code), self.assertRaises(AuthenticationError) as failure:
                self.authenticator.authenticate(self.headers(token(claims)))
            self.assertEqual(failure.exception.code, expected_code)

    def test_human_and_machine_token_types_and_session_binding_are_enforced(self):
        machine_claims = {
            **self.claims,
            "sub": "deployment-client",
            "jti": "machine-token-01",
            "roles": ["deployment_agent"],
            "actor_type": "machine",
            "scope": "events:write sensors:write alerts:read",
        }
        machine_claims.pop("session_id")
        principal = self.authenticator.authenticate(self.headers(token(machine_claims)))
        self.assertEqual(principal.role, "deployment_agent")
        self.assertEqual(principal.permissions, frozenset({"events:write", "sensors:write"}))

        cases = [
            ({key: value for key, value in self.claims.items() if key != "session_id"}, "invalid_token_claims"),
            ({**self.claims, "actor_type": "machine"}, "invalid_token_type"),
            ({**machine_claims, "actor_type": "human"}, "invalid_token_type"),
            ({**machine_claims, "roles": ["deployment_agent", "analyst"]}, "invalid_token_type"),
        ]
        for claims, expected_code in cases:
            with self.subTest(expected_code=expected_code), self.assertRaises(AuthenticationError) as failure:
                self.authenticator.authenticate(self.headers(token(claims)))
            self.assertEqual(failure.exception.code, expected_code)

    def test_static_emergency_token_and_session_revocation_fail_closed(self):
        revoked = JWTAuthenticator(
            AuthConfig(
                **{
                    **self.config.__dict__,
                    "revoked_token_ids": ("blocked-token",),
                    "revoked_session_ids": ("blocked-session",),
                }
            ),
            StaticJWKSource([
                {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "identity-test-key", "n": N, "e": E}
            ]),
            wall_clock=lambda: self.now,
        )
        for claims, expected_code in [
            ({**self.claims, "jti": "blocked-token"}, "token_revoked"),
            ({**self.claims, "session_id": "blocked-session"}, "session_revoked"),
        ]:
            with self.subTest(expected_code=expected_code), self.assertRaises(AuthenticationError) as failure:
                revoked.authenticate(self.headers(token(claims)))
            self.assertEqual(failure.exception.code, expected_code)

    def test_unsigned_and_algorithm_confusion_tokens_are_rejected(self):
        unsigned = ".".join((
            b64encode(json.dumps({"alg": "none", "kid": "identity-test-key"}).encode()),
            b64encode(json.dumps(self.claims).encode()),
            b64encode(b"not-a-signature"),
        ))
        with self.assertRaises(AuthenticationError) as failure:
            self.authenticator.authenticate(self.headers(unsigned))
        self.assertEqual(failure.exception.code, "unsupported_token_algorithm")

    def test_jwt_environment_configuration_is_fail_closed(self):
        with self.assertRaises(ValueError):
            AuthConfig.from_env({"AUTH_MODE": "jwt", "AUTH_ISSUER": "http://identity.example/oidc"})

    def test_jwks_cache_refreshes_once_for_key_rotation(self):
        calls = []

        class Response:
            def read(self, _limit):
                kid = "old-key" if len(calls) == 1 else "new-key"
                return json.dumps({"keys": [{"kid": kid, "kty": "RSA", "n": N, "e": E}]}).encode()

        def open_jwks(request, timeout):
            calls.append((request.full_url, timeout))
            return Response()

        client = JWKSClient(
            "https://identity.example/oidc/jwks", opener=open_jwks, monotonic=lambda: 100.0,
        )
        self.assertEqual(client.get_key("old-key")["kid"], "old-key")
        self.assertEqual(client.get_key("new-key")["kid"], "new-key")
        self.assertEqual(len(calls), 2)

    def test_jwks_plain_http_url_is_rejected_by_default(self):
        with self.assertRaises(ValueError):
            JWKSClient("http://identity.example/oidc/jwks", opener=lambda _request, _timeout: None)
        # The explicit development override still requires the URL scheme check.
        with self.assertRaises(ValueError):
            JWKSClient("ftp://identity.example/oidc/jwks", allow_insecure_http=True)

    def test_authenticator_factory_rejects_plain_http_jwks_without_override(self):
        environment = {
            "AUTH_MODE": "jwt",
            "AUTH_ISSUER": "https://identity.example/oidc",
            "AUTH_AUDIENCE": "https://hybrid-ndr.local/api",
            "AUTH_JWKS_URL": "http://logto:3001/oidc/jwks",
            "AUTH_TENANT_ID": "tenant-a",
            "AUTH_DEPLOYMENT_ID": "deployment-a",
        }
        with self.assertRaises(ValueError):
            build_authenticator(environ=environment)
        environment["AUTH_JWKS_ALLOW_INSECURE_HTTP"] = "1"
        self.assertIsInstance(build_authenticator(environ=environment), JWTAuthenticator)

    def test_rsa_key_with_small_exponent_is_rejected(self):
        key = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "small-e", "n": N, "e": "Aw"}
        with self.assertRaises(AuthenticationError) as failure:
            JWTAuthenticator._verify_rs256(b"signing-input", b"\x00" * 256, key)
        self.assertEqual(failure.exception.code, "invalid_signing_key")


if __name__ == "__main__":
    unittest.main()
