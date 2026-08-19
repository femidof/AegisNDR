from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from hybrid_ndr_local_api import create_application
from hybrid_ndr_storage import LocalStore


ROOT = Path(__file__).resolve().parents[2]
TENANT = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT = "22222222-2222-4222-8222-222222222222"


def provision_standalone_identity(directory: Path) -> Path:
    """Create tenant/deployment IDs and a locally signed deployment cert, then
    run the installer's standalone identity provisioning subcommand."""
    identity = directory / "identity"
    identity.mkdir(mode=0o700)
    (identity / "tenant-id").write_text(TENANT + "\n", encoding="ascii")
    (identity / "deployment-id").write_text(DEPLOYMENT + "\n", encoding="ascii")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-out", str(identity / "deployment-key.pem")],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "req", "-new", "-sha256", "-key", str(identity / "deployment-key.pem"),
         "-subj", "/CN=hybrid-ndr-customer-deployment", "-out", str(identity / "deployment.csr.pem")],
        check=True, capture_output=True,
    )
    ca_key = directory / "ca-key.pem"
    ca_cert = directory / "ca-cert.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(ca_key)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "req", "-x509", "-new", "-sha256", "-days", "2", "-key", str(ca_key),
         "-subj", "/CN=Test Standalone CA", "-out", str(ca_cert)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "x509", "-req", "-sha256", "-days", "2",
         "-in", str(identity / "deployment.csr.pem"), "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-set_serial", "0x1002", "-out", str(identity / "deployment-cert.pem")],
        check=True, capture_output=True,
    )
    subprocess.run(
        [ROOT / "installer/process-enrollment.py", "standalone", str(identity), "https://hybrid-ndr.local"],
        check=True, capture_output=True,
    )
    return identity


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for standalone identity provisioning")
class StandaloneAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.identity = provision_standalone_identity(Path(self.temporary.name))
        self.login_secret = "a" * 64
        self.environ = {
            **os.environ,
            "AUTH_MODE": "jwt",
            "AUTH_ISSUER": "https://hybrid-ndr.local/oidc",
            "AUTH_AUDIENCE": "https://hybrid-ndr.local/api",
            "AUTH_JWKS_URL": "https://hybrid-ndr.local/api/v1/system/jwks",
            "AUTH_TENANT_ID": TENANT,
            "AUTH_DEPLOYMENT_ID": DEPLOYMENT,
            "AUTH_STANDALONE_ISSUER_KEY_FILE": str(self.identity / "local-issuer-key.pem"),
            "AUTH_STANDALONE_JWKS_FILE": str(self.identity / "local-jwks.json"),
            "AUTH_STANDALONE_LOGIN_SECRET": self.login_secret,
        }
        self.previous = {key: os.environ.get(key) for key in self.environ}
        os.environ.update(self.environ)
        self.store = LocalStore(":memory:")
        self.store.reset_demo()
        self.application = create_application(self.store)
        self.api = self.application.api

    def tearDown(self) -> None:
        self.store.close()
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temporary.cleanup()

    def test_jwks_endpoint_serves_the_local_keys_without_authentication(self) -> None:
        result = self.api.handle("GET", "/api/v1/system/jwks")
        self.assertEqual(result.status, 200)
        keys = result.body["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["kty"], "RSA")
        self.assertEqual(keys[0]["alg"], "RS256")
        jwks = json.loads((self.identity / "local-jwks.json").read_text(encoding="ascii"))
        self.assertEqual(keys[0]["kid"], jwks["keys"][0]["kid"])

    def test_login_requires_the_local_bootstrap_secret(self) -> None:
        denied = self.api.handle(
            "POST", "/api/v1/system/standalone-login",
            headers={"Authorization": "Bearer wrong-secret"},
            body={"analyst": "alice", "role": "analyst"},
        )
        self.assertEqual(denied.status, 401)

    def test_issued_token_authenticates_against_the_local_api(self) -> None:
        login = self.api.handle(
            "POST", "/api/v1/system/standalone-login",
            headers={"Authorization": f"Bearer {self.login_secret}"},
            body={"analyst": "alice", "role": "analyst"},
        )
        self.assertEqual(login.status, 200, login.body)
        token = login.body["access_token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": TENANT,
            "X-Deployment-ID": DEPLOYMENT,
        }
        alerts = self.api.handle("GET", "/api/v1/alerts", headers=headers)
        self.assertEqual(alerts.status, 200, alerts.body)
        # The token is tenant-scoped; a different tenant is rejected.
        other = self.api.handle(
            "GET", "/api/v1/alerts",
            headers={**headers, "X-Tenant-ID": "33333333-3333-4333-8333-333333333333"},
        )
        self.assertEqual(other.status, 403)

    def test_standalone_login_rejects_unavailable_roles(self) -> None:
        login = self.api.handle(
            "POST", "/api/v1/system/standalone-login",
            headers={"Authorization": f"Bearer {self.login_secret}"},
            body={"analyst": "mallory", "role": "deployment_agent"},
        )
        self.assertEqual(login.status, 400)


if __name__ == "__main__":
    unittest.main()
