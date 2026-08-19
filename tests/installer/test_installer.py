from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def command(self, *arguments: str | Path, env: dict[str, str] | None = None, check: bool = True):
        return subprocess.run(
            [str(value) for value in arguments],
            cwd=ROOT,
            env=env,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def signing_material(self) -> tuple[Path, Path]:
        private = self.base / "release-private.pem"
        public = self.base / "release-public.pem"
        self.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", private)
        self.command("openssl", "pkey", "-in", private, "-pubout", "-out", public)
        return private, public

    def test_release_signature_and_checksum_reject_tampering(self) -> None:
        private, public = self.signing_material()
        release = self.base / "hybrid-ndr-1.2.3.tar.gz"
        release.write_bytes(b"signed release\n")
        digest = self.command("sha256sum", release).stdout.split()[0]
        checksum = self.base / f"{release.name}.sha256"
        checksum.write_text(f"{digest}  {release.name}\n", encoding="ascii")
        signature = self.base / f"{release.name}.sig"
        self.command("openssl", "dgst", "-sha256", "-sign", private, "-out", signature, release)
        verified = self.command(ROOT / "installer/verify-release.sh", "--public-key", public, release, checksum, signature)
        self.assertIn("release verified", verified.stdout)
        release.write_bytes(b"tampered\n")
        rejected = self.command(ROOT / "installer/verify-release.sh", "--public-key", public, release, checksum, signature, check=False)
        self.assertNotEqual(rejected.returncode, 0)

    def test_code_only_offline_bundle_build_verify_and_safe_extract(self) -> None:
        private, public = self.signing_material()
        source = self.base / "source"
        (source / "installer").mkdir(parents=True)
        (source / "infra/compose").mkdir(parents=True)
        (source / "infra/ingress").mkdir(parents=True)
        (source / "installer/install.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (source / "infra/compose/docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        (source / "infra/compose/docker-compose.https.yml").write_text("services: {}\n", encoding="utf-8")
        (source / "infra/ingress/nginx.conf.template").write_text("server {}\n", encoding="utf-8")
        os.chmod(source / "installer/install.sh", 0o755)
        output = self.base / "out"
        self.command(
            ROOT / "scripts/build-offline-bundle.sh",
            "--source-dir", source,
            "--output-dir", output,
            "--version", "1.2.3",
            "--signing-key", private,
            "--skip-images",
        )
        bundle = output / "hybrid-ndr-1.2.3-offline.tar.gz"
        extraction = self.base / "extracted"
        result = self.command(
            ROOT / "scripts/verify-offline-bundle.sh",
            "--public-key", public,
            "--extract-to", extraction,
            bundle,
            Path(f"{bundle}.sha256"),
            Path(f"{bundle}.sig"),
        )
        self.assertIn('"status": "verified"', result.stdout)
        self.assertTrue((extraction / "payload/hybrid-ndr/installer/install.sh").is_file())

    def fake_environment(self) -> tuple[dict[str, str], Path]:
        binary_dir = self.base / "bin"
        binary_dir.mkdir()
        log = self.base / "docker.log"
        docker = binary_dir / "docker"
        docker.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >>"$FAKE_DOCKER_LOG"
if [[ "${1:-}" == info ]]; then exit 0; fi
if [[ "${1:-}" == version ]]; then echo '29.7.1'; exit 0; fi
if [[ "${1:-}" == inspect ]]; then echo 'healthy'; exit 0; fi
if [[ "${1:-}" == image ]]; then exit 0; fi
if [[ "${1:-}" == compose && "${2:-}" == version ]]; then
  [[ "$*" == *--short* ]] && echo '2.40.3' || echo 'Docker Compose version v2.40.3'
  exit 0
fi
if [[ " $* " == *' config --services '* ]]; then
  printf '%s\\n' postgres clickhouse minio minio-init sensor-fixture suricata zeek vector detection-engine deployment-connector update-agent operations-agent local-api dashboard prometheus blackbox-exporter postgres-exporter grafana otel-collector ingress
  exit 0
fi
if [[ " $* " == *' ps --quiet '* ]]; then echo 'container-id'; exit 0; fi
exit 0
""",
            encoding="utf-8",
        )
        os.chmod(docker, 0o755)
        curl = binary_dir / "curl"
        curl.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
output=''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --output ]]; then output=$2; shift 2; else shift; fi
done
if [[ -n "$output" ]]; then cp "$FAKE_ENROLLMENT_RESPONSE" "$output"; printf '200'; fi
""",
            encoding="utf-8",
        )
        os.chmod(curl, 0o755)
        sys_net = self.base / "sys/class/net/eth-test"
        sys_net.mkdir(parents=True)
        (sys_net / "operstate").write_text("up\n", encoding="ascii")
        response = self.base / "enrollment.json"
        update_signing_key = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBe3BCVtVdm/ohr7OyVXwmgyFNpNo\n"
            "SpnUZQSCdbQKRIl/0fvwVX+lnrXeuYx8V6bm3o6w8mlBHOJCBr9RFzIpZQ==\n"
            "-----END PUBLIC KEY-----\n"
        )
        response.write_text(
            json.dumps(
                {
                    "tenant_id": "tenant-test",
                    "deployment_id": "deployment-test",
                    "deployment_certificate": "-----BEGIN CERTIFICATE-----\nDEMO-TEST\n-----END CERTIFICATE-----",
                    "certificate_fingerprint": "a" * 64,
                    "certificate_expires_at": "2026-12-31T00:00:00Z",
                    "entitlements": {"local_detection": True},
                    "model_policy": {"enabled": True},
                    "update_channel": "stable",
                    "update_signing_public_key": update_signing_key,
                    "endpoints": {"control_plane": "/v1"},
                    "identity": {
                        "issuer": "https://identity.vendor.example/oidc",
                        "jwks_uri": "https://identity.vendor.example/oidc/jwks",
                        "dashboard_client_id": "local-dashboard",
                        "organization_id": "org-test",
                        "dashboard_scopes": [
                            "openid",
                            "profile",
                            "urn:logto:scope:organizations",
                            "urn:logto:scope:organization_roles",
                            "alerts:read",
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{binary_dir}:{env['PATH']}",
                "FAKE_DOCKER_LOG": str(log),
                "FAKE_ENROLLMENT_RESPONSE": str(response),
                "HYBRID_NDR_SYS_CLASS_NET": str(self.base / "sys/class/net"),
                "HYBRID_NDR_MIN_CPU": "1",
                "HYBRID_NDR_MIN_MEMORY_MB": "1",
                "HYBRID_NDR_MIN_DISK_GB": "0",
                "HYBRID_NDR_REQUIRED_PORTS": "65001 65002",
            }
        )
        return env, log

    def test_install_upgrade_and_uninstall_preserve_identity_and_customer_data(self) -> None:
        env, docker_log = self.fake_environment()
        config = self.base / "config"
        state = self.base / "state"
        token = self.base / "enrollment-token"
        secret_token = "single-use-secret-token"
        token.write_text(secret_token + "\n", encoding="utf-8")
        os.chmod(token, 0o600)
        command = [
            ROOT / "installer/install.sh",
            "--project-dir", ROOT,
            "--config-dir", config,
            "--state-dir", state,
            "--interface", "eth-test",
            "--control-plane-url", "http://127.0.0.1:8081",
            "--allow-insecure-control-plane",
            "--enrollment-token-file", token,
            "--non-interactive",
        ]
        installed = self.command(*command, env=env)
        self.assertIn("installed and healthy", installed.stdout)
        self.assertFalse(token.exists())
        private_key = state / "identity/deployment-key.pem"
        first_key = private_key.read_bytes()
        first_env = (config / "customer.env").read_bytes()
        rendered_env = first_env.decode("utf-8")
        self.assertIn("CAPTURE_INTERFACE=eth-test\n", rendered_env)
        self.assertIn("SENSOR_CAPTURE_MODE=live\n", rendered_env)
        self.assertIn("SENSOR_NETWORK_MODE=host\n", rendered_env)
        self.assertIn("CUSTOMER_LAN_HOST=hybrid-ndr.local\n", rendered_env)
        self.assertIn("DASHBOARD_PUBLIC_ORIGIN=https://hybrid-ndr.local\n", rendered_env)
        self.assertIn("DASHBOARD_ALLOW_INSECURE_HTTP=false\n", rendered_env)
        # The installer provisions the internal data-plane CA by default and
        # points the customer.env at the generated TLS material.
        internal_tls_dir = state / "internal-tls"
        self.assertTrue((internal_tls_dir / "ca-cert.pem").is_file())
        self.assertTrue((internal_tls_dir / "postgres-cert.pem").is_file())
        self.assertTrue((internal_tls_dir / "clickhouse-cert.pem").is_file())
        self.assertTrue((internal_tls_dir / "minio-cert.pem").is_file())
        self.assertIn(f"HYBRID_NDR_INTERNAL_TLS_DIR={internal_tls_dir}\n", rendered_env)
        self.assertIn("AUTH_ISSUER=https://identity.vendor.example/oidc\n", rendered_env)
        self.assertIn("AUTH_JWKS_URL=https://identity.vendor.example/oidc/jwks\n", rendered_env)
        self.assertIn("AUTH_ALLOWED_ORGANIZATION_IDS=org-test\n", rendered_env)
        self.assertIn("LOGTO_ENDPOINT=https://identity.vendor.example\n", rendered_env)
        self.assertIn("LOGTO_PUBLIC_ENDPOINT=https://identity.vendor.example\n", rendered_env)
        self.assertIn("LOGTO_DASHBOARD_CLIENT_ID=local-dashboard\n", rendered_env)
        self.assertIn("LOGTO_ORGANIZATION_ID=org-test\n", rendered_env)
        self.assertIn(
            "LOGTO_DASHBOARD_SCOPES=openid profile urn:logto:scope:organizations "
            "urn:logto:scope:organization_roles alerts:read\n",
            rendered_env,
        )
        tls_certificate = config / "tls/server-cert.pem"
        tls_ca = config / "tls/ca-cert.pem"
        self.assertTrue(tls_certificate.is_file())
        self.command("openssl", "x509", "-in", tls_certificate, "-checkhost", "hybrid-ndr.local", "-noout")
        self.command("openssl", "verify", "-CAfile", tls_ca, tls_certificate)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(private_key.stat().st_mode), 0o600)
        self.assertNotIn(secret_token.encode(), b"".join(path.read_bytes() for path in [*config.rglob("*"), *state.rglob("*")] if path.is_file()))

        upgrade = [value for value in command if value not in ("--enrollment-token-file", token)]
        # Remove the token option and its value as adjacent list elements.
        upgrade = command[: command.index("--enrollment-token-file")] + command[command.index("--enrollment-token-file") + 2 :]
        self.command(*upgrade, env=env)
        self.assertEqual(first_key, private_key.read_bytes())
        self.assertEqual(first_env, (config / "customer.env").read_bytes())

        evidence = state / "evidence/customer-record"
        evidence.write_text("preserve me", encoding="utf-8")
        self.command(
            ROOT / "installer/uninstall.sh",
            "--project-dir", ROOT,
            "--config-dir", config,
            "--state-dir", state,
            env=env,
        )
        self.assertEqual(evidence.read_text(encoding="utf-8"), "preserve me")
        self.assertNotIn("--volumes", docker_log.read_text(encoding="utf-8"))

    def test_offline_image_pins_are_persisted_for_automatic_rollback(self) -> None:
        env, _ = self.fake_environment()
        config = self.base / "config"
        state = self.base / "state"
        token = self.base / "enrollment-token"
        token.write_text("single-use-secret-token\n", encoding="utf-8")
        os.chmod(token, 0o600)
        images = self.base / "images.tar"
        images.write_bytes(b"offline-container-images")
        images_digest = self.command("sha256sum", images).stdout.split()[0]
        release_override = self.base / "docker-compose.release.yml"
        release_override.write_text(
            "services:\n  dashboard:\n    image: sha256:" + "a" * 64 + "\n",
            encoding="utf-8",
        )
        command = [
            ROOT / "installer/install.sh",
            "--project-dir", ROOT,
            "--config-dir", config,
            "--state-dir", state,
            "--interface", "eth-test",
            "--control-plane-url", "http://127.0.0.1:8081",
            "--allow-insecure-control-plane",
            "--enrollment-token-file", token,
            "--release-compose-file", release_override,
            "--offline-images", images,
            "--offline-images-sha256", images_digest,
            "--non-interactive",
        ]
        installed = self.command(*command, env=env)
        self.assertIn("installed and healthy", installed.stdout)
        install_state = (config / "install-state").read_text(encoding="utf-8")
        self.assertIn(f"IMAGES_FILE={images}\n", install_state)
        self.assertIn(f"IMAGES_SHA256={images_digest}\n", install_state)

    def test_standalone_install_provisions_air_gapped_identity(self) -> None:
        env, docker_log = self.fake_environment()
        config = self.base / "config"
        state = self.base / "state"
        command = [
            ROOT / "installer/install.sh",
            "--project-dir", ROOT,
            "--config-dir", config,
            "--state-dir", state,
            "--interface", "eth-test",
            "--standalone",
            "--non-interactive",
        ]
        installed = self.command(*command, env=env)
        self.assertIn("installed and healthy", installed.stdout)
        identity = state / "identity"
        for name in (
            "tenant-id", "deployment-id", "deployment-cert.pem", "certificate-fingerprint",
            "local-issuer-key.pem", "local-jwks.json", "update-signing-public.pem", "enrollment.json",
        ):
            self.assertTrue((identity / name).is_file(), f"missing standalone identity file: {name}")
        rendered_env = (config / "customer.env").read_text(encoding="utf-8")
        self.assertIn("CONNECTOR_ENABLED=false\n", rendered_env)
        self.assertIn("AUTH_ISSUER=https://hybrid-ndr.local/oidc\n", rendered_env)
        self.assertIn("AUTH_JWKS_URL=https://hybrid-ndr.local/api/v1/system/jwks\n", rendered_env)
        self.assertIn("AUTH_ALLOWED_ORGANIZATION_IDS=standalone\n", rendered_env)
        self.assertIn("AUTH_STANDALONE_ISSUER_KEY_FILE=/var/lib/hybrid-ndr/identity/local-issuer-key.pem\n", rendered_env)
        self.assertIn("AUTH_STANDALONE_JWKS_FILE=/var/lib/hybrid-ndr/identity/local-jwks.json\n", rendered_env)
        self.assertIn("AUTH_STANDALONE_LOGIN_SECRET=", rendered_env)
        # No enrollment exchange may be attempted without a control plane.
        docker_log_text = docker_log.read_text(encoding="utf-8")
        self.assertNotIn("enrollment/exchange", docker_log_text)
        # The locally signed certificate verifies against the local CA.
        self.command(
            "openssl", "verify", "-CAfile", identity / "local-ca-cert.pem",
            identity / "deployment-cert.pem",
        )
        # The update-signing key pin is written for the standalone trust model.
        self.assertTrue((config / "update-signing-key.sha256").is_file())
        # A rerun is idempotent and keeps the same identity.
        rerun = self.command(*command, env=env)
        self.assertIn("installed and healthy", rerun.stdout)
        self.assertEqual(
            (identity / "tenant-id").read_text(encoding="utf-8"),
            (state / "identity/tenant-id").read_text(encoding="utf-8"),
        )

    def test_enrollment_identity_rejects_insecure_mismatched_and_offline_configuration(self) -> None:
        env, _ = self.fake_environment()
        response_path = Path(env["FAKE_ENROLLMENT_RESPONSE"])
        valid = json.loads(response_path.read_text(encoding="utf-8"))
        cases = []

        insecure = json.loads(json.dumps(valid))
        insecure["identity"]["issuer"] = "http://identity.vendor.example/oidc"
        insecure["identity"]["jwks_uri"] = "http://identity.vendor.example/oidc/jwks"
        cases.append(insecure)

        mismatched = json.loads(json.dumps(valid))
        mismatched["identity"]["jwks_uri"] = "https://keys.attacker.example/oidc/jwks"
        cases.append(mismatched)

        offline = json.loads(json.dumps(valid))
        offline["identity"]["dashboard_scopes"].append("offline_access")
        cases.append(offline)

        for index, payload in enumerate(cases):
            with self.subTest(index=index):
                source = self.base / f"invalid-enrollment-{index}.json"
                destination = self.base / f"invalid-identity-{index}"
                source.write_text(json.dumps(payload), encoding="utf-8")
                result = self.command(
                    ROOT / "installer/process-enrollment.py",
                    "persist",
                    source,
                    destination,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((destination / "enrollment.json").exists())

    def test_post_install_health_uses_customer_services(self) -> None:
        env, _ = self.fake_environment()
        project = self.base / "project"
        project.mkdir()
        compose = project / "compose.yml"
        https_compose = project / "compose.https.yml"
        internal_tls_compose = project / "docker-compose.internal-tls.yml"
        env_file = project / "customer.env"
        compose.write_text("services: {}\n", encoding="utf-8")
        https_compose.write_text("services: {}\n", encoding="utf-8")
        # The production installer always applies the internal-TLS overlay, so
        # the post-install health gate must resolve it as well.
        internal_tls_compose.write_text("services: {}\n", encoding="utf-8")
        ca_file = project / "ca.pem"
        ca_file.write_text("test-ca\n", encoding="utf-8")
        env_file.write_text(
            f"TENANT_ID=test\nCUSTOMER_LAN_HOST=hybrid-ndr.local\nCUSTOMER_BIND_ADDRESS=0.0.0.0\nHYBRID_NDR_TLS_CA_FILE={ca_file}\n",
            encoding="utf-8",
        )
        result = self.command(
            ROOT / "installer/post-install-health.sh",
            "--project-dir", project,
            "--compose-file", compose,
            "--https-compose-file", https_compose,
            "--env-file", env_file,
            "--timeout", "10",
            env=env,
        )
        self.assertIn("health validation passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
