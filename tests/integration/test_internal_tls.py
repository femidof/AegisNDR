from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = ROOT / "infra/compose/docker-compose.yml"
INTERNAL_TLS_COMPOSE = ROOT / "infra/compose/docker-compose.internal-tls.yml"
ENV_FILE = ROOT / "infra/compose/.env.example"


def _config(*, response=False) -> dict:
    environment = os.environ.copy()
    if response:
        environment.update(RESPONSE_CONFIG_PATH=str(ROOT / "infra/response/controller.example.json"),
                           RESPONSE_SECRETS_DIR=str(ROOT / "infra/response"))
    result = subprocess.run(
        [
            "docker", "compose", "--project-directory", str(ROOT),
            "--file", str(BASE_COMPOSE), "--file", str(INTERNAL_TLS_COMPOSE),
            "--env-file", str(ENV_FILE), "--profile", "customer",
            *(["--file", str(ROOT / "infra/compose/docker-compose.response.yml"), "--profile", "response"] if response else []),
            "config", "--format", "json",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    return json.loads(result.stdout)["services"]


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
class InternalTlsTests(unittest.TestCase):
    def test_response_overlay_preserves_scope_and_credential_boundaries(self):
        services = _config(response=True)
        worker, api = services["response-worker"], services["local-api"]
        self.assertEqual(set(worker["networks"]), {"local-data", "response-egress"})
        self.assertNotIn("response-egress", api["networks"])
        self.assertTrue(worker["read_only"])
        self.assertEqual(worker["cap_drop"], ["ALL"])
        self.assertFalse(worker.get("cap_add"))
        self.assertFalse(worker.get("privileged"))
        self.assertEqual(worker["restart"], "unless-stopped")
        self.assertEqual(worker["profiles"], ["response"])
        self.assertEqual(worker["environment"]["PERSISTENCE_PROFILE"], "production")
        self.assertEqual(worker["environment"]["PERSISTENCE_CA_FILE"], "/run/internal-tls/ca-cert.pem")
        self.assertTrue(worker["environment"]["CLICKHOUSE_URL"].startswith("https://"))
        self.assertTrue(worker["environment"]["MINIO_ENDPOINT"].startswith("https://"))
        for identity in ("TENANT_ID", "DEPLOYMENT_ID"):
            self.assertEqual(worker["environment"][identity], api["environment"][identity])
        self.assertNotIn("/run/response-secrets", {volume["target"] for volume in api["volumes"]})
        secrets = next(volume for volume in worker["volumes"] if volume["target"] == "/run/response-secrets")
        self.assertTrue(secrets["read_only"])
        self.assertNotIn("docker.sock", str(worker["volumes"]))
        self.assertIn("USER 65532:65532", (ROOT / "infra/compose/python.Dockerfile").read_text())
        defaults = json.loads((ROOT / "infra/response/controller.example.json").read_text())
        self.assertFalse(defaults["enabled"])
        self.assertFalse(defaults["automatic_proposals"])

    def test_internal_tls_overlay_encrypts_every_credential_bearing_hop(self) -> None:
        services = _config()

        # The overlay enables TLS by replacing the entrypoint; modern Compose
        # renders that override under `entrypoint` (a list) and `command` null.
        postgres_launch = services["postgres"].get("entrypoint") or services["postgres"].get("command") or []
        postgres_command = " ".join(postgres_launch) if isinstance(postgres_launch, list) else str(postgres_launch)
        self.assertIn("ssl=on", postgres_command)
        self.assertIn("ssl_cert_file=", postgres_command)
        self.assertIn("ssl_key_file=", postgres_command)

        clickhouse_mounts = {
            (item["target"] if isinstance(item, dict) else item.split(":")[1])
            for item in services["clickhouse"]["volumes"]
        }
        self.assertIn("/etc/clickhouse-server/config.d/hybrid-ndr-tls.xml", clickhouse_mounts)

        minio_mounts = {
            (item["target"] if isinstance(item, dict) else item.split(":")[1])
            for item in services["minio"]["volumes"]
        }
        self.assertIn("/run/internal-tls/public.crt", minio_mounts)
        self.assertIn("/run/internal-tls/private.key", minio_mounts)
        self.assertIn("--certs-dir", " ".join(services["minio"]["command"]))
        clickhouse_tls = (ROOT / "infra/internal-tls/clickhouse-tls.xml").read_text()
        self.assertIn('<tcp_port remove="1"/>', clickhouse_tls)
        self.assertIn('<http_port remove="1"/>', clickhouse_tls)

        for service_name in ("local-api", "detection-engine", "operations-agent"):
            environment = services[service_name]["environment"]
            self.assertEqual(environment["PERSISTENCE_CA_FILE"], "/run/internal-tls/ca-cert.pem")
            self.assertTrue(environment["CLICKHOUSE_URL"].startswith("https://"))
            if service_name != "detection-engine":
                self.assertTrue(environment["MINIO_ENDPOINT"].startswith("https://"))

        local_api_dsn = services["local-api"]["environment"]["POSTGRES_URL"]
        self.assertTrue(local_api_dsn.startswith("postgresql://"))

    def test_internal_data_plane_has_no_plaintext_listeners(self) -> None:
        services = _config()
        for private_service in ("postgres", "clickhouse", "minio"):
            self.assertNotIn("ports", services[private_service])
        vector_sink = (ROOT / "infra/internal-tls/vector-tls.yaml").read_text(encoding="utf-8")
        self.assertIn("endpoint: https://clickhouse:8443", vector_sink)
        self.assertIn("ca_file: /run/internal-tls/ca-cert.pem", vector_sink)
        minio_init = (ROOT / "infra/internal-tls/minio-init-override.sh").read_text(encoding="utf-8")
        self.assertIn("https://minio:9000", minio_init)
        grafana = (ROOT / "infra/internal-tls/grafana-datasources.yml").read_text(encoding="utf-8")
        self.assertIn("sslmode: verify-full", grafana)
        self.assertIn("sslrootcert: /run/internal-tls/ca-cert.pem", grafana)


if __name__ == "__main__":
    unittest.main()
