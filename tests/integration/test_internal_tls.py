from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = ROOT / "infra/compose/docker-compose.yml"
INTERNAL_TLS_COMPOSE = ROOT / "infra/compose/docker-compose.internal-tls.yml"
ENV_FILE = ROOT / "infra/compose/.env.example"


def _config() -> dict:
    result = subprocess.run(
        [
            "docker", "compose", "--project-directory", str(ROOT),
            "--file", str(BASE_COMPOSE), "--file", str(INTERNAL_TLS_COMPOSE),
            "--env-file", str(ENV_FILE), "--profile", "customer",
            "config", "--format", "json",
        ],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return json.loads(result.stdout)["services"]


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
class InternalTlsTests(unittest.TestCase):
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
        self.assertIn("/root/.minio/certs/public.crt", minio_mounts)
        self.assertIn("/root/.minio/certs/private.key", minio_mounts)

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
