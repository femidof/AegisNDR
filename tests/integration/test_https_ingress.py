from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = ROOT / "infra/compose/docker-compose.yml"
HTTPS_COMPOSE = ROOT / "infra/compose/docker-compose.https.yml"
ENV_FILE = ROOT / "infra/compose/.env.example"


class HttpsIngressTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
    def test_production_overlay_exposes_only_https_ingress(self) -> None:
        result = subprocess.run(
            [
                "docker", "compose", "--project-directory", str(ROOT),
                "--file", str(BASE_COMPOSE), "--file", str(HTTPS_COMPOSE),
                "--env-file", str(ENV_FILE), "--profile", "customer",
                "config", "--format", "json",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        services = json.loads(result.stdout)["services"]
        self.assertNotIn("ports", services["local-api"])
        self.assertNotIn("ports", services["dashboard"])
        self.assertNotIn("ports", services["grafana"])
        for private_service in ("postgres", "clickhouse", "minio", "prometheus"):
            self.assertNotIn("ports", services[private_service])
        published = {int(item["published"]) for item in services["ingress"]["ports"]}
        self.assertEqual({80, 443}, published)
        self.assertEqual(["operator-access"], sorted(services["ingress"]["networks"].keys()))
        self.assertTrue(services["ingress"]["read_only"])

    def test_proxy_is_host_locked_same_origin_and_hardened(self) -> None:
        config = (ROOT / "infra/ingress/nginx.conf.template").read_text(encoding="utf-8")
        for route in (
            "proxy_pass http://local-api:8080",
            "proxy_pass http://dashboard:4173",
            "proxy_pass http://grafana:3000",
        ):
            self.assertIn(route, config)
        for header in (
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
        ):
            self.assertIn(header, config)
        self.assertIn('if ($host != "${CUSTOMER_LAN_HOST}")', config)
        self.assertIn("return 308 ${DASHBOARD_PUBLIC_ORIGIN}$request_uri", config)
        self.assertNotIn("postgres:", config)
        self.assertNotIn("clickhouse:", config)


if __name__ == "__main__":
    unittest.main()
