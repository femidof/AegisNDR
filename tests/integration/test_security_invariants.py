from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_COMPOSE = ROOT / "infra/compose/docker-compose.yml"


def _config(extra_env: dict[str, str]) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as handle:
        for key, value in extra_env.items():
            handle.write(f"{key}={value}\n")
        env_file = Path(handle.name)
    try:
        result = subprocess.run(
            [
                "docker", "compose", "--project-directory", str(ROOT),
                "--file", str(BASE_COMPOSE),
                "--env-file", str(env_file), "--profile", "vendor",
                "config", "--format", "json",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return json.loads(result.stdout)["services"]
    finally:
        env_file.unlink()


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
class SecurityInvariantTests(unittest.TestCase):
    """Production invariants that must never regress."""

    def test_model_gateway_requires_verified_certificate_fingerprint_by_default(self) -> None:
        # The insecure header fallback is a loopback development escape hatch.
        # With no override, the rendered production service must keep it false.
        services = _config({
            "TENANT_ID": "11111111-1111-4111-8111-111111111111",
            "DEPLOYMENT_ID": "22222222-2222-4222-8222-222222222222",
        })
        self.assertEqual(
            services["model-gateway"]["environment"]["MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER"],
            "false",
        )

    def test_installer_generated_environment_never_enables_insecure_fingerprint(self) -> None:
        installer = (ROOT / "installer/install.sh").read_text(encoding="utf-8")
        # The installer writes customer.env from its own templates; forbid any
        # upsert/render that could enable the insecure header. A fail-closed
        # grep guard that rejects `=true` is explicitly allowed.
        for line in installer.splitlines():
            if "MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER" in line and "grep -Eq" in line:
                continue
            self.assertNotIn("MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER", line)
        self.assertIn("MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER)=true", installer)


if __name__ == "__main__":
    unittest.main()
