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
                "--env-file", str(env_file), "--profile", "customer",
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


def _minimal_env(mode: str = "pcap", interface: str = "lo", network: str = "none") -> dict[str, str]:
    return {
        "TENANT_ID": "11111111-1111-4111-8111-111111111111",
        "DEPLOYMENT_ID": "22222222-2222-4222-8222-222222222222",
        "CLICKHOUSE_DATABASE": "hybrid_ndr",
        "CLICKHOUSE_USER": "hybrid_ndr",
        "CLICKHOUSE_PASSWORD": "replace",
        "POSTGRES_DB": "hybrid_ndr",
        "POSTGRES_USER": "hybrid_ndr",
        "POSTGRES_PASSWORD": "replace",
        "POSTGRES_EXPORTER_USER": "ndr_metrics",
        "POSTGRES_EXPORTER_PASSWORD": "replace",
        "GRAFANA_POSTGRES_USER": "ndr_grafana",
        "GRAFANA_POSTGRES_PASSWORD": "replace",
        "MINIO_ROOT_USER": "hybrid_ndr",
        "MINIO_ROOT_PASSWORD": "replace",
        "GRAFANA_ADMIN_USER": "ndr-admin",
        "GRAFANA_ADMIN_PASSWORD": "replace",
        "SENSOR_CAPTURE_MODE": mode,
        "SENSOR_NETWORK_MODE": network,
        "CAPTURE_INTERFACE": interface,
    }


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
class SensorCaptureWiringTests(unittest.TestCase):
    """Prove the installer-selected interface reaches the capture containers.

    The signed installer writes `SENSOR_CAPTURE_MODE=live`,
    `SENSOR_NETWORK_MODE=host`, and `CAPTURE_INTERFACE=<selected>` into
    customer.env (asserted in tests/installer). This test proves the base
    Compose file renders those values into the Suricata and Zeek containers
    so the run-sensor.sh live path captures AF_PACKET traffic on exactly the
    interface the operator selected at enrollment.
    """

    def test_live_mode_renders_interface_and_host_networking_into_both_sensors(self) -> None:
        services = _config(_minimal_env(mode="live", interface="ens3", network="host"))
        for sensor in ("suricata", "zeek"):
            with self.subTest(sensor=sensor):
                environment = services[sensor]["environment"]
                self.assertEqual(environment["SENSOR_CAPTURE_MODE"], "live")
                self.assertEqual(environment["CAPTURE_INTERFACE"], "ens3")
                self.assertEqual(services[sensor]["network_mode"], "host")

    def test_offline_replay_keeps_isolated_network_and_fixture_defaults(self) -> None:
        services = _config(_minimal_env(mode="pcap", interface="lo", network="none"))
        for sensor in ("suricata", "zeek"):
            with self.subTest(sensor=sensor):
                environment = services[sensor]["environment"]
                self.assertEqual(environment["SENSOR_CAPTURE_MODE"], "pcap")
                self.assertEqual(environment["CAPTURE_INTERFACE"], "lo")
                self.assertEqual(services[sensor]["network_mode"], "none")

    def test_sensor_scripts_validate_live_interface_before_capture(self) -> None:
        for script in (ROOT / "infra/suricata/run-sensor.sh", ROOT / "infra/zeek/run-sensor.sh"):
            with self.subTest(script=str(script)):
                text = script.read_text(encoding="utf-8")
                self.assertIn('SENSOR_CAPTURE_MODE:-pcap', text)
                self.assertIn('CAPTURE_INTERFACE', text)
                self.assertIn('/sys/class/net/', text)
                if "suricata" in str(script):
                    self.assertIn("exec suricata", text)
                else:
                    self.assertIn("exec zeek", text)


if __name__ == "__main__":
    unittest.main()
