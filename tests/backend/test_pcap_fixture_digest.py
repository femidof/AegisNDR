from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "infra/compose/docker-compose.yml"
GENERATOR = ROOT / "tests/fixtures/generate_sensor_pcap.py"

# Matches the sensor-fixture service's pinned digest in docker-compose.yml.
HASH_LINE = re.compile(r"--verify-sha256\s*\n?\s*-?\s*([0-9a-f]{64})", re.MULTILINE)


class PcapFixtureDigestTests(unittest.TestCase):
    """The acceptance PCAP digest is pinned in Compose.

    If generate_sensor_pcap.py changes the deterministic capture, this test
    fails with the old and new digests so the operator knows to update the
    pinned hash in infra/compose/docker-compose.yml (sensor-fixture service)
    instead of debugging an opaque container failure.
    """

    def test_compose_pin_matches_the_generated_capture(self) -> None:
        compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
        match = HASH_LINE.search(compose_text)
        self.assertIsNotNone(match, "docker-compose.yml must pin --verify-sha256 for the sensor fixture")
        pinned = match.group(1)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sensor-acceptance.pcap"
            result = subprocess.run(
                ["python3", str(GENERATOR), str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = hashlib.sha256(output.read_bytes()).hexdigest()

        self.assertEqual(
            actual,
            pinned,
            "The sensor fixture digest drifted. Regenerate with:\n"
            f"  python3 tests/fixtures/generate_sensor_pcap.py {output} "
            f"--verify-sha256 {actual}\n"
            "and update --verify-sha256 in infra/compose/docker-compose.yml "
            "(sensor-fixture service).",
        )


if __name__ == "__main__":
    unittest.main()
