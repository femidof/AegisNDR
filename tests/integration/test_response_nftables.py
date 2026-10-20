"""Run only in the disposable NET_ADMIN container from test-response-enforcement.sh."""
from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from urllib.error import HTTPError
from urllib.request import urlopen
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/backend"))
import support
from hybrid_ndr_agent.response import now

spec = importlib.util.spec_from_file_location("response_enforcer", ROOT / "services/response-enforcer/enforcer.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@unittest.skipUnless(os.environ.get("AEGIS_NFT_LAB") == "1", "requires disposable nftables lab")
class NftablesAcceptanceTests(unittest.TestCase):
    def setUp(self):
        if not Path("/.dockerenv").exists():
            self.fail("this acceptance check must run inside its disposable container")
        self.directory = tempfile.TemporaryDirectory()
        self.config = dict(schema_version=1, mode="endpoint", tenant_id="lab", deployment_id="lab",
            integration_id="endpoint", device_id="endpoint", targets={"endpoint": ["198.18.0.10"]},
            management_networks=["192.0.2.0/24"], controller_fingerprints=["a" * 64])
        self.enforcer = module.Enforcer(self.config, str(Path(self.directory.name) / "state.db"))
        self.commands = []
        self.nft(["add", "table", "inet", "unrelated_lab_table"])
        for attempt in range(20):
            if self.reachable("192.0.2.20"):
                break
            time.sleep(0.25)

    def nft(self, arguments):
        return subprocess.run(["/usr/sbin/nft", *arguments], text=True, capture_output=True, check=True).stdout

    def reachable(self, address):
        try:
            with socket.create_connection((address, 8000), timeout=1):
                return True
        except OSError:
            return False

    def command(self, family="agent", address="198.18.0.10", duration=60):
        action_id = str(uuid.uuid4())
        value = dict(action_id=action_id, tenant_id="lab", deployment_id="lab", integration_id=self.config["integration_id"],
            target_id="endpoint", address=address, family=family, proposal_hash="b" * 64,
            remote_revision=self.enforcer.revision, command_expires_at=(now() + timedelta(minutes=5)).isoformat(),
            restriction_expires_at=(now() + timedelta(seconds=duration)).isoformat())
        self.commands.append(value)
        return value

    def tearDown(self):
        for command in self.commands:
            try:
                self.enforcer.release(command["action_id"])
            except KeyError:
                pass
        self.nft(["list", "table", "inet", "unrelated_lab_table"])
        self.nft(["delete", "table", "inet", "unrelated_lab_table"])
        self.enforcer.connection.close()
        self.directory.cleanup()

    def test_endpoint_blocks_ipv4_ipv6_preserves_management_and_recovers(self):
        for address in ("192.0.2.20", "198.18.0.20", "2001:db8:198:18::20"):
            self.assertTrue(self.reachable(address), address)
        command = self.command()
        action_id = command["action_id"]
        self.enforcer.prepare(action_id, command)
        self.assertTrue(self.reachable("198.18.0.20"))
        self.assertEqual(self.enforcer.apply(action_id, command)["state"], "applied")
        self.assertTrue(self.reachable("192.0.2.20"))
        self.assertFalse(self.reachable("198.18.0.20"))
        self.assertFalse(self.reachable("2001:db8:198:18::20"))
        # Simulate kernel rules lost on reboot; durable intent must restore them.
        self.nft(["delete", "table", "inet", self.enforcer._name(action_id)])
        self.assertTrue(self.reachable("198.18.0.20"))
        self.enforcer.restore()
        self.assertFalse(self.reachable("198.18.0.20"))
        self.assertEqual(self.enforcer.release(action_id)["state"], "released")
        self.assertTrue(self.reachable("198.18.0.20"))
        self.assertTrue(self.reachable("2001:db8:198:18::20"))
        self.enforcer.restore()
        self.assertEqual(self.enforcer.apply(action_id, command)["state"], "released")

    def test_gateway_kernel_timeout_survives_controller_absence(self):
        self.enforcer.connection.close()
        interfaces = json.loads(subprocess.check_output(["/usr/sbin/ip", "-j", "address", "show"]))
        interface = next(item["ifname"] for item in interfaces if any(
            address.get("local") == "198.18.0.10" for address in item.get("addr_info", [])))
        self.config.update(mode="gateway", integration_id="gateway", zone_interface=interface,
                           targets={"endpoint": ["198.18.0.20", "2001:db8:198:18::20"]})
        self.enforcer = module.Enforcer(self.config, str(Path(self.directory.name) / "gateway.db"))

        def forwarded(version):
            try:
                with urlopen("http://192.0.2.20:8000/probe/" + version, timeout=3) as response:
                    return response.status == 200
            except HTTPError as error:
                error.close()
                return False

        for address, version in (("198.18.0.20", "ipv4"), ("2001:db8:198:18::20", "ipv6")):
            for attempt in range(20):
                if forwarded(version):
                    break
                time.sleep(0.25)
            self.assertTrue(forwarded(version), version)
            command = self.command("firewall", address, duration=5)
            self.assertEqual(self.enforcer.apply(command["action_id"], command)["state"], "applied")
            self.assertFalse(forwarded(version), version)
            time.sleep(5.1)
            self.assertEqual(self.enforcer.observe(command["action_id"])["state"], "released")
            self.assertTrue(forwarded(version), version)
            self.enforcer.release(command["action_id"])
