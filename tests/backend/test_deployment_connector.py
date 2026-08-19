from __future__ import annotations

import json
import os
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import support  # noqa: F401
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hybrid_ndr_connector import Connector, ConnectorSettings, ConnectorState
from hybrid_ndr_control_api.pki import CertificateAuthority
from hybrid_ndr_transport import OutboundHTTPError


def atomic_private(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    os.chmod(path, 0o600)


class Metrics:
    def heartbeat(self):
        return {"sensor_health": {"suricata": "healthy"}, "event_count": 17, "storage_percent": 2.5}

    def usage(self):
        return {"events_processed": 17, "bytes_processed": 2048, "protected_assets": 3}


class Client:
    def __init__(self, authority: CertificateAuthority, issued: dict, *, fail_heartbeat: bool = False) -> None:
        self.authority, self.issued, self.fail_heartbeat = authority, issued, fail_heartbeat
        self.calls: list[tuple[str, str, dict, dict]] = []

    def request(self, method, path, *, body=None, headers=None):
        self.calls.append((method, path, dict(body or {}), dict(headers or {})))
        if path.endswith("/heartbeat") and self.fail_heartbeat:
            raise OutboundHTTPError("transport_unavailable")
        if path.endswith("/entitlements"):
            return {"local_detection": True, "model_investigations": True}
        if path.endswith("/model-policy"):
            return {"policy_id": "p1", "level": "balanced", "provider": "demo-zero-retention", "model": "evidence-assessor-v1", "region": "us", "retention_mode": "zero", "enabled": True}
        if path == "/v1/updates/manifest":
            manifest = {"channel": "stable", "version": "0.1.0", "artifact": "registry.example/ndr@sha256:" + "a" * 64, "published_at": "2026-08-05T00:00:00Z", "signature_algorithm": "ECDSA_P256_SHA256"}
            canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            return {**manifest, "signature": self.authority.sign_update_manifest(canonical)}
        if path == "/v1/certificates/rotate":
            return dict(self.issued)
        return {"status": "ok"}


class DeploymentConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.identity = root / "identity"
        self.identity.mkdir(mode=0o700)
        self.key = ec.generate_private_key(ec.SECP256R1())
        key_pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        atomic_private(self.identity / "deployment-key.pem", key_pem)
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "connector-test")])).sign(self.key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        atomic_private(self.identity / "deployment.csr.pem", csr_pem)
        self.authority = CertificateAuthority.create()
        old = self.authority.issue_deployment_certificate(csr_pem.decode(), tenant_id="tenant-1", deployment_id="deployment-1", validity_days=1)
        new = self.authority.issue_deployment_certificate(csr_pem.decode(), tenant_id="tenant-1", deployment_id="deployment-1", validity_days=365)
        old_fingerprint = old.fingerprint(hashes.SHA256()).hex()
        atomic_private(self.identity / "deployment-cert.pem", old.public_bytes(serialization.Encoding.PEM))
        atomic_private(self.identity / "certificate-fingerprint", (old_fingerprint + "\n").encode())
        atomic_private(self.identity / "tenant-id", b"tenant-1\n")
        atomic_private(self.identity / "deployment-id", b"deployment-1\n")
        enrollment = {
            "tenant_id": "tenant-1", "deployment_id": "deployment-1", "certificate_fingerprint": old_fingerprint,
            "certificate_expires_at": old.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
            "update_signing_public_key": self.authority.update_signing_public_key_pem(),
        }
        atomic_private(self.identity / "enrollment.json", json.dumps(enrollment).encode())
        self.issued = {
            "deployment_id": "deployment-1", "deployment_certificate": new.public_bytes(serialization.Encoding.PEM).decode(),
            "certificate_fingerprint": new.fingerprint(hashes.SHA256()).hex(),
            "certificate_expires_at": new.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        }
        self.settings = ConnectorSettings(
            control_plane_url="http://127.0.0.1:8081", identity_dir=self.identity,
            state_database=root / "connector" / "state.sqlite3", software_version="1.2.3",
            allow_insecure_loopback=True, heartbeat_seconds=60, usage_seconds=60,
            configuration_seconds=60, update_seconds=60, certificate_check_seconds=60,
            retry_initial_seconds=4, retry_max_seconds=16,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_full_cycle_reports_only_aggregates_refreshes_documents_and_rotates(self) -> None:
        client = Client(self.authority, self.issued)
        connector = Connector(self.settings, metrics=Metrics(), client_factory=lambda: client, monotonic=lambda: 100.0, random_source=random.Random(1))
        outcomes = connector.run_once()
        self.assertEqual(set(outcomes.values()), {"success"}, outcomes)
        heartbeat = next(call for call in client.calls if call[1].endswith("/heartbeat"))
        self.assertEqual(heartbeat[2]["software_version"], "1.2.3")
        self.assertNotIn("evidence", heartbeat[2])
        self.assertEqual(connector.state.document("model_policy")["policy_id"], "p1")
        self.assertTrue(connector.state.document("update_manifest")["artifact"].endswith("a" * 64))
        self.assertEqual((self.identity / "certificate-fingerprint").read_text().strip(), self.issued["certificate_fingerprint"])
        self.assertEqual(set(connector.run_once().values()), {"not_due"})

    def test_retry_preserves_idempotency_key_and_state_across_restart(self) -> None:
        failing = Client(self.authority, self.issued, fail_heartbeat=True)
        connector = Connector(self.settings, metrics=Metrics(), client_factory=lambda: failing, monotonic=lambda: 100.0, random_source=random.Random(2))
        connector.run_once()
        first = next(call for call in failing.calls if call[1].endswith("/heartbeat"))[3]["Idempotency-Key"]
        state = ConnectorState(self.settings.state_database)
        state.connection.execute("UPDATE operations SET due_at = 0 WHERE name = 'heartbeat'")
        state.connection.commit()
        recovered = Client(self.authority, self.issued)
        second = Connector(self.settings, state=state, metrics=Metrics(), client_factory=lambda: recovered, monotonic=lambda: 200.0)
        second.run_once()
        retried = next(call for call in recovered.calls if call[1].endswith("/heartbeat"))[3]["Idempotency-Key"]
        self.assertEqual(first, retried)
        self.assertIsNone(state.operation("heartbeat")["idempotency_key"])

    def test_invalid_signed_manifest_fails_closed_without_replacing_cache(self) -> None:
        client = Client(self.authority, self.issued)
        original = client.request
        def tampered(method, path, **kwargs):
            value = original(method, path, **kwargs)
            if path == "/v1/updates/manifest":
                value["version"] = "9.9.9"
            return value
        client.request = tampered
        connector = Connector(self.settings, metrics=Metrics(), client_factory=lambda: client, monotonic=lambda: 100.0)
        outcomes = connector.run_once()
        self.assertEqual(outcomes["update_manifest"], "failed")
        self.assertIsNone(connector.state.document("update_manifest"))


if __name__ == "__main__":
    unittest.main()
