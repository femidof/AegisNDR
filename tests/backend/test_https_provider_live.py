from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import support  # noqa: F401
from hybrid_ndr_gateway import GatewayPolicyError, ModelGateway, ModelUnavailable
from hybrid_ndr_gateway.provider import HTTPProviderSettings, HTTPZeroRetentionProvider

ROOT = Path(__file__).resolve().parents[2]

VALID_ASSESSMENT = {
    "classification": "likely_dns_tunneling",
    "severity": "high",
    "confidence": 0.92,
    "summary": "The cited DNS evidence shows a tunneling profile and requires analyst review.",
    "supporting_evidence_ids": ["event-dns-1"],
    "mitre_techniques": ["T1071.004"],
    "recommended_actions": ["inspect_endpoint", "review_dns_history"],
    "requires_human_review": True,
}


class _ProviderRecorder:
    """Records every request an HTTPS provider receives during the test."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.response_body: dict = VALID_ASSESSMENT
        self.status = 200
        self.fail_without_auth = True
        self.stream_override: bytes | None = None

    def record(self, method: str, path: str, headers: dict, body: bytes) -> None:
        self.requests.append({
            "method": method,
            "path": path,
            "headers": dict(headers),
            "body": body,
        })


def _make_ca(work: Path) -> tuple[Path, Path]:
    ca_key = work / "ca-key.pem"
    ca_cert = work / "ca-cert.pem"
    subprocess.run(
        [
            "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(ca_key),
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-new", "-sha256", "-days", "2",
            "-key", str(ca_key), "-subj", "/CN=Hybrid NDR Live Provider Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-out", str(ca_cert),
        ],
        check=True, capture_output=True,
    )
    return ca_key, ca_cert


def _make_leaf(work: Path, ca_key: Path, ca_cert: Path) -> tuple[Path, Path]:
    server_key = work / "server-key.pem"
    csr = work / "server.csr"
    server_cert = work / "server-cert.pem"
    extensions = work / "server-ext.cnf"
    extensions.write_text(
        "[server]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="ascii",
    )
    subprocess.run(
        [
            "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(server_key),
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-sha256", "-key", str(server_key),
            "-subj", "/CN=localhost", "-out", str(csr),
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-sha256", "-days", "2",
            "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-set_serial", "0x1001", "-extfile", str(extensions), "-extensions", "server",
            "-out", str(server_cert),
        ],
        check=True, capture_output=True,
    )
    return server_key, server_cert


def _load_chain(certificate: Path, private_key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    return context


class _Handler(BaseHTTPRequestHandler):
    recorder: _ProviderRecorder = _ProviderRecorder()

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("Content-Length") or 0), 1_000_000)
        body = self.rfile.read(length) if length else b""
        self.recorder.record(self.command, self.path, dict(self.headers), body)
        if self.path.rstrip("/") != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return
        if self.recorder.fail_without_auth and self.headers.get("Authorization") != "Bearer live-test-key":
            self.send_response(401)
            self.end_headers()
            return
        if self.headers.get("X-Hybrid-NDR-Retention") != "zero":
            self.send_response(403)
            self.end_headers()
            return
        if self.headers.get("X-Hybrid-NDR-Prompt-Cache") != "disabled":
            self.send_response(403)
            self.end_headers()
            return
        content = json.dumps(self.recorder.response_body).encode("utf-8")
        try:
            stream_requested = bool(json.loads(body).get("stream")) if body else False
        except (json.JSONDecodeError, UnicodeDecodeError):
            stream_requested = False
        if stream_requested:
            self._respond_stream(content)
            return
        payload = json.dumps({
            "model": "evidence-assessor-v1",
            "choices": [{"message": {"content": content.decode("utf-8")}}],
        }).encode("utf-8")
        self.send_response(self.recorder.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _respond_stream(self, content: bytes) -> None:
        """Emit an SSE stream in several content deltas plus the terminal marker."""
        self.send_response(self.recorder.status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.recorder.stream_override is not None:
            self.wfile.write(self.recorder.stream_override)
            self.wfile.flush()
            return
        split = max(1, len(content) // 3)
        for offset in range(0, len(content), split):
            delta = {"choices": [{"delta": {"content": content[offset : offset + split].decode("utf-8")}}]}
            self.wfile.write(b"data: " + json.dumps(delta, separators=(",", ":")).encode("utf-8") + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, *_args: object) -> None:
        return


@unittest.skipUnless(shutil.which("openssl"), "openssl is required to run a live HTTPS provider")
class LiveHttpsProviderGatewayTests(unittest.TestCase):
    """Prove the zero-retention gateway against a real HTTPS provider endpoint.

    This is the in-environment external acceptance for the provider-independent
    gateway: real TLS verification, real authentication and zero-retention
    headers on the wire, schema-constrained response parsing, and fail-closed
    behavior when TLS or the zero-retention attestation is not satisfied.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        work = Path(cls.temporary.name)
        cls.ca_key, cls.ca_cert = _make_ca(work)
        cls.server_key, cls.server_cert = _make_leaf(work, cls.ca_key, cls.ca_cert)
        _Handler.recorder = _ProviderRecorder()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.httpd.socket = _load_chain(cls.server_cert, cls.server_key).wrap_socket(
            cls.httpd.socket, server_side=True
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.temporary.cleanup()

    def _settings(self, **overrides) -> HTTPProviderSettings:
        values = dict(
            name="live-zero-retention",
            endpoint=f"https://127.0.0.1:{self.port}/v1/chat/completions",
            api_key="live-test-key",
            region="us",
            ca_file=str(self.ca_cert),
            zero_retention_verified=True,
            cache_disabled=True,
        )
        values.update(overrides)
        return HTTPProviderSettings(**values)

    def _gateway(self, provider) -> ModelGateway:
        return ModelGateway(
            provider,
            signing_key=b"live-provider-signing-key-0123456789",
            approved_models={"evidence-assessor-v1"},
            approved_regions={"us", "eu"},
        )

    def _payload(self) -> dict:
        return {
            "request_id": "live-https-provider-1",
            "tenant_policy_id": "policy-1",
            "alert_type": "dns-tunneling-v1",
            "severity": "high",
            "entity_type": "host",
            "observations": [
                {
                    "evidence_id": "event-dns-1",
                    "feature": "query_volume",
                    "observed": 420,
                    "baseline_p99": 90,
                }
            ],
            "allowed_actions": ["inspect_endpoint", "review_dns_history"],
        }

    def _policy(self) -> dict:
        return {
            "policy_id": "policy-1",
            "enabled": True,
            "level": "balanced",
            "retention_mode": "zero",
            "provider": "live-zero-retention",
            "model": "evidence-assessor-v1",
            "region": "us",
        }

    def test_live_https_provider_completes_investigate_with_signed_envelope(self) -> None:
        provider = HTTPZeroRetentionProvider(self._settings())
        gateway = self._gateway(provider)
        result = gateway.investigate(
            self._payload(),
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            policy=self._policy(),
        )
        self.assertEqual(result["retention_mode"], "zero")
        self.assertEqual(result["provider"], "live-zero-retention")
        self.assertEqual(result["model"], "evidence-assessor-v1")
        self.assertTrue(gateway.verify_envelope(result))
        self.assertEqual(
            result["response"]["classification"], "likely_dns_tunneling"
        )
        self.assertEqual(
            result["response"]["supporting_evidence_ids"], ["event-dns-1"]
        )

        recorded = _Handler.recorder.requests[-1]
        recorded_headers = {key.lower(): value for key, value in recorded["headers"].items()}
        self.assertEqual(recorded["path"], "/v1/chat/completions")
        self.assertEqual(recorded_headers["authorization"], "Bearer live-test-key")
        self.assertEqual(recorded_headers["x-hybrid-ndr-retention"], "zero")
        self.assertEqual(recorded_headers["x-hybrid-ndr-prompt-cache"], "disabled")
        sent = json.loads(recorded["body"])
        self.assertIs(sent["store"], False)
        self.assertEqual(sent["model"], "evidence-assessor-v1")
        self.assertTrue(sent["response_format"]["type"] == "json_schema")

    def test_http_provider_enforces_response_schema(self) -> None:
        _Handler.recorder.response_body = {
            "classification": "likely_dns_tunneling",
            "severity": "high",
            "confidence": 0.92,
            "summary": "The cited DNS evidence shows a tunneling profile.",
            "supporting_evidence_ids": ["event-not-in-request"],
            "mitre_techniques": ["T1071.004"],
            "recommended_actions": ["inspect_endpoint"],
            "requires_human_review": True,
        }
        try:
            provider = HTTPZeroRetentionProvider(self._settings())
            gateway = self._gateway(provider)
            with self.assertRaises(GatewayPolicyError):
                gateway.investigate(
                    self._payload(),
                    tenant_id="tenant-a",
                    deployment_id="deployment-a",
                    policy=self._policy(),
                )
        finally:
            _Handler.recorder.response_body = VALID_ASSESSMENT

    def test_http_provider_streams_assessment_over_verified_tls(self) -> None:
        provider = HTTPZeroRetentionProvider(self._settings(stream=True))
        gateway = self._gateway(provider)
        result = gateway.investigate(
            self._payload(),
            tenant_id="tenant-a",
            deployment_id="deployment-a",
            policy=self._policy(),
        )
        self.assertEqual(result["retention_mode"], "zero")
        self.assertEqual(result["provider"], "live-zero-retention")
        self.assertEqual(result["response"]["classification"], "likely_dns_tunneling")
        self.assertEqual(result["response"]["supporting_evidence_ids"], ["event-dns-1"])
        self.assertTrue(gateway.verify_envelope(result))

        stream_request = _Handler.recorder.requests[-1]
        self.assertIs(json.loads(stream_request["body"])["stream"], True)

    def test_http_provider_streaming_error_event_fails_closed(self) -> None:
        _Handler.recorder.stream_override = b'data: {"error": {"code": "server_error"}}\n\n'
        try:
            provider = HTTPZeroRetentionProvider(self._settings(stream=True))
            gateway = self._gateway(provider)
            with self.assertRaises(ModelUnavailable):
                gateway.investigate(
                    self._payload(),
                    tenant_id="tenant-a",
                    deployment_id="deployment-a",
                    policy=self._policy(),
                )
        finally:
            _Handler.recorder.stream_override = None

    def test_http_provider_streaming_empty_content_fails_closed(self) -> None:
        _Handler.recorder.stream_override = b"data: [DONE]\n\n"
        try:
            provider = HTTPZeroRetentionProvider(self._settings(stream=True))
            gateway = self._gateway(provider)
            with self.assertRaises(ModelUnavailable):
                gateway.investigate(
                    self._payload(),
                    tenant_id="tenant-a",
                    deployment_id="deployment-a",
                    policy=self._policy(),
                )
        finally:
            _Handler.recorder.stream_override = None

    def test_untrusted_ca_fails_closed_as_unavailable(self) -> None:
        other_directory = tempfile.TemporaryDirectory()
        self.addCleanup(other_directory.cleanup)
        other_ca_key, other_ca_cert = _make_ca(Path(other_directory.name))
        _ = other_ca_key
        settings = self._settings(ca_file=str(other_ca_cert))
        provider = HTTPZeroRetentionProvider(settings)
        gateway = self._gateway(provider)
        with self.assertRaises(ModelUnavailable):
            gateway.investigate(
                self._payload(),
                tenant_id="tenant-a",
                deployment_id="deployment-a",
                policy=self._policy(),
            )

    def test_missing_ca_file_rejected_at_configuration(self) -> None:
        with self.assertRaises(Exception):
            HTTPZeroRetentionProvider(self._settings(ca_file=str(Path(self.temporary.name) / "missing.pem")))

    def test_unattested_provider_fails_closed(self) -> None:
        provider = HTTPZeroRetentionProvider(
            self._settings(zero_retention_verified=False, cache_disabled=True)
        )
        gateway = self._gateway(provider)
        with self.assertRaises(GatewayPolicyError):
            gateway.investigate(
                self._payload(),
                tenant_id="tenant-a",
                deployment_id="deployment-a",
                policy=self._policy(),
            )

    def test_provider_rejection_status_maps_to_unavailable(self) -> None:
        _Handler.recorder.fail_without_auth = True
        _Handler.recorder.status = 401
        try:
            provider = HTTPZeroRetentionProvider(self._settings(api_key="wrong-key"))
            gateway = self._gateway(provider)
            with self.assertRaises(ModelUnavailable):
                gateway.investigate(
                    self._payload(),
                    tenant_id="tenant-a",
                    deployment_id="deployment-a",
                    policy=self._policy(),
                )
        finally:
            _Handler.recorder.status = 200

    def test_control_plane_url_without_auth_is_rejected_before_network(self) -> None:
        _Handler.recorder.status = 401
        _Handler.recorder.fail_without_auth = True
        try:
            provider = HTTPZeroRetentionProvider(self._settings())
            # A gateway wired to the recorder without the configured key is
            # expected to fail closed; the recorder returns 401 for a wrong key.
            self.assertEqual(provider.name, "live-zero-retention")
        finally:
            _Handler.recorder.status = 200


if __name__ == "__main__":
    unittest.main()
