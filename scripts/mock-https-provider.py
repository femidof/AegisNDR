from __future__ import annotations

"""Standalone HTTPS zero-retention provider used to prove the composed
model-gateway can reach a live provider endpoint over verified TLS.

It is a test double only: it generates a private CA and server certificate at
startup, requires a Bearer API key, rejects requests that do not declare the
zero-retention and prompt-cache headers, and returns a schema-conforming
OpenAI-compatible chat response built from the request's own evidence and
allowed actions. Every request it accepts is appended to a JSONL record file so
the acceptance script can assert what arrived over the wire.
"""

import argparse
import datetime as dt
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REQUIRED_RESPONSE_FIELDS = {
    "classification", "severity", "confidence", "summary",
    "supporting_evidence_ids", "mitre_techniques",
    "recommended_actions", "requires_human_review",
}


def _make_pki(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key = directory / "ca-key.pem"
    ca_cert = directory / "ca-cert.pem"
    server_key = directory / "server-key.pem"
    server_cert = directory / "server-cert.pem"
    if all(path.is_file() for path in (ca_key, ca_cert, server_key, server_cert)):
        return
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hybrid NDR Mock Provider CA")])
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=None, decipher_only=None,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    ca_cert.write_bytes(issuer_cert.public_bytes(serialization.Encoding.PEM))

    server = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "provider-mock")]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("provider-mock"),
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(server, hashes.SHA256())
    )
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(server.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("provider-mock"), x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    server_key.write_bytes(server.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    server_cert.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))


class _ProviderHandler(BaseHTTPRequestHandler):
    api_key = ""
    record_file = ""
    response_fields: tuple[str, ...] = tuple(sorted(REQUIRED_RESPONSE_FIELDS))

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/healthz":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        length = min(int(self.headers.get("Content-Length") or 0), 250_000)
        body = self.rfile.read(length) if length else b""
        if self.path.rstrip("/") != "/v1/chat/completions":
            self.send_error(404)
            return
        if self.headers.get("Authorization") != f"Bearer {self.api_key}":
            self._respond(401, {"error": {"code": "invalid_api_key"}})
            return
        if self.headers.get("X-Hybrid-NDR-Retention") != "zero":
            self._respond(403, {"error": {"code": "retention_not_declared"}})
            return
        if self.headers.get("X-Hybrid-NDR-Prompt-Cache") != "disabled":
            self._respond(403, {"error": {"code": "prompt_cache_not_disabled"}})
            return
        try:
            request = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": {"code": "invalid_json"}})
            return
        record = {
            "method": self.command,
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "retention": self.headers.get("X-Hybrid-NDR-Retention", ""),
            "prompt_cache": self.headers.get("X-Hybrid-NDR-Prompt-Cache", ""),
            "body": request,
        }
        with open(self.record_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        assessment = self._assessment(request)
        payload = {
            "model": request.get("model", "evidence-assessor-v1"),
            "choices": [{"message": {"content": json.dumps(assessment)}}],
        }
        if request.get("stream") is True:
            self._respond_stream(payload)
        else:
            self._respond(200, payload)

    def _assessment(self, request) -> dict:
        messages = request.get("messages", [])
        evidence_ids = []
        allowed_actions = []
        for message in messages:
            content = message.get("content", "")
            if isinstance(content, str):
                try:
                    parsed = json.loads(content)
                except (json.JSONDecodeError, TypeError):
                    continue
                if isinstance(parsed, dict):
                    evidence_ids.extend(item.get("evidence_id") for item in parsed.get("observations", []))
                    allowed_actions = list(parsed.get("allowed_actions", []))
        evidence_ids = [item for item in dict.fromkeys(evidence_ids) if item]
        return {
            "classification": "possible_dns_tunneling",
            "severity": "high",
            "confidence": 0.81,
            "summary": "A live provider completed the assessment; evidence is cited only from the request.",
            "supporting_evidence_ids": evidence_ids or ["event-provider-1"],
            "mitre_techniques": ["T1071.004"],
            "recommended_actions": allowed_actions[:2],
            "requires_human_review": True,
        }

    def _respond(self, status: int, body: dict) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _respond_stream(self, body: dict) -> None:
        """Emit the response as a chunked SSE stream of content deltas.

        The single message content is split across several deltas so the
        acceptance path exercises real incremental parsing, then terminated
        with `data: [DONE]` exactly like an OpenAI-compatible chat endpoint.
        """
        content = body["choices"][0]["message"]["content"]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        split = max(1, len(content) // 3)
        for offset in range(0, len(content), split):
            delta = {"choices": [{"delta": {"content": content[offset : offset + split]}}]}
            self.wfile.write(b"data: " + json.dumps(delta, separators=(",", ":")).encode("utf-8") + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--pki-dir", required=True)
    parser.add_argument("--record-file", default="/tmp/provider-records.jsonl")
    parser.add_argument("--api-key", default="mock-provider-api-key")
    args = parser.parse_args()

    _make_pki(Path(args.pki_dir))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        str(Path(args.pki_dir) / "server-cert.pem"),
        str(Path(args.pki_dir) / "server-key.pem"),
    )
    _ProviderHandler.api_key = args.api_key
    _ProviderHandler.record_file = args.record_file
    server = ThreadingHTTPServer((args.host, args.port), _ProviderHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"mock HTTPS provider listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
