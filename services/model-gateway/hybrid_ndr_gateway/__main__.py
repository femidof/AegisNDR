from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for path in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "redaction",
    ROOT / "packages" / "transport",
    ROOT / "packages" / "auth",
    ROOT / "services" / "model-gateway",
    ROOT / "apps" / "control-api",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_control_api.pki import CertificateAuthority  # noqa: E402
from hybrid_ndr_control_api.store import ControlStore  # noqa: E402
from hybrid_ndr_transport import make_server  # noqa: E402

from .api import create_application  # noqa: E402
from .gateway import DeterministicAssessmentProvider, ModelGateway  # noqa: E402
from .provider import HTTPProviderSettings, HTTPZeroRetentionProvider  # noqa: E402


def _enabled(name: str, default: str = "false") -> bool:
    value = os.environ.get(name, default).strip().lower()
    if value not in {"true", "false"}:
        raise SystemExit(f"{name} must be exactly 'true' or 'false'")
    return value == "true"


def _signing_key(demo: bool) -> bytes:
    filename = os.environ.get("MODEL_GATEWAY_SIGNING_KEY_FILE", "").strip()
    value = os.environ.get("MODEL_GATEWAY_SIGNING_KEY", "").encode("utf-8")
    if filename and value:
        raise SystemExit("configure only one model gateway signing-key source")
    if filename:
        path = Path(filename)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16_384:
            raise SystemExit("MODEL_GATEWAY_SIGNING_KEY_FILE is invalid")
        value = path.read_bytes().strip()
    if not value and demo:
        # Enterprise: demo fallback is an ephemeral random key (never committed).
        value = secrets.token_bytes(32)
    if len(value) < 32:
        raise SystemExit("a model gateway signing key of at least 32 bytes is required")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the independent Hybrid NDR model gateway.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    parser.add_argument("--database", default=os.environ.get("CONTROL_API_DATABASE", str(ROOT / ".data" / "control-api.sqlite3")))
    parser.add_argument("--demo-provider", action="store_true", help="Explicitly use the deterministic demo provider.")
    parser.add_argument("--tls-cert", default=os.environ.get("MODEL_GATEWAY_TLS_CERT_FILE", ""))
    parser.add_argument("--tls-key", default=os.environ.get("MODEL_GATEWAY_TLS_KEY_FILE", ""))
    parser.add_argument("--client-ca", default=os.environ.get("MODEL_GATEWAY_CLIENT_CA_FILE", ""))
    args = parser.parse_args()

    mode = "demo" if args.demo_provider else os.environ.get("MODEL_PROVIDER_MODE", "http").strip().lower()
    if mode == "demo":
        provider = DeterministicAssessmentProvider()
    elif mode == "http":
        provider = HTTPZeroRetentionProvider(HTTPProviderSettings.from_env())
    else:
        raise SystemExit("MODEL_PROVIDER_MODE must be 'http' or explicit 'demo'")

    approved_models = {
        value.strip() for value in os.environ.get("MODEL_GATEWAY_APPROVED_MODELS", "evidence-assessor-v1").split(",") if value.strip()
    }
    approved_regions = {
        value.strip() for value in os.environ.get("MODEL_GATEWAY_APPROVED_REGIONS", "us,eu").split(",") if value.strip()
    }
    ca_key = os.environ.get("CONTROL_API_CA_KEY_FILE", str(ROOT / ".data" / "pki" / "deployment-ca-key.pem"))
    ca_cert = os.environ.get("CONTROL_API_CA_CERT_FILE", str(ROOT / ".data" / "pki" / "deployment-ca-cert.pem"))
    store = ControlStore(
        args.database,
        certificate_authority=CertificateAuthority.load_or_create(ca_key, ca_cert),
    )
    gateway = ModelGateway(
        provider,
        signing_key=_signing_key(mode == "demo"),
        approved_models=approved_models,
        approved_regions=approved_regions,
        maximum_request_bytes=int(os.environ.get("MODEL_GATEWAY_MAX_REQUEST_BYTES", "50000")),
        usage_sink=store.save_gateway_usage,
    )
    allow_insecure = _enabled("MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER")
    if allow_insecure and os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
        raise SystemExit("MODEL_GATEWAY_ALLOW_INSECURE_FINGERPRINT_HEADER is forbidden when HYBRID_NDR_ENV=production")
    tls_enabled = bool(args.tls_cert and args.tls_key and args.client_ca)
    if not tls_enabled and not allow_insecure:
        raise SystemExit("model gateway requires mTLS files unless explicit insecure loopback mode is enabled")
    scheme = "https" if tls_enabled else "http"
    print(f"Model gateway listening at {scheme}://{args.host}:{args.port} (health: /healthz)")
    with make_server(
        args.host,
        args.port,
        create_application(store, gateway, allow_insecure_fingerprint_header=allow_insecure),
        certificate_file=args.tls_cert,
        private_key_file=args.tls_key,
        client_ca_file=args.client_ca,
        require_client_certificate=True,
    ) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nModel gateway stopped.")


if __name__ == "__main__":
    main()
