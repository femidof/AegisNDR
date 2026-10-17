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
    ROOT / "packages" / "observability",
    ROOT / "services" / "model-gateway",
    ROOT / "apps" / "control-api",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_control_api.api import create_application  # noqa: E402
from hybrid_ndr_control_api.pki import CertificateAuthority  # noqa: E402
from hybrid_ndr_control_api.portal_auth import build_portal_authenticator  # noqa: E402
from hybrid_ndr_control_api.store import ControlStore  # noqa: E402
from hybrid_ndr_gateway import DeterministicAssessmentProvider, ModelGateway  # noqa: E402
from hybrid_ndr_transport import make_server  # noqa: E402


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _scopes(value: str) -> list[str]:
    return list(dict.fromkeys(
        scope for scope in value.replace(",", " ").split() if scope and scope != "offline_access"
    ))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Hybrid NDR vendor control API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--database", default=str(ROOT / ".data" / "control-api.sqlite3"))
    parser.add_argument("--reset-demo", action="store_true", help="Create the deterministic demo enrollment token.")
    parser.add_argument("--demo-provider", action="store_true", help="Explicitly enable the embedded deterministic demo provider.")
    parser.add_argument("--ca-key", default=os.environ.get("CONTROL_API_CA_KEY_FILE", str(ROOT / ".data" / "pki" / "deployment-ca-key.pem")))
    parser.add_argument("--ca-cert", default=os.environ.get("CONTROL_API_CA_CERT_FILE", str(ROOT / ".data" / "pki" / "deployment-ca-cert.pem")))
    parser.add_argument("--tls-cert", default=os.environ.get("CONTROL_API_TLS_CERT_FILE", ""))
    parser.add_argument("--tls-key", default=os.environ.get("CONTROL_API_TLS_KEY_FILE", ""))
    parser.add_argument("--client-ca", default=os.environ.get("CONTROL_API_CLIENT_CA_FILE", ""))
    parser.add_argument(
        "--allow-insecure-fingerprint-header",
        action="store_true",
        default=_enabled(os.environ.get("CONTROL_API_ALLOW_INSECURE_FINGERPRINT_HEADER", "false")),
        help="Trust the legacy fingerprint header only for explicit loopback development.",
    )
    args = parser.parse_args()
    authority = CertificateAuthority.load_or_create(args.ca_key, args.ca_cert)
    dashboard_scope_input = os.environ.get("LOGTO_DASHBOARD_SCOPES", "").strip() or (
        "openid profile urn:logto:scope:organizations urn:logto:scope:organization_roles "
        "alerts:read alerts:update events:search investigations:create investigations:read "
        "cases:create cases:update transmissions:read audit:read model-policy:manage"
    )
    dashboard_scopes = _scopes(dashboard_scope_input)
    store = ControlStore(
        args.database,
        certificate_authority=authority,
        public_endpoints={
            "control_plane": os.environ.get("CONTROL_API_PUBLIC_URL", "/v1"),
            "model_gateway": os.environ.get("MODEL_GATEWAY_PUBLIC_URL", "/v1/model/investigate"),
        },
        identity_configuration={
            "issuer": os.environ.get("CONTROL_IDENTITY_ISSUER", ""),
            "jwks_uri": os.environ.get("CONTROL_IDENTITY_JWKS_URI", ""),
            "dashboard_client_id": os.environ.get("LOGTO_DASHBOARD_CLIENT_ID", ""),
            "dashboard_scopes": dashboard_scopes,
        },
    )
    if args.reset_demo:
        if os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
            raise SystemExit("--reset-demo is forbidden when HYBRID_NDR_ENV=production")
        print("WARNING: --reset-demo mints a fresh random single-use token for development only.")
        print(f"Demo enrollment token: {store.reset_demo()}")
    gateway = None
    if args.demo_provider:
        if os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
            raise SystemExit("--demo-provider is forbidden when HYBRID_NDR_ENV=production")
        gateway = ModelGateway(
            DeterministicAssessmentProvider(),
            signing_key=secrets.token_bytes(32),
            usage_sink=store.save_gateway_usage,
        )
    portal_authenticator = None
    if os.environ.get("CONTROL_PORTAL_AUTH_MODE") or os.environ.get("CONTROL_PORTAL_AUTH_ISSUER"):
        portal_authenticator = build_portal_authenticator()
    else:
        print("WARNING: cloud portal routes will fail closed because portal authentication is not configured.")
    tls_enabled = bool(args.tls_cert and args.tls_key and args.client_ca)
    if args.allow_insecure_fingerprint_header and os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
        raise SystemExit("insecure fingerprint header is forbidden when HYBRID_NDR_ENV=production")
    if not tls_enabled and not args.allow_insecure_fingerprint_header:
        print("WARNING: deployment routes will fail closed because verified mTLS is not configured.")
    scheme = "https" if tls_enabled else "http"
    print(f"Control API listening at {scheme}://{args.host}:{args.port} (health: /healthz)")
    with make_server(
        args.host,
        args.port,
        create_application(
            store,
            gateway,
            portal_authenticator=portal_authenticator,
            allow_insecure_fingerprint_header=args.allow_insecure_fingerprint_header,
        ),
        certificate_file=args.tls_cert,
        private_key_file=args.tls_key,
        client_ca_file=args.client_ca,
        # Enrollment happens before a deployment has a client certificate.
        require_client_certificate=False,
    ) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nControl API stopped.")


if __name__ == "__main__":
    main()
