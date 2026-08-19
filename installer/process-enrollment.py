#!/usr/bin/env python3
"""Build an enrollment request and safely persist a validated enrollment response."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
OIDC_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$")
REQUIRED_DASHBOARD_SCOPES = frozenset({
    "openid",
    "urn:logto:scope:organizations",
    "urn:logto:scope:organization_roles",
})


def fail(message: str) -> None:
    raise SystemExit(f"enrollment response rejected: {message}")


def regular_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"expected a regular file: {path}")
    if path.stat().st_size > maximum:
        fail(f"file is too large: {path}")
    return path.read_bytes()


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def request(token_path: Path, csr_path: Path, output_path: Path) -> None:
    token = regular_file(token_path, maximum=4096).decode("utf-8").strip()
    csr = regular_file(csr_path, maximum=20_000).decode("ascii").strip() + "\n"
    if not token or "\n" in token or "\r" in token:
        fail("the enrollment token is empty or malformed")
    if not csr.startswith("-----BEGIN CERTIFICATE REQUEST-----\n") or not csr.endswith(
        "-----END CERTIFICATE REQUEST-----\n"
    ):
        fail("the CSR is not PEM encoded")
    payload = json.dumps({"enrollment_token": token, "csr": csr}, separators=(",", ":"))
    atomic_write(output_path, payload.encode("utf-8"))


def require_identifier(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        fail(f"{key} is missing or malformed")
    return value


def identity_url(value: Any, key: str, *, expected_path: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        fail(f"identity.{key} is missing or malformed")
    try:
        value.encode("ascii")
        parsed = urlsplit(value)
        _ = parsed.port
    except (UnicodeEncodeError, ValueError):
        fail(f"identity.{key} is not a valid ASCII URL")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        fail(f"identity.{key} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail(f"identity.{key} must not contain credentials, a query, or a fragment")
    if parsed.path != expected_path:
        fail(f"identity.{key} path must be {expected_path}")
    hostname = parsed.hostname.lower()
    loopback = hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not loopback:
        fail(f"identity.{key} must use HTTPS outside loopback development")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def validate_identity(payload: dict[str, Any]) -> dict[str, Any]:
    identity = payload.get("identity")
    if not isinstance(identity, dict):
        fail("identity must be an object")
    issuer = identity_url(identity.get("issuer"), "issuer", expected_path="/oidc")
    jwks_uri = identity_url(identity.get("jwks_uri"), "jwks_uri", expected_path="/oidc/jwks")
    if jwks_uri != issuer + "/jwks":
        fail("identity.jwks_uri must belong to the configured issuer")
    dashboard_client_id = require_identifier(identity, "dashboard_client_id")
    organization_id = require_identifier(identity, "organization_id")
    scopes = identity.get("dashboard_scopes")
    if (
        not isinstance(scopes, list)
        or not scopes
        or len(scopes) > 100
        or any(not isinstance(scope, str) or not OIDC_SCOPE.fullmatch(scope) for scope in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        fail("identity.dashboard_scopes must be a unique list of valid scopes")
    if not REQUIRED_DASHBOARD_SCOPES <= set(scopes):
        fail("identity.dashboard_scopes is missing a required organization scope")
    if "offline_access" in scopes:
        fail("identity.dashboard_scopes must not request offline_access")
    return {
        "issuer": issuer,
        "jwks_uri": jwks_uri,
        "dashboard_client_id": dashboard_client_id,
        "organization_id": organization_id,
        "dashboard_scopes": scopes,
    }


def update_signing_key(payload: dict[str, Any]) -> str:
    value = payload.get("update_signing_public_key")
    if not isinstance(value, str) or len(value) > 32_000 or "\x00" in value:
        fail("update_signing_public_key is missing or malformed")
    normalized = value.strip() + "\n"
    if not normalized.startswith("-----BEGIN PUBLIC KEY-----\n") or not normalized.endswith(
        "-----END PUBLIC KEY-----\n"
    ):
        fail("update_signing_public_key is not a public-key PEM document")
    if normalized.count("-----BEGIN PUBLIC KEY-----") != 1 or normalized.count("-----END PUBLIC KEY-----") != 1:
        fail("update_signing_public_key contains multiple PEM documents")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError:
        fail("update_signing_public_key is not ASCII PEM")
    return normalized


def render_identity_environment(enrollment_path: Path, output_path: Path) -> None:
    raw = regular_file(enrollment_path, maximum=1_000_000)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"response is not valid JSON: {error}")
    if not isinstance(payload, dict):
        fail("response must be a JSON object")
    identity = validate_identity(payload)
    issuer = identity["issuer"]
    values = {
        "AUTH_ISSUER": issuer,
        "AUTH_JWKS_URL": identity["jwks_uri"],
        "AUTH_ALLOWED_ORGANIZATION_IDS": identity["organization_id"],
        "LOGTO_ENDPOINT": issuer.removesuffix("/oidc"),
        "LOGTO_PUBLIC_ENDPOINT": issuer.removesuffix("/oidc"),
        "LOGTO_DASHBOARD_CLIENT_ID": identity["dashboard_client_id"],
        "LOGTO_ORGANIZATION_ID": identity["organization_id"],
        "LOGTO_DASHBOARD_SCOPES": " ".join(identity["dashboard_scopes"]),
    }
    rendered = "".join(f"{key}={value}\n" for key, value in values.items())
    atomic_write(output_path, rendered.encode("ascii"))


def render_update_signing_key(enrollment_path: Path, output_path: Path) -> None:
    raw = regular_file(enrollment_path, maximum=1_000_000)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"response is not valid JSON: {error}")
    if not isinstance(payload, dict):
        fail("response must be a JSON object")
    atomic_write(output_path, update_signing_key(payload).encode("ascii"))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def standalone(identity_dir: Path, origin: str) -> None:
    """Provision fully local identity for a deployment with no control plane.

    This is the air-gapped enrollment path: the appliance generates its own
    tenant/deployment identifiers, signs its own deployment certificate with a
    locally generated CA, creates a local RS256 issuer key whose JWKS the
    local API serves, and provisions a local update-signing key. No outbound
    HTTPS is required at any point.
    """
    tenant_id = regular_file(identity_dir / "tenant-id", maximum=1024).decode("ascii").strip()
    deployment_id = regular_file(identity_dir / "deployment-id", maximum=1024).decode("ascii").strip()
    require_identifier({"tenant_id": tenant_id}, "tenant_id")
    require_identifier({"deployment_id": deployment_id}, "deployment_id")
    certificate = regular_file(identity_dir / "deployment-cert.pem", maximum=64_000).decode("ascii").strip() + "\n"
    if not certificate.startswith("-----BEGIN CERTIFICATE-----\n") or not certificate.endswith(
        "-----END CERTIFICATE-----\n"
    ):
        fail("deployment certificate is not PEM encoded")
    if not origin.startswith("https://") or "\n" in origin or len(origin) > 2048:
        fail("standalone origin must be an HTTPS base URL")
    fingerprint = hashlib.sha256(certificate.encode("ascii")).hexdigest()

    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = issuer_key.public_key().public_numbers()
    kid = hashlib.sha256(issuer_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).hexdigest()[:32]
    jwks = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
        }],
    }
    atomic_write(
        identity_dir / "local-issuer-key.pem",
        issuer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    atomic_write(identity_dir / "local-jwks.json", (json.dumps(jwks, sort_keys=True) + "\n").encode("ascii"))

    update_key = ec.generate_private_key(ec.SECP256R1())
    atomic_write(
        identity_dir / "update-signing-public.pem",
        update_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )

    enrollment = {
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "deployment_certificate": certificate,
        "certificate_fingerprint": fingerprint,
        "certificate_expires_at": "standalone-local-ca",
        "update_channel": "standalone",
        "entitlements": {"local_detection": True, "model_gateway": True},
        "model_policy": {
            "enabled": True, "level": "balanced", "retention_mode": "zero",
            "provider": "local-standalone", "model": "evidence-assessor-v1", "region": "us",
        },
        "endpoints": {"control_plane": ""},
        "identity": {
            "issuer": origin + "/oidc",
            "jwks_uri": origin + "/oidc/jwks",
            "dashboard_client_id": "local-standalone",
            "organization_id": "standalone",
            "dashboard_scopes": [
                "openid", "profile", "urn:logto:scope:organizations", "urn:logto:scope:organization_roles",
            ],
        },
    }
    atomic_write(
        identity_dir / "enrollment.json",
        (json.dumps(enrollment, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )


def persist(response_path: Path, identity_dir: Path) -> None:
    raw = regular_file(response_path, maximum=1_000_000)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"response is not valid JSON: {error}")
    if not isinstance(payload, dict):
        fail("response must be a JSON object")

    tenant_id = require_identifier(payload, "tenant_id")
    deployment_id = require_identifier(payload, "deployment_id")
    fingerprint = payload.get("certificate_fingerprint")
    certificate = payload.get("deployment_certificate")
    expires_at = payload.get("certificate_expires_at")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        fail("certificate_fingerprint must be a SHA-256 digest")
    if not isinstance(certificate, str) or len(certificate) > 64_000 or "\x00" in certificate:
        fail("deployment_certificate is missing or malformed")
    certificate = certificate.strip() + "\n"
    if not certificate.startswith("-----BEGIN CERTIFICATE-----\n") or not certificate.endswith(
        "-----END CERTIFICATE-----\n"
    ):
        fail("deployment_certificate is not PEM encoded")
    if not isinstance(expires_at, str) or len(expires_at) > 64:
        fail("certificate_expires_at is missing or malformed")
    for key in ("entitlements", "model_policy", "endpoints"):
        if not isinstance(payload.get(key), dict):
            fail(f"{key} must be an object")
    if not isinstance(payload.get("update_channel"), str):
        fail("update_channel must be a string")
    signing_key = update_signing_key(payload)
    validate_identity(payload)

    identity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(identity_dir, 0o700)
    metadata = {key: value for key, value in payload.items() if key != "deployment_certificate"}
    atomic_write(identity_dir / "deployment-cert.pem", certificate.encode("ascii"))
    atomic_write(identity_dir / "certificate-fingerprint", (fingerprint.lower() + "\n").encode("ascii"))
    atomic_write(identity_dir / "tenant-id", (tenant_id + "\n").encode("ascii"))
    atomic_write(identity_dir / "deployment-id", (deployment_id + "\n").encode("ascii"))
    atomic_write(identity_dir / "update-signing-public.pem", signing_key.encode("ascii"))
    atomic_write(
        identity_dir / "enrollment.json",
        (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    request_parser = subparsers.add_parser("request")
    request_parser.add_argument("token_file", type=Path)
    request_parser.add_argument("csr_file", type=Path)
    request_parser.add_argument("output_file", type=Path)
    persist_parser = subparsers.add_parser("persist")
    persist_parser.add_argument("response_file", type=Path)
    persist_parser.add_argument("identity_dir", type=Path)
    environment_parser = subparsers.add_parser("render-identity-env")
    environment_parser.add_argument("enrollment_file", type=Path)
    environment_parser.add_argument("output_file", type=Path)
    update_key_parser = subparsers.add_parser("render-update-key")
    update_key_parser.add_argument("enrollment_file", type=Path)
    update_key_parser.add_argument("output_file", type=Path)
    standalone_parser = subparsers.add_parser(
        "standalone",
        help="Provision fully local identity for an air-gapped deployment",
    )
    standalone_parser.add_argument("identity_dir", type=Path)
    standalone_parser.add_argument("origin", type=str)
    arguments = parser.parse_args()
    if arguments.command == "request":
        request(arguments.token_file, arguments.csr_file, arguments.output_file)
    elif arguments.command == "persist":
        persist(arguments.response_file, arguments.identity_dir)
    elif arguments.command == "render-identity-env":
        render_identity_environment(arguments.enrollment_file, arguments.output_file)
    elif arguments.command == "standalone":
        standalone(arguments.identity_dir, arguments.origin)
    else:
        render_update_signing_key(arguments.enrollment_file, arguments.output_file)


if __name__ == "__main__":
    main()
