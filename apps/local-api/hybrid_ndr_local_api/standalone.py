"""Air-gapped local identity for the customer API.

In standalone deployments (installer `--standalone`) there is no vendor
control plane or Logto tenant. The local API serves the locally generated
JWKS and issues short-lived RS256 analyst tokens signed by the locally
provisioned issuer key. Nothing in this module requires outbound connectivity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from hybrid_ndr_auth import DEFAULT_ROLE_PERMISSIONS

STANDALONE_ROLES = frozenset({"analyst", "auditor", "read_only"})


class StandaloneAuthError(ValueError):
    pass


def standalone_settings(environ: Mapping[str, str] | None = None) -> dict[str, str] | None:
    """Return the standalone material paths when the deployment is air-gapped."""
    env = environ if environ is not None else os.environ
    issuer_key_file = env.get("AUTH_STANDALONE_ISSUER_KEY_FILE", "").strip()
    jwks_file = env.get("AUTH_STANDALONE_JWKS_FILE", "").strip()
    if not issuer_key_file or not jwks_file:
        return None
    return {
        "issuer_key_file": issuer_key_file,
        "jwks_file": jwks_file,
        "login_secret": env.get("AUTH_STANDALONE_LOGIN_SECRET", "").strip(),
    }


def _regular_file(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 1_000_000:
        raise StandaloneAuthError("standalone identity file is invalid")
    return candidate


def load_jwks(path: str) -> dict[str, Any]:
    """Load and validate the locally provisioned JWKS document."""
    try:
        value = json.loads(_regular_file(path).read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StandaloneAuthError("standalone JWKS is not readable JSON") from exc
    keys = value.get("keys") if isinstance(value, dict) else None
    if not isinstance(keys, list) or not keys or any(not isinstance(key, dict) for key in keys):
        raise StandaloneAuthError("standalone JWKS must contain a non-empty keys list")
    for key in keys:
        if key.get("kty") != "RSA" or key.get("alg") != "RS256" or not key.get("kid"):
            raise StandaloneAuthError("standalone JWKS contains an unsupported key")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def issue_access_token(
    *,
    tenant_id: str,
    deployment_id: str,
    actor_id: str,
    role: str,
    issuer: str,
    audience: str,
    jwks_path: str,
    issuer_key_path: str,
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Mint a short-lived RS256 analyst token for the local identity issuer."""
    if role not in STANDALONE_ROLES or role not in DEFAULT_ROLE_PERMISSIONS:
        raise StandaloneAuthError("role is not available for standalone access")
    if not tenant_id.strip() or not deployment_id.strip():
        raise StandaloneAuthError("tenant and deployment identity are required")
    if not actor_id.strip() or len(actor_id) > 64:
        raise StandaloneAuthError("analyst identifier is invalid")
    import re as _re

    if not _re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", actor_id):
        raise StandaloneAuthError("analyst identifier is invalid")
    if not 60 <= ttl_seconds <= 86_400:
        raise StandaloneAuthError("token lifetime is outside the supported range")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        private_key = serialization.load_pem_private_key(
            _regular_file(issuer_key_path).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as exc:
        raise StandaloneAuthError("standalone issuer key is not readable") from exc
    jwks = load_jwks(jwks_path)
    kid = str(jwks["keys"][0]["kid"])
    now = int(time.time())
    permissions = sorted(DEFAULT_ROLE_PERMISSIONS[role])
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": actor_id,
        "tenant_id": tenant_id,
        "organization_id": "standalone",
        "organization_binding_id": "standalone",
        "deployment_ids": [deployment_id],
        "roles": [role],
        "role": role,
        "actor_type": "human",
        "session_id": str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "permissions": permissions,
        "scope": " ".join(permissions),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    )
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return {
        "access_token": signing_input + "." + _b64url(signature),
        "token_type": "Bearer",
        "expires_in": ttl_seconds,
        "scope": " ".join(permissions),
    }


def verify_login_secret(settings: Mapping[str, str], supplied: str) -> bool:
    secret = settings.get("login_secret", "")
    return bool(secret) and hmac.compare_digest(secret.encode("utf-8"), supplied.encode("utf-8"))


def key_fingerprint(path: str) -> str:
    """SHA-256 of the issuer key's DER form, used as the JWKS kid check."""
    from cryptography.hazmat.primitives import serialization

    try:
        private_key = serialization.load_pem_private_key(
            _regular_file(path).read_bytes(), password=None
        )
        der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (OSError, ValueError, TypeError) as exc:
        raise StandaloneAuthError("standalone issuer key is not readable") from exc
    return hashlib.sha256(der).hexdigest()[:32]
