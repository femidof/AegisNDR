from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "organization_owner": frozenset({
        "alerts:read", "alerts:update", "events:search", "investigations:create",
        "investigations:read", "cases:create", "cases:update", "evidence:read",
        "evidence:export", "transmissions:read", "rules:read", "rules:manage",
        "integrations:manage", "deployments:manage", "users:manage", "audit:read",
        "response:approve", "model-policy:manage",
    }),
    "security_admin": frozenset({
        "alerts:read", "alerts:update", "events:search", "investigations:read",
        "evidence:read", "evidence:export", "transmissions:read", "rules:read",
        "rules:manage", "integrations:manage", "deployments:manage", "audit:read",
        "model-policy:manage",
    }),
    "soc_manager": frozenset({
        "alerts:read", "alerts:update", "events:search", "investigations:create",
        "investigations:read", "cases:create", "cases:update", "evidence:read",
        "evidence:export", "transmissions:read", "response:approve",
    }),
    "analyst": frozenset({
        "alerts:read", "alerts:update", "events:search", "investigations:create",
        "investigations:read", "cases:create", "cases:update", "evidence:read",
        "transmissions:read",
    }),
    "auditor": frozenset({
        "alerts:read", "investigations:read", "evidence:read", "transmissions:read",
        "audit:read", "rules:read",
    }),
    "read_only": frozenset({"alerts:read", "events:search", "investigations:read"}),
    "deployment_agent": frozenset({"events:write", "sensors:write"}),
}

_OIDC_SCOPES = frozenset({
    "openid", "profile", "email", "phone", "offline_access", "roles",
    "urn:logto:scope:organizations", "urn:logto:scope:organization_roles",
})
_RS256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class AuthenticationError(RuntimeError):
    """A safe, typed authentication failure suitable for an API error response."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    organization_id: str
    deployment_id: str
    actor_id: str
    role: str
    permissions: frozenset[str]


class Authenticator(Protocol):
    def authenticate(self, headers: Mapping[str, str]) -> Principal: ...


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in (value or "").split(",") if item.strip()))


def _boolean(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


@dataclass(frozen=True)
class AuthConfig:
    mode: str = "demo_headers"
    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    expected_tenant_id: str = ""
    allowed_organization_ids: tuple[str, ...] = ()
    expected_deployment_id: str = ""
    algorithms: tuple[str, ...] = ("RS256",)
    clock_skew_seconds: int = 30
    jwks_cache_seconds: int = 300
    jwks_ca_file: str = ""
    jwks_allow_insecure_http: bool = False
    require_role_claim: bool = True
    require_actor_type_claim: bool = True
    require_session_claim: bool = True
    revoked_token_ids: tuple[str, ...] = ()
    revoked_session_ids: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "AuthConfig":
        env = environ if environ is not None else os.environ
        mode = env.get("AUTH_MODE", "demo_headers").strip().lower()
        if mode not in {"demo_headers", "jwt"}:
            raise ValueError("AUTH_MODE must be 'demo_headers' or 'jwt'")
        insecure_jwks = env.get("AUTH_JWKS_ALLOW_INSECURE_HTTP", "").strip()
        config = cls(
            mode=mode,
            issuer=env.get("AUTH_ISSUER", "").strip(),
            audience=env.get("AUTH_AUDIENCE", "").strip(),
            jwks_url=env.get("AUTH_JWKS_URL", "").strip(),
            expected_tenant_id=env.get("AUTH_TENANT_ID", env.get("TENANT_ID", "")).strip(),
            allowed_organization_ids=_csv(env.get("AUTH_ALLOWED_ORGANIZATION_IDS") or env.get("AUTH_ORGANIZATION_ID")),
            expected_deployment_id=env.get("AUTH_DEPLOYMENT_ID", env.get("DEPLOYMENT_ID", "")).strip(),
            algorithms=_csv(env.get("AUTH_ALGORITHMS", "RS256")),
            clock_skew_seconds=int(env.get("AUTH_CLOCK_SKEW_SECONDS", "30")),
            jwks_cache_seconds=int(env.get("AUTH_JWKS_CACHE_SECONDS", "300")),
            jwks_ca_file=env.get("AUTH_JWKS_CA_FILE", "").strip(),
            # Explicit development-only escape hatch. The installer never sets
            # it, so production JWKS fetches are verified HTTPS (see
            # JWKSClient); this mirrors DASHBOARD_ALLOW_INSECURE_HTTP.
            jwks_allow_insecure_http=_boolean(insecure_jwks, False) if insecure_jwks else False,
            require_role_claim=_boolean(env.get("AUTH_REQUIRE_ROLE_CLAIM"), True),
            require_actor_type_claim=_boolean(env.get("AUTH_REQUIRE_ACTOR_TYPE_CLAIM"), True),
            require_session_claim=_boolean(env.get("AUTH_REQUIRE_SESSION_CLAIM"), True),
            revoked_token_ids=_csv(env.get("AUTH_REVOKED_TOKEN_IDS")),
            revoked_session_ids=_csv(env.get("AUTH_REVOKED_SESSION_IDS")),
        )
        if config.mode == "jwt":
            missing = [
                name for name, value in (
                    ("AUTH_ISSUER", config.issuer),
                    ("AUTH_AUDIENCE", config.audience),
                    ("AUTH_JWKS_URL", config.jwks_url),
                    ("AUTH_TENANT_ID", config.expected_tenant_id),
                    ("AUTH_DEPLOYMENT_ID", config.expected_deployment_id),
                ) if not value
            ]
            if missing:
                raise ValueError("JWT authentication requires " + ", ".join(missing))
            if config.algorithms != ("RS256",):
                raise ValueError("Only AUTH_ALGORITHMS=RS256 is supported")
            if not (0 <= config.clock_skew_seconds <= 300):
                raise ValueError("AUTH_CLOCK_SKEW_SECONDS must be between 0 and 300")
            if not (30 <= config.jwks_cache_seconds <= 86_400):
                raise ValueError("AUTH_JWKS_CACHE_SECONDS must be between 30 and 86400")
            if len(config.revoked_token_ids) > 1_000 or len(config.revoked_session_ids) > 1_000:
                raise ValueError("static token/session revocation lists are limited to 1000 entries")
        return config


class HeaderAuthenticator:
    """Explicit demo-only authentication; never selected by the production Compose profile."""

    def __init__(self, role_permissions: Mapping[str, frozenset[str]] | None = None) -> None:
        self.role_permissions = dict(role_permissions or DEFAULT_ROLE_PERMISSIONS)

    def authenticate(self, headers: Mapping[str, str]) -> Principal:
        tenant_id = headers.get("x-tenant-id", "").strip()
        deployment_id = headers.get("x-deployment-id", "").strip()
        actor_id = headers.get("x-actor-id", "").strip()
        role = headers.get("x-role", "read_only").strip().lower().replace("-", "_")
        if not tenant_id or not deployment_id or not actor_id:
            raise AuthenticationError(
                401, "authentication_required",
                "X-Tenant-ID, X-Deployment-ID, and X-Actor-ID are required in demo authentication mode.",
            )
        if role not in self.role_permissions:
            raise AuthenticationError(403, "unknown_role", "The supplied organization role is not recognized.")
        supplied = frozenset(_csv(headers.get("x-permissions")))
        role_allowed = self.role_permissions[role]
        if supplied:
            permissions = supplied if "*" in role_allowed else supplied & role_allowed
        else:
            permissions = role_allowed
        return Principal(tenant_id, tenant_id, deployment_id, actor_id, role, frozenset(permissions))


class JWKSource(Protocol):
    def get_key(self, kid: str) -> Mapping[str, Any]: ...


class StaticJWKSource:
    def __init__(self, keys: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...]) -> None:
        self._keys = {str(key.get("kid", "")): dict(key) for key in keys if key.get("kid")}

    def get_key(self, kid: str) -> Mapping[str, Any]:
        try:
            return self._keys[kid]
        except KeyError as exc:
            raise AuthenticationError(401, "unknown_signing_key", "The token signing key is not recognized.") from exc


class JWKSClient:
    """Bounded JWKS cache with one forced refresh to support signing-key rotation.

    The signing-key document is a trust anchor: fetching it over plain HTTP lets
    a network attacker inject their own RSA keys and mint accepted tokens, so
    HTTPS is required. Private-CA deployments pin the issuing CA with
    ``ca_file``; ``allow_insecure_http`` is an explicit development-only
    escape hatch that production configuration never sets.
    """

    def __init__(
        self,
        url: str,
        *,
        cache_seconds: int = 300,
        timeout_seconds: float = 3.0,
        ca_file: str = "",
        allow_insecure_http: bool = False,
        opener: Callable[..., Any] = urlopen,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not url.startswith("https://") and not (allow_insecure_http and url.startswith("http://")):
            raise ValueError("JWKS URL must use HTTPS (plain HTTP is only permitted with an explicit development override)")
        if url.startswith("http://") and allow_insecure_http:
            from hybrid_ndr_observability import warning as log_warning

            log_warning("auth.jwks_insecure_http", reason="explicit_development_override")
        self.url = url
        self.cache_seconds = cache_seconds
        self.timeout_seconds = timeout_seconds
        self._monotonic = monotonic
        self._expires_at = 0.0
        self._keys: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._opener = self._verified_opener(opener, ca_file, url)

    @staticmethod
    def _verified_opener(
        opener: Callable[..., Any], ca_file: str, url: str
    ) -> Callable[..., Any]:
        if opener is not urlopen or not url.startswith("https://"):
            # Tests inject a stub opener; production HTTPS fetches are verified
            # against the pinned CA (or the system trust store).
            return opener
        import ssl
        from urllib.request import HTTPSHandler, build_opener

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file or None)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return build_opener(HTTPSHandler(context=context))

    def _read_bounded(self, response: Any, amount: int) -> bytes:
        """Read with a socket-level deadline so a stalled JWKS server cannot
        hang the token verifier indefinitely (Slowloris)."""
        socket = getattr(getattr(response, "fp", None), "raw", None)
        underlying = getattr(socket, "_sock", None)
        if underlying is None:
            return response.read(amount)
        previous = underlying.gettimeout()
        underlying.settimeout(self.timeout_seconds)
        try:
            return response.read(amount)
        finally:
            try:
                underlying.settimeout(previous)
            except OSError:
                # The peer closed the socket once the body was fully read.
                pass

    def get_key(self, kid: str) -> Mapping[str, Any]:
        if not kid:
            raise AuthenticationError(401, "invalid_token_header", "The token is missing a signing key identifier.")
        now = self._monotonic()
        if now >= self._expires_at:
            self._refresh()
        key = self._keys.get(kid)
        if key is None:
            # A key may have rotated before the cache TTL elapsed.
            self._refresh()
            key = self._keys.get(kid)
        if key is None:
            raise AuthenticationError(401, "unknown_signing_key", "The token signing key is not recognized.")
        return key

    def _refresh(self) -> None:
        with self._lock:
            try:
                request = Request(self.url, headers={"Accept": "application/json", "User-Agent": "hybrid-ndr-local-api/1"})
                response = self._opener(request, timeout=self.timeout_seconds)
                raw = self._read_bounded(response, 262_145)
                if len(raw) > 262_144:
                    raise ValueError("JWKS response is too large")
                payload = json.loads(raw)
                keys = payload.get("keys") if isinstance(payload, dict) else None
                if not isinstance(keys, list):
                    raise ValueError("JWKS payload does not contain a keys array")
                parsed = {
                    str(key["kid"]): dict(key)
                    for key in keys
                    if isinstance(key, dict) and isinstance(key.get("kid"), str)
                }
                if not parsed:
                    raise ValueError("JWKS payload contains no keyed signing keys")
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
                raise AuthenticationError(503, "identity_provider_unavailable", "Signing keys are temporarily unavailable.") from exc
            self._keys = parsed
            self._expires_at = self._monotonic() + self.cache_seconds


def _b64url_decode(value: str, *, maximum: int = 65_536) -> bytes:
    if not value or len(value) > maximum:
        raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.") from exc
    # JWT compact serialization requires the unpadded, URL-safe canonical
    # encoding. Reject alternate spellings whose unused pad bits decode to the
    # same bytes; accepting them makes a signed token textually malleable.
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(value, canonical):
        raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _json_segment(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64url_decode(value), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.") from exc
    if not isinstance(decoded, dict):
        raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.")
    return decoded


def _integer_claim(claims: Mapping[str, Any], name: str, *, required: bool) -> int | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    # bool is an int subclass and must not be accepted as a timestamp.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AuthenticationError(401, "invalid_token_claims", f"The token has an invalid {name} claim.")
    return int(value)


class JWTAuthenticator:
    def __init__(
        self,
        config: AuthConfig,
        keys: JWKSource,
        *,
        role_permissions: Mapping[str, frozenset[str]] | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if config.mode != "jwt":
            raise ValueError("JWTAuthenticator requires AuthConfig(mode='jwt')")
        self.config = config
        self.keys = keys
        self.role_permissions = dict(role_permissions or DEFAULT_ROLE_PERMISSIONS)
        self.known_permissions = frozenset(
            permission
            for values in self.role_permissions.values()
            for permission in values
            if permission != "*"
        )
        self.wall_clock = wall_clock

    def authenticate(self, headers: Mapping[str, str]) -> Principal:
        authorization = headers.get("authorization", "").strip()
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            raise AuthenticationError(401, "authentication_required", "A bearer access token is required.")
        claims = self._verify(parts[1])
        tenant_id = self._required_string(claims, "tenant_id")
        if not hmac.compare_digest(tenant_id, self.config.expected_tenant_id):
            raise AuthenticationError(403, "tenant_mismatch", "The token is not valid for this tenant.")
        organization_id = self._required_string(claims, "organization_id")
        organization_binding_id = self._required_string(claims, "organization_binding_id")
        if not hmac.compare_digest(organization_id, organization_binding_id):
            raise AuthenticationError(
                403, "organization_mismatch",
                "The token organization does not match its signed application binding.",
            )
        if self.config.allowed_organization_ids and organization_id not in self.config.allowed_organization_ids:
            raise AuthenticationError(403, "organization_mismatch", "The token is not valid for this organization.")
        supplied_tenant = headers.get("x-tenant-id", "").strip()
        if supplied_tenant and not hmac.compare_digest(supplied_tenant, tenant_id):
            raise AuthenticationError(403, "tenant_mismatch", "The requested tenant does not match the token.")

        deployment_id = headers.get("x-deployment-id", "").strip() or self.config.expected_deployment_id
        allowed_deployments = self._string_set(claims.get("deployment_ids"), "deployment_ids")
        single_deployment = claims.get("deployment_id")
        if single_deployment is not None:
            allowed_deployments |= {self._claim_string(single_deployment, "deployment_id")}
        if not allowed_deployments:
            raise AuthenticationError(403, "deployment_claim_missing", "The token has no deployment assignment.")
        if not hmac.compare_digest(deployment_id, self.config.expected_deployment_id):
            raise AuthenticationError(403, "deployment_mismatch", "The requested deployment is not served by this API.")
        if deployment_id not in allowed_deployments:
            raise AuthenticationError(403, "deployment_mismatch", "The token is not assigned to this deployment.")

        actor_id = self._required_string(claims, "sub")
        token_id = self._required_string(claims, "jti")
        if token_id in self.config.revoked_token_ids:
            raise AuthenticationError(401, "token_revoked", "The bearer token has been revoked.")
        roles = self._roles(claims, organization_id)
        if self.config.require_role_claim and not roles:
            raise AuthenticationError(403, "role_claim_missing", "The token has no recognized organization role.")
        unknown_roles = roles - self.role_permissions.keys()
        if unknown_roles:
            raise AuthenticationError(403, "unknown_role", "The token contains an unrecognized organization role.")
        machine_role = "deployment_agent" in roles
        if machine_role and roles != {"deployment_agent"}:
            raise AuthenticationError(403, "invalid_token_type", "Machine and human roles cannot be combined.")
        actor_type = claims.get("actor_type")
        if self.config.require_actor_type_claim:
            actor_type = self._claim_string(actor_type, "actor_type")
            expected_actor_type = "machine" if machine_role else "human"
            if actor_type != expected_actor_type:
                raise AuthenticationError(403, "invalid_token_type", "The token actor type does not match its role.")
        session_id = claims.get("session_id")
        if not machine_role and self.config.require_session_claim:
            session_id = self._claim_string(session_id, "session_id")
            if session_id in self.config.revoked_session_ids:
                raise AuthenticationError(401, "session_revoked", "The Logto session has been revoked.")
        elif session_id is not None:
            self._claim_string(session_id, "session_id")
        role = self._select_role(roles)
        permissions = self._permissions(claims)
        if role:
            role_allowed = self.role_permissions[role]
            if "*" not in role_allowed:
                permissions &= role_allowed
        if not permissions:
            raise AuthenticationError(403, "permission_claim_missing", "The token grants no product permissions.")
        return Principal(tenant_id, organization_id, deployment_id, actor_id, role or "token_scoped", frozenset(permissions))

    def _verify(self, token: str) -> dict[str, Any]:
        if len(token) > 16_384:
            raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.")
        segments = token.split(".")
        if len(segments) != 3:
            raise AuthenticationError(401, "malformed_token", "The bearer token is malformed.")
        header = _json_segment(segments[0])
        claims = _json_segment(segments[1])
        if header.get("alg") != "RS256" or header.get("alg") not in self.config.algorithms:
            raise AuthenticationError(401, "unsupported_token_algorithm", "The token signing algorithm is not allowed.")
        if "crit" in header:
            raise AuthenticationError(401, "invalid_token_header", "Critical token header extensions are not supported.")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError(401, "invalid_token_header", "The token is missing a signing key identifier.")
        key = self.keys.get_key(kid)
        self._verify_rs256(f"{segments[0]}.{segments[1]}".encode("ascii"), _b64url_decode(segments[2]), key)

        issuer = claims.get("iss")
        if not isinstance(issuer, str) or not hmac.compare_digest(issuer, self.config.issuer):
            raise AuthenticationError(401, "invalid_token_issuer", "The token issuer is not trusted.")
        audience = claims.get("aud")
        audiences = {audience} if isinstance(audience, str) else self._string_set(audience, "aud")
        if self.config.audience not in audiences:
            raise AuthenticationError(401, "invalid_token_audience", "The token audience is not valid for this API.")
        now = int(self.wall_clock())
        skew = self.config.clock_skew_seconds
        expires_at = _integer_claim(claims, "exp", required=True)
        not_before = _integer_claim(claims, "nbf", required=False)
        issued_at = _integer_claim(claims, "iat", required=True)
        if expires_at is None or expires_at <= now - skew:
            raise AuthenticationError(401, "token_expired", "The bearer token has expired.")
        if not_before is not None and not_before > now + skew:
            raise AuthenticationError(401, "token_not_yet_valid", "The bearer token is not yet valid.")
        if issued_at is None or issued_at > now + skew:
            raise AuthenticationError(401, "invalid_token_claims", "The token issued-at time is invalid.")
        return claims

    @staticmethod
    def _verify_rs256(signing_input: bytes, signature: bytes, key: Mapping[str, Any]) -> None:
        if key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
            raise AuthenticationError(401, "invalid_signing_key", "The signing key is not valid for RS256.")
        n_raw = _b64url_decode(str(key.get("n", "")), maximum=4096)
        e_raw = _b64url_decode(str(key.get("e", "")), maximum=32)
        modulus = int.from_bytes(n_raw, "big")
        exponent = int.from_bytes(e_raw, "big")
        if modulus.bit_length() < 2048 or exponent < 65537 or exponent % 2 == 0:
            raise AuthenticationError(401, "invalid_signing_key", "The RSA signing key is not sufficiently strong.")
        key_bytes = (modulus.bit_length() + 7) // 8
        if len(signature) != key_bytes:
            raise AuthenticationError(401, "invalid_token_signature", "The bearer token signature is invalid.")
        encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_bytes, "big")
        digest_info = _RS256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
        padding_length = key_bytes - len(digest_info) - 3
        expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
        if padding_length < 8 or not hmac.compare_digest(encoded, expected):
            raise AuthenticationError(401, "invalid_token_signature", "The bearer token signature is invalid.")

    def _permissions(self, claims: Mapping[str, Any]) -> set[str]:
        values: set[str] = set()
        scope = claims.get("scope")
        if isinstance(scope, str):
            values.update(scope.split())
        elif scope is not None:
            values.update(self._string_set(scope, "scope"))
        permissions = claims.get("permissions")
        if permissions is not None:
            values.update(self._string_set(permissions, "permissions"))
        # OIDC/Logto protocol scopes and unrelated resource scopes confer no local authority.
        return (values - _OIDC_SCOPES) & self.known_permissions

    def _roles(self, claims: Mapping[str, Any], organization_id: str) -> set[str]:
        values: set[str] = set()
        for claim_name in ("roles", "organization_roles"):
            raw = claims.get(claim_name)
            if raw is None:
                continue
            for value in self._string_set(raw, claim_name):
                if claim_name == "organization_roles" and ":" in value:
                    org_id, name = value.split(":", 1)
                    if org_id != organization_id:
                        continue
                    value = name
                values.add(value.strip().lower().replace("-", "_"))
        role = claims.get("role")
        if role is not None:
            values.add(self._claim_string(role, "role").strip().lower().replace("-", "_"))
        return {value for value in values if value}

    def _select_role(self, roles: set[str]) -> str:
        order = (
            "organization_owner", "security_admin", "soc_manager", "analyst",
            "auditor", "read_only", "deployment_agent",
        )
        return next((role for role in order if role in roles), "")

    @staticmethod
    def _claim_string(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise AuthenticationError(401, "invalid_token_claims", f"The token has an invalid {name} claim.")
        return value.strip()

    @classmethod
    def _required_string(cls, claims: Mapping[str, Any], name: str) -> str:
        return cls._claim_string(claims.get(name), name)

    @classmethod
    def _string_set(cls, value: Any, name: str) -> set[str]:
        if not isinstance(value, (list, tuple, set)) or len(value) > 100:
            if value is None:
                return set()
            raise AuthenticationError(401, "invalid_token_claims", f"The token has an invalid {name} claim.")
        return {cls._claim_string(item, name) for item in value}


def build_authenticator(
    config: AuthConfig | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    role_permissions: Mapping[str, frozenset[str]] | None = None,
) -> Authenticator:
    selected = config or AuthConfig.from_env(environ)
    if selected.mode == "demo_headers":
        return HeaderAuthenticator(role_permissions)
    if selected.jwks_url.startswith("http://") and not selected.jwks_allow_insecure_http:
        raise ValueError(
            "AUTH_JWKS_URL must use HTTPS; plain HTTP would let a network attacker "
            "inject signing keys (explicit dev override: AUTH_JWKS_ALLOW_INSECURE_HTTP=1)"
        )
    keys = JWKSClient(
        selected.jwks_url,
        cache_seconds=selected.jwks_cache_seconds,
        ca_file=selected.jwks_ca_file,
        allow_insecure_http=selected.jwks_allow_insecure_http,
    )
    return JWTAuthenticator(selected, keys, role_permissions=role_permissions)
