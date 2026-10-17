from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Mapping, Protocol

from hybrid_ndr_auth import (
    AuthConfig,
    AuthenticationError,
    JWKSClient,
    JWTAuthenticator,
)
from hybrid_ndr_auth.tokens import _boolean


PORTAL_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "organization_owner": frozenset({"*"}),
    "security_admin": frozenset({
        "organizations:read",
        "users:read",
        "deployments:read",
        "deployments:manage",
        "entitlements:read",
        "policy:read",
        "policy:manage",
        "usage:read",
        "updates:read",
        "updates:manage",
        "support:read",
        "support:manage",
    }),
    "soc_manager": frozenset({
        "organizations:read",
        "deployments:read",
        "entitlements:read",
        "policy:read",
        "usage:read",
        "updates:read",
        "support:read",
    }),
    "analyst": frozenset({"organizations:read", "deployments:read", "usage:read", "updates:read"}),
    "auditor": frozenset({
        "organizations:read",
        "users:read",
        "deployments:read",
        "entitlements:read",
        "policy:read",
        "usage:read",
        "updates:read",
        "support:read",
    }),
    "read_only": frozenset({
        "organizations:read",
        "deployments:read",
        "entitlements:read",
        "policy:read",
        "usage:read",
        "updates:read",
        "support:read",
    }),
}


@dataclass(frozen=True)
class PortalPrincipal:
    tenant_id: str
    organization_id: str
    actor_id: str
    role: str
    permissions: frozenset[str]


class PortalAuthenticator(Protocol):
    def authenticate(self, headers: Mapping[str, str]) -> PortalPrincipal: ...


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in (value or "").split(",") if item.strip()))


@dataclass(frozen=True)
class PortalAuthConfig:
    mode: str = "jwt"
    issuer: str = ""
    audience: str = ""
    jwks_url: str = ""
    allowed_organization_ids: tuple[str, ...] = ()
    clock_skew_seconds: int = 30
    jwks_cache_seconds: int = 300
    jwks_ca_file: str = ""
    jwks_allow_insecure_http: bool = False
    revoked_token_ids: tuple[str, ...] = ()
    revoked_session_ids: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "PortalAuthConfig":
        env = environ if environ is not None else os.environ
        mode = env.get("CONTROL_PORTAL_AUTH_MODE", "jwt").strip().lower()
        if mode not in {"jwt", "demo_headers"}:
            raise ValueError("CONTROL_PORTAL_AUTH_MODE must be 'jwt' or 'demo_headers'")
        if mode == "demo_headers":
            if env.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
                raise ValueError("CONTROL_PORTAL_AUTH_MODE=demo_headers is forbidden when HYBRID_NDR_ENV=production")
            if env.get("HYBRID_NDR_ALLOW_DEMO_AUTH", "").strip().lower() not in {"1", "true", "yes", "on"}:
                raise ValueError("CONTROL_PORTAL_AUTH_MODE=demo_headers requires HYBRID_NDR_ALLOW_DEMO_AUTH=true")
        insecure_jwks = env.get("CONTROL_PORTAL_AUTH_JWKS_ALLOW_INSECURE_HTTP", "").strip()
        config = cls(
            mode=mode,
            issuer=env.get("CONTROL_PORTAL_AUTH_ISSUER", "").strip(),
            audience=env.get("CONTROL_PORTAL_AUTH_AUDIENCE", "https://hybrid-ndr.cloud/api").strip(),
            jwks_url=env.get("CONTROL_PORTAL_AUTH_JWKS_URL", "").strip(),
            allowed_organization_ids=_csv(env.get("CONTROL_PORTAL_AUTH_ALLOWED_ORGANIZATION_IDS")),
            clock_skew_seconds=int(env.get("CONTROL_PORTAL_AUTH_CLOCK_SKEW_SECONDS", "30")),
            jwks_cache_seconds=int(env.get("CONTROL_PORTAL_AUTH_JWKS_CACHE_SECONDS", "300")),
            jwks_ca_file=env.get("CONTROL_PORTAL_AUTH_JWKS_CA_FILE", "").strip(),
            # Explicit development-only escape hatch; production never sets it.
            jwks_allow_insecure_http=_boolean(insecure_jwks, False) if insecure_jwks else False,
            revoked_token_ids=_csv(env.get("CONTROL_PORTAL_AUTH_REVOKED_TOKEN_IDS")),
            revoked_session_ids=_csv(env.get("CONTROL_PORTAL_AUTH_REVOKED_SESSION_IDS")),
        )
        if config.mode == "jwt":
            missing = [
                name
                for name, value in (
                    ("CONTROL_PORTAL_AUTH_ISSUER", config.issuer),
                    ("CONTROL_PORTAL_AUTH_AUDIENCE", config.audience),
                    ("CONTROL_PORTAL_AUTH_JWKS_URL", config.jwks_url),
                )
                if not value
            ]
            if missing:
                raise ValueError("Cloud portal JWT authentication requires " + ", ".join(missing))
            if not (0 <= config.clock_skew_seconds <= 300):
                raise ValueError("CONTROL_PORTAL_AUTH_CLOCK_SKEW_SECONDS must be between 0 and 300")
            if not (30 <= config.jwks_cache_seconds <= 86_400):
                raise ValueError("CONTROL_PORTAL_AUTH_JWKS_CACHE_SECONDS must be between 30 and 86400")
            if len(config.revoked_token_ids) > 1_000 or len(config.revoked_session_ids) > 1_000:
                raise ValueError("Cloud portal token/session revocation lists are limited to 1000 entries")
        return config


class PortalJWTAuthenticator:
    """Verify a Logto organization token without trusting a caller-selected tenant."""

    def __init__(
        self,
        config: PortalAuthConfig,
        keys=None,
        *,
        role_permissions: Mapping[str, frozenset[str]] | None = None,
        wall_clock=None,
    ) -> None:
        if config.mode != "jwt":
            raise ValueError("PortalJWTAuthenticator requires PortalAuthConfig(mode='jwt')")
        self.config = config
        self.role_permissions = dict(role_permissions or PORTAL_ROLE_PERMISSIONS)
        verifier_config = AuthConfig(
            mode="jwt",
            issuer=config.issuer,
            audience=config.audience,
            jwks_url=config.jwks_url,
            algorithms=("RS256",),
            clock_skew_seconds=config.clock_skew_seconds,
            jwks_cache_seconds=config.jwks_cache_seconds,
            require_role_claim=True,
        )
        source = keys or JWKSClient(
            config.jwks_url,
            cache_seconds=config.jwks_cache_seconds,
            ca_file=config.jwks_ca_file,
            allow_insecure_http=config.jwks_allow_insecure_http,
        )
        options = {"role_permissions": self.role_permissions}
        if wall_clock is not None:
            options["wall_clock"] = wall_clock
        self.verifier = JWTAuthenticator(verifier_config, source, **options)

    def authenticate(self, headers: Mapping[str, str]) -> PortalPrincipal:
        authorization = headers.get("authorization", "").strip()
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            raise AuthenticationError(401, "authentication_required", "A bearer access token is required.")
        claims = self.verifier._verify(parts[1])
        tenant_id = self.verifier._required_string(claims, "tenant_id")
        organization_id = self.verifier._required_string(claims, "organization_id")
        binding_id = self.verifier._required_string(claims, "organization_binding_id")
        if not hmac.compare_digest(organization_id, binding_id):
            raise AuthenticationError(
                403,
                "organization_mismatch",
                "The token organization does not match its signed application binding.",
            )
        if self.config.allowed_organization_ids and organization_id not in self.config.allowed_organization_ids:
            raise AuthenticationError(403, "organization_mismatch", "The token is not valid for this organization.")
        selected_organization = headers.get("x-organization-id", "").strip()
        if selected_organization and not hmac.compare_digest(selected_organization, organization_id):
            raise AuthenticationError(403, "organization_mismatch", "The requested organization does not match the token.")
        selected_tenant = headers.get("x-tenant-id", "").strip()
        if selected_tenant and not hmac.compare_digest(selected_tenant, tenant_id):
            raise AuthenticationError(403, "tenant_mismatch", "The requested tenant does not match the token.")

        roles = self.verifier._roles(claims, organization_id)
        unknown = roles - self.role_permissions.keys() - {"deployment_agent"}
        if unknown:
            raise AuthenticationError(403, "unknown_role", "The token contains an unrecognized organization role.")
        if "deployment_agent" in roles:
            code = "invalid_token_type" if len(roles) > 1 else "human_role_required"
            raise AuthenticationError(403, code, "A human cloud-console organization role is required.")
        role = self.verifier._select_role(roles)
        if not role or role not in self.role_permissions:
            raise AuthenticationError(403, "human_role_required", "A human cloud-console organization role is required.")
        token_id = self.verifier._required_string(claims, "jti")
        if token_id in self.config.revoked_token_ids:
            raise AuthenticationError(401, "token_revoked", "The bearer token has been revoked.")
        actor_type = self.verifier._required_string(claims, "actor_type")
        if actor_type != "human":
            raise AuthenticationError(403, "invalid_token_type", "The cloud console requires a human access token.")
        session_id = self.verifier._required_string(claims, "session_id")
        if session_id in self.config.revoked_session_ids:
            raise AuthenticationError(401, "session_revoked", "The Logto session has been revoked.")
        permissions = self.verifier._permissions(claims)
        ceiling = self.role_permissions[role]
        if "*" not in ceiling:
            permissions &= ceiling
        if not permissions:
            raise AuthenticationError(403, "permission_claim_missing", "The token grants no cloud-console permissions.")
        return PortalPrincipal(
            tenant_id=tenant_id,
            organization_id=organization_id,
            actor_id=self.verifier._required_string(claims, "sub"),
            role=role,
            permissions=frozenset(permissions),
        )


class PortalHeaderAuthenticator:
    """Explicit loopback/demo authenticator; the vendor Compose profile never selects it by default."""

    def __init__(self, role_permissions: Mapping[str, frozenset[str]] | None = None) -> None:
        self.role_permissions = dict(role_permissions or PORTAL_ROLE_PERMISSIONS)

    def authenticate(self, headers: Mapping[str, str]) -> PortalPrincipal:
        tenant_id = headers.get("x-tenant-id", "").strip()
        organization_id = headers.get("x-organization-id", "").strip()
        actor_id = headers.get("x-actor-id", "").strip()
        role = headers.get("x-role", "read_only").strip().lower().replace("-", "_")
        if not tenant_id or not organization_id or not actor_id:
            raise AuthenticationError(
                401,
                "authentication_required",
                "X-Tenant-ID, X-Organization-ID, and X-Actor-ID are required in portal demo mode.",
            )
        if role not in self.role_permissions:
            raise AuthenticationError(403, "unknown_role", "The supplied organization role is not recognized.")
        allowed = self.role_permissions[role]
        known = {permission for values in self.role_permissions.values() for permission in values if permission != "*"}
        permissions = frozenset(known if "*" in allowed else allowed)
        return PortalPrincipal(tenant_id, organization_id, actor_id, role, permissions)


def build_portal_authenticator(config: PortalAuthConfig | None = None, *, environ=None) -> PortalAuthenticator:
    selected = config or PortalAuthConfig.from_env(environ)
    if selected.mode == "demo_headers":
        return PortalHeaderAuthenticator()
    return PortalJWTAuthenticator(selected)
