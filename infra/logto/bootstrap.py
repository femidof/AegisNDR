#!/usr/bin/env python3
"""Idempotently reconcile the checked-in AegisNDR identity plane with Logto.

For a local, pinned Logto OSS 1.39 deployment the script can create an
ephemeral Management API client directly in Logto's PostgreSQL schema. The
client is removed after reconciliation. External Logto deployments instead
provide an existing Management API token or M2M credentials.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve().parent
MANAGEMENT_RESOURCE = "https://default.logto.app/api"
BOOTSTRAP_CLIENT_ID = "hybrid-ndr-bootstrap"
PROTOCOL_SCOPES = (
    "openid",
    "profile",
    "urn:logto:scope:organizations",
    "urn:logto:scope:organization_roles",
)
REQUIRED_ROLES = frozenset({
    "organization_owner",
    "security_admin",
    "soc_manager",
    "analyst",
    "auditor",
    "read_only",
    "deployment_agent",
})
SPEC_LOCAL_PERMISSIONS = frozenset({
    "alerts:read",
    "alerts:update",
    "events:search",
    "investigations:create",
    "investigations:read",
    "cases:create",
    "cases:update",
    "evidence:read",
    "evidence:export",
    "transmissions:read",
    "rules:read",
    "rules:manage",
    "integrations:manage",
    "deployments:manage",
    "users:manage",
    "audit:read",
    "response:approve",
})
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_EPHEMERAL_SECRET = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


class BootstrapError(RuntimeError):
    pass


def _json_entity(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise BootstrapError(f"Logto returned an invalid {label}")
    return dict(value)


def _browser_url(value: str, label: str, *, origin_only: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise BootstrapError(f"{label} is not a valid URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BootstrapError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BootstrapError(f"{label} must not contain credentials, a query, or a fragment")
    is_loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not is_loopback:
        raise BootstrapError(f"{label} must use HTTPS outside loopback development")
    if origin_only and parsed.path not in {"", "/"}:
        raise BootstrapError(f"{label} must be an origin without a path")
    path = "" if origin_only else parsed.path
    return urlunsplit((parsed.scheme, parsed.netloc, path.rstrip("/") if path != "/" else "", "", ""))


def _management_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise BootstrapError("management endpoint is not a valid URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BootstrapError("management endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BootstrapError("management endpoint must not contain credentials, a query, or a fragment")
    if parsed.path not in {"", "/"}:
        raise BootstrapError("management endpoint must not contain a path")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _issuer(value: str) -> str:
    normalized = _browser_url(value, "OIDC issuer")
    parsed = urlsplit(normalized)
    if parsed.path != "/oidc":
        raise BootstrapError("OIDC issuer path must be /oidc")
    return normalized


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _csv(value: str | None) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in (value or "").split(",") if item.strip()))


@dataclass
class LogtoClient:
    endpoint: str
    access_token: str
    timeout_seconds: float = 5.0

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.endpoint.rstrip("/") + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "hybrid-ndr-logto-bootstrap/2",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise BootstrapError("Logto response exceeded the safety limit")
                return json.loads(raw) if raw else None
        except HTTPError as exc:
            # Do not echo bodies; Management API errors may contain identity data.
            raise BootstrapError(
                f"Logto Management API returned HTTP {exc.code} for {method} {path}"
            ) from exc
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise BootstrapError(f"Logto is unavailable for {method} {path}") from exc

    def list(self, path: str, *, query: str = "") -> list[dict[str, Any]]:
        params: dict[str, str | int] = {"page": 1, "page_size": 100}
        if query:
            params["q"] = query
        result = self.request("GET", f"{path}?{urlencode(params)}")
        if not isinstance(result, list):
            raise BootstrapError(f"Logto returned an invalid list for {path}")
        return [dict(item) for item in result if isinstance(item, dict)]


Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass
class LocalManagementSeeder:
    compose_file: Path
    database_user: str = "logto"
    database_name: str = "logto"
    compose_env_file: Path | None = None
    project_name: str = ""
    service_name: str = "logto-postgres"
    runner: Runner = subprocess.run

    def _command(self) -> list[str]:
        command = ["docker", "compose"]
        if self.project_name:
            command.extend(["--project-name", self.project_name])
        command.extend(["--file", str(self.compose_file)])
        if self.compose_env_file:
            command.extend(["--env-file", str(self.compose_env_file)])
        command.extend([
            "exec",
            "-T",
            self.service_name,
            "psql",
            "--no-psqlrc",
            "--username",
            self.database_user,
            "--dbname",
            self.database_name,
        ])
        return command

    def _run(self, sql: str) -> None:
        if not self.compose_file.is_file():
            raise BootstrapError(f"Compose file is missing: {self.compose_file}")
        try:
            result = self.runner(
                self._command(),
                input=sql,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BootstrapError("automatic local Management API client seed could not run") from exc
        if result.returncode != 0:
            raise BootstrapError(
                "automatic local Management API client seed failed; ensure the vendor Logto "
                "services are healthy or provide Management API credentials "
                "(LOGTO_MANAGEMENT_CLIENT_ID/LOGTO_MANAGEMENT_CLIENT_SECRET or "
                "LOGTO_MANAGEMENT_ACCESS_TOKEN; use --no-local-management-seed to require them)"
            )

    def seed(self, client_secret: str) -> None:
        if not _EPHEMERAL_SECRET.fullmatch(client_secret):
            raise BootstrapError("generated bootstrap secret has an invalid format")
        sql = (HERE / "seed-management-client.sql").read_text(encoding="utf-8")
        # psql variable input travels over stdin rather than the process list.
        self._run(f"\\set bootstrap_client_secret {client_secret}\n{sql}")

    def remove(self) -> None:
        self._run((HERE / "remove-management-client.sql").read_text(encoding="utf-8"))


def management_token(
    endpoint: str,
    client_id: str,
    client_secret: str,
    timeout_seconds: float = 5.0,
) -> str:
    encoded = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "resource": MANAGEMENT_RESOURCE,
        "scope": "all",
    }).encode("ascii")
    request = Request(
        endpoint.rstrip("/") + "/oidc/token",
        data=encoded,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(65_537)
            if len(raw) > 65_536:
                raise BootstrapError("Management token response exceeded the safety limit")
            result = json.loads(raw)
    except HTTPError as exc:
        raise BootstrapError(f"Management token request returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise BootstrapError("Management token request failed") from exc
    token = result.get("access_token") if isinstance(result, dict) else None
    if not isinstance(token, str) or not token:
        raise BootstrapError("Management token response did not contain an access token")
    return token


def exact(items: list[dict[str, Any]], key: str, value: str) -> dict[str, Any] | None:
    return next((item for item in items if item.get(key) == value), None)


def render_manifest(
    manifest: Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Apply deployment-specific, non-secret environment values to a manifest copy."""
    env = environ if environ is not None else os.environ
    rendered = copy.deepcopy(dict(manifest))
    applications = rendered.get("applications")
    if isinstance(applications, dict):
        for application in applications.values():
            if not isinstance(application, dict):
                continue
            overrides = application.get("environment_overrides", {})
            if not isinstance(overrides, dict):
                continue
            for environment_name in overrides.values():
                if not isinstance(environment_name, str) or not _ENVIRONMENT_NAME.fullmatch(environment_name):
                    raise BootstrapError("application environment override contains an invalid variable name")
            configured_origin = env.get(str(overrides.get("origin", "")), "").strip()
            configured_redirect = env.get(str(overrides.get("redirect_uri", "")), "").strip()
            configured_logout = env.get(str(overrides.get("post_logout_redirect_uri", "")), "").strip()
            if not any((configured_origin, configured_redirect, configured_logout)):
                continue
            if configured_origin:
                origin = _browser_url(configured_origin, "application public origin", origin_only=True)
            elif configured_redirect:
                origin = _origin(_browser_url(configured_redirect, "application redirect URI"))
            else:
                origin = _origin(_browser_url(configured_logout, "application post-logout URI"))
            redirect = configured_redirect or origin + "/callback"
            logout = configured_logout or origin
            application["redirect_uris"] = [_browser_url(redirect, "application redirect URI")]
            application["post_logout_redirect_uris"] = [
                _browser_url(logout, "application post-logout URI")
            ]
            application["cors_allowed_origins"] = [origin]

    organization = rendered.get("organization")
    if isinstance(organization, dict):
        if env.get("LOGTO_ORGANIZATION_NAME", "").strip():
            organization["name"] = env["LOGTO_ORGANIZATION_NAME"].strip()
        if env.get("TENANT_ID", "").strip():
            organization["tenant_id"] = env["TENANT_ID"].strip()
        deployment_ids = _csv(env.get("LOGTO_DEPLOYMENT_IDS"))
        if not deployment_ids and env.get("DEPLOYMENT_ID", "").strip():
            deployment_ids = [env["DEPLOYMENT_ID"].strip()]
        if deployment_ids:
            organization["deployment_ids"] = deployment_ids
    return rendered


def validate_manifest(manifest: Mapping[str, Any]) -> None:
    required = {
        "oidc",
        "api_resources",
        "applications",
        "deployment_application",
        "organization",
        "organization_roles",
    }
    if set(manifest) != required:
        raise BootstrapError(f"manifest top-level keys must be exactly {sorted(required)}")
    oidc = manifest["oidc"]
    if not isinstance(oidc, dict) or oidc.get("signing_key_algorithm") != "RSA":
        raise BootstrapError("oidc signing_key_algorithm must be RSA")
    if oidc.get("session_bound_refresh_tokens") is not True:
        raise BootstrapError("session-bound refresh tokens must be enabled")

    resources = manifest["api_resources"]
    if not isinstance(resources, dict) or not resources:
        raise BootstrapError("manifest must define API resources")
    indicators: set[str] = set()
    scopes_by_resource: dict[str, set[str]] = {}
    for resource_key, resource in resources.items():
        if not isinstance(resource_key, str) or not isinstance(resource, dict):
            raise BootstrapError("API resource entries must be objects")
        indicator = resource.get("indicator")
        scopes = resource.get("scopes")
        ttl = resource.get("access_token_ttl")
        if not isinstance(resource.get("name"), str) or not resource["name"]:
            raise BootstrapError(f"API resource {resource_key!r} must have a name")
        if not isinstance(indicator, str) or not indicator.startswith("https://") or indicator in indicators:
            raise BootstrapError(f"API resource {resource_key!r} has an invalid or duplicate indicator")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 3600:
            raise BootstrapError(f"API resource {resource_key!r} access token TTL must be 60-3600 seconds")
        if not isinstance(scopes, dict) or not scopes or not all(
            isinstance(name, str) and name and isinstance(description, str) and description
            for name, description in scopes.items()
        ):
            raise BootstrapError(f"API resource {resource_key!r} must define named scopes")
        indicators.add(indicator)
        scopes_by_resource[resource_key] = set(scopes)
    if "local_api" not in scopes_by_resource or not SPEC_LOCAL_PERMISSIONS <= scopes_by_resource["local_api"]:
        raise BootstrapError("local_api is missing permissions required by the technical specification")
    if "control_api" not in scopes_by_resource:
        raise BootstrapError("control_api resource is required")

    roles = manifest["organization_roles"]
    if not isinstance(roles, dict) or set(roles) != REQUIRED_ROLES:
        raise BootstrapError(f"organization roles must be exactly {sorted(REQUIRED_ROLES)}")
    for role_name, role in roles.items():
        if not isinstance(role, dict) or role.get("type") not in {"User", "MachineToMachine"}:
            raise BootstrapError(f"role {role_name!r} has an invalid type")
        if not isinstance(role.get("description"), str) or not role["description"]:
            raise BootstrapError(f"role {role_name!r} must have a description")
        resource_scopes = role.get("resource_scopes")
        if not isinstance(resource_scopes, dict) or not resource_scopes:
            raise BootstrapError(f"role {role_name!r} must define resource scopes")
        for resource_key, role_scopes in resource_scopes.items():
            if resource_key not in scopes_by_resource:
                raise BootstrapError(f"role {role_name!r} references an unknown API resource")
            if not isinstance(role_scopes, list) or not set(role_scopes) <= scopes_by_resource[resource_key]:
                raise BootstrapError(f"role {role_name!r} references an unknown scope")
    if roles["deployment_agent"]["type"] != "MachineToMachine":
        raise BootstrapError("deployment_agent must be a MachineToMachine role")
    if any(role["type"] != "User" for name, role in roles.items() if name != "deployment_agent"):
        raise BootstrapError("human organization roles must have type User")

    applications = manifest["applications"]
    if not isinstance(applications, dict) or not {"local_dashboard", "cloud_portal"} <= set(applications):
        raise BootstrapError("local dashboard and cloud portal applications are required")
    for app_key, application in applications.items():
        if not isinstance(application, dict) or application.get("type") != "SPA":
            raise BootstrapError(f"application {app_key!r} must be a SPA")
        if application.get("resource") not in resources:
            raise BootstrapError(f"application {app_key!r} references an unknown resource")
        for field in ("redirect_uris", "post_logout_redirect_uris", "cors_allowed_origins"):
            values = application.get(field)
            if not isinstance(values, list) or not values:
                raise BootstrapError(f"application {app_key!r} must define {field}")
            for value in values:
                _browser_url(value, f"application {app_key} {field}", origin_only=field == "cors_allowed_origins")
        ttl = application.get("refresh_token_ttl_days")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 180:
            raise BootstrapError(f"application {app_key!r} refresh token TTL must be 1-180 days")
        if application.get("rotate_refresh_token") is not True:
            raise BootstrapError(f"application {app_key!r} must rotate refresh tokens")
        maximum = application.get("max_allowed_grants")
        if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
            raise BootstrapError(f"application {app_key!r} must limit active grants")

    organization = manifest["organization"]
    if not isinstance(organization, dict) or not isinstance(organization.get("tenant_id"), str) or not organization["tenant_id"]:
        raise BootstrapError("organization tenant_id is required")
    if not isinstance(organization.get("deployment_ids"), list) or not organization["deployment_ids"]:
        raise BootstrapError("organization deployment_ids must be a non-empty list")

    deployment_application = manifest["deployment_application"]
    deployment_role = deployment_application.get("organization_role") if isinstance(deployment_application, dict) else None
    if not isinstance(deployment_application, dict) or deployment_application.get("type") != "MachineToMachine":
        raise BootstrapError("deployment_application type must be MachineToMachine")
    if deployment_role not in roles or roles[deployment_role]["type"] != "MachineToMachine":
        raise BootstrapError("deployment_application must reference a machine organization role")


def _reconcile_resource(
    client: LogtoClient,
    resource_config: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, str]]:
    resources = client.list("/api/resources", query=str(resource_config["indicator"]))
    resource = exact(resources, "indicator", str(resource_config["indicator"]))
    resource_body = {
        "name": resource_config["name"],
        "indicator": resource_config["indicator"],
        "accessTokenTtl": resource_config["access_token_ttl"],
    }
    if resource is None:
        resource = _json_entity(client.request("POST", "/api/resources", resource_body), "API resource")
    else:
        client.request("PATCH", f"/api/resources/{resource['id']}", {
            "name": resource_body["name"],
            "accessTokenTtl": resource_body["accessTokenTtl"],
        })

    existing_scopes = client.list(f"/api/resources/{resource['id']}/scopes")
    scopes_by_name = {item.get("name"): item for item in existing_scopes}
    scope_ids: dict[str, str] = {}
    for name, description in resource_config["scopes"].items():
        scope = scopes_by_name.get(name)
        if scope is None:
            scope = _json_entity(client.request("POST", f"/api/resources/{resource['id']}/scopes", {
                "name": name,
                "description": description,
            }), "API resource scope")
        elif scope.get("description") != description:
            scope = _json_entity(
                client.request("PATCH", f"/api/resources/{resource['id']}/scopes/{scope['id']}", {
                    "name": name,
                    "description": description,
                }),
                "API resource scope",
            )
        scope_id = scope.get("id")
        if not isinstance(scope_id, str):
            raise BootstrapError("Logto returned an API resource scope without an ID")
        scope_ids[name] = scope_id
    return resource, scope_ids


def _application_scopes(
    manifest: Mapping[str, Any],
    resource_key: str,
) -> list[str]:
    granted = {
        scope
        for role in manifest["organization_roles"].values()
        if role["type"] == "User"
        for scope in role["resource_scopes"].get(resource_key, [])
    }
    declared = manifest["api_resources"][resource_key]["scopes"]
    return [*PROTOCOL_SCOPES, *(scope for scope in declared if scope in granted)]


def reconcile(
    client: LogtoClient,
    manifest: Mapping[str, Any],
    customizer_script: str,
    *,
    issuer: str | None = None,
) -> dict[str, Any]:
    public_issuer = _issuer(issuer or client.endpoint.rstrip("/") + "/oidc")
    signing_keys = client.request("GET", "/api/configs/oidc/private-keys")
    if not isinstance(signing_keys, list) or not signing_keys:
        raise BootstrapError("Logto returned no OIDC private signing-key metadata")
    current_key = next((key for key in signing_keys if key.get("status") == "Current"), signing_keys[0])
    if current_key.get("signingKeyAlgorithm") != manifest["oidc"]["signing_key_algorithm"]:
        signing_keys = client.request("POST", "/api/configs/oidc/private-keys/rotate", {
            "signingKeyAlgorithm": "RSA",
            "rotationGracePeriod": 0,
        })
        if not isinstance(signing_keys, list) or not any(
            key.get("signingKeyAlgorithm") == "RSA" for key in signing_keys
        ):
            raise BootstrapError("Logto did not activate an RSA OIDC signing key")

    resource_entities: dict[str, dict[str, Any]] = {}
    scope_ids: dict[str, dict[str, str]] = {}
    for resource_key, resource_config in manifest["api_resources"].items():
        resource, resource_scope_ids = _reconcile_resource(client, resource_config)
        resource_entities[resource_key] = resource
        scope_ids[resource_key] = resource_scope_ids

    role_items = client.list("/api/organization-roles")
    role_ids: dict[str, str] = {}
    for role_name, role_config in manifest["organization_roles"].items():
        role = exact(role_items, "name", role_name)
        assigned_ids = [
            scope_ids[resource_key][scope]
            for resource_key, scopes in role_config["resource_scopes"].items()
            for scope in scopes
        ]
        if role is None:
            role = _json_entity(client.request("POST", "/api/organization-roles", {
                "name": role_name,
                "description": role_config["description"],
                "type": role_config["type"],
                "organizationScopeIds": [],
                "resourceScopeIds": assigned_ids,
            }), "organization role")
        elif role.get("type") != role_config["type"]:
            raise BootstrapError(f"existing organization role {role_name!r} has the wrong immutable type")
        else:
            if role.get("description") != role_config["description"]:
                client.request("PATCH", f"/api/organization-roles/{role['id']}", {
                    "description": role_config["description"],
                })
            client.request(
                "PUT",
                f"/api/organization-roles/{role['id']}/resource-scopes",
                {"scopeIds": assigned_ids},
            )
        role_ids[role_name] = role["id"]

    organization_config = manifest["organization"]
    organizations = client.list("/api/organizations", query=organization_config["name"])
    organization = exact(organizations, "name", organization_config["name"])
    organization_body = {
        "name": organization_config["name"],
        "description": organization_config["description"],
        "customData": {
            "tenant_id": organization_config["tenant_id"],
            "deployment_ids": organization_config["deployment_ids"],
        },
        "isMfaRequired": bool(organization_config.get("require_mfa", False)),
    }
    if organization is None:
        organization = _json_entity(
            client.request("POST", "/api/organizations", organization_body),
            "organization",
        )
    else:
        organization = _json_entity(
            client.request("PATCH", f"/api/organizations/{organization['id']}", organization_body),
            "organization",
        )

    binding = {
        "organization_id": organization["id"],
        "tenant_id": organization_config["tenant_id"],
        "deployment_ids": organization_config["deployment_ids"],
    }

    application_ids: dict[str, str] = {}
    application_scopes: dict[str, list[str]] = {}
    for application_key, application_config in manifest["applications"].items():
        applications = client.list("/api/applications", query=application_config["name"])
        application = exact(applications, "name", application_config["name"])
        resource_key = application_config["resource"]
        requested_scopes = _application_scopes(manifest, resource_key)
        application_body = {
            "name": application_config["name"],
            "description": application_config["description"],
            "type": application_config["type"],
            "oidcClientMetadata": {
                "redirectUris": application_config["redirect_uris"],
                "postLogoutRedirectUris": application_config["post_logout_redirect_uris"],
            },
            "customClientMetadata": {
                "corsAllowedOrigins": application_config["cors_allowed_origins"],
                "refreshTokenTtlInDays": application_config["refresh_token_ttl_days"],
                "rotateRefreshToken": application_config["rotate_refresh_token"],
                # The clients deliberately omit offline_access. Logto still issues
                # a refresh token, but binds it to the browser session/grant so
                # end-session and session revocation invalidate future refreshes.
                "alwaysIssueRefreshToken": True,
                "maxAllowedGrants": application_config["max_allowed_grants"],
            },
            "customData": {
                "hybrid_ndr_binding": binding,
                "hybrid_ndr_resource": manifest["api_resources"][resource_key]["indicator"],
            },
        }
        if application is None:
            application = _json_entity(
                client.request("POST", "/api/applications", application_body),
                f"{application_key} application",
            )
        elif application.get("type") != application_config["type"]:
            raise BootstrapError(
                f"existing {application_key.replace('_', ' ')} application has the wrong immutable type"
            )
        else:
            application = _json_entity(
                client.request(
                    "PATCH",
                    f"/api/applications/{application['id']}",
                    {key: value for key, value in application_body.items() if key != "type"},
                ),
                f"{application_key} application",
            )
        application_ids[application_key] = application["id"]
        application_scopes[application_key] = requested_scopes

    deployment_config = manifest["deployment_application"]
    deployment_applications = client.list("/api/applications", query=deployment_config["name"])
    deployment_application = exact(deployment_applications, "name", deployment_config["name"])
    deployment_body = {
        "name": deployment_config["name"],
        "description": deployment_config["description"],
        "type": deployment_config["type"],
        "customData": {
            "hybrid_ndr_binding": {
                **binding,
                "machine_role": deployment_config["organization_role"],
            }
        },
    }
    if deployment_application is None:
        deployment_application = _json_entity(
            client.request("POST", "/api/applications", deployment_body),
            "deployment application",
        )
    elif deployment_application.get("type") != deployment_config["type"]:
        raise BootstrapError("existing deployment application has the wrong immutable type")
    else:
        deployment_application = _json_entity(
            client.request(
                "PATCH",
                f"/api/applications/{deployment_application['id']}",
                {key: value for key, value in deployment_body.items() if key != "type"},
            ),
            "deployment application",
        )

    organization_applications = client.list(f"/api/organizations/{organization['id']}/applications")
    if exact(organization_applications, "id", deployment_application["id"]) is None:
        client.request(
            "POST",
            f"/api/organizations/{organization['id']}/applications",
            {"applicationIds": [deployment_application["id"]]},
        )
    client.request(
        "PUT",
        f"/api/organizations/{organization['id']}/applications/{deployment_application['id']}/roles",
        {"organizationRoleIds": [role_ids[deployment_config["organization_role"]]]},
    )

    customizer_body = {
        "script": customizer_script,
        "environmentVariables": {},
        "blockIssuanceOnError": True,
    }
    client.request("PUT", "/api/configs/jwt-customizer/access-token", customizer_body)
    client.request("PUT", "/api/configs/jwt-customizer/client-credentials", customizer_body)

    bootstrap_user = os.environ.get("LOGTO_BOOTSTRAP_USER_ID", "").strip()
    bootstrap_role = os.environ.get("LOGTO_BOOTSTRAP_USER_ROLE", "organization_owner").strip()
    if bootstrap_user:
        if bootstrap_role not in role_ids:
            raise BootstrapError("LOGTO_BOOTSTRAP_USER_ROLE is not defined in the manifest")
        users = client.list(f"/api/organizations/{organization['id']}/users", query=bootstrap_user)
        if exact(users, "id", bootstrap_user) is None:
            client.request(
                "POST",
                f"/api/organizations/{organization['id']}/users",
                {"userIds": [bootstrap_user]},
            )
        user_roles = client.list(f"/api/organizations/{organization['id']}/users/{bootstrap_user}/roles")
        if exact(user_roles, "id", role_ids[bootstrap_role]) is None:
            client.request(
                "POST",
                f"/api/organizations/{organization['id']}/users/{bootstrap_user}/roles",
                {"organizationRoleIds": [role_ids[bootstrap_role]]},
            )

    return {
        "issuer": public_issuer,
        "jwks_uri": public_issuer + "/jwks",
        "audiences": {
            key: value["indicator"] for key, value in manifest["api_resources"].items()
        },
        "resource_ids": {key: value["id"] for key, value in resource_entities.items()},
        "applications": {
            **application_ids,
            "deployment_agent": deployment_application["id"],
        },
        "application_scopes": application_scopes,
        # Stable compatibility keys for the current customer/vendor config.
        "audience": manifest["api_resources"]["local_api"]["indicator"],
        "application_id": application_ids["local_dashboard"],
        "control_application_id": application_ids["cloud_portal"],
        "deployment_application_id": deployment_application["id"],
        "organization_id": organization["id"],
        "tenant_id": organization_config["tenant_id"],
        "deployment_ids": organization_config["deployment_ids"],
        "signing_key_algorithm": "RSA",
        "access_token_ttl_seconds": {
            key: value["access_token_ttl"] for key, value in manifest["api_resources"].items()
        },
        "refresh_tokens": {
            "session_bound": True,
            "rotation_enabled": True,
            "offline_access_requested": False,
        },
        "role_ids": role_ids,
    }


def _private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _default_issuer(endpoint: str, environ: Mapping[str, str]) -> str:
    configured = environ.get("LOGTO_ISSUER", "").strip()
    if configured:
        return configured
    public_endpoint = environ.get("LOGTO_PUBLIC_ENDPOINT", "").strip()
    if public_endpoint:
        return public_endpoint.rstrip("/") + "/oidc"
    return endpoint.rstrip("/") + "/oidc"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile the AegisNDR Logto identity manifest.")
    parser.add_argument(
        "--management-endpoint",
        "--endpoint",
        dest="management_endpoint",
        default=os.environ.get("LOGTO_MANAGEMENT_ENDPOINT") or os.environ.get("LOGTO_ENDPOINT", "http://localhost:3011"),
        help="Logto transport endpoint used by this command (the legacy --endpoint alias is accepted).",
    )
    parser.add_argument(
        "--issuer",
        help="Canonical browser-visible OIDC issuer; defaults to LOGTO_ISSUER or LOGTO_PUBLIC_ENDPOINT/oidc.",
    )
    parser.add_argument("--manifest", type=Path, default=HERE / "manifest.json")
    parser.add_argument("--customizer", type=Path, default=HERE / "custom-access-token.js")
    parser.add_argument("--output", type=Path, help="Optional non-secret bootstrap state JSON destination.")
    parser.add_argument("--dry-run", action="store_true", help="Validate rendered local inputs without calling Logto.")
    parser.add_argument(
        "--no-local-management-seed",
        action="store_true",
        help="Require an access token or M2M credentials instead of automatically seeding local Logto OSS.",
    )
    parser.add_argument(
        "--retain-bootstrap-client",
        action="store_true",
        help="Retain the local ephemeral Management API client (diagnostics only; not recommended).",
    )
    parser.add_argument("--compose-file", type=Path, default=HERE.parent / "compose" / "docker-compose.yml")
    parser.add_argument("--compose-env-file", type=Path, default=None)
    parser.add_argument("--compose-project", default=os.environ.get("LOGTO_COMPOSE_PROJECT", ""))
    args = parser.parse_args()
    try:
        endpoint = _management_endpoint(args.management_endpoint)
        issuer = _issuer(args.issuer or _default_issuer(endpoint, os.environ))
        source_manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        manifest = render_manifest(source_manifest)
        customizer = args.customizer.read_text(encoding="utf-8")
        validate_manifest(manifest)
        if "getCustomJwtClaims" not in customizer:
            raise BootstrapError("custom access-token script has the wrong export")
        if args.dry_run:
            print(json.dumps({
                "status": "valid",
                "manifest": str(args.manifest),
                "issuer": issuer,
            }, separators=(",", ":")))
            return 0

        access_token = os.environ.get("LOGTO_MANAGEMENT_ACCESS_TOKEN", "").strip()
        client_id = os.environ.get("LOGTO_MANAGEMENT_CLIENT_ID", "").strip()
        client_secret = os.environ.get("LOGTO_MANAGEMENT_CLIENT_SECRET", "").strip()
        seeded = False
        seeder: LocalManagementSeeder | None = None
        if not access_token and bool(client_id) != bool(client_secret):
            raise BootstrapError(
                "LOGTO_MANAGEMENT_CLIENT_ID and LOGTO_MANAGEMENT_CLIENT_SECRET must be supplied together"
            )
        ephemeral_secret = ""
        try:
            if not access_token and client_id:
                access_token = management_token(endpoint, client_id, client_secret)
            elif not access_token:
                if args.no_local_management_seed:
                    raise BootstrapError(
                        "LOGTO_MANAGEMENT_ACCESS_TOKEN or Management API M2M credentials are required"
                    )
                compose_env_file = args.compose_env_file
                if compose_env_file is None:
                    # The generated local environment (untracked; .env.example
                    # is the committed template) supplies vendor passwords for
                    # the `docker compose exec` psql seed. A symlink or absent
                    # file falls back to Compose's own .env auto-load.
                    candidate = args.compose_file.parent / ".env"
                    compose_env_file = candidate if candidate.is_file() and not candidate.is_symlink() else None
                seeder = LocalManagementSeeder(
                    compose_file=args.compose_file,
                    compose_env_file=compose_env_file,
                    project_name=args.compose_project,
                    database_user=os.environ.get("LOGTO_POSTGRES_USER", "logto"),
                    database_name=os.environ.get("LOGTO_POSTGRES_DB", "logto"),
                    service_name=os.environ.get("LOGTO_POSTGRES_SERVICE", "logto-postgres"),
                )
                ephemeral_secret = secrets.token_urlsafe(32)
                seeder.seed(ephemeral_secret)
                seeded = True
                access_token = management_token(endpoint, BOOTSTRAP_CLIENT_ID, ephemeral_secret)
            result = reconcile(LogtoClient(endpoint, access_token), manifest, customizer, issuer=issuer)
        finally:
            ephemeral_secret = ""
            if seeded and seeder and not args.retain_bootstrap_client:
                seeder.remove()

        if args.output:
            _private_json(args.output, result)
        print(json.dumps(result, indent=2, sort_keys=True) + "\n", end="")
        return 0
    except (BootstrapError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
