from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .pki import CertificateAuthority, CertificateError


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


DEFAULT_ENTITLEMENTS: dict[str, Any] = {
    "subscription_status": "active",
    "edition": "enterprise",
    "local_detection": True,
    "model_investigations": True,
    "ai_monthly_limit": 1000,
    "protected_assets_limit": 10_000,
    "offline_grace_days": 14,
}

DEFAULT_MODEL_POLICY: dict[str, Any] = {
    "policy_id": "policy-disabled",
    "level": "disabled",
    "provider": "none",
    "model": "none",
    "region": "none",
    "retention_mode": "zero",
    "enabled": False,
}

DEFAULT_SUPPORT: dict[str, Any] = {
    "support_tier": "standard",
    "service_level": "business-hours",
    "support_email": "",
    "external_customer_ref": "",
}

PERMITTED_HEALTH_FIELDS = frozenset({
    "software_version", "sensor_health", "event_count", "storage_percent", "update_status", "error_codes"
})
PERMITTED_USAGE_FIELDS = frozenset({
    "events_processed", "bytes_processed", "protected_assets", "storage_percent",
    "model_requests", "input_tokens", "output_tokens",
})
SENSOR_STATES = frozenset({"healthy", "online", "degraded", "offline", "unknown", "disabled"})
UPDATE_CHANNELS = frozenset({"stable", "preview", "extended"})


def _version_key(value: str) -> tuple[int, ...]:
    try:
        core = value.strip().lower().removeprefix("v").split("-", 1)[0]
        numbers = tuple(int(part) for part in core.split("."))
        return numbers if numbers else (0,)
    except (TypeError, ValueError):
        return (0,)


class ControlStore:
    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        certificate_authority: CertificateAuthority | None = None,
        public_endpoints: Mapping[str, str] | None = None,
        identity_configuration: Mapping[str, Any] | None = None,
    ) -> None:
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        # In-memory callers (primarily tests) still exercise genuine X.509.
        # Long-running entrypoints always inject a filesystem-backed CA.
        self.certificate_authority = certificate_authority or CertificateAuthority.create()
        self.public_endpoints = {
            "control_plane": "/v1",
            "model_gateway": "/v1/model/investigate",
            **dict(public_endpoints or {}),
        }
        self.identity_configuration = dict(identity_configuration or {})
        self._migrate()

    def _migrate(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash TEXT PRIMARY KEY,
                enrollment_id TEXT,
                tenant_id TEXT NOT NULL,
                deployment_name TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                entitlements_json TEXT NOT NULL,
                model_policy_json TEXT NOT NULL,
                update_channel TEXT NOT NULL,
                created_at TEXT,
                identity_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS deployments (
                deployment_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                deployment_name TEXT NOT NULL,
                status TEXT NOT NULL,
                installed_version TEXT NOT NULL,
                update_channel TEXT NOT NULL,
                certificate_fingerprint TEXT NOT NULL,
                certificate_expires_at TEXT NOT NULL,
                last_seen TEXT,
                health_json TEXT NOT NULL,
                usage_json TEXT NOT NULL,
                entitlements_json TEXT NOT NULL,
                model_policy_json TEXT NOT NULL,
                support_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS deployments_tenant ON deployments (tenant_id, deployment_id);
            CREATE TABLE IF NOT EXISTS organizations (
                tenant_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                support_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS software_releases (
                channel TEXT NOT NULL,
                version TEXT NOT NULL,
                artifact TEXT NOT NULL,
                published_at TEXT NOT NULL,
                release_notes_url TEXT NOT NULL,
                PRIMARY KEY (channel, version)
            );
            CREATE TABLE IF NOT EXISTS control_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS control_audit_tenant ON control_audit (tenant_id, sequence DESC);
            CREATE TABLE IF NOT EXISTS idempotency_records (
                operation TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (operation, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS gateway_usage (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,
                error_code TEXT,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )
        # Forward-only compatibility for pilot databases created before the
        # human cloud-console schema existed.
        self._ensure_column("enrollment_tokens", "enrollment_id", "TEXT")
        self._ensure_column("enrollment_tokens", "created_at", "TEXT")
        self._ensure_column("enrollment_tokens", "identity_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("deployments", "support_json", "TEXT NOT NULL DEFAULT '{}'")
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS enrollment_tokens_id ON enrollment_tokens (enrollment_id) WHERE enrollment_id IS NOT NULL"
        )
        self.connection.execute(
            """INSERT OR IGNORE INTO software_releases
               (channel, version, artifact, published_at, release_notes_url)
               VALUES ('stable', '0.1.0', ?, '2026-08-05T00:00:00Z', 'https://docs.example.invalid/releases/0.1.0')""",
            ("registry.example/hybrid-ndr@sha256:" + "0" * 64,),
        )
        self.connection.commit()

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        columns = {str(row["name"]) for row in self.connection.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_enrollment_token(
        self,
        tenant_id: str,
        *,
        deployment_name: str = "Primary site",
        token: str | None = None,
        ttl_minutes: int = 15,
        entitlements: Mapping[str, Any] | None = None,
        model_policy: Mapping[str, Any] | None = None,
        update_channel: str = "stable",
        identity: Mapping[str, Any] | None = None,
    ) -> str:
        if update_channel not in UPDATE_CHANNELS:
            raise ControlError("invalid_update_channel", "The requested update channel is not supported.")
        if not isinstance(deployment_name, str) or not 2 <= len(deployment_name.strip()) <= 120:
            raise ControlError("invalid_deployment_metadata", "Deployment name must contain 2-120 characters.")
        token = token or secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat().replace("+00:00", "Z")
        entitlements = dict(entitlements or DEFAULT_ENTITLEMENTS)
        policy = dict(model_policy or DEFAULT_MODEL_POLICY)
        if set(entitlements) - (set(DEFAULT_ENTITLEMENTS) | {"valid_until"}):
            raise ControlError("invalid_entitlements", "Entitlements contain an unsupported field.")
        entitlements = {**DEFAULT_ENTITLEMENTS, **entitlements}
        self._validate_entitlements(entitlements)
        if set(policy) - set(DEFAULT_MODEL_POLICY):
            raise ControlError("invalid_model_policy", "Model policy contains an unsupported field.")
        policy = {**DEFAULT_MODEL_POLICY, **policy}
        self._validate_model_policy(policy)
        enrollment_id = str(uuid.uuid4())
        created_at = now()
        identity = dict(identity or {})
        self.connection.execute(
            """INSERT OR REPLACE INTO enrollment_tokens
               (token_hash, enrollment_id, tenant_id, deployment_name, expires_at, used_at,
                entitlements_json, model_policy_json, update_channel, created_at, identity_json)
               VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)""",
            (
                self.hash_token(token), enrollment_id, tenant_id, deployment_name, expires_at,
                canonical(entitlements), canonical(policy), update_channel, created_at, canonical(identity),
            ),
        )
        self.connection.commit()
        return token

    def create_portal_enrollment(
        self,
        tenant_id: str,
        *,
        deployment_name: str,
        organization_id: str,
        update_channel: str = "stable",
        ttl_minutes: int = 15,
    ) -> dict[str, Any]:
        identity = {
            **self.identity_configuration,
            "organization_id": organization_id,
        }
        self._validate_identity_configuration(identity)
        token = self.create_enrollment_token(
            tenant_id,
            deployment_name=deployment_name,
            update_channel=update_channel,
            ttl_minutes=ttl_minutes,
            identity=identity,
        )
        row = self.connection.execute(
            """SELECT enrollment_id, deployment_name, expires_at, update_channel, created_at
               FROM enrollment_tokens WHERE token_hash = ? AND tenant_id = ?""",
            (self.hash_token(token), tenant_id),
        ).fetchone()
        assert row is not None
        return {
            "enrollment_id": row["enrollment_id"],
            "deployment_name": row["deployment_name"],
            "status": "pending",
            "update_channel": row["update_channel"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            # This is the only response that contains the single-use secret.
            "enrollment_token": token,
        }

    @staticmethod
    def _validate_identity_configuration(identity: Mapping[str, Any]) -> None:
        expected = {"issuer", "jwks_uri", "dashboard_client_id", "organization_id", "dashboard_scopes"}
        if set(identity) != expected:
            raise ControlError("identity_configuration_unavailable", "Enrollment identity configuration is incomplete.")
        for key in expected - {"dashboard_scopes"}:
            if not isinstance(identity.get(key), str) or not identity[key]:
                raise ControlError("identity_configuration_unavailable", "Enrollment identity configuration is incomplete.")
        for key in ("issuer", "jwks_uri"):
            parsed = urlparse(str(identity[key]))
            loopback_development = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if parsed.scheme != "https" and not loopback_development:
                raise ControlError(
                    "identity_configuration_unavailable",
                    "Enrollment identity endpoints require HTTPS outside explicit loopback development.",
                )
        issuer = str(identity["issuer"]).rstrip("/")
        if not issuer.endswith("/oidc") or str(identity["jwks_uri"]).rstrip("/") != issuer + "/jwks":
            raise ControlError(
                "identity_configuration_unavailable",
                "Enrollment identity JWKS must match the configured OIDC issuer.",
            )
        scopes = identity.get("dashboard_scopes")
        if not isinstance(scopes, list) or not scopes or any(not isinstance(value, str) or not value for value in scopes):
            raise ControlError("identity_configuration_unavailable", "Enrollment dashboard scopes are invalid.")
        required_scopes = {
            "openid", "urn:logto:scope:organizations", "urn:logto:scope:organization_roles",
        }
        if not required_scopes <= set(scopes):
            raise ControlError("identity_configuration_unavailable", "Enrollment dashboard scopes are incomplete.")
        if "offline_access" in scopes:
            raise ControlError("identity_configuration_unavailable", "Enrollment bootstrap must not persist offline access scope.")

    def exchange_enrollment(self, token: str, csr: str) -> dict[str, Any]:
        if not csr.startswith("-----BEGIN CERTIFICATE REQUEST-----") or len(csr) > 20_000:
            raise ControlError("invalid_certificate_request", "A PEM certificate signing request is required.")
        token_hash = self.hash_token(token)
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.connection.execute(
                    "SELECT * FROM enrollment_tokens WHERE token_hash = ?", (token_hash,)
                ).fetchone()
                if not row:
                    raise ControlError("invalid_enrollment_token", "The enrollment token is invalid.")
                if row["used_at"]:
                    raise ControlError("enrollment_token_used", "The enrollment token has already been used.")
                if parse_time(row["expires_at"]) <= datetime.now(timezone.utc):
                    raise ControlError("enrollment_token_expired", "The enrollment token has expired.")
                deployment_id = str(uuid.uuid4())
                try:
                    certificate = self.certificate_authority.issue_deployment_certificate(
                        csr,
                        tenant_id=row["tenant_id"],
                        deployment_id=deployment_id,
                    )
                except CertificateError as exc:
                    raise ControlError("invalid_certificate_request", str(exc)) from exc
                certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
                fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
                certificate_expires_at = certificate.not_valid_after_utc.isoformat().replace("+00:00", "Z")
                created = now()
                self.connection.execute(
                    """INSERT INTO deployments (
                           deployment_id, tenant_id, deployment_name, status, installed_version, update_channel,
                           certificate_fingerprint, certificate_expires_at, last_seen, health_json, usage_json,
                           entitlements_json, model_policy_json, created_at
                       ) VALUES (?, ?, ?, 'enrolled', '0.1.0', ?, ?, ?, NULL, '{}', '{}', ?, ?, ?)""",
                    (
                        deployment_id,
                        row["tenant_id"],
                        row["deployment_name"],
                        row["update_channel"],
                        fingerprint,
                        certificate_expires_at,
                        row["entitlements_json"],
                        row["model_policy_json"],
                        created,
                    ),
                )
                self.connection.execute(
                    "UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ?", (created, token_hash)
                )
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise
        result = {
            "tenant_id": row["tenant_id"], "deployment_id": deployment_id,
            "deployment_certificate": certificate_pem,
            "certificate_fingerprint": fingerprint, "certificate_expires_at": certificate_expires_at,
            "entitlements": json.loads(row["entitlements_json"]), "model_policy": json.loads(row["model_policy_json"]),
            "update_channel": row["update_channel"],
            "endpoints": dict(self.public_endpoints),
            "update_signing_public_key": self.certificate_authority.update_signing_public_key_pem(),
        }
        identity = json.loads(row["identity_json"] or "{}")
        if identity:
            self._validate_identity_configuration(identity)
            result["identity"] = identity
        return result

    def get_deployment(self, tenant_id: str, deployment_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM deployments WHERE tenant_id = ? AND deployment_id = ?", (tenant_id, deployment_id)
        ).fetchone()
        if not row:
            raise ControlError("deployment_not_found", "The deployment was not found for this tenant.")
        item = dict(row)
        for column in ("health_json", "usage_json", "entitlements_json", "model_policy_json"):
            item[column.removesuffix("_json")] = json.loads(item.pop(column))
        item["support"] = json.loads(item.pop("support_json", "{}") or "{}")
        return item

    def ensure_organization(self, tenant_id: str, organization_id: str) -> dict[str, Any]:
        with self._lock:
            by_tenant = self.connection.execute(
                "SELECT * FROM organizations WHERE tenant_id = ?", (tenant_id,)
            ).fetchone()
            by_organization = self.connection.execute(
                "SELECT * FROM organizations WHERE organization_id = ?", (organization_id,)
            ).fetchone()
            if by_tenant and by_tenant["organization_id"] != organization_id:
                raise ControlError(
                    "organization_binding_conflict",
                    "The signed tenant is already bound to another identity organization.",
                )
            if by_organization and by_organization["tenant_id"] != tenant_id:
                raise ControlError(
                    "organization_binding_conflict",
                    "The signed identity organization is already bound to another tenant.",
                )
            if not by_tenant:
                created = now()
                self.connection.execute(
                    """INSERT INTO organizations
                       (tenant_id, organization_id, name, support_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        organization_id,
                        "Customer organization",
                        canonical(DEFAULT_SUPPORT),
                        created,
                        created,
                    ),
                )
                self.connection.commit()
        return self.get_organization(tenant_id, organization_id)

    def get_organization(self, tenant_id: str, organization_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM organizations WHERE tenant_id = ? AND organization_id = ?",
            (tenant_id, organization_id),
        ).fetchone()
        if not row:
            raise ControlError("organization_not_found", "The organization was not found.")
        deployment_count = self.connection.execute(
            "SELECT count(*) AS count FROM deployments WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()["count"]
        result = dict(row)
        result["support"] = json.loads(result.pop("support_json"))
        result["deployment_count"] = int(deployment_count)
        return result

    def update_organization(
        self,
        tenant_id: str,
        organization_id: str,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        current = self.get_organization(tenant_id, organization_id)
        allowed = {"name", "support_tier", "service_level", "support_email", "external_customer_ref"}
        if not values or set(values) - allowed:
            raise ControlError("invalid_organization_metadata", "Only approved organization and support metadata may be changed.")
        name = values.get("name", current["name"])
        if not isinstance(name, str) or not 2 <= len(name.strip()) <= 120:
            raise ControlError("invalid_organization_metadata", "Organization name must contain 2-120 characters.")
        support = {**DEFAULT_SUPPORT, **current["support"]}
        for key in allowed - {"name"}:
            if key in values:
                support[key] = values[key]
        self._validate_support(support)
        changed = now()
        self.connection.execute(
            """UPDATE organizations SET name = ?, support_json = ?, updated_at = ?
               WHERE tenant_id = ? AND organization_id = ?""",
            (name.strip(), canonical(support), changed, tenant_id, organization_id),
        )
        self.connection.commit()
        return self.get_organization(tenant_id, organization_id)

    @staticmethod
    def _validate_support(support: Mapping[str, Any]) -> None:
        if set(support) - set(DEFAULT_SUPPORT):
            raise ControlError("invalid_support_metadata", "Support metadata contains an unsupported field.")
        tiers = {"standard", "priority", "premium", "dedicated"}
        service_levels = {"business-hours", "24x5", "24x7"}
        if support.get("support_tier") not in tiers or support.get("service_level") not in service_levels:
            raise ControlError("invalid_support_metadata", "Support tier or service level is invalid.")
        email = support.get("support_email", "")
        reference = support.get("external_customer_ref", "")
        if not isinstance(email, str) or len(email) > 254 or (email and ("@" not in email or any(character.isspace() for character in email))):
            raise ControlError("invalid_support_metadata", "Support email is invalid.")
        if not isinstance(reference, str) or len(reference) > 80 or any(
            not (character.isalnum() or character in "-_.") for character in reference
        ):
            raise ControlError("invalid_support_metadata", "External customer reference is invalid.")

    def list_enrollments(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT enrollment_id, deployment_name, expires_at, used_at, update_channel, created_at
               FROM enrollment_tokens WHERE tenant_id = ? ORDER BY created_at DESC, expires_at DESC""",
            (tenant_id,),
        ).fetchall()
        current = datetime.now(timezone.utc)
        items: list[dict[str, Any]] = []
        for row in rows:
            status = "used" if row["used_at"] else "expired" if parse_time(row["expires_at"]) <= current else "pending"
            items.append({
                "enrollment_id": row["enrollment_id"],
                "deployment_name": row["deployment_name"],
                "status": status,
                "update_channel": row["update_channel"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
            })
        return items

    def list_deployments(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT deployment_id FROM deployments WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()
        return [self.portal_deployment(tenant_id, row["deployment_id"], summary=True) for row in rows]

    def portal_deployment(self, tenant_id: str, deployment_id: str, *, summary: bool = False) -> dict[str, Any]:
        deployment = self.get_deployment(tenant_id, deployment_id)
        release = self.latest_release(deployment["update_channel"])
        health = deployment["health"] if isinstance(deployment["health"], Mapping) else {}
        sensors = [
            {"sensor_id": identifier, "status": state}
            for identifier, state in sorted((health.get("sensor_health") or {}).items())
            if isinstance(identifier, str) and isinstance(state, str)
        ]
        installed = str(deployment["installed_version"])
        available = str(release["version"])
        item: dict[str, Any] = {
            "deployment_id": deployment["deployment_id"],
            "name": deployment["deployment_name"],
            "status": deployment["status"],
            "created_at": deployment["created_at"],
            "last_seen": deployment["last_seen"],
            "software": {
                "installed_version": installed,
                "available_version": available,
                "update_available": _version_key(available) > _version_key(installed),
                "update_channel": deployment["update_channel"],
                "update_status": health.get("update_status", "idle"),
                "published_at": release["published_at"],
                "release_notes_url": release["release_notes_url"],
            },
            "health": {
                "storage_percent": health.get("storage_percent"),
                "event_count": health.get("event_count"),
                "error_codes": list(health.get("error_codes") or []),
            },
            "sensors": sensors,
            "certificate": {
                "expires_at": deployment["certificate_expires_at"],
                "status": "expired" if parse_time(deployment["certificate_expires_at"]) <= datetime.now(timezone.utc) else "valid",
            },
        }
        if not summary:
            item.update({
                "usage": {key: deployment["usage"][key] for key in PERMITTED_USAGE_FIELDS if key in deployment["usage"]},
                "entitlements": {
                    key: deployment["entitlements"][key]
                    for key in (set(DEFAULT_ENTITLEMENTS) | {"valid_until"})
                    if key in deployment["entitlements"]
                },
                "model_policy": {
                    key: deployment["model_policy"][key]
                    for key in DEFAULT_MODEL_POLICY
                    if key in deployment["model_policy"]
                },
                "support": {
                    key: deployment["support"][key]
                    for key in DEFAULT_SUPPORT
                    if key in deployment["support"]
                },
            })
        return item

    def latest_release(self, channel: str) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT * FROM software_releases WHERE channel = ?", (channel,)
        ).fetchall()
        if not rows and channel != "stable":
            rows = self.connection.execute(
                "SELECT * FROM software_releases WHERE channel = 'stable'"
            ).fetchall()
        if not rows:
            raise ControlError("update_release_unavailable", "No software release is available for this update channel.")
        return dict(max(rows, key=lambda row: (_version_key(str(row["version"])), str(row["published_at"]))))

    def set_entitlements(self, tenant_id: str, deployment_id: str, values: Mapping[str, Any]) -> dict[str, Any]:
        deployment = self.get_deployment(tenant_id, deployment_id)
        allowed = set(DEFAULT_ENTITLEMENTS) | {"valid_until"}
        if not values or set(values) - allowed:
            raise ControlError("invalid_entitlements", "Entitlements contain an unsupported field.")
        updated = {**DEFAULT_ENTITLEMENTS, **deployment["entitlements"], **dict(values)}
        self._validate_entitlements(updated)
        self.connection.execute(
            "UPDATE deployments SET entitlements_json = ? WHERE tenant_id = ? AND deployment_id = ?",
            (canonical(updated), tenant_id, deployment_id),
        )
        self.connection.commit()
        return updated

    @staticmethod
    def _validate_entitlements(values: Mapping[str, Any]) -> None:
        if values.get("subscription_status") not in {"active", "grace", "suspended", "expired"}:
            raise ControlError("invalid_entitlements", "Subscription status is invalid.")
        if values.get("edition") not in {"enterprise", "dedicated", "regulated", "sovereign", "managed"}:
            raise ControlError("invalid_entitlements", "Edition is invalid.")
        for key in ("local_detection", "model_investigations"):
            if not isinstance(values.get(key), bool):
                raise ControlError("invalid_entitlements", f"{key} must be boolean.")
        for key, maximum in (("ai_monthly_limit", 100_000_000), ("protected_assets_limit", 100_000_000), ("offline_grace_days", 90)):
            value = values.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
                raise ControlError("invalid_entitlements", f"{key} is outside the permitted range.")
        valid_until = values.get("valid_until")
        if valid_until is not None:
            try:
                parse_time(str(valid_until))
            except (TypeError, ValueError) as exc:
                raise ControlError("invalid_entitlements", "valid_until must be an ISO-8601 timestamp.") from exc

    def set_model_policy(self, tenant_id: str, deployment_id: str, values: Mapping[str, Any]) -> dict[str, Any]:
        deployment = self.get_deployment(tenant_id, deployment_id)
        allowed = set(DEFAULT_MODEL_POLICY)
        if not values or set(values) - allowed:
            raise ControlError("invalid_model_policy", "Model policy contains an unsupported field.")
        updated = {**DEFAULT_MODEL_POLICY, **deployment["model_policy"], **dict(values)}
        self._validate_model_policy(updated)
        self.connection.execute(
            "UPDATE deployments SET model_policy_json = ? WHERE tenant_id = ? AND deployment_id = ?",
            (canonical(updated), tenant_id, deployment_id),
        )
        self.connection.commit()
        return updated

    @staticmethod
    def _validate_model_policy(values: Mapping[str, Any]) -> None:
        if values.get("level") not in {"disabled", "strict", "balanced"}:
            raise ControlError("invalid_model_policy", "Model policy level is invalid.")
        if values.get("retention_mode") != "zero":
            raise ControlError("invalid_model_policy", "Only zero-retention model policy is supported.")
        if not isinstance(values.get("enabled"), bool):
            raise ControlError("invalid_model_policy", "Model policy enabled must be boolean.")
        for key in ("policy_id", "provider", "model", "region"):
            value = values.get(key)
            if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(
                character.isalnum() or character in "-_." for character in value
            ):
                raise ControlError("invalid_model_policy", f"{key} is invalid.")
        if values["enabled"] and (values["provider"] == "none" or values["model"] == "none" or values["region"] == "none"):
            raise ControlError("invalid_model_policy", "Enabled model policy requires an approved provider, model, and region.")

    def set_update_channel(self, tenant_id: str, deployment_id: str, channel: str) -> dict[str, Any]:
        if channel not in UPDATE_CHANNELS:
            raise ControlError("invalid_update_channel", "The requested update channel is not supported.")
        self.get_deployment(tenant_id, deployment_id)
        self.connection.execute(
            "UPDATE deployments SET update_channel = ? WHERE tenant_id = ? AND deployment_id = ?",
            (channel, tenant_id, deployment_id),
        )
        self.connection.commit()
        return self.portal_deployment(tenant_id, deployment_id)["software"]

    def record_control_audit(
        self,
        tenant_id: str,
        organization_id: str,
        actor_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        # Deliberately store action metadata only. Request bodies and customer
        # event/evidence content have no column in the vendor audit table.
        self.connection.execute(
            """INSERT INTO control_audit
               (tenant_id, organization_id, actor_id, action, resource_type, resource_id, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, organization_id, actor_id, action, resource_type, resource_id, now()),
        )
        self.connection.commit()

    def authenticate(self, tenant_id: str, deployment_id: str, fingerprint: str) -> dict[str, Any]:
        deployment = self.get_deployment(tenant_id, deployment_id)
        normalized = fingerprint.strip().lower()
        if (
            len(normalized) != 64
            or any(character not in "0123456789abcdef" for character in normalized)
            or not secrets.compare_digest(normalized, deployment["certificate_fingerprint"])
        ):
            raise ControlError("invalid_deployment_certificate", "Deployment certificate authentication failed.")
        if parse_time(deployment["certificate_expires_at"]) <= datetime.now(timezone.utc):
            raise ControlError("expired_deployment_certificate", "The deployment certificate has expired.")
        return deployment

    def heartbeat(self, tenant_id: str, deployment_id: str, health: Mapping[str, Any]) -> dict[str, Any]:
        if set(health) - PERMITTED_HEALTH_FIELDS:
            raise ControlError("forbidden_health_field", "Heartbeat contains data outside the permitted cloud schema.")
        sanitized = self._validate_health(health)
        seen = now()
        self.connection.execute(
            """UPDATE deployments SET status = 'online', installed_version = ?, last_seen = ?, health_json = ?
               WHERE tenant_id = ? AND deployment_id = ?""",
            (str(sanitized.get("software_version", "unknown")), seen, canonical(sanitized), tenant_id, deployment_id),
        )
        self.connection.commit()
        return {"deployment_id": deployment_id, "status": "online", "received_at": seen}

    @staticmethod
    def _validate_health(health: Mapping[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        version = health.get("software_version")
        if version is not None:
            if not isinstance(version, str) or not 1 <= len(version) <= 64 or not all(
                character.isalnum() or character in ".+-_" for character in version
            ):
                raise ControlError("invalid_health_payload", "Software version is invalid.")
            result["software_version"] = version
        sensors = health.get("sensor_health")
        if sensors is not None:
            if not isinstance(sensors, Mapping) or len(sensors) > 100:
                raise ControlError("invalid_health_payload", "Sensor health must be a bounded status map.")
            normalized_sensors: dict[str, str] = {}
            for identifier, state in sensors.items():
                if not isinstance(identifier, str) or not 1 <= len(identifier) <= 80 or not all(
                    character.isalnum() or character in "-_." for character in identifier
                ):
                    raise ControlError("invalid_health_payload", "Sensor identifiers are invalid.")
                if not isinstance(state, str) or state.lower() not in SENSOR_STATES:
                    raise ControlError("invalid_health_payload", "Sensor health values must be status labels.")
                normalized_sensors[identifier] = state.lower()
            result["sensor_health"] = normalized_sensors
        for name in ("event_count", "storage_percent"):
            value = health.get(name)
            if value is None:
                continue
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise ControlError("invalid_health_payload", f"{name} must be a non-negative number.")
            if name == "storage_percent" and value > 100:
                raise ControlError("invalid_health_payload", "storage_percent cannot exceed 100.")
            result[name] = value
        update_status = health.get("update_status")
        if update_status is not None:
            allowed = {"idle", "available", "scheduled", "downloading", "installing", "complete", "failed", "rolled_back"}
            if not isinstance(update_status, str) or update_status not in allowed:
                raise ControlError("invalid_health_payload", "Update status is invalid.")
            result["update_status"] = update_status
        error_codes = health.get("error_codes")
        if error_codes is not None:
            if not isinstance(error_codes, list) or len(error_codes) > 50:
                raise ControlError("invalid_health_payload", "Error codes must be a bounded list.")
            normalized_codes: list[str] = []
            for value in error_codes:
                if not isinstance(value, str) or not 1 <= len(value) <= 64 or not all(
                    character.isupper() or character.isdigit() or character in "-_" for character in value
                ):
                    raise ControlError("invalid_health_payload", "Only anonymized error codes are permitted.")
                normalized_codes.append(value)
            result["error_codes"] = normalized_codes
        return result

    def record_usage(self, tenant_id: str, deployment_id: str, usage: Mapping[str, Any]) -> dict[str, Any]:
        if set(usage) - PERMITTED_USAGE_FIELDS or any(not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 for value in usage.values()):
            raise ControlError("invalid_usage_payload", "Usage may contain only permitted non-negative numeric aggregates.")
        if "storage_percent" in usage and usage["storage_percent"] > 100:
            raise ControlError("invalid_usage_payload", "storage_percent cannot exceed 100.")
        self.connection.execute(
            "UPDATE deployments SET usage_json = ? WHERE tenant_id = ? AND deployment_id = ?",
            (canonical(dict(usage)), tenant_id, deployment_id),
        )
        self.connection.commit()
        return {"deployment_id": deployment_id, "usage": dict(usage), "received_at": now()}

    def rotate_certificate(self, tenant_id: str, deployment_id: str, csr: str) -> dict[str, Any]:
        if not csr.startswith("-----BEGIN CERTIFICATE REQUEST-----") or len(csr) > 20_000:
            raise ControlError("invalid_certificate_request", "A PEM certificate signing request is required.")
        self.get_deployment(tenant_id, deployment_id)
        try:
            certificate = self.certificate_authority.issue_deployment_certificate(
                csr,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
            )
        except CertificateError as exc:
            raise ControlError("invalid_certificate_request", str(exc)) from exc
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        expires = certificate.not_valid_after_utc.isoformat().replace("+00:00", "Z")
        self.connection.execute(
            """UPDATE deployments SET certificate_fingerprint = ?, certificate_expires_at = ?
               WHERE tenant_id = ? AND deployment_id = ?""",
            (fingerprint, expires, tenant_id, deployment_id),
        )
        self.connection.commit()
        return {
            "deployment_id": deployment_id,
            "deployment_certificate": certificate_pem,
            "certificate_fingerprint": fingerprint,
            "certificate_expires_at": expires,
        }

    def model_entitled(self, deployment: Mapping[str, Any]) -> bool:
        entitlements = deployment.get("entitlements")
        if not isinstance(entitlements, Mapping) or entitlements.get("model_investigations") is not True:
            return False
        if entitlements.get("subscription_status", "active") != "active":
            return False
        valid_until = entitlements.get("valid_until")
        if valid_until is None:
            return True
        try:
            expires = parse_time(str(valid_until))
            grace = int(entitlements.get("offline_grace_days", 0))
        except (TypeError, ValueError):
            return False
        return datetime.now(timezone.utc) <= expires + timedelta(days=max(0, min(grace, 90)))

    def update_manifest(self, deployment: Mapping[str, Any]) -> dict[str, Any]:
        release = self.latest_release(str(deployment["update_channel"]))
        manifest = {
            "channel": deployment["update_channel"],
            "version": release["version"],
            "artifact": release["artifact"],
            "published_at": release["published_at"],
        }
        manifest["signature_algorithm"] = "ECDSA_P256_SHA256"
        manifest["signature"] = self.certificate_authority.sign_update_manifest(
            canonical(manifest).encode("utf-8")
        )
        return manifest

    def get_idempotent(self, operation: str, key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT response_json FROM idempotency_records WHERE operation = ? AND idempotency_key = ?", (operation, key)
        ).fetchone()
        return json.loads(row["response_json"]) if row else None

    def save_idempotent(self, operation: str, key: str, response: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO idempotency_records (operation, idempotency_key, response_json, created_at) VALUES (?, ?, ?, ?)",
            (operation, key, canonical(dict(response)), now()),
        )
        self.connection.commit()

    def save_gateway_usage(self, metadata: Mapping[str, Any]) -> None:
        # Deliberately enumerate metadata columns: prompt/evidence/response cannot be stored here.
        self.connection.execute(
            """INSERT INTO gateway_usage
               (request_id, tenant_id, deployment_id, provider, model, status, error_code,
                input_tokens, output_tokens, latency_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (metadata.get("request_id", "unknown"), metadata.get("tenant_id", "unknown"), metadata.get("deployment_id", "unknown"), metadata.get("provider", "unknown"), metadata.get("model", "unknown"), metadata.get("status", "unknown"), metadata.get("error_code"), int(metadata.get("input_tokens", 0)), int(metadata.get("output_tokens", 0)), int(metadata.get("latency_ms", 0)), metadata.get("timestamp", now())),
        )
        self.connection.commit()

    def reset_demo(self) -> str:
        """Dev/test-only reset. Always mints a fresh random single-use token."""
        self.connection.execute("DELETE FROM enrollment_tokens WHERE tenant_id = 'demo-tenant'")
        self.connection.execute("DELETE FROM deployments WHERE tenant_id = 'demo-tenant'")
        self.connection.execute("DELETE FROM organizations WHERE tenant_id = 'demo-tenant'")
        self.connection.commit()
        self.ensure_organization("demo-tenant", "demo-organization")
        self.update_organization(
            "demo-tenant",
            "demo-organization",
            {
                "name": "Northstar Labs",
                "support_tier": "priority",
                "service_level": "24x7",
                "support_email": "security@northstar.example",
                "external_customer_ref": "CUST-10042",
            },
        )
        return self.create_enrollment_token(
            "demo-tenant",
            deployment_name="Demo edge site",
            model_policy={
                "policy_id": "policy-v1",
                "level": "balanced",
                "provider": "demo-zero-retention",
                "model": "evidence-assessor-v1",
                "region": "us",
                "retention_mode": "zero",
                "enabled": True,
            },
        )

    def close(self) -> None:
        self.connection.close()
