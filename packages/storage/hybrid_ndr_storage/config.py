from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from .adapters import (
    ClickHouseEventAdapter,
    FilesystemEvidenceAdapter,
    MinIOEvidenceAdapter,
    PostgresMetadataAdapter,
    SQLiteAdapter,
)
from .tls import postgres_dsn_with_tls


def _require_url(name: str, value: str, schemes: set[str]) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in schemes or not parsed.hostname:
        raise ValueError(f"{name} must be a valid {', '.join(sorted(schemes))} URL")
    return value


@dataclass(frozen=True)
class PersistenceSettings:
    profile: str = "demo"
    sqlite_path: str = ":memory:"
    evidence_path: str = ".data/evidence"
    postgres_dsn: str = ""
    postgres_schema: str = "local_state"
    clickhouse_url: str = ""
    clickhouse_database: str = "hybrid_ndr"
    clickhouse_user: str = ""
    clickhouse_password: str = ""
    minio_endpoint: str = ""
    minio_bucket: str = "hybrid-ndr-evidence"
    minio_access_key: str = ""
    minio_secret_key: str = ""
    minio_region: str = "us-east-1"
    ca_file: str = ""
    readiness_required: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "PersistenceSettings":
        env = environ if environ is not None else os.environ
        profile = env.get("PERSISTENCE_PROFILE", "demo").strip().lower()
        if profile not in {"demo", "production"}:
            raise ValueError("PERSISTENCE_PROFILE must be 'demo' or 'production'")
        settings = cls(
            profile=profile,
            sqlite_path=env.get("SQLITE_DATABASE", ":memory:").strip(),
            evidence_path=env.get("EVIDENCE_PATH", ".data/evidence").strip(),
            postgres_dsn=env.get("POSTGRES_URL", "").strip(),
            postgres_schema=env.get("POSTGRES_SCHEMA", "local_state").strip(),
            clickhouse_url=env.get("CLICKHOUSE_URL", "").strip(),
            clickhouse_database=env.get("CLICKHOUSE_DATABASE", "hybrid_ndr").strip(),
            clickhouse_user=env.get("CLICKHOUSE_USER", "").strip(),
            clickhouse_password=env.get("CLICKHOUSE_PASSWORD", "").strip(),
            minio_endpoint=env.get("MINIO_ENDPOINT", "").strip(),
            minio_bucket=env.get("MINIO_BUCKET", "hybrid-ndr-evidence").strip(),
            minio_access_key=env.get("MINIO_ACCESS_KEY", env.get("MINIO_ROOT_USER", "")).strip(),
            minio_secret_key=env.get("MINIO_SECRET_KEY", env.get("MINIO_ROOT_PASSWORD", "")).strip(),
            minio_region=env.get("MINIO_REGION", "us-east-1").strip(),
            ca_file=env.get("PERSISTENCE_CA_FILE", "").strip(),
            readiness_required=env.get("PERSISTENCE_READINESS_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"},
        )
        if profile == "production":
            missing = [
                name for name, value in (
                    ("POSTGRES_URL", settings.postgres_dsn),
                    ("CLICKHOUSE_URL", settings.clickhouse_url),
                    ("CLICKHOUSE_USER", settings.clickhouse_user),
                    ("CLICKHOUSE_PASSWORD", settings.clickhouse_password),
                    ("MINIO_ENDPOINT", settings.minio_endpoint),
                    ("MINIO_ACCESS_KEY", settings.minio_access_key),
                    ("MINIO_SECRET_KEY", settings.minio_secret_key),
                ) if not value
            ]
            if missing:
                raise ValueError("production persistence requires " + ", ".join(missing))
            _require_url("POSTGRES_URL", settings.postgres_dsn, {"postgres", "postgresql"})
            _require_url("CLICKHOUSE_URL", settings.clickhouse_url, {"http", "https"})
            _require_url("MINIO_ENDPOINT", settings.minio_endpoint, {"http", "https"})
            if not settings.postgres_schema.replace("_", "").isalnum():
                raise ValueError("POSTGRES_SCHEMA contains invalid characters")
        return settings


class PersistenceAdapters:
    """Selected storage ports and aggregate readiness for deployment health."""

    def __init__(self, settings: PersistenceSettings, metadata: Any, events: Any, evidence: Any) -> None:
        self.settings = settings
        self.metadata = metadata
        self.events = events
        self.evidence = evidence

    @property
    def profile(self) -> str:
        return self.settings.profile

    def readiness(self) -> dict[str, Any]:
        checks = {
            "metadata": self.metadata.readiness(),
            "events": self.events.readiness(),
            "evidence": self.evidence.readiness(),
        }
        ready = all(result.ready for result in checks.values())
        return {
            "profile": self.profile,
            "ready": ready,
            "required": self.settings.readiness_required,
            "adapters": {name: result.to_dict() for name, result in checks.items()},
            "product_io": {
                name: bool(getattr(adapter, "supports_product_io", False))
                for name, adapter in (("metadata", self.metadata), ("events", self.events), ("evidence", self.evidence))
            },
        }


def build_persistence(settings: PersistenceSettings) -> PersistenceAdapters:
    if settings.profile == "demo":
        evidence_path = Path(settings.evidence_path)
        evidence_path.mkdir(parents=True, exist_ok=True)
        return PersistenceAdapters(
            settings,
            SQLiteAdapter(settings.sqlite_path),
            SQLiteAdapter(settings.sqlite_path),
            FilesystemEvidenceAdapter(str(evidence_path)),
        )
    postgres_dsn = settings.postgres_dsn
    if settings.ca_file:
        # A private-LAN CA requires verified TLS on every credential-bearing hop.
        postgres_dsn = postgres_dsn_with_tls(postgres_dsn, settings.ca_file)
    return PersistenceAdapters(
        settings,
        PostgresMetadataAdapter(postgres_dsn, schema=settings.postgres_schema),
        ClickHouseEventAdapter(
            settings.clickhouse_url,
            database=settings.clickhouse_database,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
            ca_file=settings.ca_file,
        ),
        MinIOEvidenceAdapter(
            settings.minio_endpoint,
            bucket=settings.minio_bucket,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            region=settings.minio_region,
            ca_file=settings.ca_file,
        ),
    )


def build_store(settings: PersistenceSettings, persistence: PersistenceAdapters | None = None) -> Any:
    """Build the product store selected by the persistence profile."""
    selected = persistence or build_persistence(settings)
    if settings.profile == "demo":
        from .local import LocalStore

        return LocalStore(settings.sqlite_path)
    from .production import ProductionStore

    return ProductionStore(selected.metadata, selected.events, selected.evidence)
