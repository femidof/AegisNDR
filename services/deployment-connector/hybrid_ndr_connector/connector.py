from __future__ import annotations

import base64
import json
import os
import random
import re
import sqlite3
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hybrid_ndr_transport import JSONHTTPClient, OutboundHTTPError


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _utc_now()).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _verify_update_signature(public_key_pem: str, payload: bytes, signature: str) -> bool:
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            return False
        padding = "=" * (-len(signature) % 4)
        key.verify(base64.urlsafe_b64decode(signature + padding), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, TypeError, InvalidSignature, UnicodeEncodeError):
        return False


def _boolean(env: Mapping[str, str], name: str, default: str = "false") -> bool:
    value = env.get(name, default).strip().lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be exactly 'true' or 'false'")
    return value == "true"


def _regular(path: Path, *, maximum: int = 1_000_000) -> Path:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"required private file is invalid: {path}")
    return path


def _private_file(path: Path, *, maximum: int = 1_000_000) -> Path:
    _regular(path, maximum=maximum)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"private file permissions are too broad: {path}")
    return path


@dataclass(frozen=True)
class ConnectorSettings:
    control_plane_url: str
    identity_dir: Path
    state_database: Path
    software_version: str
    update_manifest_file: Path | None = None
    ca_file: str = ""
    allow_insecure_loopback: bool = False
    heartbeat_seconds: int = 60
    usage_seconds: int = 300
    configuration_seconds: int = 300
    update_seconds: int = 3600
    certificate_check_seconds: int = 21600
    certificate_rotate_before_days: int = 30
    retry_initial_seconds: int = 5
    retry_max_seconds: int = 900
    request_timeout_seconds: float = 15.0
    # Mutable identity material (rotated certificate, fingerprint, enrollment
    # metadata) is written here, so the installer-provisioned identity
    # directory can be mounted read-only. Defaults to identity_dir for
    # development/standalone compatibility.
    identity_write_dir: Path | None = None

    @property
    def mutable_identity_dir(self) -> Path:
        return self.identity_write_dir or self.identity_dir

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "ConnectorSettings":
        env = os.environ if environ is None else environ
        state_dir = Path(env.get("HYBRID_NDR_STATE_DIR", "/var/lib/hybrid-ndr"))
        settings = cls(
            control_plane_url=env.get("CONTROL_PLANE_URL", "").strip(),
            identity_dir=Path(env.get("CONNECTOR_IDENTITY_DIR", str(state_dir / "identity"))),
            state_database=Path(env.get("CONNECTOR_STATE_DATABASE", str(state_dir / "connector" / "state.sqlite3"))),
            software_version=env.get("HYBRID_NDR_RELEASE_VERSION", "0.1.0").strip(),
            update_manifest_file=Path(env["CONNECTOR_UPDATE_MANIFEST_FILE"]) if env.get("CONNECTOR_UPDATE_MANIFEST_FILE", "").strip() else None,
            ca_file=env.get("CONTROL_PLANE_CA_FILE", "").strip(),
            allow_insecure_loopback=_boolean(env, "CONTROL_PLANE_ALLOW_INSECURE_LOOPBACK"),
            heartbeat_seconds=int(env.get("CONNECTOR_HEARTBEAT_SECONDS", "60")),
            usage_seconds=int(env.get("CONNECTOR_USAGE_SECONDS", "300")),
            configuration_seconds=int(env.get("CONNECTOR_CONFIGURATION_SECONDS", "300")),
            update_seconds=int(env.get("CONNECTOR_UPDATE_SECONDS", "3600")),
            certificate_check_seconds=int(env.get("CONNECTOR_CERTIFICATE_CHECK_SECONDS", "21600")),
            certificate_rotate_before_days=int(env.get("CONNECTOR_CERTIFICATE_ROTATE_BEFORE_DAYS", "30")),
            retry_initial_seconds=int(env.get("CONNECTOR_RETRY_INITIAL_SECONDS", "5")),
            retry_max_seconds=int(env.get("CONNECTOR_RETRY_MAX_SECONDS", "900")),
            request_timeout_seconds=float(env.get("CONNECTOR_REQUEST_TIMEOUT_SECONDS", "15")),
            identity_write_dir=Path(env["CONNECTOR_IDENTITY_WRITE_DIR"].strip())
            if env.get("CONNECTOR_IDENTITY_WRITE_DIR", "").strip() else None,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.control_plane_url:
            raise ValueError("CONTROL_PLANE_URL is required")
        if not self.software_version or len(self.software_version) > 128:
            raise ValueError("HYBRID_NDR_RELEASE_VERSION is invalid")
        values = (
            self.heartbeat_seconds,
            self.usage_seconds,
            self.configuration_seconds,
            self.update_seconds,
            self.certificate_check_seconds,
        )
        if any(value < 1 or value > 604800 for value in values):
            raise ValueError("connector intervals must be between 1 second and 7 days")
        if not 1 <= self.certificate_rotate_before_days <= 180:
            raise ValueError("certificate rotation window must be between 1 and 180 days")
        if self.retry_initial_seconds < 1 or self.retry_max_seconds < self.retry_initial_seconds:
            raise ValueError("connector retry bounds are invalid")


class Metrics(Protocol):
    def heartbeat(self) -> Mapping[str, Any]: ...
    def usage(self) -> Mapping[str, int | float]: ...


class SystemMetrics:
    """Collects only allowlisted aggregates from an optional local metrics file."""

    HEARTBEAT = {"sensor_health", "event_count", "storage_percent", "update_status", "error_codes"}
    USAGE = {"events_processed", "bytes_processed", "protected_assets", "storage_percent", "model_requests", "input_tokens", "output_tokens"}

    def __init__(self, path: str | Path = "") -> None:
        self.path = Path(path) if path else None

    def _read(self) -> dict[str, Any]:
        if self.path is None or not self.path.exists():
            return {}
        raw = _regular(self.path, maximum=64_000).read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("local connector metrics must be an object")
        return value

    def heartbeat(self) -> Mapping[str, Any]:
        source = self._read().get("heartbeat", {})
        selected = {key: value for key, value in source.items() if key in self.HEARTBEAT} if isinstance(source, dict) else {}
        try:
            filesystem = self.path.parent if self.path is not None else Path("/var/lib/hybrid-ndr")
            usage = os.statvfs(filesystem)
            selected.setdefault("storage_percent", round((1 - usage.f_bavail / max(1, usage.f_blocks)) * 100, 2))
        except OSError:
            selected.setdefault("storage_percent", 0)
        selected.setdefault("sensor_health", {})
        selected.setdefault("event_count", 0)
        selected.setdefault("update_status", "idle")
        selected.setdefault("error_codes", [])
        return selected

    def usage(self) -> Mapping[str, int | float]:
        source = self._read().get("usage", {})
        if not isinstance(source, dict):
            source = {}
        selected = {
            key: value for key, value in source.items()
            if key in self.USAGE and isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0
        }
        for key in self.USAGE:
            selected.setdefault(key, 0)
        return selected


class ConnectorState:
    """Private SQLite state preserving schedules and idempotency across restarts."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self.connection = sqlite3.connect(self.path)
        os.chmod(self.path, 0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS operations (
              name TEXT PRIMARY KEY, due_at REAL NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
              idempotency_key TEXT, last_success_at TEXT, last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS documents (
              name TEXT PRIMARY KEY, body_json TEXT NOT NULL, received_at TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def operation(self, name: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM operations WHERE name = ?", (name,)).fetchone()
        if row is None:
            self.connection.execute("INSERT INTO operations(name) VALUES (?)", (name,))
            self.connection.commit()
            return {"name": name, "due_at": 0.0, "failures": 0, "idempotency_key": None, "last_success_at": None, "last_error": None}
        return dict(row)

    def idempotency_key(self, name: str) -> str:
        operation = self.operation(name)
        if operation["idempotency_key"]:
            return str(operation["idempotency_key"])
        key = f"connector-{name}-{uuid.uuid4()}"
        self.connection.execute("UPDATE operations SET idempotency_key = ? WHERE name = ?", (key, name))
        self.connection.commit()
        return key

    def succeeded(self, name: str, *, now_monotonic: float, interval: int) -> None:
        self.operation(name)
        self.connection.execute(
            "UPDATE operations SET due_at = ?, failures = 0, idempotency_key = NULL, last_success_at = ?, last_error = NULL WHERE name = ?",
            (now_monotonic + interval, _timestamp(), name),
        )
        self.connection.commit()

    def failed(self, name: str, *, now_monotonic: float, delay: float, code: str) -> None:
        operation = self.operation(name)
        self.connection.execute(
            "UPDATE operations SET due_at = ?, failures = ?, last_error = ? WHERE name = ?",
            (now_monotonic + delay, int(operation["failures"]) + 1, code[:128], name),
        )
        self.connection.commit()

    def save_document(self, name: str, body: Mapping[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO documents(name, body_json, received_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET body_json=excluded.body_json, received_at=excluded.received_at",
            (name, json.dumps(dict(body), sort_keys=True, separators=(",", ":")), _timestamp()),
        )
        self.connection.commit()

    def document(self, name: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT body_json FROM documents WHERE name = ?", (name,)).fetchone()
        return json.loads(row["body_json"]) if row else None


class Connector:
    INTERVAL_NAMES = {
        "heartbeat": "heartbeat_seconds", "usage": "usage_seconds", "entitlements": "configuration_seconds",
        "model_policy": "configuration_seconds", "update_manifest": "update_seconds", "certificate": "certificate_check_seconds",
    }

    def __init__(
        self,
        settings: ConnectorSettings,
        *,
        state: ConnectorState | None = None,
        metrics: Metrics | None = None,
        client_factory: Callable[[], JSONHTTPClient] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        random_source: random.Random | None = None,
    ) -> None:
        settings.validate()
        self.settings = settings
        self.state = state or ConnectorState(settings.state_database)
        self.metrics = metrics or SystemMetrics(os.environ.get("CONNECTOR_METRICS_FILE", ""))
        self.monotonic = monotonic
        self.random = random_source or random.Random()
        self.identity = self._identity()
        self.client_factory = client_factory or self._client

    def _mutable_read(self, name: str) -> Path:
        """Path for reading mutable identity material.

        The writable identity directory wins once it holds the file; otherwise
        the legacy identity-directory location is used so upgraded volumes keep
        working. The installer-provisioned key and CSR are never routed here.
        """
        writable = self.settings.mutable_identity_dir / name
        legacy = self.settings.identity_dir / name
        if writable.is_file():
            return writable
        if legacy.is_file():
            return legacy
        return writable

    def _mutable_write(self, name: str) -> Path:
        """Path for writing mutable identity material: always the writable
        directory, so the installer-provisioned identity stays read-only."""
        return self.settings.mutable_identity_dir / name

    def _identity(self) -> dict[str, Any]:
        directory = self.settings.identity_dir
        enrollment = json.loads(_private_file(self._mutable_read("enrollment.json")).read_text(encoding="utf-8"))
        tenant = _private_file(directory / "tenant-id", maximum=1024).read_text().strip()
        deployment = _private_file(directory / "deployment-id", maximum=1024).read_text().strip()
        fingerprint = _private_file(self._mutable_read("certificate-fingerprint"), maximum=1024).read_text().strip().lower()
        if enrollment.get("tenant_id") != tenant or enrollment.get("deployment_id") != deployment:
            raise ValueError("enrollment identity does not match persisted identifiers")
        if len(fingerprint) != 64 or any(character not in "0123456789abcdef" for character in fingerprint):
            raise ValueError("persisted certificate fingerprint is invalid")
        return {**enrollment, "tenant_id": tenant, "deployment_id": deployment, "certificate_fingerprint": fingerprint}

    def _client(self) -> JSONHTTPClient:
        return JSONHTTPClient(
            self.settings.control_plane_url,
            ca_file=self.settings.ca_file,
            certificate_file=str(_private_file(self._mutable_read("deployment-cert.pem"))),
            private_key_file=str(_private_file(self.settings.identity_dir / "deployment-key.pem")),
            allow_insecure_loopback=self.settings.allow_insecure_loopback,
            timeout_seconds=self.settings.request_timeout_seconds,
        )

    def _headers(self, operation: str, *, idempotent: bool = False) -> dict[str, str]:
        headers = {"X-Tenant-ID": self.identity["tenant_id"], "X-Deployment-ID": self.identity["deployment_id"]}
        if self.settings.allow_insecure_loopback:
            headers["X-Client-Certificate-Fingerprint"] = self.identity["certificate_fingerprint"]
        if idempotent:
            headers["Idempotency-Key"] = self.state.idempotency_key(operation)
        return headers

    def run_once(self) -> dict[str, str]:
        outcomes: dict[str, str] = {}
        current = self.monotonic()
        for name, action in (
            ("heartbeat", self._heartbeat), ("usage", self._usage), ("entitlements", self._entitlements),
            ("model_policy", self._model_policy), ("update_manifest", self._update_manifest), ("certificate", self._certificate),
        ):
            operation = self.state.operation(name)
            if float(operation["due_at"]) > current:
                outcomes[name] = "not_due"
                continue
            try:
                action()
                interval = int(getattr(self.settings, self.INTERVAL_NAMES[name]))
                self.state.succeeded(name, now_monotonic=current, interval=interval)
                outcomes[name] = "success"
            except (OutboundHTTPError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                failures = int(operation["failures"])
                ceiling = min(self.settings.retry_max_seconds, self.settings.retry_initial_seconds * (2 ** min(failures, 16)))
                delay = ceiling * self.random.uniform(0.5, 1.0)
                code = getattr(exc, "code", exc.__class__.__name__)
                self.state.failed(name, now_monotonic=current, delay=delay, code=str(code))
                outcomes[name] = "failed"
        return outcomes

    def seconds_until_due(self) -> float:
        current = self.monotonic()
        due = [float(self.state.operation(name)["due_at"]) for name in self.INTERVAL_NAMES]
        return max(0.0, min(due) - current)

    def _heartbeat(self) -> None:
        payload = {"software_version": self.settings.software_version, **dict(self.metrics.heartbeat())}
        self.client_factory().request(
            "POST", f"/v1/deployments/{self.identity['deployment_id']}/heartbeat",
            body=payload, headers=self._headers("heartbeat", idempotent=True),
        )

    def _usage(self) -> None:
        self.client_factory().request(
            "POST", f"/v1/deployments/{self.identity['deployment_id']}/usage",
            body=dict(self.metrics.usage()), headers=self._headers("usage", idempotent=True),
        )

    def _entitlements(self) -> None:
        value = self.client_factory().request(
            "GET", f"/v1/deployments/{self.identity['deployment_id']}/entitlements", headers=self._headers("entitlements")
        )
        if not value or any(not isinstance(key, str) for key in value):
            raise ValueError("invalid entitlements response")
        self.state.save_document("entitlements", value)

    def _model_policy(self) -> None:
        value = self.client_factory().request(
            "GET", f"/v1/deployments/{self.identity['deployment_id']}/model-policy", headers=self._headers("model_policy")
        )
        required = {"policy_id", "level", "provider", "model", "region", "retention_mode", "enabled"}
        if not required <= set(value):
            raise ValueError("invalid model policy response")
        self.state.save_document("model_policy", value)

    def _update_manifest(self) -> None:
        manifest = self.client_factory().request("GET", "/v1/updates/manifest", headers=self._headers("update_manifest"))
        if not isinstance(manifest, dict):
            raise ValueError("update manifest must be an object")
        required = {"channel", "version", "artifact", "published_at", "signature_algorithm", "signature"}
        if not required <= set(manifest):
            raise ValueError("update manifest fields are incomplete")
        signature = str(manifest.get("signature", ""))
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        key = self.identity.get("update_signing_public_key")
        if manifest.get("signature_algorithm") != "ECDSA_P256_SHA256" or not isinstance(key, str):
            raise ValueError("update manifest trust metadata is invalid")
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not _verify_update_signature(key, canonical, signature):
            raise ValueError("update manifest signature is invalid")
        artifact = str(manifest.get("artifact", ""))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:-]{0,511}@sha256:[0-9a-f]{64}", artifact):
            raise ValueError("update artifact is not digest pinned")
        self.state.save_document("update_manifest", manifest)
        if self.settings.update_manifest_file is not None:
            self._atomic_write(
                self.settings.update_manifest_file,
                (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            )

    def _certificate(self) -> None:
        certificate_path = _private_file(self._mutable_read("deployment-cert.pem"))
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        if certificate.not_valid_after_utc > _utc_now() + timedelta(days=self.settings.certificate_rotate_before_days):
            return
        csr = _private_file(self.settings.identity_dir / "deployment.csr.pem", maximum=20_000).read_text(encoding="ascii")
        result = self.client_factory().request(
            "POST", "/v1/certificates/rotate", body={"csr": csr}, headers=self._headers("certificate", idempotent=True)
        )
        self._install_certificate(result)

    def _install_certificate(self, result: Mapping[str, Any]) -> None:
        pem = str(result.get("deployment_certificate", "")).encode("ascii")
        certificate = x509.load_pem_x509_certificate(pem)
        private_key = serialization.load_pem_private_key(
            _private_file(self.settings.identity_dir / "deployment-key.pem").read_bytes(), password=None
        )
        if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
            raise ValueError("rotated certificate does not match the deployment key")
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        if fingerprint != str(result.get("certificate_fingerprint", "")).lower():
            raise ValueError("rotated certificate fingerprint is invalid")
        expires = _parse_time(str(result.get("certificate_expires_at", "")))
        if expires != certificate.not_valid_after_utc or expires <= _utc_now():
            raise ValueError("rotated certificate expiry is invalid")
        self._atomic_write(self._mutable_write("deployment-cert.pem"), pem)
        self._atomic_write(self._mutable_write("certificate-fingerprint"), (fingerprint + "\n").encode("ascii"))
        enrollment_path = self._mutable_write("enrollment.json")
        enrollment = json.loads(_private_file(self._mutable_read("enrollment.json")).read_text(encoding="utf-8"))
        enrollment.update(certificate_fingerprint=fingerprint, certificate_expires_at=_timestamp(expires))
        self._atomic_write(enrollment_path, (json.dumps(enrollment, sort_keys=True, indent=2) + "\n").encode())
        self.identity = self._identity()

    @staticmethod
    def _atomic_write(path: Path, value: bytes) -> None:
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
