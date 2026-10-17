from __future__ import annotations

import base64
import binascii
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from hybrid_ndr_audit import AuditIntegrityError, AuditLog


MAX_MANIFEST_BYTES = 1_000_000
MAX_ARCHIVE_ENTRIES = 200_000
MAX_ARCHIVE_BYTES = 40 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
CHANNEL_RE = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
ARTIFACT_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9./_:-]{0,511})@sha256:(?P<digest>[0-9a-f]{64})$")


class UpdateError(RuntimeError):
    """An update failed with a stable, non-secret-bearing reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class UpdateRejected(UpdateError):
    """The requested update was rejected before software activation."""


class UpdateRolledBack(UpdateError):
    """The requested release failed, and the previous healthy release was restored."""


@dataclass(frozen=True)
class VerifiedManifest:
    channel: str
    version: str
    artifact_digest: str
    manifest_digest: str
    body: Mapping[str, Any]


@dataclass(frozen=True)
class StagedRelease:
    version: str
    project_dir: Path
    compose_file: Path
    https_compose_file: Path
    release_compose_file: Path | None
    images_file: Path
    images_digest: str
    manifest_digest: str
    artifact_digest: str


@dataclass(frozen=True)
class ReleaseTarget:
    version: str
    project_dir: Path
    compose_file: Path
    https_compose_file: Path
    release_compose_file: Path | None = None
    images_file: Path | None = None
    images_digest: str | None = None


@dataclass(frozen=True)
class InstallContext:
    config_dir: Path
    state_dir: Path
    project_name: str
    capture_interface: str
    bind_address: str
    lan_host: str
    health_timeout: int


@dataclass(frozen=True)
class InstallResult:
    success: bool
    code: str


class InstallerExecutor(Protocol):
    def install(self, release: ReleaseTarget, context: InstallContext, *, allow_downgrade: bool) -> InstallResult: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _regular_file(path: Path, *, maximum: int | None = None, private: bool = False) -> Path:
    try:
        details = path.lstat()
    except OSError as exc:
        raise UpdateRejected("file_missing", "A required update file is missing.") from exc
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise UpdateRejected("file_type_invalid", "Update inputs must be regular, non-symlink files.")
    if maximum is not None and details.st_size > maximum:
        raise UpdateRejected("file_too_large", "An update input exceeds its safety limit.")
    if private and stat.S_IMODE(details.st_mode) & 0o077:
        raise UpdateRejected("private_file_permissions", "A private update-state file has unsafe permissions.")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_timestamp(value: Any) -> None:
    if not isinstance(value, str) or len(value) > 64:
        raise UpdateRejected("manifest_timestamp_invalid", "The update manifest timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UpdateRejected("manifest_timestamp_invalid", "The update manifest timestamp is invalid.") from exc
    if parsed.tzinfo is None:
        raise UpdateRejected("manifest_timestamp_invalid", "The update manifest timestamp must include a timezone.")


def _reason_code(value: str) -> str:
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) else "installer_failed"


def _version_key(version: str) -> tuple[Any, ...]:
    match = VERSION_RE.fullmatch(version)
    if not match:
        raise UpdateRejected("version_invalid", "The requested release version is not valid SemVer.")
    prerelease = match.group(4)
    # A release sorts after its prereleases. Numeric prerelease identifiers sort
    # numerically and before text identifiers, as required by SemVer.
    if prerelease is None:
        suffix: tuple[Any, ...] = (1,)
    else:
        identifiers: list[tuple[int, Any]] = []
        for item in prerelease.split("."):
            if item.isdigit():
                if len(item) > 1 and item.startswith("0"):
                    raise UpdateRejected("version_invalid", "The requested release version is not valid SemVer.")
                identifiers.append((0, int(item)))
            else:
                identifiers.append((1, item))
        suffix = (0, *identifiers)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), suffix


def _read_key_values(path: Path, required: set[str]) -> dict[str, str]:
    _regular_file(path, maximum=64_000, private=True)
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise UpdateRejected("state_invalid", "Installed release state is malformed.")
        key, value = raw.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", key):
            raise UpdateRejected("state_invalid", "Installed release state contains an invalid key.")
        if len(value) > 4096:
            raise UpdateRejected("state_invalid", "Installed release state value is too long.")
        if key in result:
            raise UpdateRejected("state_invalid", "Installed release state contains a duplicate key.")
        result[key] = value
    if not required <= set(result):
        raise UpdateRejected("state_incomplete", "Installed release state is incomplete.")
    return result


def _confined(path: Path, root: Path, *, label: str) -> Path:
    """Resolve symlinks and require containment under root (enterprise path confinement)."""
    resolved = path.resolve()
    root_resolved = root.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise UpdateRejected("state_invalid", f"The installed {label} escapes its permitted directory.")
    return resolved


def _safe_archive_name(name: str) -> PurePosixPath:
    if "\x00" in name:
        raise UpdateRejected("bundle_path_invalid", "The release bundle contains an unsafe path.")
    candidate = PurePosixPath(name)
    while candidate.parts and candidate.parts[0] == ".":
        candidate = PurePosixPath(*candidate.parts[1:])
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise UpdateRejected("bundle_path_invalid", "The release bundle contains an unsafe path.")
    return candidate


def _archive_digest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    stream = archive.extractfile(member)
    if stream is None:
        raise UpdateRejected("bundle_member_unreadable", "A release-bundle member could not be read.")
    return hashlib.file_digest(stream, "sha256").hexdigest()


def _validate_release_override(raw: bytes, expected: Mapping[str, Any]) -> None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UpdateRejected("release_compose_invalid", "The release image override is invalid.") from exc
    discovered: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        service = re.fullmatch(r"  ([a-z0-9][a-z0-9-]{0,62}):", line)
        if service:
            current = service.group(1)
            continue
        image = re.fullmatch(r"    image: (sha256:[0-9a-f]{64})", line)
        if image and current:
            discovered[current] = image.group(1)
    if not expected or discovered != dict(expected):
        raise UpdateRejected("release_image_pins_invalid", "The release image pins do not match the signed bundle manifest.")


class ReleaseBundle:
    """Validate and extract a digest-authenticated, image-bearing offline bundle."""

    REQUIRED = {
        PurePosixPath("BUNDLE-MANIFEST.json"),
        PurePosixPath("images.tar"),
        PurePosixPath("sbom/source.cdx.json"),
        PurePosixPath("payload/hybrid-ndr/RELEASE_VERSION"),
        PurePosixPath("payload/hybrid-ndr/installer/install.sh"),
        PurePosixPath("payload/hybrid-ndr/installer/post-install-health.sh"),
        PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.yml"),
        PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.https.yml"),
        PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.release.yml"),
    }

    def __init__(self, path: Path, expected_version: str) -> None:
        self.path = path
        self.expected_version = expected_version
        self.members: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        self.by_name: dict[PurePosixPath, tarfile.TarInfo] = {}
        self.manifest: dict[str, Any] = {}

    def validate(self) -> None:
        _regular_file(self.path, maximum=MAX_ARCHIVE_BYTES)
        try:
            with tarfile.open(self.path, "r:gz") as archive:
                expanded = 0
                for member in archive.getmembers():
                    name = _safe_archive_name(member.name)
                    if name in self.by_name:
                        raise UpdateRejected("bundle_duplicate_path", "The release bundle contains duplicate paths.")
                    if not (member.isfile() or member.isdir()):
                        raise UpdateRejected("bundle_special_file", "The release bundle contains a link or special file.")
                    expanded += member.size
                    if expanded > MAX_ARCHIVE_BYTES:
                        raise UpdateRejected("bundle_expansion_limit", "The release bundle expands beyond its safety limit.")
                    self.by_name[name] = member
                    self.members.append((member, name))
                if len(self.members) > MAX_ARCHIVE_ENTRIES:
                    raise UpdateRejected("bundle_entry_limit", "The release bundle has too many entries.")
                if not self.REQUIRED <= set(self.by_name):
                    raise UpdateRejected("bundle_incomplete", "The release bundle is missing a required signed-release component.")
                manifest_stream = archive.extractfile(self.by_name[PurePosixPath("BUNDLE-MANIFEST.json")])
                if manifest_stream is None:
                    raise UpdateRejected("bundle_manifest_unreadable", "The bundle manifest could not be read.")
                try:
                    value = json.load(manifest_stream)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise UpdateRejected("bundle_manifest_invalid", "The bundle manifest is invalid JSON.") from exc
                if not isinstance(value, dict):
                    raise UpdateRejected("bundle_manifest_invalid", "The bundle manifest must be an object.")
                self.manifest = value
                self._validate_manifest(archive)
        except (tarfile.TarError, OSError) as exc:
            raise UpdateRejected("bundle_invalid", "The release artifact is not a valid gzip-compressed tar bundle.") from exc

    def _validate_manifest(self, archive: tarfile.TarFile) -> None:
        if (
            self.manifest.get("schema_version") != 1
            or self.manifest.get("product") != "hybrid-ndr"
            or self.manifest.get("version") != self.expected_version
            or self.manifest.get("payload") != "payload/hybrid-ndr"
            or self.manifest.get("compose_profile") != "customer"
        ):
            raise UpdateRejected("bundle_manifest_mismatch", "The signed release bundle does not describe the requested Hybrid NDR release.")

        images = self.manifest.get("images")
        if not isinstance(images, dict) or images.get("included") is not True:
            raise UpdateRejected("bundle_images_required", "Customer updates require an image-bearing offline bundle.")
        image_digest = images.get("sha256")
        image_services = images.get("services")
        if (
            images.get("path") != "images.tar"
            or not isinstance(image_digest, str)
            or not SHA256_RE.fullmatch(image_digest)
            or not isinstance(image_services, dict)
            or any(
                not isinstance(service, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", service)
                or not isinstance(reference, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", reference)
                for service, reference in image_services.items()
            )
        ):
            raise UpdateRejected("bundle_image_metadata_invalid", "The signed release image metadata is invalid.")
        if _archive_digest(archive, self.by_name[PurePosixPath("images.tar")]) != image_digest:
            raise UpdateRejected("bundle_images_tampered", "The bundled image archive does not match its signed digest.")

        sbom = self.manifest.get("sbom")
        if not isinstance(sbom, dict):
            raise UpdateRejected("bundle_sbom_missing", "The release bundle has no signed SBOM metadata.")
        sbom_path, sbom_digest = sbom.get("path"), sbom.get("sha256")
        if sbom_path != "sbom/source.cdx.json" or not isinstance(sbom_digest, str) or not SHA256_RE.fullmatch(sbom_digest):
            raise UpdateRejected("bundle_sbom_invalid", "The release SBOM metadata is invalid.")
        if _archive_digest(archive, self.by_name[PurePosixPath(sbom_path)]) != sbom_digest:
            raise UpdateRejected("bundle_sbom_tampered", "The release SBOM does not match its signed digest.")
        sbom_stream = archive.extractfile(self.by_name[PurePosixPath(sbom_path)])
        try:
            sbom_body = json.load(sbom_stream) if sbom_stream is not None else None
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateRejected("bundle_sbom_invalid", "The release SBOM is invalid JSON.") from exc
        if not isinstance(sbom_body, dict) or sbom_body.get("bomFormat") != "CycloneDX":
            raise UpdateRejected("bundle_sbom_invalid", "The release SBOM is not CycloneDX JSON.")

        override = archive.extractfile(self.by_name[PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.release.yml")])
        if override is None:
            raise UpdateRejected("release_compose_invalid", "The release image override could not be read.")
        _validate_release_override(override.read(), image_services)

        version_stream = archive.extractfile(self.by_name[PurePosixPath("payload/hybrid-ndr/RELEASE_VERSION")])
        if version_stream is None or version_stream.read().decode("ascii", "strict").strip() != self.expected_version:
            raise UpdateRejected("bundle_version_mismatch", "The staged payload version does not match the signed manifest.")

    def extract(self, destination: Path) -> None:
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        root = destination.resolve()
        try:
            with tarfile.open(self.path, "r:gz") as archive:
                for member, name in self.members:
                    target = destination.joinpath(*name.parts)
                    resolved = target.resolve()
                    if resolved != root and root not in resolved.parents:
                        raise UpdateRejected("bundle_path_invalid", "The release bundle escaped the staging directory.")
                    if member.isdir():
                        target.mkdir(mode=member.mode & 0o755, parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise UpdateRejected("bundle_member_unreadable", "A release-bundle member could not be read.")
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode & 0o755 or 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        shutil.copyfileobj(source, output)
        except BaseException:
            shutil.rmtree(destination, ignore_errors=True)
            raise


class UpdateAudit:
    def __init__(self, state_dir: Path, identity_dir: Path) -> None:
        updates = state_dir / "updates"
        updates.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(updates, 0o700)
        self.database = updates / "audit.sqlite3"
        self.tenant_id = _regular_file(identity_dir / "tenant-id", maximum=1024, private=True).read_text().strip()
        self.deployment_id = _regular_file(identity_dir / "deployment-id", maximum=1024, private=True).read_text().strip()
        if not IDENTIFIER_RE.fullmatch(self.tenant_id) or not IDENTIFIER_RE.fullmatch(self.deployment_id):
            raise UpdateRejected("identity_invalid", "The local deployment identity is invalid.")
        self.log = AuditLog(str(self.database))
        self._secure_files()

    def _secure_files(self) -> None:
        for path in (self.database, Path(f"{self.database}-wal"), Path(f"{self.database}-shm")):
            if not path.exists():
                continue
            os.chmod(path, 0o600)
            if os.geteuid() == 0:
                os.chown(path, 65532, 65532)

    def verify(self) -> None:
        try:
            self.log.verify(self.tenant_id, self.deployment_id)
        except AuditIntegrityError as exc:
            raise UpdateRejected("audit_integrity_failed", "The software-update audit chain failed integrity validation.") from exc

    def append(
        self,
        *,
        action: str,
        actor_id: str,
        target_version: str,
        result: str,
        request_id: str,
        metadata: Mapping[str, Any],
    ) -> None:
        allowed = {
            "from_version",
            "to_version",
            "manifest_sha256",
            "artifact_sha256",
            "reason_code",
            "automatic",
            "downgrade_approved",
        }
        if set(metadata) - allowed:
            raise ValueError("software update audit metadata is not allowlisted")
        self.log.append(
            tenant_id=self.tenant_id,
            deployment_id=self.deployment_id,
            actor_id=actor_id,
            actor_type="human" if actor_id != "update-agent" else "service",
            action=action,
            resource_type="software_release",
            resource_id=target_version if VERSION_RE.fullmatch(target_version) else "unknown",
            request_id=request_id,
            result=result,
            metadata=metadata,
        )
        self._secure_files()

    def close(self) -> None:
        self.log.close()


class SubprocessInstallerExecutor:
    """Invoke the signed release installer without forwarding ambient secrets."""

    SAFE_ENVIRONMENT = ("PATH", "LANG", "LC_ALL", "TZ", "HOME", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")

    def install(self, release: ReleaseTarget, context: InstallContext, *, allow_downgrade: bool) -> InstallResult:
        installer = _regular_file(release.project_dir / "installer/install.sh", maximum=2_000_000)
        arguments = [
            str(installer),
            "--project-dir",
            str(release.project_dir),
            "--compose-file",
            str(release.compose_file),
            "--https-compose-file",
            str(release.https_compose_file),
            "--config-dir",
            str(context.config_dir),
            "--state-dir",
            str(context.state_dir),
            "--interface",
            context.capture_interface,
            "--bind-address",
            context.bind_address,
            "--lan-host",
            context.lan_host,
            "--release-version",
            release.version,
            "--health-timeout",
            str(context.health_timeout),
            "--non-interactive",
        ]
        if release.release_compose_file is not None:
            arguments.extend(("--release-compose-file", str(release.release_compose_file)))
        if release.images_file is not None and release.images_digest is not None:
            arguments.extend(("--offline-images", str(release.images_file), "--offline-images-sha256", release.images_digest))
        if context.capture_interface == "lo":
            arguments.append("--allow-loopback")
        if allow_downgrade:
            arguments.append("--allow-downgrade")
        environment = {name: os.environ[name] for name in self.SAFE_ENVIRONMENT if name in os.environ}
        environment.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        completed = subprocess.run(arguments, env=environment, check=False)
        return InstallResult(completed.returncode == 0, "healthy" if completed.returncode == 0 else "installer_failed")


class UpdateAgent:
    def __init__(
        self,
        *,
        state_dir: str | Path,
        config_dir: str | Path,
        public_key: str | Path | None = None,
        executor: InstallerExecutor | None = None,
    ) -> None:
        self.state_dir = Path(state_dir).resolve()
        self.config_dir = Path(config_dir).resolve()
        self.identity_dir = self.state_dir / "identity"
        self.public_key = Path(public_key).resolve() if public_key else self.identity_dir / "update-signing-public.pem"
        self.executor = executor or SubprocessInstallerExecutor()
        self.updates_dir = self.state_dir / "updates"
        self.updates_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.updates_dir, 0o700)
        self.audit = UpdateAudit(self.state_dir, self.identity_dir)

    @contextlib.contextmanager
    def _lock(self):
        lock_path = self.updates_dir / "agent.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateRejected("update_in_progress", "Another software update is already active.") from exc
            yield
        finally:
            os.close(descriptor)

    def close(self) -> None:
        self.audit.close()

    def verify_audit(self) -> None:
        self.audit.verify()

    def _verify_key_pin(self) -> None:
        _regular_file(self.public_key, maximum=32_000)
        inspected = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(self.public_key), "-text", "-noout"],
            check=False,
            capture_output=True,
            text=True,
        )
        key_text = inspected.stdout + inspected.stderr
        if inspected.returncode != 0 or ("prime256v1" not in key_text and "P-256" not in key_text):
            raise UpdateRejected("update_key_invalid", "The trusted update key is not an ECDSA P-256 public key.")
        exported = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(self.public_key), "-outform", "DER"],
            check=False,
            capture_output=True,
        )
        if exported.returncode != 0:
            raise UpdateRejected("update_key_invalid", "The trusted update key could not be normalized.")
        key_digest = hashlib.sha256(exported.stdout).hexdigest()
        pin_path = self.config_dir / "update-signing-key.sha256"
        expected = _regular_file(pin_path, maximum=128, private=True).read_text(encoding="ascii").strip().lower()
        if not SHA256_RE.fullmatch(expected) or expected != key_digest:
            raise UpdateRejected("update_key_pin_mismatch", "The trusted update key does not match the customer installation pin.")

    def verify_manifest(self, manifest_path: str | Path) -> VerifiedManifest:
        path = _regular_file(Path(manifest_path).resolve(), maximum=MAX_MANIFEST_BYTES)
        try:
            body = json.loads(path.read_bytes())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateRejected("manifest_json_invalid", "The update manifest is invalid JSON.") from exc
        if not isinstance(body, dict):
            raise UpdateRejected("manifest_invalid", "The update manifest must be an object.")
        required = {"channel", "version", "artifact", "published_at", "signature_algorithm", "signature"}
        allowed = required | {"schema_version", "product", "release_notes_url", "minimum_version"}
        if not required <= set(body) or set(body) - allowed:
            raise UpdateRejected("manifest_fields_invalid", "The update manifest fields are invalid.")
        if body.get("schema_version", 1) != 1 or body.get("product", "hybrid-ndr") != "hybrid-ndr":
            raise UpdateRejected("manifest_schema_invalid", "The update manifest schema or product is unsupported.")
        channel, version, artifact = body.get("channel"), body.get("version"), body.get("artifact")
        if not isinstance(channel, str) or not CHANNEL_RE.fullmatch(channel):
            raise UpdateRejected("manifest_channel_invalid", "The update channel is invalid.")
        if not isinstance(version, str):
            raise UpdateRejected("version_invalid", "The requested release version is invalid.")
        _version_key(version)
        if not isinstance(artifact, str) or not (artifact_match := ARTIFACT_RE.fullmatch(artifact)):
            raise UpdateRejected("artifact_not_digest_pinned", "The update artifact is not pinned to a SHA-256 digest.")
        _parse_timestamp(body.get("published_at"))
        if body.get("signature_algorithm") != "ECDSA_P256_SHA256":
            raise UpdateRejected("signature_algorithm_invalid", "The update manifest signature algorithm is not approved.")
        signature = body.get("signature")
        if not isinstance(signature, str) or not signature or len(signature) > 1024:
            raise UpdateRejected("signature_invalid", "The update manifest signature is malformed.")

        self._verify_key_pin()
        unsigned = {key: value for key, value in body.items() if key != "signature"}
        canonical = _canonical(unsigned)
        try:
            padding = "=" * (-len(signature) % 4)
            decoded = base64.b64decode(signature + padding, altchars=b"-_", validate=True)
        except (ValueError, binascii.Error) as exc:
            raise UpdateRejected("signature_invalid", "The update manifest signature is malformed.") from exc
        with tempfile.TemporaryDirectory(prefix=".signature-", dir=self.updates_dir) as temporary_name:
            temporary = Path(temporary_name)
            payload_path, signature_path = temporary / "manifest", temporary / "signature"
            payload_path.write_bytes(canonical)
            signature_path.write_bytes(decoded)
            os.chmod(payload_path, 0o600)
            os.chmod(signature_path, 0o600)
            verified = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(self.public_key),
                    "-signature",
                    str(signature_path),
                    str(payload_path),
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if verified.returncode != 0:
            raise UpdateRejected("signature_verification_failed", "The update manifest signature is invalid.")
        return VerifiedManifest(
            channel=channel,
            version=version,
            artifact_digest=artifact_match.group("digest"),
            manifest_digest=hashlib.sha256(_canonical(body)).hexdigest(),
            body=body,
        )

    def stage(self, manifest: VerifiedManifest, artifact_path: str | Path) -> StagedRelease:
        artifact = _regular_file(Path(artifact_path).resolve(), maximum=MAX_ARCHIVE_BYTES)
        actual_digest = _sha256(artifact)
        if actual_digest != manifest.artifact_digest:
            raise UpdateRejected("artifact_digest_mismatch", "The release artifact does not match the signed manifest digest.")
        bundle = ReleaseBundle(artifact, manifest.version)
        bundle.validate()
        releases = self.updates_dir / "releases"
        releases.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = releases / f".staging-{uuid.uuid4()}"
        bundle.extract(temporary)
        destination = releases / f"{manifest.version}-{manifest.manifest_digest[:16]}-{uuid.uuid4().hex[:8]}"
        os.replace(temporary, destination)
        project = destination / "payload/hybrid-ndr"
        marker = {
            "version": manifest.version,
            "manifest_sha256": manifest.manifest_digest,
            "artifact_sha256": manifest.artifact_digest,
        }
        marker_path = destination / ".verified-release.json"
        marker_path.write_bytes(_canonical(marker) + b"\n")
        os.chmod(marker_path, 0o600)
        images = bundle.manifest["images"]
        return StagedRelease(
            version=manifest.version,
            project_dir=project,
            compose_file=project / "infra/compose/docker-compose.yml",
            https_compose_file=project / "infra/compose/docker-compose.https.yml",
            release_compose_file=project / "infra/compose/docker-compose.release.yml",
            images_file=destination / "images.tar",
            images_digest=images["sha256"],
            manifest_digest=manifest.manifest_digest,
            artifact_digest=manifest.artifact_digest,
        )

    def _installed(self, health_timeout: int) -> tuple[ReleaseTarget, InstallContext]:
        if not 10 <= health_timeout <= 3600:
            raise UpdateRejected("health_timeout_invalid", "The health deadline must be between 10 and 3600 seconds.")
        state = _read_key_values(
            self.config_dir / "install-state",
            {"VERSION", "PROJECT_DIR", "COMPOSE_FILE", "HTTPS_COMPOSE_FILE", "COMPOSE_PROJECT"},
        )
        _version_key(state["VERSION"])
        environment = _read_key_values(
            self.config_dir / "customer.env",
            {"CAPTURE_INTERFACE", "CUSTOMER_BIND_ADDRESS", "CUSTOMER_LAN_HOST"},
        )
        capture = environment["CAPTURE_INTERFACE"]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", capture):
            raise UpdateRejected("state_invalid", "The installed capture interface is invalid.")
        bind_address = environment["CUSTOMER_BIND_ADDRESS"]
        lan_host = environment["CUSTOMER_LAN_HOST"]
        try:
            import ipaddress as _ipaddress

            _ipaddress.IPv4Address(bind_address)
        except ValueError as exc:
            raise UpdateRejected("state_invalid", "The installed bind address is invalid.") from exc
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", lan_host):
            raise UpdateRejected("state_invalid", "The installed LAN host is invalid.")
        project_raw = Path(state["PROJECT_DIR"])
        if not project_raw.is_absolute():
            raise UpdateRejected("state_invalid", "The installed project directory must be absolute.")
        project = project_raw.resolve()
        # Enterprise: compose files must live inside the release's infra/compose
        # directory so a crafted install-state cannot redirect execution to an
        # arbitrary install.sh.
        compose_root = project / "infra" / "compose"
        compose_file = _confined(Path(state["COMPOSE_FILE"]), compose_root, label="compose file")
        https_compose_file = _confined(Path(state["HTTPS_COMPOSE_FILE"]), compose_root, label="HTTPS compose file")
        release_compose_value = state.get("RELEASE_COMPOSE_FILE", "")
        release_compose = _confined(Path(release_compose_value), compose_root, label="release compose file") if release_compose_value else None
        # Image-level rollback needs the exact offline archive the installed
        # release was loaded from. install.sh persists the digest-pinned path;
        # re-verify it before any rollback can depend on it.
        images_file_value = state.get("IMAGES_FILE", "").strip()
        images_digest_value = state.get("IMAGES_SHA256", "").strip().lower()
        images_file: Path | None = None
        images_digest: str | None = None
        if images_file_value:
            # Enterprise: the offline archive must live under the state dir.
            images_file = _confined(Path(images_file_value), self.state_dir, label="release image archive")
            _regular_file(images_file, maximum=MAX_ARCHIVE_BYTES)
            if not SHA256_RE.fullmatch(images_digest_value):
                raise UpdateRejected("state_invalid", "The installed release image pin is invalid.")
            images_digest = images_digest_value
            if _sha256(images_file) != images_digest:
                raise UpdateRejected("state_invalid", "The installed release image archive does not match its pin.")
        elif images_digest_value:
            raise UpdateRejected("state_invalid", "The installed release image pin is incomplete.")
        project_name = state["COMPOSE_PROJECT"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", project_name):
            raise UpdateRejected("state_invalid", "The installed compose project name is invalid.")
        target = ReleaseTarget(
            version=state["VERSION"],
            project_dir=project,
            compose_file=compose_file,
            https_compose_file=https_compose_file,
            release_compose_file=release_compose,
            images_file=images_file,
            images_digest=images_digest,
        )
        context = InstallContext(
            config_dir=self.config_dir,
            state_dir=self.state_dir,
            project_name=project_name,
            capture_interface=capture,
            bind_address=bind_address,
            lan_host=lan_host,
            health_timeout=health_timeout,
        )
        return target, context

    def _record_rejection(
        self,
        *,
        actor_id: str,
        request_id: str,
        target_version: str,
        current_version: str,
        code: str,
        manifest_digest: str = "",
        artifact_digest: str = "",
    ) -> None:
        self.audit.append(
            action="software.update.rejected",
            actor_id=actor_id,
            target_version=target_version,
            result="denied",
            request_id=request_id,
            metadata={
                "from_version": current_version,
                "to_version": target_version if VERSION_RE.fullmatch(target_version) else "unknown",
                "manifest_sha256": manifest_digest,
                "artifact_sha256": artifact_digest,
                "reason_code": code,
                "automatic": False,
                "downgrade_approved": False,
            },
        )

    def apply(
        self,
        *,
        manifest_path: str | Path,
        artifact_path: str | Path,
        approve_downgrade: str | None = None,
        actor_id: str = "local-operator",
        health_timeout: int = 300,
    ) -> StagedRelease:
        if not IDENTIFIER_RE.fullmatch(actor_id):
            raise UpdateRejected("actor_invalid", "The local operator identifier is invalid.")
        request_id = str(uuid.uuid4())
        with self._lock():
            self.audit.verify()
            current, context = self._installed(health_timeout)
            verified: VerifiedManifest | None = None
            staged: StagedRelease | None = None
            try:
                verified = self.verify_manifest(manifest_path)
                is_downgrade = _version_key(verified.version) < _version_key(current.version)
                if is_downgrade and approve_downgrade != verified.version:
                    raise UpdateRejected(
                        "downgrade_not_approved",
                        "A downgrade requires --approve-downgrade with the exact signed target version.",
                    )
                if approve_downgrade is not None and approve_downgrade != verified.version:
                    raise UpdateRejected("downgrade_approval_mismatch", "The downgrade approval does not name the signed target version.")
                staged = self.stage(verified, artifact_path)
            except UpdateRejected as exc:
                self._record_rejection(
                    actor_id=actor_id,
                    request_id=request_id,
                    target_version=verified.version if verified else "unknown",
                    current_version=current.version,
                    code=exc.code,
                    manifest_digest=verified.manifest_digest if verified else "",
                    artifact_digest=verified.artifact_digest if verified else "",
                )
                raise

            assert verified is not None and staged is not None
            is_downgrade = _version_key(staged.version) < _version_key(current.version)
            metadata = {
                "from_version": current.version,
                "to_version": staged.version,
                "manifest_sha256": staged.manifest_digest,
                "artifact_sha256": staged.artifact_digest,
                "reason_code": "verified_and_staged",
                "automatic": False,
                "downgrade_approved": is_downgrade,
            }
            self.audit.append(
                action="software.update.staged",
                actor_id=actor_id,
                target_version=staged.version,
                result="success",
                request_id=request_id,
                metadata=metadata,
            )

            candidate = ReleaseTarget(
                version=staged.version,
                project_dir=staged.project_dir,
                compose_file=staged.compose_file,
                https_compose_file=staged.https_compose_file,
                release_compose_file=staged.release_compose_file,
                images_file=staged.images_file,
                images_digest=staged.images_digest,
            )
            with tempfile.TemporaryDirectory(prefix=".update-rollback-", dir=self.config_dir) as backup_name:
                backup = Path(backup_name)
                for name in ("customer.env", "install-state"):
                    source = self.config_dir / name
                    shutil.copyfile(source, backup / name)
                    os.chmod(backup / name, 0o600)
                result = self.executor.install(candidate, context, allow_downgrade=is_downgrade)
                if result.success:
                    self.audit.append(
                        action="software.update.applied",
                        actor_id=actor_id,
                        target_version=staged.version,
                        result="success",
                        request_id=request_id,
                        metadata={**metadata, "reason_code": "post_apply_health_passed"},
                    )
                    return staged

                self.audit.append(
                    action="software.update.failed",
                    actor_id="update-agent",
                    target_version=staged.version,
                    result="failure",
                    request_id=request_id,
                    metadata={**metadata, "reason_code": _reason_code(result.code), "automatic": True},
                )
                # Restore the exact pre-update configuration before invoking the
                # previous signed installer. This prevents new environment keys
                # or partial install-state from leaking across the rollback.
                for name in ("customer.env", "install-state"):
                    destination = self.config_dir / name
                    replacement = self.config_dir / f".{name}.rollback-{uuid.uuid4().hex}"
                    shutil.copyfile(backup / name, replacement)
                    os.chmod(replacement, 0o600)
                    os.replace(replacement, destination)
                rollback = self.executor.install(current, context, allow_downgrade=True)
                if rollback.success:
                    self.audit.append(
                        action="software.update.rollback.applied",
                        actor_id="update-agent",
                        target_version=current.version,
                        result="success",
                        request_id=request_id,
                        metadata={
                            "from_version": staged.version,
                            "to_version": current.version,
                            "manifest_sha256": staged.manifest_digest,
                            "artifact_sha256": staged.artifact_digest,
                            "reason_code": "automatic_health_rollback",
                            "automatic": True,
                            "downgrade_approved": True,
                        },
                    )
                    raise UpdateRolledBack(
                        "candidate_failed_rolled_back",
                        "The candidate release failed health verification; the previous healthy release was restored.",
                    )
                self.audit.append(
                    action="software.update.rollback.failed",
                    actor_id="update-agent",
                    target_version=current.version,
                    result="failure",
                    request_id=request_id,
                    metadata={
                        "from_version": staged.version,
                        "to_version": current.version,
                        "manifest_sha256": staged.manifest_digest,
                        "artifact_sha256": staged.artifact_digest,
                        "reason_code": _reason_code(rollback.code),
                        "automatic": True,
                        "downgrade_approved": True,
                    },
                )
                raise UpdateError(
                    "automatic_rollback_failed",
                    "The candidate and automatic rollback health checks both failed; local operator intervention is required.",
                )


def verify_audit_database(state_dir: str | Path) -> bool:
    """Read and validate an existing update audit database for the monitor."""

    state = Path(state_dir)
    identity = state / "identity"
    tenant = _regular_file(identity / "tenant-id", maximum=1024, private=True).read_text().strip()
    deployment = _regular_file(identity / "deployment-id", maximum=1024, private=True).read_text().strip()
    database = state / "updates/audit.sqlite3"
    if not database.exists():
        return True
    _regular_file(database, private=True)
    connection = sqlite3.connect(str(database))
    try:
        log = AuditLog(connection)
        return log.verify(tenant, deployment)
    finally:
        connection.close()
