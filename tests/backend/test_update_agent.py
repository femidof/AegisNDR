from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401
from cryptography.hazmat.primitives import serialization

from hybrid_ndr_control_api.pki import CertificateAuthority
from hybrid_ndr_update.agent import (
    InstallResult,
    ReleaseTarget,
    InstallContext,
    SubprocessInstallerExecutor,
    UpdateAgent,
    UpdateRejected,
    UpdateRolledBack,
    verify_audit_database,
)


def atomic_private(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(value)
    os.chmod(path, 0o600)


def write_state(config: Path, version: str = "1.0.0", project: Path | None = None, images_file: Path | None = None, images_digest: str = "") -> None:
    project = project or config / "project"
    install_state = {
        "VERSION": version,
        "PROJECT_DIR": str(project),
        "COMPOSE_FILE": str(project / "compose.yml"),
        "HTTPS_COMPOSE_FILE": str(project / "compose.https.yml"),
        "COMPOSE_PROJECT": "hybrid-ndr-customer",
    }
    if images_file is not None:
        install_state["IMAGES_FILE"] = str(images_file)
        install_state["IMAGES_SHA256"] = images_digest
    values = {**install_state, "INSTALLED_AT": "2026-08-05T00:00:00Z"}
    atomic_private(config / "install-state", "".join(f"{key}={value}\n" for key, value in values.items()).encode())
    atomic_private(
        config / "customer.env",
        b"CAPTURE_INTERFACE=eth0\nCUSTOMER_BIND_ADDRESS=0.0.0.0\nCUSTOMER_LAN_HOST=hybrid-ndr.local\n",
    )


def public_key_digest(public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def write_identity(state: Path, authority: CertificateAuthority) -> None:
    identity = state / "identity"
    atomic_private(identity / "tenant-id", b"tenant-1\n")
    atomic_private(identity / "deployment-id", b"deployment-1\n")
    atomic_private(identity / "update-signing-public.pem", authority.update_signing_public_key_pem().encode("ascii"))


def signed_manifest(authority: CertificateAuthority, *, version: str = "1.1.0", artifact_digest: str, channel: str = "stable") -> dict:
    manifest = {
        "schema_version": 1,
        "product": "hybrid-ndr",
        "channel": channel,
        "version": version,
        "artifact": f"registry.example/hybrid-ndr@sha256:{artifact_digest}",
        "published_at": "2026-08-05T00:00:00Z",
        "signature_algorithm": "ECDSA_P256_SHA256",
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**manifest, "signature": authority.sign_update_manifest(canonical)}


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_bytes((json.dumps(manifest, separators=(",", ":")) + "\n").encode("utf-8"))
    os.chmod(path, 0o600)


def make_artifact(version: str = "1.1.0", *, services: dict[str, str] | None = None, tamper: bool = False) -> bytes:
    services = services or {"dashboard": "sha256:" + "b" * 64}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        add(archive, "images.tar", b"x" * 32)
        add(archive, "sbom/source.cdx.json", json.dumps({"bomFormat": "CycloneDX", "version": 1}).encode())
        add(archive, "payload/hybrid-ndr/RELEASE_VERSION", (version + "\n").encode())
        add(archive, "payload/hybrid-ndr/installer/install.sh", b"#!/usr/bin/env bash\nexit 0\n")
        add(archive, "payload/hybrid-ndr/installer/post-install-health.sh", b"#!/usr/bin/env bash\nexit 0\n")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.yml", b"services: {}\n")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.https.yml", b"services: {}\n")
        override = ["services:"]
        for service, digest in services.items():
            override.append(f"  {service}:")
            override.append(f"    image: {digest}")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.release.yml", ("\n".join(override) + "\n").encode())
    body = buffer.getvalue()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        images_digest = _member_digest(archive, "images.tar")
        sbom_digest = _member_digest(archive, "sbom/source.cdx.json")
    payload = {
        "schema_version": 1,
        "product": "hybrid-ndr",
        "version": version,
        "compose_profile": "customer",
        "payload": "payload/hybrid-ndr",
        "images": {
            "included": True,
            "path": "images.tar",
            "sha256": images_digest,
            "services": services,
        },
        "sbom": {"path": "sbom/source.cdx.json", "sha256": sbom_digest, "format": "CycloneDX-1.6", "images": []},
        "created_at": "2026-08-05T00:00:00Z",
    }
    final = io.BytesIO()
    with tarfile.open(fileobj=final, mode="w:gz") as archive:
        add(archive, "BUNDLE-MANIFEST.json", json.dumps(payload, indent=2, sort_keys=True).encode())
        add(archive, "images.tar", b"x" * 32)
        add(archive, "sbom/source.cdx.json", json.dumps({"bomFormat": "CycloneDX", "version": 1}).encode())
        add(archive, "payload/hybrid-ndr/RELEASE_VERSION", (version + "\n").encode())
        add(archive, "payload/hybrid-ndr/installer/install.sh", b"#!/usr/bin/env bash\nexit 0\n")
        add(archive, "payload/hybrid-ndr/installer/post-install-health.sh", b"#!/usr/bin/env bash\nexit 0\n")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.yml", b"services: {}\n")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.https.yml", b"services: {}\n")
        override = ["services:"]
        for service, digest in services.items():
            override.append(f"  {service}:")
            override.append(f"    image: {digest}")
        add(archive, "payload/hybrid-ndr/infra/compose/docker-compose.release.yml", ("\n".join(override) + "\n").encode())
    return final.getvalue()


def _member_digest(archive: tarfile.TarFile, name: str) -> str:
    member = archive.getmember(name)
    stream = archive.extractfile(member)
    assert stream is not None
    return hashlib.file_digest(stream, "sha256").hexdigest()


def add(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    archive.addfile(info, io.BytesIO(value))


class RecordingExecutor:
    def __init__(self, results: list[InstallResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[ReleaseTarget, InstallContext, bool]] = []

    def install(self, release: ReleaseTarget, context: InstallContext, *, allow_downgrade: bool) -> InstallResult:
        self.calls.append((release, context, allow_downgrade))
        return self.results.pop(0)


class UpdateAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.config = self.root / "config"
        self.config.mkdir(mode=0o700)
        self.authority = CertificateAuthority.create()
        write_identity(self.state, self.authority)
        write_state(self.config)
        atomic_private(
            self.config / "update-signing-key.sha256",
            (public_key_digest(self.authority.update_signing_public_key_pem()) + "\n").encode("ascii"),
        )
        self.artifact = self.root / "release.tar.gz"
        self.artifact_bytes = make_artifact()
        self.artifact.write_bytes(self.artifact_bytes)
        os.chmod(self.artifact, 0o600)
        self.artifact_digest = hashlib.sha256(self.artifact_bytes).hexdigest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def agent(self, executor=None) -> UpdateAgent:
        return UpdateAgent(state_dir=self.state, config_dir=self.config, executor=executor or RecordingExecutor([InstallResult(True, "healthy")]))

    def apply(self, executor=None, **kwargs) -> None:
        manifest = signed_manifest(self.authority, artifact_digest=self.artifact_digest)
        manifest_path = self.root / "manifest.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent(executor)
        try:
            return agent.apply(manifest_path=manifest_path, artifact_path=self.artifact, **kwargs), manifest
        finally:
            agent.close()

    def test_manifest_signature_and_pin_are_validated(self) -> None:
        staged, manifest = self.apply()
        self.assertEqual(staged.version, "1.1.0")
        expected = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(staged.manifest_digest, expected)
        self.assertTrue((self.state / "updates" / "releases" / staged.version).exists() or staged.project_dir.exists())

    def test_tampered_manifest_fails_closed_with_audit_rejection(self) -> None:
        manifest = signed_manifest(self.authority, artifact_digest=self.artifact_digest)
        manifest["version"] = "9.9.9"
        manifest_path = self.root / "tampered.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent()
        try:
            with self.assertRaises(UpdateRejected):
                agent.apply(manifest_path=manifest_path, artifact_path=self.artifact)
            entries = agent.audit.log.list("tenant-1", "deployment-1")
        finally:
            agent.close()
        self.assertEqual(entries[0]["action"], "software.update.rejected")
        self.assertEqual(entries[0]["metadata"]["reason_code"], "signature_verification_failed")

    def test_wrong_signing_key_is_rejected(self) -> None:
        other = CertificateAuthority.create()
        manifest = signed_manifest(other, artifact_digest=self.artifact_digest)
        manifest_path = self.root / "wrong-key.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent()
        with self.assertRaises(UpdateRejected):
            try:
                agent.apply(manifest_path=manifest_path, artifact_path=self.artifact)
            finally:
                agent.close()

    def test_digest_mismatch_artifact_is_rejected(self) -> None:
        self.artifact.write_bytes(b"different bytes")
        manifest = signed_manifest(self.authority, artifact_digest=self.artifact_digest)
        manifest_path = self.root / "digest.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent()
        with self.assertRaises(UpdateRejected):
            try:
                agent.apply(manifest_path=manifest_path, artifact_path=self.artifact)
            finally:
                agent.close()

    def test_downgrade_requires_explicit_approval(self) -> None:
        write_state(self.config, version="1.5.0")
        manifest = signed_manifest(self.authority, version="1.0.0", artifact_digest=self.artifact_digest)
        manifest_path = self.root / "downgrade.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent()
        try:
            with self.assertRaises(UpdateRejected):
                agent.apply(manifest_path=manifest_path, artifact_path=self.artifact)
            entries = agent.audit.log.list("tenant-1", "deployment-1")
        finally:
            agent.close()
        self.assertEqual(entries[0]["metadata"]["reason_code"], "downgrade_not_approved")

    def test_post_apply_health_failure_restores_previous_release(self) -> None:
        executor = RecordingExecutor([InstallResult(False, "health_failed"), InstallResult(True, "healthy")])
        with self.assertRaises(UpdateRolledBack):
            self.apply(executor=executor)
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(executor.calls[0][0].version, "1.1.0")
        self.assertEqual(executor.calls[1][0].version, "1.0.0")
        entries = agent_audit(self)
        self.assertEqual(entries[0]["action"], "software.update.rollback.applied")

    def test_rollback_reloads_pinned_images_of_the_previous_release(self) -> None:
        # The installed release was loaded from a digest-pinned offline archive
        # (install.sh persists IMAGES_FILE/IMAGES_SHA256 in install-state). A
        # failed candidate must roll back to exactly those images, not to a
        # registry pull that an offline appliance cannot perform.
        images = self.root / "installed-images.tar"
        images.write_bytes(b"pinned-offline-images")
        os.chmod(images, 0o600)
        pinned_digest = hashlib.sha256(images.read_bytes()).hexdigest()
        write_state(self.config, images_file=images, images_digest=pinned_digest)

        executor = RecordingExecutor([InstallResult(False, "health_failed"), InstallResult(True, "healthy")])
        with self.assertRaises(UpdateRolledBack):
            self.apply(executor=executor)
        self.assertEqual(len(executor.calls), 2)
        current_release = executor.calls[1][0]
        self.assertEqual(current_release.version, "1.0.0")
        self.assertEqual(current_release.images_file, images)
        self.assertEqual(current_release.images_digest, pinned_digest)

    def test_rollback_rejects_a_tampered_installed_image_pin(self) -> None:
        images = self.root / "installed-images.tar"
        images.write_bytes(b"pinned-offline-images")
        os.chmod(images, 0o600)
        write_state(
            self.config,
            images_file=images,
            images_digest="0" * 64,
        )
        executor = RecordingExecutor([InstallResult(False, "health_failed"), InstallResult(True, "healthy")])
        manifest = signed_manifest(self.authority, artifact_digest=self.artifact_digest)
        manifest_path = self.root / "manifest.json"
        write_manifest(manifest_path, manifest)
        agent = self.agent(executor)
        try:
            with self.assertRaises(UpdateRejected) as raised:
                agent.apply(manifest_path=manifest_path, artifact_path=self.artifact)
            self.assertEqual(raised.exception.code, "state_invalid")
        finally:
            agent.close()
        # A tampered pin must fail closed before any install attempt.
        self.assertEqual(executor.calls, [])

    def test_automatic_rollback_failure_is_reported(self) -> None:
        executor = RecordingExecutor([InstallResult(False, "health_failed"), InstallResult(False, "rollback_failed")])
        from hybrid_ndr_update.agent import UpdateError

        with self.assertRaises(UpdateError):
            self.apply(executor=executor)

    def test_audit_database_verifies_and_detects_tampering(self) -> None:
        self.apply()
        self.assertTrue(verify_audit_database(self.state))
        database = self.state / "updates" / "audit.sqlite3"
        connection = __import__("sqlite3").connect(str(database))
        connection.execute("DROP TRIGGER audit_events_no_update")
        connection.execute("DROP TRIGGER audit_events_no_delete")
        connection.execute("UPDATE audit_events SET metadata_json = '{\"x\": 1}' WHERE action = 'software.update.applied'")
        connection.commit()
        connection.close()
        with self.assertRaises(Exception):
            verify_audit_database(self.state)

    def test_subprocess_executor_requires_regular_installer(self) -> None:
        executor = SubprocessInstallerExecutor()
        missing = self.root / "missing-project"
        release = ReleaseTarget(version="1.1.0", project_dir=missing, compose_file=missing / "compose.yml", https_compose_file=missing / "compose.https.yml")
        context = InstallContext(config_dir=self.config, state_dir=self.state, project_name="hybrid-ndr-customer", capture_interface="eth0", bind_address="0.0.0.0", lan_host="hybrid-ndr.local", health_timeout=30)
        with self.assertRaises(UpdateRejected):
            executor.install(release, context, allow_downgrade=False)

    def test_subprocess_executor_reloads_pinned_images_on_rollback(self) -> None:
        # The rollback re-invokes the previous release installer with the
        # digest-pinned offline archive so image-level restoration does not
        # depend on registry access.
        project = self.root / "project"
        project.mkdir()
        for name in ("compose.yml", "compose.https.yml"):
            (project / name).write_text("services: {}\n", encoding="utf-8")
        installer = project / "installer"
        installer.mkdir()
        record = self.root / "installer-args.txt"
        script = installer / "install.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >>\"" + str(record) + "\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        images = self.root / "images.tar"
        images.write_bytes(b"offline-images")
        images.chmod(0o600)
        digest = hashlib.sha256(b"offline-images").hexdigest()

        release = ReleaseTarget(
            version="1.0.0",
            project_dir=project,
            compose_file=project / "compose.yml",
            https_compose_file=project / "compose.https.yml",
            images_file=images,
            images_digest=digest,
        )
        context = InstallContext(config_dir=self.config, state_dir=self.state, project_name="hybrid-ndr-customer", capture_interface="eth0", bind_address="0.0.0.0", lan_host="hybrid-ndr.local", health_timeout=30)
        executor = SubprocessInstallerExecutor()
        result = executor.install(release, context, allow_downgrade=True)
        self.assertTrue(result.success)
        arguments = record.read_text(encoding="utf-8").strip().split()
        self.assertIn("--offline-images", arguments)
        self.assertIn(str(images), arguments)
        self.assertIn("--offline-images-sha256", arguments)
        self.assertIn(digest, arguments)
        self.assertIn("--allow-downgrade", arguments)


def agent_audit(test: UpdateAgentTests):
    from hybrid_ndr_update.agent import UpdateAgent

    agent = UpdateAgent(state_dir=test.state, config_dir=test.config)
    try:
        return agent.audit.log.list("tenant-1", "deployment-1")
    finally:
        agent.close()


if __name__ == "__main__":
    unittest.main()
