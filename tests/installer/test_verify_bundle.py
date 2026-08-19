from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
INSTALLER_DIR = ROOT / "installer"


def load_verify_bundle():
    spec = importlib.util.spec_from_file_location("verify_bundle", INSTALLER_DIR / "verify-bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerifyBundleModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_verify_bundle()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    # ---- safe_name ----

    def test_safe_name_rejects_absolute_traversal_and_nul(self) -> None:
        m = self.module
        for bad in ("/etc/passwd", "../escape", "a/../../escape", "ok\x00/path"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit) as context:
                m.safe_name(bad)
            self.assertIn("unsafe archive path", str(context.exception))

    def test_safe_name_strips_leading_dots_and_returns_relative(self) -> None:
        m = self.module
        self.assertEqual(m.safe_name("./payload/x"), PurePosixPath("payload/x"))
        self.assertEqual(m.safe_name("payload/x"), PurePosixPath("payload/x"))

    # ---- validate: structural ----

    def test_valid_code_only_bundle_passes(self) -> None:
        bundle = self.make_bundle(include_images=False)
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
            members, manifest = self.module.validate(archive)
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertFalse(manifest["images"]["included"])
        self.assertTrue(any(name == PurePosixPath("payload/hybrid-ndr/installer/install.sh") for _, name in members))

    def test_valid_image_bearing_bundle_passes(self) -> None:
        bundle = self.make_bundle(include_images=True)
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
            members, manifest = self.module.validate(archive)
        self.assertEqual(manifest["version"], "1.2.3")
        self.assertTrue(manifest["images"]["included"])
        self.assertIn(PurePosixPath("images.tar"), {name for _, name in members})
        self.assertTrue(manifest["sbom"]["images"])

    def test_missing_required_member_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, drop="payload/hybrid-ndr/installer/install.sh")
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("missing its manifest, installer, HTTPS ingress, or Compose definition", str(context.exception))

    def test_duplicate_member_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, duplicate="payload/hybrid-ndr/RELEASE_VERSION")
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("duplicate path", str(context.exception))

    def test_link_and_special_files_are_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, special_member=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("links and special files are forbidden", str(context.exception))

    # ---- validate: manifest ----

    def test_invalid_manifest_json_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, corrupt_manifest=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("manifest is invalid JSON", str(context.exception))

    def test_wrong_schema_or_product_is_rejected(self) -> None:
        for override in ({"schema_version": 2}, {"product": "other"}, {"compose_profile": "vendor"}):
            with self.subTest(override=override):
                bundle = self.make_bundle(include_images=False, manifest_override=override)
                with self.assertRaises(SystemExit) as context:
                    self.run_validate(bundle)
                self.assertIn("manifest", str(context.exception))

    def test_wrong_payload_path_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, manifest_override={"payload": "payload/other"})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("payload path is invalid", str(context.exception))

    def test_missing_version_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, manifest_override={"version": None})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("version is missing", str(context.exception))

    # ---- validate: image-bearing specifics ----

    def test_image_bundle_without_images_tar_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, drop="images.tar")
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("declares images.tar but it is absent", str(context.exception))

    def test_image_bundle_without_release_override_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, drop="payload/hybrid-ndr/infra/compose/docker-compose.release.yml")
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("missing its digest-only release Compose override", str(context.exception))

    def test_images_tar_digest_mismatch_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, tamper_images_tar=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("images.tar digest does not match the signed manifest", str(context.exception))

    def test_release_override_pins_mismatch_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, override_mismatch=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("release Compose image pins do not match the signed manifest", str(context.exception))

    def test_invalid_image_digest_format_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, manifest_override={"images": {"included": True, "path": "images.tar", "sha256": "not-a-digest", "services": {}}})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("image digest is invalid", str(context.exception))

    def test_code_only_bundle_with_undeclared_images_tar_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, extra_images_tar=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("undeclared images.tar is present", str(context.exception))

    def test_code_only_bundle_declaring_service_pins_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, manifest_override={"images": {"included": False, "services": {"dashboard": "sha256:" + "a" * 64}}})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("code-only bundle declares image service pins", str(context.exception))

    # ---- validate: SBOM ----

    def test_source_sbom_digest_mismatch_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, tamper_sbom=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("source SBOM digest does not match the signed manifest", str(context.exception))

    def test_non_cyclonedx_sbom_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, sbom_format="not-cyclonedx")
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("not CycloneDX JSON", str(context.exception))

    def test_invalid_sbom_format_field_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=False, manifest_override={"sbom": {"path": "sbom/source.cdx.json", "sha256": "a" * 64, "format": "CycloneDX-1.5", "images": []}})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("source SBOM metadata is invalid", str(context.exception))

    def test_image_sbom_digest_mismatch_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, tamper_image_sbom=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("image SBOM digest does not match the signed manifest", str(context.exception))

    def test_image_sbom_missing_from_archive_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, drop_image_sbom=True)
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("image SBOM path is duplicate or missing", str(context.exception))

    def test_image_bundle_without_image_sboms_is_rejected(self) -> None:
        bundle = self.make_bundle(include_images=True, manifest_override={"sbom": {"path": "sbom/source.cdx.json", "sha256": "a" * 64, "format": "CycloneDX-1.6", "images": []}})
        with self.assertRaises(SystemExit) as context:
            self.run_validate(bundle)
        self.assertIn("image SBOM metadata is invalid", str(context.exception))

    # ---- extract ----

    def test_extract_to_non_empty_destination_is_rejected(self) -> None:
        destination = self.base / "dest"
        destination.mkdir()
        (destination / "existing").write_text("x")
        bundle = self.make_bundle(include_images=False)
        with self.assertRaises(SystemExit) as context:
            with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
                members, _ = self.module.validate(archive)
                self.module.extract(archive, members, destination)
        self.assertIn("must be empty", str(context.exception))

    def test_extract_writes_safe_payload_with_restricted_modes(self) -> None:
        destination = self.base / "dest"
        bundle = self.make_bundle(include_images=False)
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
            members, _ = self.module.validate(archive)
            self.module.extract(archive, members, destination)
        payload = destination / "payload/hybrid-ndr/RELEASE_VERSION"
        self.assertTrue(payload.is_file())
        self.assertEqual(payload.read_text(encoding="ascii").strip(), "1.2.3")
        self.assertEqual(os.stat(destination).st_mode & 0o777, 0o700)

    # ---- helpers ----

    def run_validate(self, bundle: bytes):
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as archive:
            return self.module.validate(archive)

    def make_bundle(
        self,
        *,
        include_images: bool,
        drop: str | None = None,
        duplicate: str | None = None,
        special_member: bool = False,
        corrupt_manifest: bool = False,
        manifest_override: dict | None = None,
        tamper_images_tar: bool = False,
        override_mismatch: bool = False,
        extra_images_tar: bool = False,
        tamper_sbom: bool = False,
        sbom_format: str = "CycloneDX",
        tamper_image_sbom: bool = False,
        drop_image_sbom: bool = False,
    ) -> bytes:
        image_services = {"dashboard": "sha256:" + "b" * 64, "local-api": "sha256:" + "c" * 64}
        image_sbom_path = "sbom/images/" + ("d" * 64) + ".cdx.json"
        image_sbom_body = json.dumps({"bomFormat": "CycloneDX", "version": 1}).encode()
        image_sbom = {
            "path": image_sbom_path,
            "sha256": hashlib.sha256(image_sbom_body).hexdigest(),
            "image": "sha256:" + "f" * 64,
            "format": "CycloneDX-1.6",
        }
        if tamper_image_sbom:
            image_sbom["sha256"] = "1" * 64
        if sbom_format == "CycloneDX":
            sbom_body = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
        else:
            sbom_body = {"bomFormat": "Other", "version": 1}
        sbom_bytes = json.dumps(sbom_body).encode()
        sbom_sha256 = hashlib.sha256(sbom_bytes).hexdigest() if not tamper_sbom else "0" * 64
        images_tar_bytes = b"x" * 32
        image_sha256 = hashlib.sha256(images_tar_bytes).hexdigest() if not tamper_images_tar else "0" * 64
        manifest = {
            "schema_version": 1,
            "product": "hybrid-ndr",
            "version": "1.2.3",
            "compose_profile": "customer",
            "payload": "payload/hybrid-ndr",
            "images": {
                "included": include_images,
                "path": "images.tar" if include_images else None,
                "sha256": image_sha256 if include_images else None,
                "services": image_services if include_images else {},
            },
            "sbom": {
                "path": "sbom/source.cdx.json",
                "sha256": sbom_sha256,
                "format": "CycloneDX-1.6",
                "images": [image_sbom] if include_images else [],
            },
        }
        if manifest_override:
            if "images" in manifest_override:
                base_images = dict(manifest["images"])
                base_images.update(manifest_override["images"])
                manifest["images"] = base_images
            elif "sbom" in manifest_override:
                base_sbom = dict(manifest["sbom"])
                base_sbom.update(manifest_override["sbom"])
                manifest["sbom"] = base_sbom
            else:
                manifest.update(manifest_override)
        if override_mismatch:
            image_services = {"dashboard": "sha256:" + "b" * 64, "local-api": "sha256:" + "c" * 64, "suricata": "sha256:" + "a" * 64}
        if manifest_override and "sbom" in manifest_override:
            base_sbom = dict(manifest["sbom"])
            base_sbom.update(manifest_override["sbom"])
            if manifest_override["sbom"].get("sha256") == "a" * 64:
                base_sbom["sha256"] = sbom_sha256
            manifest["sbom"] = base_sbom

        entries: list[tuple[str, bytes | None, bool]] = []
        entries.append(("BUNDLE-MANIFEST.json", (json.dumps(manifest, indent=2) if not corrupt_manifest else "{not-json").encode(), False))
        entries.append(("sbom/source.cdx.json", sbom_bytes, False))
        entries.append(("payload/hybrid-ndr/RELEASE_VERSION", b"1.2.3\n", False))
        entries.append(("payload/hybrid-ndr/installer/install.sh", b"#!/usr/bin/env bash\nexit 0\n", True))
        entries.append(("payload/hybrid-ndr/installer/post-install-health.sh", b"#!/usr/bin/env bash\nexit 0\n", True))
        entries.append(("payload/hybrid-ndr/infra/compose/docker-compose.yml", b"services: {}\n", False))
        entries.append(("payload/hybrid-ndr/infra/compose/docker-compose.https.yml", b"services: {}\n", False))
        entries.append(("payload/hybrid-ndr/infra/ingress/nginx.conf.template", b"server {}\n", False))
        override_lines = ["services:"]
        for service, digest in image_services.items():
            override_lines.extend((f"  {service}:", f"    image: {digest}"))
        entries.append(("payload/hybrid-ndr/infra/compose/docker-compose.release.yml", ("\n".join(override_lines) + "\n").encode(), False))
        if include_images or extra_images_tar:
            entries.append(("images.tar", images_tar_bytes, False))
        if include_images and not drop_image_sbom:
            entries.append((image_sbom_path, image_sbom_body, False))

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            written: set[str] = set()
            for name, value, executable in entries:
                if drop and name == drop:
                    continue
                if name in written:
                    continue
                written.add(name)
                info = tarfile.TarInfo(name)
                info.size = len(value or b"")
                info.mode = 0o755 if executable else 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                archive.addfile(info, io.BytesIO(value or b""))
            if special_member:
                info = tarfile.TarInfo("payload/hybrid-ndr/evil-link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
            if duplicate:
                source = next((value for name, value, _ in entries if name == duplicate), None)
                info = tarfile.TarInfo(duplicate)
                info.size = len(source or b"")
                info.mode = 0o644
                info.mtime = 0
                archive.addfile(info, io.BytesIO(source or b""))
        return buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
