from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_generate_sbom():
    spec = importlib.util.spec_from_file_location("generate_sbom", ROOT / "scripts/generate-sbom.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateSbomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_generate_sbom()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "app.py").write_text("x = 1\n")
        (self.source / "requirements.txt").write_text("flask==3.0.0\n# a comment\nrequests>=2.0\n")
        (self.source / ".env").write_text("SECRET=1\n")
        (self.source / "customer.env").write_text("K=V\n")
        (self.source / "install-state").write_text("VERSION=1\n")
        secret = self.source / "credentials"
        secret.mkdir()
        (secret / "id_rsa.key").write_text("key\n")
        (self.source / "dist").mkdir()
        (self.source / "dist" / "bundle.js").write_text("var x;\n")
        (self.source / "node_modules").mkdir()
        (self.source / "node_modules" / "dep.js").write_text("dep\n")
        (self.source / "__pycache__").mkdir()
        (self.source / "__pycache__" / "c.pyc").write_bytes(b"\x00\x01")
        self.output = self.base / "out" / "sbom.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_included_files_excludes_secrets_and_build_artifacts(self) -> None:
        m = self.module
        files = {path.relative_to(self.source).as_posix() for path in m.included_files(self.source, self.output)}
        self.assertIn("app.py", files)
        self.assertIn("requirements.txt", files)
        self.assertNotIn(".env", files)
        self.assertNotIn("customer.env", files)
        self.assertNotIn("install-state", files)
        self.assertNotIn("credentials/id_rsa.key", files)
        self.assertNotIn("dist/bundle.js", files)
        self.assertNotIn("node_modules/dep.js", files)
        self.assertNotIn("__pycache__/c.pyc", files)

    def test_dependency_components_parse_pinned_requirements(self) -> None:
        m = self.module
        components = {item["name"]: item for item in m.dependency_components(self.source)}
        self.assertIn("flask", components)
        self.assertEqual(components["flask"]["purl"], "pkg:pypi/flask@3.0.0")
        self.assertNotIn("requests", components)

    def test_sha256_matches_hashlib(self) -> None:
        m = self.module
        payload = b"content to hash\n"
        path = self.base / "payload.txt"
        path.write_bytes(payload)
        self.assertEqual(m.sha256(path), hashlib.sha256(payload).hexdigest())

    def test_main_produces_deterministic_cyclonedx_document(self) -> None:
        os.environ["SOURCE_DATE_EPOCH"] = "0"
        try:
            self.run_main("--source", str(self.source), "--output", str(self.output), "--version", "1.2.3")
        finally:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        document = json.loads(self.output.read_text())
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.6")
        self.assertEqual(document["metadata"]["component"]["version"], "1.2.3")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
        self.assertIn("urn:uuid:", document["serialNumber"])

    def run_main(self, *arguments: str) -> None:
        old_argv = sys.argv
        sys.argv = ["generate-sbom.py", *arguments]
        try:
            self.module.main()
        finally:
            sys.argv = old_argv

    def test_invalid_version_is_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            self.run_main("--source", str(self.source), "--output", str(self.output), "--version", "not-a-version")

    def test_missing_source_directory_is_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            self.run_main("--source", str(self.base / "missing"), "--output", str(self.output), "--version", "1.0.0")

    def test_sbom_excludes_large_files(self) -> None:
        m = self.module
        large = self.source / "large.bin"
        large.write_bytes(b"x" * (m.HASHED_FILE_LIMIT + 1))
        files = {path.relative_to(self.source).as_posix() for path in m.included_files(self.source, self.output)}
        self.assertNotIn("large.bin", files)


if __name__ == "__main__":
    unittest.main()
