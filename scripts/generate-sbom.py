#!/usr/bin/env python3
"""Generate a deterministic CycloneDX source/dependency SBOM without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EXCLUDED_DIRECTORIES = {".git", ".data", ".runtime", "dist", "node_modules", "runtime", "secrets", "__pycache__"}
EXCLUDED_FILENAMES = {".env", "customer.env", "install-state"}
SECRET_SUFFIXES = {".key", ".p12", ".pfx", ".token"}
HASHED_FILE_LIMIT = 64 * 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def included_files(source: Path, output: Path) -> Iterable[Path]:
    output_resolved = output.resolve()
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file() or path.is_symlink() or path.resolve() == output_resolved:
            continue
        relative = path.relative_to(source)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if path.name in EXCLUDED_FILENAMES or path.suffix.lower() in SECRET_SUFFIXES or path.name.endswith(".pyc"):
            continue
        if path.stat().st_size > HASHED_FILE_LIMIT:
            continue
        yield path


def dependency_components(source: Path) -> list[dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    lock = source / "package-lock.json"
    if lock.is_file():
        value = json.loads(lock.read_text(encoding="utf-8"))
        packages = value.get("packages", {}) if isinstance(value, dict) else {}
        if isinstance(packages, dict):
            for location, metadata in packages.items():
                if not location.startswith("node_modules/") or not isinstance(metadata, dict):
                    continue
                name = location.removeprefix("node_modules/")
                version = metadata.get("version")
                if not isinstance(version, str) or not version:
                    continue
                purl = f"pkg:npm/{name}@{version}"
                component: dict[str, Any] = {
                    "type": "library",
                    "bom-ref": purl,
                    "name": name,
                    "version": version,
                    "purl": purl,
                }
                integrity = metadata.get("integrity")
                if isinstance(integrity, str) and integrity.startswith("sha512-"):
                    component["properties"] = [{"name": "npm:integrity", "value": integrity}]
                components[purl] = component

    for requirements in sorted(source.rglob("*requirements*.txt")):
        if any(part in EXCLUDED_DIRECTORIES for part in requirements.relative_to(source).parts):
            continue
        for raw in requirements.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)", line)
            if not match:
                continue
            name, version = match.groups()
            normalized = name.lower().replace("_", "-")
            purl = f"pkg:pypi/{normalized}@{version}"
            components[purl] = {
                "type": "library",
                "bom-ref": purl,
                "name": normalized,
                "version": version,
                "purl": purl,
            }
    return [components[key] for key in sorted(components)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    source, output = arguments.source.resolve(), arguments.output.resolve()
    if not source.is_dir():
        raise SystemExit("SBOM source directory does not exist")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", arguments.version):
        raise SystemExit("SBOM release version is invalid")

    files = []
    for path in included_files(source, output):
        relative = path.relative_to(source).as_posix()
        files.append(
            {
                "type": "file",
                "bom-ref": f"file:{relative}",
                "name": relative,
                "hashes": [{"alg": "SHA-256", "content": sha256(path)}],
            }
        )
    dependencies = dependency_components(source)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    timestamp = datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
    fingerprint = hashlib.sha256(
        json.dumps(files + dependencies, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    root_ref = f"pkg:generic/hybrid-ndr@{arguments.version}"
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, root_ref + ':' + fingerprint)}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "hybrid-ndr-source-sbom", "version": "1"}]},
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "hybrid-ndr",
                "version": arguments.version,
                "purl": root_ref,
            },
        },
        "components": dependencies + files,
    }
    output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, output)
        os.chmod(output, 0o644)
    finally:
        Path(temporary_name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
