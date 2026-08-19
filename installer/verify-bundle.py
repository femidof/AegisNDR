#!/usr/bin/env python3
"""Validate and optionally safely extract a cryptographically verified bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath


MAX_ENTRIES = 200_000
MAX_EXPANDED_BYTES = 40 * 1024 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def reject(message: str) -> None:
    raise SystemExit(f"offline bundle rejected: {message}")


def safe_name(name: str) -> PurePosixPath:
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or ".." in candidate.parts or "\x00" in name:
        reject(f"unsafe archive path: {name!r}")
    while candidate.parts and candidate.parts[0] == ".":
        candidate = PurePosixPath(*candidate.parts[1:])
    if not candidate.parts:
        return PurePosixPath(".")
    return candidate


def validate(archive: tarfile.TarFile) -> tuple[list[tuple[tarfile.TarInfo, PurePosixPath]], dict]:
    members = archive.getmembers()
    if len(members) > MAX_ENTRIES:
        reject("archive contains too many entries")
    expanded = 0
    seen: set[PurePosixPath] = set()
    validated: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    for member in members:
        name = safe_name(member.name)
        if name == PurePosixPath("."):
            continue
        if name in seen:
            reject(f"archive contains duplicate path: {name}")
        seen.add(name)
        if not (member.isdir() or member.isfile()):
            reject(f"links and special files are forbidden: {name}")
        expanded += member.size
        if expanded > MAX_EXPANDED_BYTES:
            reject("archive expands beyond the configured safety limit")
        validated.append((member, name))

    required = {
        PurePosixPath("BUNDLE-MANIFEST.json"),
        PurePosixPath("sbom/source.cdx.json"),
        PurePosixPath("payload/hybrid-ndr/installer/install.sh"),
        PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.yml"),
        PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.https.yml"),
        PurePosixPath("payload/hybrid-ndr/infra/ingress/nginx.conf.template"),
    }
    if not required.issubset(seen):
        reject("bundle is missing its manifest, installer, HTTPS ingress, or Compose definition")
    manifest_member = archive.getmember("./BUNDLE-MANIFEST.json") if "./BUNDLE-MANIFEST.json" in archive.getnames() else archive.getmember("BUNDLE-MANIFEST.json")
    manifest_stream = archive.extractfile(manifest_member)
    if manifest_stream is None:
        reject("manifest is not readable")
    try:
        manifest = json.load(manifest_stream)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        reject(f"manifest is invalid JSON: {error}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        reject("unsupported manifest schema")
    if manifest.get("product") != "hybrid-ndr" or manifest.get("compose_profile") != "customer":
        reject("manifest does not describe a customer Hybrid NDR bundle")
    if manifest.get("payload") != "payload/hybrid-ndr":
        reject("manifest payload path is invalid")
    if not isinstance(manifest.get("version"), str):
        reject("manifest version is missing")
    images = manifest.get("images")
    if not isinstance(images, dict) or not isinstance(images.get("included"), bool):
        reject("manifest image metadata is invalid")
    if images["included"]:
        digest = images.get("sha256")
        if images.get("path") != "images.tar" or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            reject("manifest image digest is invalid")
        if PurePosixPath("images.tar") not in seen:
            reject("manifest declares images.tar but it is absent")
        release_override = PurePosixPath("payload/hybrid-ndr/infra/compose/docker-compose.release.yml")
        if release_override not in seen:
            reject("image-bearing bundle is missing its digest-only release Compose override")
        services = images.get("services")
        if not isinstance(services, dict) or not services:
            reject("manifest image service pins are invalid")
        for service, reference in services.items():
            if (
                not isinstance(service, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", service)
                or not isinstance(reference, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", reference)
            ):
                reject("manifest image service pins are invalid")
        image_member = next(member for member, name in validated if name == PurePosixPath("images.tar"))
        image_stream = archive.extractfile(image_member)
        if image_stream is None:
            reject("images.tar is not readable")
        actual = hashlib.file_digest(image_stream, "sha256").hexdigest()
        if actual != digest:
            reject("images.tar digest does not match the signed manifest")
        override_member = next(member for member, name in validated if name == release_override)
        override_stream = archive.extractfile(override_member)
        if override_stream is None:
            reject("release Compose override is not readable")
        try:
            override_text = override_stream.read().decode("utf-8")
        except UnicodeDecodeError:
            reject("release Compose override is invalid")
        discovered: dict[str, str] = {}
        current = None
        for line in override_text.splitlines():
            service_match = re.fullmatch(r"  ([a-z0-9][a-z0-9-]{0,62}):", line)
            if service_match:
                current = service_match.group(1)
                continue
            image_match = re.fullmatch(r"    image: (sha256:[0-9a-f]{64})", line)
            if image_match and current:
                discovered[current] = image_match.group(1)
        if discovered != services:
            reject("release Compose image pins do not match the signed manifest")
    elif PurePosixPath("images.tar") in seen:
        reject("undeclared images.tar is present")
    elif images.get("services") not in ({}, None):
        reject("code-only bundle declares image service pins")

    sbom = manifest.get("sbom")
    if not isinstance(sbom, dict):
        reject("manifest SBOM metadata is invalid")
    sbom_path = sbom.get("path")
    sbom_digest = sbom.get("sha256")
    if (
        sbom_path != "sbom/source.cdx.json"
        or not isinstance(sbom_digest, str)
        or not SHA256.fullmatch(sbom_digest)
        or sbom.get("format") != "CycloneDX-1.6"
    ):
        reject("manifest source SBOM metadata is invalid")
    sbom_member = next(member for member, name in validated if name == PurePosixPath(sbom_path))
    sbom_stream = archive.extractfile(sbom_member)
    if sbom_stream is None:
        reject("source SBOM is not readable")
    sbom_bytes = sbom_stream.read()
    if hashlib.sha256(sbom_bytes).hexdigest() != sbom_digest:
        reject("source SBOM digest does not match the signed manifest")
    try:
        sbom_document = json.loads(sbom_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("source SBOM is invalid JSON")
    if not isinstance(sbom_document, dict) or sbom_document.get("bomFormat") != "CycloneDX":
        reject("source SBOM is not CycloneDX JSON")

    image_sboms = sbom.get("images")
    if not isinstance(image_sboms, list) or (images["included"] and not image_sboms) or (not images["included"] and image_sboms):
        reject("manifest image SBOM metadata is invalid")
    declared_image_sbom_paths: set[PurePosixPath] = set()
    for record in image_sboms:
        if not isinstance(record, dict):
            reject("manifest image SBOM metadata is invalid")
        path, digest, image = record.get("path"), record.get("sha256"), record.get("image")
        if (
            not isinstance(path, str)
            or not re.fullmatch(r"sbom/images/[0-9a-f]{64}\.cdx\.json", path)
            or not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or not isinstance(image, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
            or record.get("format") != "CycloneDX-1.6"
        ):
            reject("manifest image SBOM metadata is invalid")
        member_path = PurePosixPath(path)
        if member_path in declared_image_sbom_paths or member_path not in seen:
            reject("manifest image SBOM path is duplicate or missing")
        declared_image_sbom_paths.add(member_path)
        member = next(item for item, name in validated if name == member_path)
        stream = archive.extractfile(member)
        if stream is None or hashlib.file_digest(stream, "sha256").hexdigest() != digest:
            reject("image SBOM digest does not match the signed manifest")
    return validated, manifest


def extract(archive: tarfile.TarFile, members: list[tuple[tarfile.TarInfo, PurePosixPath]], destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        reject("extraction destination must be empty")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    root = destination.resolve()
    for member, name in members:
        target = destination.joinpath(*name.parts)
        if root not in target.resolve().parents and target.resolve() != root:
            reject(f"extraction escaped destination: {name}")
        if member.isdir():
            target.mkdir(mode=member.mode & 0o755, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            reject(f"could not read archive member: {name}")
        with target.open("xb") as output:
            shutil.copyfileobj(source, output)
        os.chmod(target, member.mode & 0o755)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--extract-to", type=Path)
    arguments = parser.parse_args()
    with tarfile.open(arguments.bundle, "r:gz") as archive:
        members, manifest = validate(archive)
        if arguments.extract_to:
            extract(archive, members, arguments.extract_to)
    print(json.dumps({"status": "verified", "version": manifest["version"], "images": manifest["images"]["included"]}))


if __name__ == "__main__":
    main()
