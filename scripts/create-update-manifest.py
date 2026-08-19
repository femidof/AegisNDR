#!/usr/bin/env python3
"""Create the canonical P-256 signed manifest consumed by customer update agents."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--artifact-name", required=True, help="registry/repository logical name without @sha256")
    parser.add_argument("--version", required=True)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--published-at")
    arguments = parser.parse_args()
    if not arguments.artifact.is_file() or arguments.artifact.is_symlink():
        raise SystemExit("artifact must be a regular non-symlink file")
    if not arguments.signing_key.is_file() or arguments.signing_key.is_symlink():
        raise SystemExit("signing key must be a regular non-symlink file")
    if stat.S_IMODE(arguments.signing_key.stat().st_mode) & 0o077:
        raise SystemExit("signing key permissions must not allow group or other access")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", arguments.version):
        raise SystemExit("version is invalid")
    if not re.fullmatch(r"[a-z][a-z0-9._-]{0,31}", arguments.channel):
        raise SystemExit("channel is invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:-]{0,511}", arguments.artifact_name):
        raise SystemExit("artifact name is invalid")
    inspected = subprocess.run(
        ["openssl", "pkey", "-in", str(arguments.signing_key), "-text", "-noout"],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspected.returncode != 0 or ("prime256v1" not in inspected.stdout and "P-256" not in inspected.stdout):
        raise SystemExit("manifest signing key must be ECDSA P-256")
    published = arguments.published_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit("published-at is invalid") from exc
    if parsed.tzinfo is None:
        raise SystemExit("published-at must include a timezone")
    manifest = {
        "schema_version": 1,
        "product": "hybrid-ndr",
        "channel": arguments.channel,
        "version": arguments.version,
        "artifact": f"{arguments.artifact_name}@sha256:{digest(arguments.artifact)}",
        "published_at": published,
        "signature_algorithm": "ECDSA_P256_SHA256",
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    with tempfile.TemporaryDirectory() as temporary_name:
        temporary = Path(temporary_name)
        payload, signature = temporary / "manifest", temporary / "signature"
        payload.write_bytes(canonical)
        os.chmod(payload, 0o600)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(arguments.signing_key), "-out", str(signature), str(payload)],
            check=True,
        )
        manifest["signature"] = base64.urlsafe_b64encode(signature.read_bytes()).decode("ascii").rstrip("=")
    arguments.output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{arguments.output.name}.", dir=arguments.output.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, arguments.output)
        os.chmod(arguments.output, 0o644)
    finally:
        Path(temporary_name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
