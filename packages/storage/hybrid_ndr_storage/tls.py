from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse
from urllib.request import HTTPSHandler, build_opener


def verified_opener(ca_file: str) -> Any:
    """Return a callable opener that verifies a private-LAN CA over TLS 1.2+.

    A missing or non-regular CA file is a configuration failure: internal
    credential-bearing hops must not silently downgrade to unverified HTTPS.
    The returned callable matches the ``opener(request, timeout=...)`` contract
    used by the storage adapters.
    """
    path = Path(ca_file)
    if not path.is_file() or path.is_symlink():
        raise ValueError("CA file must reference a regular non-symlink file")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    director = build_opener(HTTPSHandler(context=context))

    def open(request, timeout: float | None = None):  # noqa: ANN001, ANN201
        return director.open(request, timeout=timeout)

    return open


def postgres_dsn_with_tls(dsn: str, ca_file: str) -> str:
    """Add ``sslmode=verify-full`` and the private CA to a Postgres URL."""
    parsed = urlparse(dsn)
    if not parsed.hostname:
        raise ValueError("POSTGRES_URL must include a host")
    params = []
    if parsed.query:
        existing = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)
        params.extend(f"{key}={value}" for key, value in existing.items())
    params.append("sslmode=verify-full")
    params.append(f"sslrootcert={ca_file}")
    return urlunparse(parsed._replace(query="&".join(params)))