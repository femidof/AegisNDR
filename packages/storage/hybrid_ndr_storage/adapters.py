from __future__ import annotations

import datetime as dt
import base64
import hashlib
import hmac
import importlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from .ports import Readiness, ReadinessOnlyAdapter
from .tls import verified_opener


def _elapsed(start: float) -> int:
    return max(0, round((time.monotonic() - start) * 1000))


def _safe_error(exc: BaseException) -> str:
    # Never put DSNs, credentials, response bodies, or raw exception reprs in health output.
    if isinstance(exc, ModuleNotFoundError):
        return "database driver is not installed"
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, (TimeoutError, URLError, OSError)):
        return "connection failed"
    return "readiness query failed"


@dataclass
class SQLiteAdapter:
    path: str
    backend: str = "sqlite"
    supports_product_io: bool = True

    def readiness(self) -> Readiness:
        started = time.monotonic()
        try:
            connection = sqlite3.connect(self.path, timeout=1)
            try:
                connection.execute("SELECT 1").fetchone()
            finally:
                connection.close()
            return Readiness(self.backend, True, "sql", "query succeeded", _elapsed(started))
        except (OSError, sqlite3.Error) as exc:
            return Readiness(self.backend, False, "sql", _safe_error(exc), _elapsed(started))


@dataclass
class FilesystemEvidenceAdapter:
    path: str
    backend: str = "filesystem"
    supports_product_io: bool = True

    def readiness(self) -> Readiness:
        started = time.monotonic()
        directory = Path(self.path)
        ready = directory.is_dir() and os.access(directory, os.R_OK | os.W_OK | os.X_OK)
        return Readiness(
            self.backend, ready, "filesystem", "directory accessible" if ready else "directory is not accessible", _elapsed(started)
        )


class _ReadinessOnlyPostgresMetadataAdapter(ReadinessOnlyAdapter):
    backend = "postgresql"

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "local_state",
        timeout_seconds: float = 3.0,
        driver_loader: Callable[[str], Any] = importlib.import_module,
    ) -> None:
        self.dsn = dsn
        self.schema = schema
        self.timeout_seconds = timeout_seconds
        self._driver_loader = driver_loader

    def readiness(self) -> Readiness:
        started = time.monotonic()
        try:
            psycopg = self._driver_loader("psycopg")
            with psycopg.connect(self.dsn, connect_timeout=max(1, int(self.timeout_seconds))) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT to_regnamespace(%s)", (self.schema,))
                    row = cursor.fetchone()
                    if not row or row[0] is None:
                        return Readiness(self.backend, False, "schema", "required schema is missing", _elapsed(started))
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            return Readiness(self.backend, True, "schema", "connection and schema verified", _elapsed(started))
        except Exception as exc:  # driver-specific error hierarchy is loaded dynamically
            return Readiness(self.backend, False, "schema", _safe_error(exc), _elapsed(started))


class _ReadinessOnlyClickHouseEventAdapter(ReadinessOnlyAdapter):
    backend = "clickhouse"

    def __init__(
        self,
        endpoint: str,
        *,
        database: str = "hybrid_ndr",
        user: str = "",
        password: str = "",
        timeout_seconds: float = 3.0,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.database = database
        self.user = user
        self.password = password
        self.timeout_seconds = timeout_seconds
        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)

    def readiness(self) -> Readiness:
        started = time.monotonic()
        query = f"SELECT count() FROM system.databases WHERE name = {self._quote(self.database)} FORMAT TabSeparated"
        url = f"{self.endpoint}/?{urlencode({'query': query})}"
        try:
            headers = {"Accept": "text/plain", "User-Agent": "hybrid-ndr-local-api/1"}
            if self.user:
                credentials = base64.b64encode(f"{self.user}:{self.password}".encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {credentials}"
            response = self._opener(
                Request(url, headers=headers),
                timeout=self.timeout_seconds,
            )
            body = response.read(65).decode("ascii", "strict").strip()
            ready = body == "1"
            return Readiness(
                self.backend, ready, "database", "database verified" if ready else "required database is missing", _elapsed(started)
            )
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError) as exc:
            return Readiness(self.backend, False, "database", _safe_error(exc), _elapsed(started))

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


class _ReadinessOnlyMinIOEvidenceAdapter(ReadinessOnlyAdapter):
    backend = "minio"

    def __init__(
        self,
        endpoint: str,
        *,
        bucket: str,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
        timeout_seconds: float = 3.0,
        ca_file: str = "",
        opener: Callable[..., Any] | None = None,
        utcnow: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.bucket = bucket
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.timeout_seconds = timeout_seconds
        self._opener = opener if opener is not None else (verified_opener(ca_file) if ca_file else urlopen)
        self._utcnow = utcnow

    def readiness(self) -> Readiness:
        started = time.monotonic()
        try:
            health = self._opener(
                Request(f"{self.endpoint}/minio/health/ready", headers={"User-Agent": "hybrid-ndr-local-api/1"}),
                timeout=self.timeout_seconds,
            )
            status = getattr(health, "status", 200)
            if status != 200:
                return Readiness(self.backend, False, "bucket", "service is not ready", _elapsed(started))
            bucket_request = self._signed_head_bucket()
            bucket_response = self._opener(bucket_request, timeout=self.timeout_seconds)
            bucket_status = getattr(bucket_response, "status", 200)
            ready = bucket_status in {200, 204}
            return Readiness(
                self.backend, ready, "bucket", "service and bucket verified" if ready else "required bucket is missing", _elapsed(started)
            )
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return Readiness(self.backend, False, "bucket", _safe_error(exc), _elapsed(started))

    def _signed_head_bucket(self) -> Request:
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("invalid MinIO endpoint")
        timestamp = self._utcnow().astimezone(dt.timezone.utc)
        amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = timestamp.strftime("%Y%m%d")
        canonical_uri = f"/{quote(self.bucket, safe='-_.~')}"
        host = parsed.netloc
        payload_hash = hashlib.sha256(b"").hexdigest()
        canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = "\n".join(("HEAD", canonical_uri, "", canonical_headers, signed_headers, payload_hash))
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join((
            "AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        ))
        signing_key = self._signature_key(date_stamp)
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return Request(
            f"{self.endpoint}{canonical_uri}", method="HEAD",
            headers={
                "Authorization": authorization,
                "Host": host,
                "X-Amz-Content-Sha256": payload_hash,
                "X-Amz-Date": amz_date,
                "User-Agent": "hybrid-ndr-local-api/1",
            },
        )

    def _signature_key(self, date_stamp: str) -> bytes:
        date_key = hmac.new(("AWS4" + self.secret_key).encode("utf-8"), date_stamp.encode("ascii"), hashlib.sha256).digest()
        region_key = hmac.new(date_key, self.region.encode("utf-8"), hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
        return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


# Keep the public adapter import paths stable while replacing the former
# readiness-only production implementations with full product I/O adapters.
from .production import (  # noqa: E402
    ClickHouseEventAdapter,
    MinIOEvidenceAdapter,
    PostgresMetadataAdapter,
)
