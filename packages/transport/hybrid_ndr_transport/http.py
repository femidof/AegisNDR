from __future__ import annotations

import hashlib
import http.client
import json
import socket
import ssl
import sys
import threading
import traceback
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class TransportConfigurationError(ValueError):
    """Raised before a transport can run with unsafe or incomplete settings."""


class OutboundHTTPError(RuntimeError):
    """A content-free outbound request failure safe to record locally."""

    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _is_loopback(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _regular_file(name: str, value: str) -> str:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise TransportConfigurationError(f"{name} must reference a regular non-symlink file")
    return str(path)


class JSONHTTPClient:
    """Bounded JSON client that uses verified TLS and optional client certificates.

    It intentionally has no logging, cookies, redirect handling, response cache, or
    persistence hook. Callers may record only their own allowlisted metadata.
    """

    def __init__(
        self,
        base_url: str,
        *,
        ca_file: str = "",
        certificate_file: str = "",
        private_key_file: str = "",
        allow_insecure_loopback: bool = False,
        timeout_seconds: float = 15.0,
        maximum_response_bytes: int = 1_000_000,
        default_headers: Mapping[str, str] | None = None,
        opener: Any | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise TransportConfigurationError("outbound base URL must not contain credentials, a query, or a fragment")
        if parsed.scheme == "http":
            if not allow_insecure_loopback or not _is_loopback(parsed.hostname):
                raise TransportConfigurationError("outbound HTTP is permitted only for explicitly enabled loopback development")
        elif parsed.scheme != "https" or not parsed.hostname:
            raise TransportConfigurationError("outbound base URL must be an HTTPS URL")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise TransportConfigurationError("outbound timeout must be between 0 and 120 seconds")
        if maximum_response_bytes < 1_024 or maximum_response_bytes > 10_000_000:
            raise TransportConfigurationError("maximum response size is outside the supported range")

        self.base_url = base_url.rstrip("/") + "/"
        self.timeout_seconds = float(timeout_seconds)
        self.maximum_response_bytes = int(maximum_response_bytes)
        self.default_headers = dict(default_headers or {})

        if opener is not None:
            self._opener = opener
            return
        handlers: list[Any] = [_NoRedirects()]
        if parsed.scheme == "https":
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=_regular_file("CA file", ca_file) if ca_file else None,
            )
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if bool(certificate_file) != bool(private_key_file):
                raise TransportConfigurationError("client certificate and private key must be configured together")
            if certificate_file:
                context.load_cert_chain(
                    _regular_file("client certificate", certificate_file),
                    _regular_file("client private key", private_key_file),
                )
            handlers.append(HTTPSHandler(context=context))
        self._opener = build_opener(*handlers)

    @staticmethod
    def _bounded_read(response: Any, amount: int, timeout_seconds: float) -> bytes:
        """Read with a socket-level deadline.

        ``urlopen(timeout=...)`` only bounds connection/handshake; a Slowloris
        peer that dribbles the body could otherwise stall the reader thread
        indefinitely. Setting the underlying socket timeout bounds each read.
        """
        raw = getattr(getattr(response, "fp", None), "raw", None)
        underlying = getattr(raw, "_sock", None)
        if underlying is None:
            return response.read(amount)
        previous = underlying.gettimeout()
        underlying.settimeout(timeout_seconds)
        try:
            return response.read(amount)
        finally:
            try:
                underlying.settimeout(previous)
            except OSError:
                # The peer closed the socket once the body was fully read;
                # there is nothing left to restore.
                pass

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/"):
            raise TransportConfigurationError("outbound request path must be absolute")
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "hybrid-ndr/0.1",
            **self.default_headers,
            **dict(headers or {}),
        }
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(
            urljoin(self.base_url, path.lstrip("/")),
            data=encoded,
            headers=request_headers,
            method=method.upper(),
        )
        response = None
        try:
            response = self._opener.open(request, timeout=self.timeout_seconds)
            raw = self._bounded_read(response, self.maximum_response_bytes + 1, self.timeout_seconds)
        except HTTPError as exc:
            # Never read or propagate an upstream error body: it can contain
            # reflected evidence, provider internals, or credentials.
            exc.close()
            raise OutboundHTTPError("http_error", status=int(exc.code)) from None
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise OutboundHTTPError("transport_unavailable") from None
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if close is not None:
                    close()
        if len(raw) > self.maximum_response_bytes:
            raise OutboundHTTPError("response_too_large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise OutboundHTTPError("invalid_json_response") from None
        if not isinstance(value, dict):
            raise OutboundHTTPError("invalid_json_response")
        return value

    def request_stream(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        chunk_size: int = 4096,
    ) -> Iterator[bytes]:
        """Stream a bounded response body without buffering the whole payload.

        The same TLS verification, authentication headers, redirect refusal,
        and total byte bound as `request` apply. Each yielded chunk is at most
        `chunk_size` bytes and the caller must consume the iterator; abandoning
        it releases the socket through garbage collection of the response.
        """
        if not path.startswith("/"):
            raise TransportConfigurationError("outbound request path must be absolute")
        encoded = None if body is None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "hybrid-ndr/0.1",
            **self.default_headers,
            **dict(headers or {}),
        }
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(
            urljoin(self.base_url, path.lstrip("/")),
            data=encoded,
            headers=request_headers,
            method=method.upper(),
        )
        try:
            response = self._opener.open(request, timeout=self.timeout_seconds)
        except HTTPError as exc:
            # Never read or propagate an upstream error body: it can contain
            # reflected evidence, provider internals, or credentials.
            raise OutboundHTTPError("http_error", status=int(exc.code)) from None
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise OutboundHTTPError("transport_unavailable") from None
        remaining = self.maximum_response_bytes
        try:
            while True:
                chunk = self._bounded_read(response, min(chunk_size, remaining + 1), self.timeout_seconds)
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise OutboundHTTPError("response_too_large")
                remaining -= len(chunk)
                yield chunk
        except (TimeoutError, OSError, http.client.HTTPException):
            raise OutboundHTTPError("transport_unavailable") from None


class _WSGIRequestHandler(BaseHTTPRequestHandler):
    """Production WSGI connection handler.

    wsgiref's handler/server is explicitly documented as unsuitable for
    production: single-threaded, no request timeouts, no header limits, and
    no keep-alive. This handler provides concurrent handling (via
    ThreadingHTTPServer), a per-request socket timeout, explicit request-line
    and header caps, HTTP/1.1 keep-alive, and verified mTLS peer fingerprints
    in the WSGI environ.
    """

    protocol_version = "HTTP/1.1"
    timeout = 30.0
    server_version = "HybridNDR/1"
    sys_version = ""
    maximum_request_line = 8_192
    maximum_header_count = 100
    maximum_header_bytes = 65_536
    maximum_body_bytes = 16_777_216

    def handle_one_request(self) -> None:
        # Defaults make send_error safe even when parsing fails before the
        # request line is fully validated.
        self.command = ""
        self.path = ""
        self.request_version = "HTTP/1.1"
        try:
            self.raw_requestline = self.rfile.readline(self.maximum_request_line + 1)
            if not self.raw_requestline:
                self.close_connection = True
                return
            self.requestline = self.raw_requestline.decode("iso-8859-1").rstrip("\r\n")
            if len(self.raw_requestline) > self.maximum_request_line:
                self.send_error(414, "Request-URI Too Long")
                self.close_connection = True
                return
            words = self.requestline.split()
            if len(words) != 3 or not words[2].startswith("HTTP/"):
                self.send_error(400, "Bad request syntax")
                self.close_connection = True
                return
            command, path, version = words
            headers: dict[str, str] = {}
            total_bytes = 0
            while True:
                line = self.rfile.readline(self.maximum_header_bytes + 1)
                if not line or line in (b"\r\n", b"\n"):
                    break
                total_bytes += len(line)
                if len(line) > self.maximum_header_bytes or total_bytes > self.maximum_header_bytes:
                    self.send_error(431, "Request Header Fields Too Large")
                    self.close_connection = True
                    return
                if len(headers) >= self.maximum_header_count:
                    self.send_error(431, "Request Header Fields Too Large")
                    self.close_connection = True
                    return
                name, _, value = line.decode("iso-8859-1").partition(":")
                name = name.strip()
                if not name or not name.replace("-", "").isalnum():
                    self.send_error(400, "Bad request syntax")
                    self.close_connection = True
                    return
                headers[name.lower()] = value.strip()
            transfer_encoding = headers.get("transfer-encoding", "").lower()
            if transfer_encoding and transfer_encoding != "identity":
                self.send_error(501, "Unsupported transfer encoding")
                self.close_connection = True
                return
            try:
                content_length = int(headers.get("content-length", "0") or "0")
            except ValueError:
                self.send_error(400, "Bad request syntax")
                self.close_connection = True
                return
            if content_length < 0 or content_length > self.maximum_body_bytes:
                self.send_error(413, "Request Entity Too Large")
                self.close_connection = True
                return
            connection_token = headers.get("connection", "").lower()
            self.close_connection = (
                version != "HTTP/1.1" or connection_token == "close" or "keep-alive" not in connection_token
            )
            body = self.rfile.read(content_length) if content_length else b""
            self.command, self.path, self.request_version = command, path, version
            self._dispatch(environ_for(self, headers, content_length, body))
        except (TimeoutError, socket.timeout):
            self.close_connection = True
        except Exception:
            self.close_connection = True
            traceback.print_exc(file=sys.stderr)

    def _dispatch(self, environ: dict[str, Any]) -> None:
        status: list[str] = ["500 Internal Server Error"]
        response_headers: list[tuple[str, str]] = []
        try:
            result = self.server.application(environ, self._start_response_factory(status, response_headers))
            body = b"".join(result)
            if hasattr(result, "close"):
                result.close()
        except Exception:
            traceback.print_exc(file=sys.stderr)
            body = b""
            status = ["500 Internal Server Error"]
            response_headers = [("Content-Type", "text/plain; charset=utf-8")]
        self._send_response(status[0], response_headers, body)

    def _start_response_factory(
        self, status: list[str], response_headers: list[tuple[str, str]]
    ) -> Any:
        def start_response(provided_status: str, provided_headers: list[tuple[str, str]], exc_info=None):  # noqa: ANN001
            if exc_info is not None:
                raise exc_info[1].with_traceback(exc_info[2])
            status[0] = provided_status
            response_headers[:] = list(provided_headers)
            return lambda _data: None

        return start_response

    def _send_response(self, status: str, response_headers: list[tuple[str, str]], body: bytes) -> None:
        if self.command == "HEAD":
            body = b""
        try:
            code = int(status.split(" ", 1)[0])
            reason = status.split(" ", 1)[1] if " " in status else ""
        except (ValueError, IndexError):
            code, reason = 500, "Internal Server Error"
        headers = list(response_headers)
        names = {name.lower() for name, _value in headers}
        if "content-length" not in names:
            headers.append(("Content-Length", str(len(body))))
        if "server" not in names:
            headers.append(("Server", self.version_string()))
        if self.close_connection:
            headers.append(("Connection", "close"))
        header_block = (
            f"HTTP/1.1 {code} {reason}\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in headers)
            + "\r\n"
        ).encode("iso-8859-1")
        try:
            self.wfile.write(header_block)
            if body:
                self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            self.close_connection = True

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Access logs are intentionally not emitted; failures surface through
        # traceback.print_exc so operational errors are not silently lost.
        return None

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        print(f"hybrid-ndr-wsgi: {format % args}", file=sys.stderr)


def environ_for(
    handler: _WSGIRequestHandler,
    headers: Mapping[str, str],
    content_length: int,
    body: bytes,
) -> dict[str, Any]:
    path, _, query = handler.path.partition("?")
    environ: dict[str, Any] = {
        "REQUEST_METHOD": handler.command,
        "SCRIPT_NAME": "",
        "PATH_INFO": unquote(path, errors="replace"),
        "QUERY_STRING": query,
        "CONTENT_TYPE": headers.get("content-type", ""),
        "CONTENT_LENGTH": str(content_length),
        "SERVER_NAME": str(handler.server.server_address[0]) or "localhost",
        "SERVER_PORT": str(handler.server.server_address[1]),
        "SERVER_PROTOCOL": handler.request_version,
        "SERVER_SOFTWARE": handler.version_string(),
        "REMOTE_ADDR": handler.client_address[0],
        "REMOTE_HOST": handler.client_address[0],
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "https" if isinstance(handler.connection, ssl.SSLSocket) else "http",
        "wsgi.input": BytesIO(body),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    for name, value in headers.items():
        if name in {"content-type", "content-length"}:
            continue
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    if isinstance(handler.connection, ssl.SSLSocket):
        certificate = handler.connection.getpeercert(binary_form=True)
        if certificate:
            environ["SSL_CLIENT_CERT_SHA256"] = hashlib.sha256(certificate).hexdigest()
    return environ


class _ProductionWSGIServer(ThreadingHTTPServer):
    """Threaded WSGI server with bounded concurrency and optional verified TLS.

    Connections are handled concurrently in daemon threads; a bounded
    semaphore refuses connections beyond the concurrency cap instead of
    spawning unbounded threads. The server socket carries a per-connection
    read timeout and the handler enforces request-line/header/body caps.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        application: Any,
        *,
        ssl_context: ssl.SSLContext | None = None,
        maximum_concurrent_requests: int = 64,
    ) -> None:
        self.application = application
        self.ssl_context = ssl_context
        self._request_slots = threading.BoundedSemaphore(max(int(maximum_concurrent_requests), 4))
        super().__init__(server_address, _WSGIRequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            try:
                request.shutdown(socket.SHUT_RDWR)
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        finally:
            self._request_slots.release()

    def server_bind(self) -> None:
        super().server_bind()
        if self.ssl_context is not None:
            self.socket = self.ssl_context.wrap_socket(self.socket, server_side=True)


def make_server(
    host: str,
    port: int,
    application: Any,
    *,
    certificate_file: str = "",
    private_key_file: str = "",
    client_ca_file: str = "",
    require_client_certificate: bool = True,
) -> _ProductionWSGIServer:
    """Create a production WSGI server, enabling verified TLS whenever TLS
    files are set.

    `CERT_OPTIONAL` is useful for a control plane that serves unauthenticated
    enrollment and authenticated deployment routes on the same listener. The
    application still requires a verified peer fingerprint on protected routes.
    """

    tls_values = (certificate_file, private_key_file, client_ca_file)
    if any(tls_values) and not all(tls_values):
        raise TransportConfigurationError("server certificate, key, and client CA must be configured together")
    ssl_context = None
    if all(tls_values):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(
            _regular_file("server certificate", certificate_file),
            _regular_file("server private key", private_key_file),
        )
        context.load_verify_locations(cafile=_regular_file("client CA", client_ca_file))
        context.verify_mode = ssl.CERT_REQUIRED if require_client_certificate else ssl.CERT_OPTIONAL
        ssl_context = context
    return _ProductionWSGIServer((host, port), application, ssl_context=ssl_context)
