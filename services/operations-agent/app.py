#!/usr/bin/env python3
from __future__ import annotations

import hmac
import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
for dependency in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "audit",
    ROOT / "packages" / "storage",
    ROOT / "packages" / "observability",
    ROOT / "services" / "operations-agent",
):
    sys.path.insert(0, str(dependency))

from hybrid_ndr_observability import Telemetry  # noqa: E402
from hybrid_ndr_operations import (  # noqa: E402
    ClickHouseOperations,
    OperationsAgent,
    OperationsConfig,
    PostgresOperations,
    render_prometheus,
)
from hybrid_ndr_operations.service import LocalOperationsBackend  # noqa: E402


def authorized_for_metrics(metrics_token: str, authorization: str) -> bool:
    """True when the scrape is authenticated; no token configured = open."""
    if not metrics_token:
        return True
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return False
    return hmac.compare_digest(metrics_token.encode("utf-8"), value.strip().encode("utf-8"))


def main() -> int:
    config = OperationsConfig.from_env(os.environ)
    postgres = PostgresOperations(config.postgres_url)
    postgres.migrate(config.migration_file)
    clickhouse = ClickHouseOperations(
        config.clickhouse_url,
        config.clickhouse_database,
        config.clickhouse_user,
        config.clickhouse_password,
        ca_file=config.ca_file,
    )
    agent = OperationsAgent(
        config,
        LocalOperationsBackend(postgres, clickhouse, config.minio_url, ca_file=config.ca_file),
    )
    telemetry = Telemetry("operations-agent")
    stop = threading.Event()

    def poll() -> None:
        while not stop.is_set():
            with telemetry.span("operations.poll"):
                snapshot = agent.poll()
            print(json.dumps({
                "event": "operations_health",
                "status": snapshot["status"],
                "checked_at": snapshot["checked_at"],
            }, separators=(",", ":"), sort_keys=True), flush=True)
            stop.wait(config.poll_seconds)

    polling = threading.Thread(target=poll, name="operations-poll", daemon=True)
    polling.start()

    # Prometheus scrape token. When configured, /metrics requires a bearer
    # token so storage capacity telemetry is not readable by any container on
    # the internal data network.
    metrics_token = os.environ.get("OPERATIONS_METRICS_TOKEN", "").strip()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                if not authorized_for_metrics(metrics_token, self.headers.get("Authorization", "")):
                    body = b'{"error":{"code":"metrics_authentication_required"}}'
                    status = 401
                    content_type = "application/json; charset=utf-8"
                    self.send_response(status)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("WWW-Authenticate", 'Bearer realm="hybrid-ndr-metrics"')
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = render_prometheus(agent).encode("utf-8")
                status = 200
                content_type = "text/plain; version=0.0.4; charset=utf-8"
            elif path in {"/healthz", "/v1/support/health"}:
                body = json.dumps(agent.snapshot, separators=(",", ":"), sort_keys=True).encode("utf-8")
                status = 200 if agent.snapshot.get("status") == "healthy" else 503
                content_type = "application/json; charset=utf-8"
            else:
                body = b'{"error":{"code":"route_not_found"}}'
                status = 404
                content_type = "application/json; charset=utf-8"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("0.0.0.0", 9108), Handler)

    def shutdown(_signum: int, _frame: object) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever()
    finally:
        stop.set()
        polling.join(timeout=5)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
