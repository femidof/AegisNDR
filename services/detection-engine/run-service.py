#!/usr/bin/env python3
"""Run the customer-local ClickHouse-to-PostgreSQL detection loop."""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
for dependency in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "audit",
    ROOT / "packages" / "storage",
    ROOT / "packages" / "observability",
    ROOT / "services" / "detection-engine",
):
    sys.path.insert(0, str(dependency))

from hybrid_ndr_detection import DetectionService, DetectionServiceConfig  # noqa: E402
from hybrid_ndr_observability import Telemetry, exception as log_exception, info as log_info  # noqa: E402
from hybrid_ndr_storage.adapters import ClickHouseEventAdapter, PostgresMetadataAdapter  # noqa: E402
from hybrid_ndr_storage.tls import postgres_dsn_with_tls  # noqa: E402


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _write_health(path: Path, stats: dict[str, int]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(
            {
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                **stats,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> int:
    config = DetectionServiceConfig.from_env()
    ca_file = os.environ.get("PERSISTENCE_CA_FILE", "").strip()
    metadata = PostgresMetadataAdapter(
        _required("POSTGRES_URL") if not ca_file else postgres_dsn_with_tls(_required("POSTGRES_URL"), ca_file),
        schema=os.environ.get("POSTGRES_SCHEMA", "local_state"),
    )
    events = ClickHouseEventAdapter(
        _required("CLICKHOUSE_URL"),
        database=os.environ.get("CLICKHOUSE_DATABASE", "hybrid_ndr"),
        user=_required("CLICKHOUSE_USER"),
        password=_required("CLICKHOUSE_PASSWORD"),
        timeout_seconds=float(os.environ.get("DETECTION_BACKEND_TIMEOUT_SECONDS", "10")),
        ca_file=ca_file,
    )
    metadata.ensure_detection_schema()
    service = DetectionService(config, events, metadata)
    telemetry = Telemetry("detection-engine")
    health_path = Path(os.environ.get("DETECTION_HEALTH_FILE", "/tmp/hybrid-ndr-detection-health.json"))
    stop = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    log_info("detection.service_started")
    try:
        while not stop.is_set():
            cycle_started = time.monotonic()
            try:
                with telemetry.span("detection.cycle"):
                    stats = service.run_cycle()
                telemetry.record_detection_cycle(
                    stats, (time.monotonic() - cycle_started) * 1000, succeeded=True
                )
                _write_health(health_path, stats)
                if stats["alerts_created"] or stats["baselines"]:
                    log_info(
                        "detection.cycle.completed",
                        events=stats["events"], alerts_created=stats["alerts_created"],
                        elapsed_ms=int((time.monotonic() - cycle_started) * 1000),
                    )
            except Exception as exc:  # The local backends can restart independently; retry without losing checkpoints.
                telemetry.record_detection_cycle(
                    {}, (time.monotonic() - cycle_started) * 1000, succeeded=False
                )
                log_exception(
                    "detection.cycle.failed", exc,
                    elapsed_ms=int((time.monotonic() - cycle_started) * 1000),
                )
            stop.wait(config.poll_seconds)
    finally:
        metadata.close()
        events.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
