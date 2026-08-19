#!/usr/bin/env python3
"""Detection-engine load benchmark.

Generates synthetic sensor traffic and times the full detection pipeline
(window normalization + all detectors) so operators can validate the
configured DETECTION_MAX_EVENTS_PER_WINDOW under realistic volumes before a
deployment carries live traffic.

Usage:
  python3 scripts/load-test-detection.py --events 100000 --sources 2000

The script prints events/sec, the elapsed wall time, and the detector result
breakdown. It never touches a network, database, or model endpoint.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "packages" / "contracts-python", ROOT / "services" / "detection-engine"):
    sys.path.insert(0, str(path))

from hybrid_ndr_contracts import NormalizedEvent  # noqa: E402
from hybrid_ndr_detection import DetectionEngine  # noqa: E402

BASE = datetime(2026, 8, 5, 5, 35, tzinfo=timezone.utc)


def make_events(count: int, sources: int) -> list[NormalizedEvent]:
    source_ips = [f"10.20.{index // 250}.{1 + index % 250}" for index in range(sources)]
    events: list[NormalizedEvent] = []
    for index in range(count):
        src_ip = source_ips[index % sources]
        value = {
            "tenant_id": "tenant-a", "deployment_id": "dep-a", "event_id": f"event-{index:08d}",
            "event_time": (BASE + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
            "source": "zeek", "event_type": "network.connection", "sensor_id": "sensor-1",
            "src_ip": src_ip, "src_port": 40000 + (index % 1000), "dst_ip": "8.8.8.8",
            "dst_port": 443 + (index % 97), "protocol": "tcp", "bytes_out": 200, "bytes_in": 40,
            "details": {},
        }
        if index % 8 == 0:
            value.update({
                "source": "zeek", "event_type": "network.dns", "dst_ip": "1.1.1.1",
                "dst_port": 53, "protocol": "udp", "bytes_out": 90, "bytes_in": 30,
                "details": {"query": f"x9k2m7q4v8z1b5n6c3d0f{index:04d}.tunnel.example", "query_type": "TXT"},
            })
        elif index % 23 == 0:
            value.update({
                "source": "suricata", "event_type": "network.alert",
                "details": {"signature": "ET MALWARE Test", "severity": 2},
            })
        events.append(NormalizedEvent.from_dict(value))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Load-test the local detection engine.")
    parser.add_argument("--events", type=int, default=100_000, help="total synthetic events (default 100000)")
    parser.add_argument("--sources", type=int, default=2_000, help="distinct source entities (default 2000)")
    parser.add_argument("--cycles", type=int, default=1, help="repeated windows to average (default 1)")
    args = parser.parse_args()
    if args.events < 1_000 or args.sources < 1 or args.cycles < 1:
        parser.error("--events must be >= 1000, --sources and --cycles must be >= 1")

    events = make_events(args.events, args.sources)
    engine = DetectionEngine()
    print(f"synthesized {len(events)} events across {args.sources} sources "
          f"(window cap default: 10000; run {args.cycles} cycle(s))")
    total_started = time.monotonic()
    best_rate = 0.0
    for cycle in range(args.cycles):
        started = time.monotonic()
        results = engine.run(events)
        elapsed = time.monotonic() - started
        rate = len(events) / elapsed
        best_rate = max(best_rate, rate)
        by_detector: dict[str, int] = {}
        for result in results:
            by_detector[result.detector_id] = by_detector.get(result.detector_id, 0) + 1
        print(f"cycle {cycle + 1}: {elapsed:.2f}s, {rate:,.0f} events/s, "
              f"{len(results)} detections {by_detector or ''}")
    print(f"total: {(time.monotonic() - total_started):.2f}s, best throughput {best_rate:,.0f} events/s")


if __name__ == "__main__":
    main()
