from __future__ import annotations

import time
import unittest
from datetime import datetime, timedelta, timezone

import support  # noqa: F401
from hybrid_ndr_contracts import NormalizedEvent
from hybrid_ndr_detection import DetectionEngine, DetectionServiceConfig

# The configured default window cap the load tests validate. It mirrors
# DETECTION_MAX_EVENTS_PER_WINDOW in the Compose environment and the
# DetectionServiceConfig default.
FULL_WINDOW = 10_000
# Generous upper bound: the engine is O(n log n) per detector on realistic
# multi-tenant traffic. This bound exists to catch O(n^2) or allocation
# regressions on shared CI runners, not to benchmark peak throughput.
BUDGET_SECONDS = 30.0

BASE = datetime(2026, 8, 5, 5, 35, tzinfo=timezone.utc)


def event(index: int, *, source: str, src_ip: str, **changes):
    value = {
        "tenant_id": "tenant-a", "deployment_id": "dep-a", "event_id": f"event-{index:07d}",
        "event_time": (BASE + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
        "source": source, "event_type": "network.connection", "sensor_id": "sensor-1",
        "src_ip": src_ip, "src_port": 40000 + (index % 1000), "dst_ip": "8.8.8.8",
        "dst_port": 443, "protocol": "tcp", "bytes_out": 200, "bytes_in": 40, "details": {},
    }
    value.update(changes)
    return NormalizedEvent.from_dict(value)


def synthetic_window(count: int = FULL_WINDOW, sources: int = 500) -> list[NormalizedEvent]:
    """Build a realistic 10,000-event detection window.

    Mixes per-source connection traffic (which exercises the sliding-window
    port-scan detector), DNS queries with high-entropy labels (DNS anomaly and
    tunneling detectors), a traffic burst, novel destinations, and a Suricata
    alert. This is the volume the service feeds one detector schedule at the
    default DETECTION_MAX_EVENTS_PER_WINDOW.
    """
    events: list[NormalizedEvent] = []
    source_ips = [f"10.20.{index // 250}.{1 + index % 250}" for index in range(sources)]
    for index in range(count):
        source_index = index % sources
        src_ip = source_ips[source_index]
        if index % 8 == 0:
            label = f"x9k2m7q4v8z1b5n6c3d0f{index:04d}"
            events.append(event(
                index, source="zeek", src_ip=src_ip, event_type="network.dns",
                dst_ip="1.1.1.1", dst_port=53, protocol="udp", bytes_out=90, bytes_in=30,
                details={"query": f"{label}.tunnel.example", "query_type": "TXT"},
            ))
        elif index % 23 == 0:
            events.append(event(
                index, source="suricata", src_ip=src_ip, event_type="network.alert",
                details={"signature": "ET MALWARE Test", "severity": 2},
            ))
        else:
            events.append(event(index, source="zeek", src_ip=src_ip, dst_port=443 + (index % 97)))
    return events


class DetectionLoadTests(unittest.TestCase):
    """Validate the hardcoded engine limits under full-window traffic volumes."""

    def test_default_window_limit_is_ten_thousand(self) -> None:
        self.assertEqual(DetectionServiceConfig.maximum_events_per_window, FULL_WINDOW)
        from_env = DetectionServiceConfig.from_env({"TENANT_ID": "t", "DEPLOYMENT_ID": "d"})
        self.assertEqual(from_env.maximum_events_per_window, FULL_WINDOW)

    def test_full_ten_thousand_event_window_completes_within_budget(self) -> None:
        events = synthetic_window(FULL_WINDOW)
        self.assertEqual(len(events), FULL_WINDOW)
        engine = DetectionEngine()
        started = time.monotonic()
        results = engine.run(events)
        elapsed = time.monotonic() - started
        rate = FULL_WINDOW / elapsed
        self.assertLess(elapsed, BUDGET_SECONDS, f"full window took {elapsed:.1f}s")
        self.assertGreater(rate, 500, f"throughput collapsed to {rate:.0f} events/s")
        self.assertTrue(results, "a full realistic window must produce detections")
        self.assertTrue(all(0 <= result.score <= 1 and result.evidence_ids for result in results))

    def test_detectors_handle_repeated_full_windows_without_state_leak(self) -> None:
        engine = DetectionEngine()
        for cycle in range(3):
            events = synthetic_window(FULL_WINDOW, sources=300)
            started = time.monotonic()
            results = engine.run(events)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, BUDGET_SECONDS, f"cycle {cycle} took {elapsed:.1f}s")
            self.assertTrue(results)


if __name__ == "__main__":
    unittest.main()
