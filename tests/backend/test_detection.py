from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

import support  # noqa: F401
from hybrid_ndr_contracts import NormalizedEvent
from hybrid_ndr_detection import DetectionEngine


BASE = datetime(2026, 8, 5, 5, 35, tzinfo=timezone.utc)


def event(index: int, **changes):
    value = {
        "tenant_id": "tenant-a", "deployment_id": "dep-a", "event_id": f"event-{index:03d}",
        "event_time": (BASE + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
        "source": "zeek", "event_type": "network.connection", "sensor_id": "sensor-1",
        "src_ip": "10.0.0.5", "src_port": 50000 + index, "dst_ip": "8.8.8.8",
        "dst_port": 443, "protocol": "tcp", "bytes_out": 100, "bytes_in": 10, "details": {},
    }
    value.update(changes)
    return NormalizedEvent.from_dict(value)


class DetectionTests(unittest.TestCase):
    def test_all_required_detectors_emit_evidence_backed_results(self):
        events = [event(index, dst_port=1000 + index) for index in range(51)]
        for index in range(45):
            label = f"x9k2m7q4v8z1b5n6c3d0f{index:03d}"
            events.append(event(
                100 + index, event_id=f"dns-{index:03d}", event_type="network.dns", src_ip="10.0.0.9",
                dst_ip="1.1.1.1", dst_port=53, protocol="udp", bytes_out=90, bytes_in=30,
                details={"query": f"{label}.tunnel.example", "query_type": "TXT"},
            ))
        events.extend([
            event(200, event_id="spike-1", src_ip="10.0.0.20", bytes_out=50_000),
            event(201, event_id="novel-1", src_ip="10.0.0.30", dst_ip="9.9.9.9"),
            event(202, event_id="suricata-1", source="suricata", event_type="network.alert", src_ip="10.0.0.40", details={"signature": "ET MALWARE Test", "severity": 2}),
        ])
        baselines = {
            "10.0.0.9": {"dns_median": 5, "dns_mad": 1, "dns_p99": 12, "peer_dns_p99": 15, "known_dns_destinations": ["8.8.8.8"]},
            "10.0.0.20": {"traffic_p99": 1000, "peer_traffic_p99": 1200, "absolute_traffic_threshold": 2000},
            "10.0.0.30": {"known_destinations": ["8.8.8.8"]},
        }
        results = DetectionEngine().run(events, baselines)
        ids = {result.detector_id for result in results}
        self.assertTrue({"port-scan-v1", "dns-volume-v1", "dns-tunneling-v1", "traffic-spike-v1", "new-destination-v1", "suricata-conversion-v1"}.issubset(ids))
        self.assertTrue(all(result.evidence_ids and 0 <= result.score <= 1 for result in results))

    def test_detection_has_no_cloud_dependency(self):
        engine = DetectionEngine()
        results = engine.run([event(index, dst_port=2000 + index) for index in range(51)])
        self.assertIn("port-scan-v1", {result.detector_id for result in results})


if __name__ == "__main__":
    unittest.main()
