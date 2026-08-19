from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone

import support  # noqa: F401
from hybrid_ndr_contracts import NormalizedEvent
from hybrid_ndr_detection import DetectionService, DetectionServiceConfig, summarize_baseline_buckets


TENANT = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT = "22222222-2222-4222-8222-222222222222"
NOW = datetime(2026, 8, 5, 10, 0, tzinfo=timezone.utc)


def sensor_alert(index: int, ingested_at: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        tenant_id=TENANT,
        deployment_id=DEPLOYMENT,
        event_id=f"aaaaaaaa-aaaa-4aaa-8aaa-{index:012d}",
        event_time=(NOW + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
        ingested_at=ingested_at.isoformat().replace("+00:00", "Z"),
        source="suricata",
        event_type="network.alert",
        sensor_id="sensor-suricata-01",
        community_id="1:AAAAAAAAAAAAAAAAAAAAAAAAAAA",
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="tcp",
        raw_reference=f"/var/log/sensors/suricata/eve.json#flow_id={index}",
        details={"signature": f"Acceptance signature {index}", "severity": 2},
    )


class MemoryEventSource:
    def __init__(self, events):
        self.events = list(events)
        self.window_calls = []
        self.baseline_calls = []

    def events_ingested_between(self, tenant_id, deployment_id, start, end, *, limit):
        self.window_calls.append((tenant_id, deployment_id, start, end, limit))
        return [
            event
            for event in self.events
            if start <= datetime.fromisoformat(event.ingested_at.replace("Z", "+00:00")) <= end
        ][:limit]

    def calculate_detection_baselines(self, tenant_id, deployment_id, start, end):
        self.baseline_calls.append((tenant_id, deployment_id, start, end))
        return {
            "10.0.0.10": {
                "dns_median": 2.0,
                "dns_mad": 1.0,
                "dns_p99": 5.0,
                "peer_dns_p99": 6.0,
                "traffic_p99": 1000.0,
                "peer_traffic_p99": 1200.0,
                "known_destinations": ["203.0.113.10"],
            }
        }


class MemoryStateStore:
    def __init__(self):
        self.checkpoints = {}
        self.baselines = {}
        self.alerts = {}
        self.evidence = {}

    def get_detection_checkpoint(self, tenant_id, deployment_id, job_name):
        return self.checkpoints.get((tenant_id, deployment_id, job_name))

    def set_detection_checkpoint(self, tenant_id, deployment_id, job_name, completed_at):
        self.checkpoints[(tenant_id, deployment_id, job_name)] = completed_at.isoformat().replace("+00:00", "Z")

    def list_detection_baselines(self, tenant_id, deployment_id):
        return dict(self.baselines)

    def set_baseline(self, tenant_id, deployment_id, entity_id, baseline):
        self.baselines[entity_id] = dict(baseline)
        return baseline

    def save_detected_alert(
        self, tenant_id, deployment_id, detection, evidence, *, fingerprint, alert_id, created_at
    ):
        created = fingerprint not in self.alerts
        if created:
            self.alerts[fingerprint] = {
                "alert_id": alert_id,
                "tenant_id": tenant_id,
                "deployment_id": deployment_id,
                "detector_id": detection.detector_id,
                "evidence_ids": list(detection.evidence_ids),
                "created_at": created_at,
            }
            self.evidence[alert_id] = [item.to_dict() for item in evidence]
        return created, self.alerts[fingerprint]


class ContinuousDetectionTests(unittest.TestCase):
    def config(self):
        return DetectionServiceConfig(
            tenant_id=TENANT,
            deployment_id=DEPLOYMENT,
            poll_seconds=1,
            fast_interval_seconds=10,
            behavior_interval_seconds=60,
            tunneling_interval_seconds=300,
            baseline_interval_seconds=3600,
            baseline_window_days=7,
            baseline_exclusion_seconds=300,
            bootstrap_lookback_seconds=86400,
            maximum_events_per_window=1000,
        )

    def test_sensor_event_becomes_idempotent_alert_with_persisted_evidence(self):
        event = sensor_alert(1, NOW - timedelta(seconds=1))
        source = MemoryEventSource([event])
        state = MemoryStateStore()
        service = DetectionService(self.config(), source, state)

        first = service.run_cycle(NOW)
        self.assertEqual(first["alerts_created"], 1)
        alert = next(iter(state.alerts.values()))
        self.assertEqual(alert["detector_id"], "suricata-conversion-v1")
        self.assertEqual(alert["evidence_ids"], [event.event_id])
        self.assertEqual(state.evidence[alert["alert_id"]][0]["raw_reference"], event.raw_reference)

        # Overlapping windows and restarts use persisted job checkpoints plus a
        # deterministic alert key instead of duplicating the same sensor alert.
        second = DetectionService(self.config(), source, state).run_cycle(NOW + timedelta(seconds=10))
        self.assertEqual(second["alerts_created"], 0)
        self.assertEqual(len(state.alerts), 1)

    def test_local_detection_continues_with_cloud_and_llm_disabled(self):
        previous = os.environ.get("MODEL_GATEWAY_AVAILABLE")
        os.environ["MODEL_GATEWAY_AVAILABLE"] = "false"
        try:
            source = MemoryEventSource([sensor_alert(2, NOW - timedelta(seconds=1))])
            state = MemoryStateStore()
            stats = DetectionService(self.config(), source, state).run_cycle(NOW)
        finally:
            if previous is None:
                os.environ.pop("MODEL_GATEWAY_AVAILABLE", None)
            else:
                os.environ["MODEL_GATEWAY_AVAILABLE"] = previous
        self.assertEqual(stats["alerts_created"], 1)
        self.assertEqual(len(state.alerts), 1)

    def test_schedule_and_hourly_baseline_refresh_are_checkpointed(self):
        source = MemoryEventSource([])
        state = MemoryStateStore()
        service = DetectionService(self.config(), source, state)
        first = service.run_cycle(NOW)
        self.assertEqual(first["jobs"], 3)
        self.assertEqual(first["baselines"], 1)
        self.assertEqual(first["models_retrained"], 1)
        self.assertEqual(len(source.baseline_calls), 2)
        self.assertIn(
            (TENANT, DEPLOYMENT, "model-retraining-daily"),
            state.checkpoints,
        )

        early = service.run_cycle(NOW + timedelta(seconds=5))
        self.assertEqual(early["jobs"], 0)
        self.assertEqual(early["baselines"], 0)
        ten_seconds = service.run_cycle(NOW + timedelta(seconds=10))
        self.assertEqual(ten_seconds["jobs"], 1)
        self.assertEqual(ten_seconds["models_retrained"], 0)
        self.assertEqual(len(source.baseline_calls), 2)

    def test_bootstrap_evaluates_lookback_once_then_checkpoints_forward(self):
        # A large historical backlog inside the 1-day bootstrap lookback.
        events = [
            sensor_alert(index, NOW - timedelta(minutes=30) + timedelta(seconds=index))
            for index in range(1500)
        ]
        source = MemoryEventSource(events)
        state = MemoryStateStore()
        config = DetectionServiceConfig(
            tenant_id=TENANT,
            deployment_id=DEPLOYMENT,
            poll_seconds=2,
            fast_interval_seconds=10,
            behavior_interval_seconds=60,
            tunneling_interval_seconds=300,
            baseline_interval_seconds=3600,
            baseline_window_days=7,
            baseline_exclusion_seconds=300,
            bootstrap_lookback_seconds=86400,
            maximum_events_per_window=2000,
        )
        service = DetectionService(config, source, state)

        bootstrap = service.run_cycle(NOW)
        self.assertGreater(bootstrap["alerts_created"], 0)
        # The first evaluation checkpoints every schedule immediately, so a
        # cycle two seconds later performs no work at all (intervals not due).
        idle = service.run_cycle(NOW + timedelta(seconds=2))
        self.assertEqual(idle["jobs"], 0)
        self.assertEqual(idle["events"], 0)
        # When the fast schedule is due again, its window is bounded to the
        # context window (5 minutes), never the 86,400-second lookback.
        window_calls_before = len(source.window_calls)
        rerun = service.run_cycle(NOW + timedelta(seconds=10))
        self.assertEqual(rerun["jobs"], 1)
        self.assertEqual(rerun["alerts_created"], 0, "overlap re-evaluation must not duplicate alerts")
        fast_window = source.window_calls[window_calls_before]
        window_span = (fast_window[3] - fast_window[2]).total_seconds()
        # The window opens at the previous checkpoint minus the context window,
        # never the 86,400-second bootstrap lookback; the +10s cycle time makes
        # the measured span 310s, not ~86,400s.
        self.assertLessEqual(window_span, 310, "post-bootstrap windows must be context-window bounded")
        # Deterministic alert keys keep the total alert set stable.
        self.assertEqual(len(state.alerts), bootstrap["alerts_created"])

    def test_baseline_summary_includes_robust_and_peer_values(self):
        baselines = summarize_baseline_buckets(
            {
                "10.0.0.1": [
                    {"dns_queries": 1, "traffic_bytes": 100},
                    {"dns_queries": 2, "traffic_bytes": 200},
                    {"dns_queries": 30, "traffic_bytes": 900},
                ],
                "10.0.0.2": [{"dns_queries": 4, "traffic_bytes": 400}],
            },
            {
                "10.0.0.1": {
                    "known_destinations": ["8.8.8.8"],
                    "known_dns_destinations": ["1.1.1.1"],
                }
            },
        )
        self.assertEqual(baselines["10.0.0.1"]["dns_median"], 2.0)
        self.assertEqual(baselines["10.0.0.1"]["dns_mad"], 1.0)
        self.assertEqual(baselines["10.0.0.1"]["dns_p99"], 30.0)
        self.assertEqual(baselines["10.0.0.1"]["known_destinations"], ["8.8.8.8"])
        self.assertEqual(baselines["10.0.0.1"]["peer_dns_p99"], 30.0)


if __name__ == "__main__":
    unittest.main()
