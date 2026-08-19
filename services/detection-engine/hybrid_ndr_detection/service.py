from __future__ import annotations

import hashlib
import os
import statistics
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Protocol

from hybrid_ndr_contracts import DetectionResult, NormalizedEvent

from .engine import (
    DNSAnomalyDetector,
    DetectionEngine,
    NewDestinationDetector,
    PortScanDetector,
    SuricataAlertDetector,
    TrafficSpikeDetector,
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _utc(value)
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _positive_int(environment: Mapping[str, str], name: str, default: int) -> int:
    raw = environment.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class DetectionEventSource(Protocol):
    def events_ingested_between(
        self,
        tenant_id: str,
        deployment_id: str,
        start: datetime,
        end: datetime,
        *,
        limit: int,
    ) -> list[NormalizedEvent | Mapping[str, Any]]: ...

    def calculate_detection_baselines(
        self,
        tenant_id: str,
        deployment_id: str,
        start: datetime,
        end: datetime,
    ) -> Mapping[str, Mapping[str, Any]]: ...


class DetectionStateStore(Protocol):
    def get_detection_checkpoint(self, tenant_id: str, deployment_id: str, job_name: str) -> str | None: ...

    def set_detection_checkpoint(
        self, tenant_id: str, deployment_id: str, job_name: str, completed_at: datetime
    ) -> None: ...

    def list_detection_baselines(self, tenant_id: str, deployment_id: str) -> Mapping[str, Mapping[str, Any]]: ...

    def set_baseline(
        self, tenant_id: str, deployment_id: str, entity_id: str, baseline: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def save_detected_alert(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent | Mapping[str, Any]],
        *,
        fingerprint: str,
        alert_id: str,
        created_at: str,
    ) -> tuple[bool, Mapping[str, Any]]: ...

    def list_detection_rules(self, tenant_id: str, deployment_id: str) -> list[Mapping[str, Any]]: ...

    def is_detection_suppressed(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent | Mapping[str, Any]],
        *,
        at: datetime | None = None,
    ) -> bool: ...


@dataclass(frozen=True)
class DetectionServiceConfig:
    tenant_id: str
    deployment_id: str
    poll_seconds: int = 2
    fast_interval_seconds: int = 10
    behavior_interval_seconds: int = 60
    tunneling_interval_seconds: int = 300
    baseline_interval_seconds: int = 3600
    model_retraining_interval_seconds: int = 86_400
    baseline_window_days: int = 7
    baseline_exclusion_seconds: int = 300
    bootstrap_lookback_seconds: int = 86400
    maximum_events_per_window: int = 10_000

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "DetectionServiceConfig":
        env = environ if environ is not None else os.environ
        tenant_id = env.get("TENANT_ID", "").strip()
        deployment_id = env.get("DEPLOYMENT_ID", "").strip()
        if not tenant_id or not deployment_id:
            raise ValueError("TENANT_ID and DEPLOYMENT_ID are required")
        return cls(
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            poll_seconds=_positive_int(env, "DETECTION_POLL_SECONDS", 2),
            fast_interval_seconds=_positive_int(env, "DETECTION_FAST_INTERVAL_SECONDS", 10),
            behavior_interval_seconds=_positive_int(env, "DETECTION_BEHAVIOR_INTERVAL_SECONDS", 60),
            tunneling_interval_seconds=_positive_int(env, "DETECTION_TUNNELING_INTERVAL_SECONDS", 300),
            baseline_interval_seconds=_positive_int(env, "DETECTION_BASELINE_INTERVAL_SECONDS", 3600),
            model_retraining_interval_seconds=_positive_int(
                env, "DETECTION_MODEL_RETRAIN_INTERVAL_SECONDS", 86_400
            ),
            baseline_window_days=_positive_int(env, "DETECTION_BASELINE_WINDOW_DAYS", 7),
            baseline_exclusion_seconds=_positive_int(env, "DETECTION_BASELINE_EXCLUSION_SECONDS", 300),
            bootstrap_lookback_seconds=_positive_int(env, "DETECTION_BOOTSTRAP_LOOKBACK_SECONDS", 86400),
            maximum_events_per_window=_positive_int(env, "DETECTION_MAX_EVENTS_PER_WINDOW", 10_000),
        )


@dataclass(frozen=True)
class ScheduledDetection:
    name: str
    interval: timedelta
    context_window: timedelta
    engine: DetectionEngine
    accepted_detector_ids: frozenset[str]


def _default_schedules(config: DetectionServiceConfig) -> tuple[ScheduledDetection, ...]:
    return (
        ScheduledDetection(
            name="fast-10s",
            interval=timedelta(seconds=config.fast_interval_seconds),
            context_window=timedelta(minutes=5),
            engine=DetectionEngine([PortScanDetector(), SuricataAlertDetector()]),
            accepted_detector_ids=frozenset({"port-scan-v1", "suricata-conversion-v1"}),
        ),
        ScheduledDetection(
            name="behavior-1m",
            interval=timedelta(seconds=config.behavior_interval_seconds),
            context_window=timedelta(minutes=5),
            engine=DetectionEngine([DNSAnomalyDetector(), TrafficSpikeDetector(), NewDestinationDetector()]),
            accepted_detector_ids=frozenset({"dns-volume-v1", "traffic-spike-v1", "new-destination-v1"}),
        ),
        ScheduledDetection(
            name="tunneling-5m",
            interval=timedelta(seconds=config.tunneling_interval_seconds),
            context_window=timedelta(minutes=5),
            engine=DetectionEngine([DNSAnomalyDetector()]),
            accepted_detector_ids=frozenset({"dns-tunneling-v1"}),
        ),
    )


class _ConfiguredDetector:
    """Bind one stored rule to a detector implementation and stable alert identifier."""

    def __init__(self, rule: Mapping[str, Any]) -> None:
        self.rule = dict(rule)
        self.detector_id = str(rule["rule_id"])
        detector_id = str(rule["detector_id"])
        thresholds = dict(rule.get("thresholds", {}))
        if detector_id == "port-scan-v1":
            self.inner = PortScanDetector(
                vertical_port_threshold=int(thresholds.get("vertical_port_threshold", 50)),
                horizontal_host_threshold=int(thresholds.get("horizontal_host_threshold", 100)),
            )
        elif detector_id == "dns-volume-v1":
            self.inner = DNSAnomalyDetector(default_p99=float(thresholds.get("default_p99", 30)))
        elif detector_id == "dns-tunneling-v1":
            self.inner = DNSAnomalyDetector(tunnel_threshold=float(thresholds.get("tunnel_score_threshold", 0.62)))
        elif detector_id == "traffic-spike-v1":
            self.inner = TrafficSpikeDetector(
                absolute_threshold_bytes=int(thresholds.get("absolute_threshold_bytes", 10_000_000))
            )
        elif detector_id == "new-destination-v1":
            self.inner = NewDestinationDetector()
        elif detector_id == "suricata-conversion-v1":
            self.inner = SuricataAlertDetector()
        else:
            raise ValueError("stored detection rule references an unavailable detector")

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]]
    ) -> list[DetectionResult]:
        expected = str(self.rule["detector_id"])
        minimum_priority = float(self.rule.get("thresholds", {}).get("minimum_priority", 3))
        configured_severity = str(self.rule.get("severity", "dynamic"))
        results: list[DetectionResult] = []
        for result in self.inner.evaluate(events, baselines):
            if result.detector_id != expected:
                continue
            if expected == "suricata-conversion-v1" and result.feature_values.get("suricata_severity", 99) > minimum_priority:
                continue
            results.append(replace(
                result,
                detector_id=self.detector_id,
                severity=result.severity if configured_severity == "dynamic" else configured_severity,
            ))
        return results


def _configured_schedules(
    config: DetectionServiceConfig, rules: Iterable[Mapping[str, Any]]
) -> tuple[ScheduledDetection, ...]:
    definitions = {
        "fast-10s": (timedelta(seconds=config.fast_interval_seconds), timedelta(minutes=5)),
        "behavior-1m": (timedelta(seconds=config.behavior_interval_seconds), timedelta(minutes=5)),
        "tunneling-5m": (timedelta(seconds=config.tunneling_interval_seconds), timedelta(minutes=5)),
    }
    grouped: dict[str, list[_ConfiguredDetector]] = {name: [] for name in definitions}
    for rule in rules:
        if rule.get("enabled") is True and rule.get("schedule") in grouped:
            grouped[str(rule["schedule"])].append(_ConfiguredDetector(rule))
    schedules: list[ScheduledDetection] = []
    for name, detectors in grouped.items():
        if not detectors:
            continue
        interval, context = definitions[name]
        schedules.append(ScheduledDetection(
            name=name,
            interval=interval,
            context_window=context,
            engine=DetectionEngine(detectors),
            accepted_detector_ids=frozenset(detector.detector_id for detector in detectors),
        ))
    return tuple(schedules)


class DetectionService:
    """Continuously evaluates resident telemetry without a cloud or LLM dependency."""

    baseline_job_name = "baseline-hourly"
    model_retraining_job_name = "model-retraining-daily"

    def __init__(
        self,
        config: DetectionServiceConfig,
        event_source: DetectionEventSource,
        state_store: DetectionStateStore,
        *,
        schedules: Iterable[ScheduledDetection] | None = None,
    ) -> None:
        self.config = config
        self.event_source = event_source
        self.state_store = state_store
        self._dynamic_rules = schedules is None and callable(getattr(state_store, "list_detection_rules", None))
        self.schedules = tuple(schedules or _default_schedules(config))

    def run_cycle(self, now: datetime | None = None) -> dict[str, int]:
        cycle_time = _utc(now or datetime.now(timezone.utc))
        baselines = dict(
            self.state_store.list_detection_baselines(self.config.tenant_id, self.config.deployment_id)
        )
        stats = {
            "jobs": 0,
            "events": 0,
            "detections": 0,
            "alerts_created": 0,
            "suppressed": 0,
            "baselines": 0,
            "models_retrained": 0,
        }

        schedules = self.schedules
        if self._dynamic_rules:
            rules = self.state_store.list_detection_rules(self.config.tenant_id, self.config.deployment_id)
            schedules = _configured_schedules(self.config, rules)

        for schedule in schedules:
            checkpoint = _parse_timestamp(
                self.state_store.get_detection_checkpoint(
                    self.config.tenant_id, self.config.deployment_id, schedule.name
                )
            )
            if checkpoint is not None and cycle_time < checkpoint + schedule.interval:
                continue
            start = (
                checkpoint - schedule.context_window
                if checkpoint is not None
                else cycle_time - timedelta(seconds=self.config.bootstrap_lookback_seconds)
            )
            rows = self.event_source.events_ingested_between(
                self.config.tenant_id,
                self.config.deployment_id,
                start,
                cycle_time,
                limit=self.config.maximum_events_per_window,
            )
            events = [row if isinstance(row, NormalizedEvent) else NormalizedEvent.from_dict(row) for row in rows]
            # Re-evaluate the overlap deliberately. Vector/ClickHouse delivery
            # can cross a wall-clock checkpoint; deterministic alert keys make
            # the overlap safe and prevent that race from dropping late rows.
            candidate_ids = {event.event_id for event in events}
            stats["jobs"] += 1
            stats["events"] += len(candidate_ids)
            if candidate_ids:
                by_id = {event.event_id: event for event in events}
                for detection in schedule.engine.run(events, baselines):
                    if detection.detector_id not in schedule.accepted_detector_ids:
                        continue
                    evidence = [by_id[evidence_id] for evidence_id in detection.evidence_ids if evidence_id in by_id]
                    if len(evidence) != len(detection.evidence_ids):
                        continue
                    suppressor = getattr(self.state_store, "is_detection_suppressed", None)
                    if callable(suppressor) and suppressor(
                        self.config.tenant_id,
                        self.config.deployment_id,
                        detection,
                        evidence,
                        at=cycle_time,
                    ):
                        stats["suppressed"] += 1
                        continue
                    fingerprint = self._fingerprint(schedule, detection, evidence)
                    # The fingerprint is already a collision-resistant SHA-256
                    # digest; reuse its first 128 bits directly as the
                    # deterministic alert UUID instead of re-hashing it.
                    alert_id = str(uuid.UUID(fingerprint[:32]))
                    created, _alert = self.state_store.save_detected_alert(
                        self.config.tenant_id,
                        self.config.deployment_id,
                        detection,
                        evidence,
                        fingerprint=fingerprint,
                        alert_id=alert_id,
                        created_at=_timestamp(cycle_time),
                    )
                    stats["detections"] += 1
                    stats["alerts_created"] += int(created)
            self.state_store.set_detection_checkpoint(
                self.config.tenant_id, self.config.deployment_id, schedule.name, cycle_time
            )

        baseline_checkpoint = _parse_timestamp(
            self.state_store.get_detection_checkpoint(
                self.config.tenant_id, self.config.deployment_id, self.baseline_job_name
            )
        )
        baseline_interval = timedelta(seconds=self.config.baseline_interval_seconds)
        if baseline_checkpoint is None or cycle_time >= baseline_checkpoint + baseline_interval:
            stats["baselines"] = self._refresh_statistical_models(
                cycle_time, self.baseline_job_name
            )

        # The MVP's statistical anomaly models are detector baselines. Their
        # hourly refresh provides responsive thresholds, while this independent
        # daily retraining checkpoint proves the longer scheduled job ran and
        # remains restart-safe as required by the operating specification.
        training_checkpoint = _parse_timestamp(
            self.state_store.get_detection_checkpoint(
                self.config.tenant_id, self.config.deployment_id, self.model_retraining_job_name
            )
        )
        training_interval = timedelta(seconds=self.config.model_retraining_interval_seconds)
        if training_checkpoint is None or cycle_time >= training_checkpoint + training_interval:
            stats["models_retrained"] = self._refresh_statistical_models(
                cycle_time, self.model_retraining_job_name
            )
        return stats

    def _refresh_statistical_models(self, cycle_time: datetime, job_name: str) -> int:
        baseline_end = cycle_time - timedelta(seconds=self.config.baseline_exclusion_seconds)
        baseline_start = baseline_end - timedelta(days=self.config.baseline_window_days)
        refreshed = self.event_source.calculate_detection_baselines(
            self.config.tenant_id, self.config.deployment_id, baseline_start, baseline_end
        )
        for entity_id, baseline in refreshed.items():
            self.state_store.set_baseline(
                self.config.tenant_id, self.config.deployment_id, entity_id, baseline
            )
        self.state_store.set_detection_checkpoint(
            self.config.tenant_id, self.config.deployment_id, job_name, cycle_time
        )
        return len(refreshed)

    @staticmethod
    def _fingerprint(
        schedule: ScheduledDetection,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent],
    ) -> str:
        evidence_items = list(evidence)
        if detection.detector_id == "suricata-conversion-v1":
            discriminator = ",".join(sorted(detection.evidence_ids))
        else:
            latest = max(_parse_timestamp(item.event_time) for item in evidence_items)
            assert latest is not None
            bucket_seconds = max(1, int(schedule.interval.total_seconds()))
            discriminator = str(int(latest.timestamp()) // bucket_seconds)
        first_evidence = evidence_items[0]
        material = "\x1f".join(
            (
                first_evidence.tenant_id,
                first_evidence.deployment_id,
                detection.detector_id,
                detection.entity_type,
                detection.entity_id,
                discriminator,
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def percentile(values: Iterable[float], quantile: float) -> float:
    """Nearest-rank percentile used by the small hourly MVP baseline refresh."""

    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.999999)))
    return ordered[index]


def summarize_baseline_buckets(
    buckets: Mapping[str, Iterable[Mapping[str, Any]]],
    destinations: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Convert ClickHouse minute buckets into detector-ready seven-day baselines."""

    destination_map = destinations or {}
    result: dict[str, dict[str, Any]] = {}
    for entity_id, rows_iterable in buckets.items():
        rows = list(rows_iterable)
        dns_counts = [float(row.get("dns_queries", 0)) for row in rows]
        traffic = [float(row.get("traffic_bytes", 0)) for row in rows]
        median = statistics.median(dns_counts) if dns_counts else 0.0
        deviations = [abs(value - median) for value in dns_counts]
        target = destination_map.get(entity_id, {})
        result[entity_id] = {
            "dns_median": float(median),
            "dns_mad": float(statistics.median(deviations) if deviations else 0.0),
            "dns_p99": percentile(dns_counts, 0.99),
            "traffic_p99": percentile(traffic, 0.99),
            "known_destinations": sorted(set(target.get("known_destinations", ())))[:256],
            "known_dns_destinations": sorted(set(target.get("known_dns_destinations", ())))[:64],
            "sample_windows": len(rows),
        }
    peer_dns_p99 = percentile((item["dns_p99"] for item in result.values()), 0.99)
    peer_traffic_p99 = percentile((item["traffic_p99"] for item in result.values()), 0.99)
    for baseline in result.values():
        baseline["peer_dns_p99"] = peer_dns_p99
        baseline["peer_traffic_p99"] = peer_traffic_p99
    return result
