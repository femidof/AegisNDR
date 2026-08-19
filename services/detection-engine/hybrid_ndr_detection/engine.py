from __future__ import annotations

import math
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol

from hybrid_ndr_contracts import DetectionResult, NormalizedEvent


def _time(event: NormalizedEvent) -> datetime:
    return datetime.fromisoformat(event.event_time.replace("Z", "+00:00"))


def _severity(score: float) -> str:
    if score >= 0.92:
        return "critical"
    if score >= 0.78:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


class Detector(Protocol):
    detector_id: str

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]]
    ) -> list[DetectionResult]: ...


class PortScanDetector:
    detector_id = "port-scan-v1"

    def __init__(self, *, vertical_port_threshold: int = 50, horizontal_host_threshold: int = 100) -> None:
        self.vertical_port_threshold = vertical_port_threshold
        self.horizontal_host_threshold = horizontal_host_threshold

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]] | None = None
    ) -> list[DetectionResult]:
        connections = [event for event in events if event.src_ip and event.dst_ip and event.dst_port]
        by_source: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in connections:
            by_source[event.src_ip].append(event)
        results: list[DetectionResult] = []
        for source, source_events in by_source.items():
            source_events.sort(key=_time)
            best_vertical: list[NormalizedEvent] = []
            left = 0
            for right, current in enumerate(source_events):
                while (_time(current) - _time(source_events[left])).total_seconds() > 60:
                    left += 1
                window = source_events[left : right + 1]
                if len({event.dst_port for event in window}) > len({event.dst_port for event in best_vertical}):
                    best_vertical = window
            horizontal_by_port: dict[int, list[NormalizedEvent]] = defaultdict(list)
            for event in source_events:
                horizontal_by_port[event.dst_port].append(event)
            best_horizontal: list[NormalizedEvent] = []
            for port_events in horizontal_by_port.values():
                port_events.sort(key=_time)
                left = 0
                for right, current in enumerate(port_events):
                    while (_time(current) - _time(port_events[left])).total_seconds() > 300:
                        left += 1
                    window = port_events[left : right + 1]
                    if len({event.dst_ip for event in window}) > len({event.dst_ip for event in best_horizontal}):
                        best_horizontal = window
            unique_ports = len({event.dst_port for event in best_vertical})
            unique_hosts = len({event.dst_ip for event in best_horizontal})
            if unique_ports <= self.vertical_port_threshold and unique_hosts <= self.horizontal_host_threshold:
                continue
            vertical_score = unique_ports / max(self.vertical_port_threshold * 2, 1)
            horizontal_score = unique_hosts / max(self.horizontal_host_threshold * 2, 1)
            score = min(1.0, max(vertical_score, horizontal_score))
            evidence = best_vertical if vertical_score >= horizontal_score else best_horizontal
            kind = "destination ports" if vertical_score >= horizontal_score else "destination hosts"
            results.append(
                DetectionResult(
                    detector_id=self.detector_id,
                    entity_type="host",
                    entity_id=source,
                    severity=_severity(score),
                    score=score,
                    evidence_ids=tuple(event.event_id for event in evidence[:100]),
                    feature_values={"unique_destination_ports": float(unique_ports), "unique_destination_hosts": float(unique_hosts)},
                    baseline_values={
                        "port_threshold_60s": float(self.vertical_port_threshold),
                        "host_threshold_5m": float(self.horizontal_host_threshold),
                    },
                    title=f"Potential port scan across {max(unique_ports, unique_hosts)} {kind}",
                )
            )
        return results


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


class DNSAnomalyDetector:
    detector_id = "dns-anomaly-v1"

    def __init__(self, *, default_p99: float = 30.0, tunnel_threshold: float = 0.62) -> None:
        self.default_p99 = default_p99
        self.tunnel_threshold = tunnel_threshold

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]] | None = None
    ) -> list[DetectionResult]:
        baselines = baselines or {}
        by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.src_ip and ("dns" in event.event_type.lower() or event.details.get("query")):
                by_host[event.src_ip].append(event)
        results: list[DetectionResult] = []
        for host, dns_events in by_host.items():
            baseline = baselines.get(host, {})
            median = float(baseline.get("dns_median", 10.0))
            mad = max(1.0, float(baseline.get("dns_mad", 3.0)))
            p99 = float(baseline.get("dns_p99", self.default_p99))
            peer_p99 = float(baseline.get("peer_dns_p99", p99))
            volume_threshold = max(p99, peer_p99, median + 6 * mad)
            volume = len(dns_events)
            if volume > volume_threshold:
                ratio = volume / max(volume_threshold, 1)
                score = min(1.0, 0.55 + math.log2(ratio + 1) / 3)
                results.append(
                    DetectionResult(
                        detector_id="dns-volume-v1",
                        entity_type="host",
                        entity_id=host,
                        severity=_severity(score),
                        score=score,
                        evidence_ids=tuple(event.event_id for event in dns_events[:100]),
                        feature_values={"dns_queries_window": float(volume)},
                        baseline_values={"median": median, "mad": mad, "p99": p99, "peer_p99": peer_p99},
                        title="Abnormal DNS query volume",
                    )
                )

            queries = [str(event.details.get("query", "")) for event in dns_events]
            labels = [query.split(".")[0] for query in queries if query]
            txt_rate = sum(str(event.details.get("query_type", "")).upper() == "TXT" for event in dns_events) / max(volume, 1)
            average_entropy = statistics.fmean(_entropy(label) for label in labels) if labels else 0.0
            long_ratio = sum(len(label) >= 24 for label in labels) / max(len(labels), 1)
            unique_ratio = len(set(labels)) / max(len(labels), 1)
            known_destinations = set(baseline.get("known_dns_destinations", []))
            destinations = {event.dst_ip for event in dns_events if event.dst_ip}
            novelty = len(destinations - known_destinations) / max(len(destinations), 1) if known_destinations else 0.5
            times = sorted(_time(event).timestamp() for event in dns_events)
            gaps = [right - left for left, right in zip(times, times[1:]) if right > left]
            if len(gaps) >= 3 and statistics.fmean(gaps) > 0:
                periodicity = max(0.0, 1 - min(1.0, statistics.pstdev(gaps) / statistics.fmean(gaps)))
            else:
                periodicity = 0.0
            tunnel_score = min(
                1.0,
                0.25 * min(1.0, txt_rate * 2)
                + 0.2 * min(1.0, average_entropy / 4.2)
                + 0.2 * long_ratio
                + 0.15 * unique_ratio
                + 0.1 * periodicity
                + 0.1 * novelty,
            )
            if volume >= 8 and tunnel_score >= self.tunnel_threshold:
                results.append(
                    DetectionResult(
                        detector_id="dns-tunneling-v1",
                        entity_type="host",
                        entity_id=host,
                        severity=_severity(tunnel_score),
                        score=tunnel_score,
                        evidence_ids=tuple(event.event_id for event in dns_events[:100]),
                        feature_values={
                            "txt_query_rate": txt_rate,
                            "average_subdomain_entropy": average_entropy,
                            "long_subdomain_ratio": long_ratio,
                            "unique_subdomain_ratio": unique_ratio,
                            "query_periodicity": periodicity,
                            "destination_novelty": novelty,
                        },
                        baseline_values={"tunnel_score_threshold": self.tunnel_threshold},
                        title="Possible DNS tunneling behavior",
                    )
                )
        return results


class TrafficSpikeDetector:
    detector_id = "traffic-spike-v1"

    def __init__(self, *, absolute_threshold_bytes: int = 10_000_000) -> None:
        self.absolute_threshold_bytes = absolute_threshold_bytes

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]] | None = None
    ) -> list[DetectionResult]:
        baselines = baselines or {}
        by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.src_ip and event.bytes_out:
                by_host[event.src_ip].append(event)
        results: list[DetectionResult] = []
        for host, host_events in by_host.items():
            observed = sum(event.bytes_out for event in host_events)
            baseline = baselines.get(host, {})
            host_p99 = float(baseline.get("traffic_p99", 0))
            peer_p99 = float(baseline.get("peer_traffic_p99", 0))
            configured_absolute = float(baseline.get("absolute_traffic_threshold", self.absolute_threshold_bytes))
            threshold = max(host_p99, peer_p99, configured_absolute)
            if observed <= threshold:
                continue
            score = min(1.0, 0.55 + math.log2(observed / max(threshold, 1)) / 4)
            results.append(
                DetectionResult(
                    detector_id=self.detector_id,
                    entity_type="host",
                    entity_id=host,
                    severity=_severity(score),
                    score=score,
                    evidence_ids=tuple(event.event_id for event in host_events[:100]),
                    feature_values={"bytes_out_window": float(observed)},
                    baseline_values={"host_p99": host_p99, "peer_p99": peer_p99, "absolute_threshold": configured_absolute},
                    title="Outbound traffic spike",
                )
            )
        return results


class NewDestinationDetector:
    detector_id = "new-destination-v1"

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]] | None = None
    ) -> list[DetectionResult]:
        baselines = baselines or {}
        by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.src_ip and event.dst_ip:
                by_host[event.src_ip].append(event)
        results: list[DetectionResult] = []
        for host, host_events in by_host.items():
            known = set(baselines.get(host, {}).get("known_destinations", []))
            if not known:
                continue  # No established baseline: learn, do not alert.
            novel_events = [event for event in host_events if event.dst_ip not in known]
            if not novel_events:
                continue
            novel_destinations = {event.dst_ip for event in novel_events}
            score = min(0.95, 0.55 + 0.08 * len(novel_destinations))
            results.append(
                DetectionResult(
                    detector_id=self.detector_id,
                    entity_type="host",
                    entity_id=host,
                    severity=_severity(score),
                    score=score,
                    evidence_ids=tuple(event.event_id for event in novel_events[:100]),
                    feature_values={"new_destination_count": float(len(novel_destinations))},
                    baseline_values={"known_destination_count": float(len(known))},
                    title="Previously unseen network destination",
                )
            )
        return results


class SuricataAlertDetector:
    detector_id = "suricata-conversion-v1"

    def evaluate(
        self, events: Iterable[NormalizedEvent], baselines: Mapping[str, Mapping[str, Any]] | None = None
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for event in events:
            is_alert = event.source.lower() == "suricata" and (
                "alert" in event.event_type.lower() or "signature" in event.details
            )
            if not is_alert:
                continue
            numeric_severity = int(event.details.get("severity", 3))
            severity = {1: "critical", 2: "high", 3: "medium"}.get(numeric_severity, "low")
            score = {"critical": 0.96, "high": 0.85, "medium": 0.68, "low": 0.4}[severity]
            signature = str(event.details.get("signature", "Suricata network alert"))[:160]
            results.append(
                DetectionResult(
                    detector_id=self.detector_id,
                    entity_type="host",
                    entity_id=event.src_ip or event.sensor_id,
                    severity=severity,
                    score=score,
                    evidence_ids=(event.event_id,),
                    feature_values={"suricata_severity": float(numeric_severity)},
                    baseline_values={},
                    title=signature,
                )
            )
        return results


class DetectionEngine:
    """Runs all local detectors; it contains no network or model dependencies."""

    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self.detectors = list(
            detectors
            or [PortScanDetector(), DNSAnomalyDetector(), TrafficSpikeDetector(), NewDestinationDetector(), SuricataAlertDetector()]
        )

    def run(
        self,
        events: Iterable[NormalizedEvent | Mapping[str, Any]],
        baselines: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> list[DetectionResult]:
        normalized = [event if isinstance(event, NormalizedEvent) else NormalizedEvent.from_dict(event) for event in events]
        baselines = baselines or {}
        results: list[DetectionResult] = []
        for detector in self.detectors:
            results.extend(detector.evaluate(normalized, baselines))
        return results
