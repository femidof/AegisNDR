from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


SEVERITIES = frozenset({"low", "medium", "high", "critical"})
ALERT_STATUSES = frozenset({"open", "triaged", "investigating", "resolved", "dismissed"})
ALLOWED_ACTIONS = frozenset(
    {
        "inspect_endpoint",
        "review_dns_history",
        "review_connection_history",
        "collect_packet_capture",
        "create_case",
        "escalate_to_soc",
        "isolate_with_approval",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
# Zeek V1 community IDs are "1:" followed by 27 base64 characters (20 bytes,
# no padding). Both the standard and URL-safe alphabets are accepted.
_COMMUNITY_ID = re.compile(r"^1:[A-Za-z0-9+/_-]{27}$")
# Protocol labels are short lowercase tokens (tcp, udp, dns, tls, ...).
_PROTOCOL = re.compile(r"^[a-z][a-z0-9+-]{0,15}$")


class ValidationError(ValueError):
    """Raised when data does not satisfy a boundary contract."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{name} must be a non-empty safe identifier")
    return value


def _timestamp(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be an ISO-8601 timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    return value


def _number(value: Any, name: str, *, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValidationError(f"{name} must be a finite number")
    result = float(value)
    if minimum is not None and result < minimum:
        raise ValidationError(f"{name} must be at least {minimum}")
    return result


def _integer(value: Any, name: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"{name} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValidationError(f"{name} must be <= {maximum}")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be an object")
    return {str(key): item for key, item in value.items()}


@dataclass(frozen=True)
class NormalizedEvent:
    tenant_id: str
    deployment_id: str
    event_id: str
    event_time: str
    source: str
    event_type: str
    sensor_id: str
    ingested_at: str = field(default_factory=utc_now)
    community_id: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    duration_ms: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    raw_reference: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "deployment_id", "event_id", "source", "event_type", "sensor_id"):
            _identifier(getattr(self, name), name)
        _timestamp(self.event_time, "event_time")
        _timestamp(self.ingested_at, "ingested_at")
        for name in ("src_port", "dst_port"):
            _integer(getattr(self, name), name, maximum=65535)
        for name in ("duration_ms", "bytes_out", "bytes_in"):
            _integer(getattr(self, name), name)
        for name in ("src_ip", "dst_ip"):
            value = getattr(self, name)
            if value:
                try:
                    ipaddress.ip_address(value)
                except ValueError as exc:
                    raise ValidationError(f"{name} must be an IPv4 or IPv6 address") from exc
        if self.community_id and not _COMMUNITY_ID.fullmatch(self.community_id):
            raise ValidationError(
                "community_id must be empty or a valid V1 community ID (1: followed by 27 base64 characters)"
            )
        if self.protocol and not _PROTOCOL.fullmatch(self.protocol):
            raise ValidationError("protocol must be empty or a short lowercase protocol token")
        if self.raw_reference:
            if not isinstance(self.raw_reference, str) or len(self.raw_reference) > 512:
                raise ValidationError("raw_reference must be a string of at most 512 characters")
            if any(ord(character) < 32 or ord(character) == 127 for character in self.raw_reference):
                raise ValidationError("raw_reference must not contain control characters")
        if not isinstance(self.details, dict):
            raise ValidationError("details must be an object")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NormalizedEvent":
        required = ("tenant_id", "deployment_id", "event_id", "event_time", "source", "event_type", "sensor_id")
        missing = [name for name in required if name not in value]
        if missing:
            raise ValidationError(f"missing event fields: {', '.join(missing)}")
        return cls(
            tenant_id=value["tenant_id"],
            deployment_id=value["deployment_id"],
            event_id=value["event_id"],
            event_time=value["event_time"],
            ingested_at=value.get("ingested_at", utc_now()),
            source=value["source"],
            event_type=value["event_type"],
            sensor_id=value["sensor_id"],
            community_id=str(value.get("community_id", "")),
            src_ip=str(value.get("src_ip", "")),
            src_port=_integer(value.get("src_port", 0), "src_port", maximum=65535),
            dst_ip=str(value.get("dst_ip", "")),
            dst_port=_integer(value.get("dst_port", 0), "dst_port", maximum=65535),
            protocol=str(value.get("protocol", "")),
            duration_ms=_integer(value.get("duration_ms", 0), "duration_ms"),
            bytes_out=_integer(value.get("bytes_out", 0), "bytes_out"),
            bytes_in=_integer(value.get("bytes_in", 0), "bytes_in"),
            raw_reference=str(value.get("raw_reference", "")),
            details=_mapping(value.get("details"), "details"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionResult:
    detector_id: str
    entity_type: str
    entity_id: str
    severity: str
    score: float
    evidence_ids: tuple[str, ...]
    feature_values: dict[str, float]
    baseline_values: dict[str, float]
    title: str

    def __post_init__(self) -> None:
        for name in ("detector_id", "entity_type", "entity_id"):
            _identifier(getattr(self, name), name)
        if self.severity not in SEVERITIES:
            raise ValidationError("invalid detection severity")
        if not 0 <= _number(self.score, "score") <= 1:
            raise ValidationError("score must be between 0 and 1")
        if not self.evidence_ids:
            raise ValidationError("detection must cite at least one evidence ID")
        for evidence_id in self.evidence_ids:
            _identifier(evidence_id, "evidence_id")
        if not isinstance(self.title, str) or not self.title.strip():
            raise ValidationError("title is required")


@dataclass(frozen=True)
class Alert:
    alert_id: str
    tenant_id: str
    deployment_id: str
    created_at: str
    detector_id: str
    title: str
    severity: str
    status: str
    entity_type: str
    entity_id: str
    score: float
    evidence_ids: tuple[str, ...]
    baseline: dict[str, float] = field(default_factory=dict)
    features: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("alert_id", "tenant_id", "deployment_id", "detector_id", "entity_type", "entity_id"):
            _identifier(getattr(self, name), name)
        _timestamp(self.created_at, "created_at")
        if self.severity not in SEVERITIES:
            raise ValidationError("invalid alert severity")
        if self.status not in ALERT_STATUSES:
            raise ValidationError("invalid alert status")
        if not 0 <= _number(self.score, "score") <= 1:
            raise ValidationError("score must be between 0 and 1")
        if not self.evidence_ids:
            raise ValidationError("alert must cite evidence")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Alert":
        return cls(
            alert_id=value["alert_id"],
            tenant_id=value["tenant_id"],
            deployment_id=value["deployment_id"],
            created_at=value["created_at"],
            detector_id=value["detector_id"],
            title=value["title"],
            severity=value["severity"],
            status=value.get("status", "open"),
            entity_type=value["entity_type"],
            entity_id=value["entity_id"],
            score=_number(value["score"], "score"),
            evidence_ids=tuple(value["evidence_ids"]),
            baseline={key: _number(item, f"baseline.{key}") for key, item in _mapping(value.get("baseline"), "baseline").items()},
            features={key: _number(item, f"features.{key}") for key, item in _mapping(value.get("features"), "features").items()},
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence_ids"] = list(self.evidence_ids)
        return result


@dataclass(frozen=True)
class EvidenceObservation:
    evidence_id: str
    feature: str
    observed: float | str | bool
    baseline_p99: float | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        _identifier(self.feature, "feature")
        if isinstance(self.observed, float) and not math.isfinite(self.observed):
            raise ValidationError("observed must be finite")
        if self.baseline_p99 is not None:
            _number(self.baseline_p99, "baseline_p99", minimum=0)
        if not isinstance(self.context, dict):
            raise ValidationError("context must be an object")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceObservation":
        observed = value.get("observed")
        if isinstance(observed, (dict, list)) or observed is None:
            raise ValidationError("observed must be a scalar")
        return cls(
            evidence_id=value["evidence_id"],
            feature=value["feature"],
            observed=observed,
            baseline_p99=value.get("baseline_p99"),
            context=_mapping(value.get("context"), "context"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ModelRequest:
    request_id: str
    tenant_policy_id: str
    alert_type: str
    severity: str
    entity_type: str
    observations: tuple[EvidenceObservation, ...]
    allowed_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("request_id", "tenant_policy_id", "alert_type", "entity_type"):
            _identifier(getattr(self, name), name)
        if self.severity not in SEVERITIES:
            raise ValidationError("invalid request severity")
        if not self.observations:
            raise ValidationError("at least one observation is required")
        if len(self.observations) > 100:
            raise ValidationError("model request exceeds 100 observations")
        unknown = set(self.allowed_actions) - ALLOWED_ACTIONS
        if unknown:
            raise ValidationError(f"unsupported allowed actions: {sorted(unknown)}")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelRequest":
        # Strict like ModelResponse.from_dict: unrecognized fields can smuggle
        # untrusted instructions past structural validation into downstream
        # consumers, so they are rejected rather than silently dropped.
        expected = {
            "request_id",
            "tenant_policy_id",
            "alert_type",
            "severity",
            "entity_type",
            "observations",
            "allowed_actions",
        }
        extra = set(value) - expected
        if extra:
            raise ValidationError(f"unknown model request fields: {sorted(extra)}")
        observations = value.get("observations")
        if not isinstance(observations, list):
            raise ValidationError("observations must be a list")
        actions = value.get("allowed_actions")
        if not isinstance(actions, list):
            raise ValidationError("allowed_actions must be a list")
        return cls(
            request_id=value["request_id"],
            tenant_policy_id=value["tenant_policy_id"],
            alert_type=value["alert_type"],
            severity=value["severity"],
            entity_type=value["entity_type"],
            observations=tuple(EvidenceObservation.from_dict(item) for item in observations),
            allowed_actions=tuple(actions),
        )

    @property
    def evidence_ids(self) -> set[str]:
        return {item.evidence_id for item in self.observations}

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tenant_policy_id": self.tenant_policy_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "entity_type": self.entity_type,
            "observations": [item.to_dict() for item in self.observations],
            "allowed_actions": list(self.allowed_actions),
        }


@dataclass(frozen=True)
class ModelResponse:
    classification: str
    severity: str
    confidence: float
    summary: str
    supporting_evidence_ids: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    requires_human_review: bool

    def __post_init__(self) -> None:
        _identifier(self.classification, "classification")
        if self.severity not in SEVERITIES:
            raise ValidationError("invalid response severity")
        if not 0 <= _number(self.confidence, "confidence") <= 1:
            raise ValidationError("confidence must be between 0 and 1")
        if not isinstance(self.summary, str) or not self.summary.strip() or len(self.summary) > 2000:
            raise ValidationError("summary must contain 1-2000 characters")
        if not self.supporting_evidence_ids:
            raise ValidationError("response must cite supporting evidence")
        unknown_actions = set(self.recommended_actions) - ALLOWED_ACTIONS
        if unknown_actions:
            raise ValidationError(f"unsupported recommended actions: {sorted(unknown_actions)}")
        if not isinstance(self.requires_human_review, bool):
            raise ValidationError("requires_human_review must be boolean")
        for technique in self.mitre_techniques:
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                raise ValidationError(f"invalid MITRE technique: {technique}")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        known_evidence_ids: Iterable[str] | None = None,
        allowed_actions: Iterable[str] | None = None,
    ) -> "ModelResponse":
        expected = {
            "classification",
            "severity",
            "confidence",
            "summary",
            "supporting_evidence_ids",
            "mitre_techniques",
            "recommended_actions",
            "requires_human_review",
        }
        extra = set(value) - expected
        missing = expected - set(value)
        if missing:
            raise ValidationError(f"missing model response fields: {sorted(missing)}")
        if extra:
            raise ValidationError(f"unknown model response fields: {sorted(extra)}")
        response = cls(
            classification=value["classification"],
            severity=value["severity"],
            confidence=_number(value["confidence"], "confidence"),
            summary=value["summary"],
            supporting_evidence_ids=tuple(value["supporting_evidence_ids"]),
            mitre_techniques=tuple(value["mitre_techniques"]),
            recommended_actions=tuple(value["recommended_actions"]),
            requires_human_review=value["requires_human_review"],
        )
        if known_evidence_ids is not None:
            unknown = set(response.supporting_evidence_ids) - set(known_evidence_ids)
            if unknown:
                raise ValidationError(f"model cited unknown evidence IDs: {sorted(unknown)}")
        if allowed_actions is not None:
            unsupported = set(response.recommended_actions) - set(allowed_actions)
            if unsupported:
                raise ValidationError(f"model recommended disallowed actions: {sorted(unsupported)}")
        return response

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("supporting_evidence_ids", "mitre_techniques", "recommended_actions"):
            result[key] = list(result[key])
        return result
