from __future__ import annotations

import math
import ipaddress
import re
import unicodedata
import uuid
from datetime import datetime
from typing import Any, Mapping
from urllib.parse import urlparse

from hybrid_ndr_contracts import utc_now


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")


DEFAULT_DETECTION_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "port-scan-v1",
        "name": "Port scan",
        "description": "Detect vertical scans over 60 seconds and horizontal scans over five minutes.",
        "detector_id": "port-scan-v1",
        "severity": "dynamic",
        "schedule": "fast-10s",
        "thresholds": {"vertical_port_threshold": 50, "horizontal_host_threshold": 100},
    },
    {
        "rule_id": "dns-volume-v1",
        "name": "DNS volume anomaly",
        "description": "Compare per-host DNS volume with robust host and peer baselines.",
        "detector_id": "dns-volume-v1",
        "severity": "dynamic",
        "schedule": "behavior-1m",
        "thresholds": {"default_p99": 30},
    },
    {
        "rule_id": "dns-tunneling-v1",
        "name": "DNS tunneling signal",
        "description": "Combine TXT rate, entropy, uniqueness, periodicity, and destination novelty.",
        "detector_id": "dns-tunneling-v1",
        "severity": "dynamic",
        "schedule": "tunneling-5m",
        "thresholds": {"tunnel_score_threshold": 0.62},
    },
    {
        "rule_id": "traffic-spike-v1",
        "name": "Outbound traffic spike",
        "description": "Detect outbound volume above host, peer, and absolute safety thresholds.",
        "detector_id": "traffic-spike-v1",
        "severity": "dynamic",
        "schedule": "behavior-1m",
        "thresholds": {"absolute_threshold_bytes": 10_000_000},
    },
    {
        "rule_id": "new-destination-v1",
        "name": "New destination",
        "description": "Detect destinations absent from the established local baseline.",
        "detector_id": "new-destination-v1",
        "severity": "dynamic",
        "schedule": "behavior-1m",
        "thresholds": {"baseline_window_days": 7},
    },
    {
        "rule_id": "suricata-conversion-v1",
        "name": "Suricata alert conversion",
        "description": "Map eligible Suricata signatures into the common local alert schema.",
        "detector_id": "suricata-conversion-v1",
        "severity": "dynamic",
        "schedule": "fast-10s",
        "thresholds": {"minimum_priority": 3},
    },
)

DEFAULT_SYSTEM_SETTINGS: dict[str, Any] = {
    "event_retention_days": 30,
    "raw_evidence_retention_days": 14,
    "alert_retention_days": 365,
    "case_retention_days": 365,
    "audit_retention_days": 3650,
    "support_bundle_ttl_hours": 72,
    "timezone": "UTC",
}

_DETECTOR_THRESHOLD_KEYS = {
    "port-scan-v1": {"vertical_port_threshold", "horizontal_host_threshold"},
    "dns-volume-v1": {"default_p99"},
    "dns-tunneling-v1": {"tunnel_score_threshold"},
    "traffic-spike-v1": {"absolute_threshold_bytes"},
    "new-destination-v1": {"baseline_window_days"},
    "suricata-conversion-v1": {"minimum_priority"},
}


def _text(value: Any, field: str, *, maximum: int, required: bool = True) -> str:
    result = str(value or "").strip()
    if required and not result:
        raise ValueError(f"{field} is required")
    if len(result) > maximum or any(ord(character) < 32 and character not in "\t" for character in result):
        raise ValueError(f"{field} exceeds its safe length")
    # Reject Unicode format characters (zero-width spaces/joiners, RTL/LTR
    # overrides, bidi isolates, word joiners, BOM): they are invisible and can
    # be used for identifier spoofing and log injection.
    if any(unicodedata.category(character) == "Cf" for character in result):
        raise ValueError(f"{field} contains Unicode format characters")
    return result


def _identifier(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not _SAFE_ID.fullmatch(result):
        raise ValueError(f"{field} must be a safe identifier")
    return result


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer between {minimum} and {maximum}")
    return value


def _timestamp(value: Any, field: str, *, optional: bool = False) -> str | None:
    if optional and value in {None, ""}:
        return None
    result = _text(value, field, maximum=64)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return result


def default_detection_rules(tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
    now = utc_now()
    return [
        {
            **value,
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "enabled": True,
            "builtin": True,
            "version": 1,
            "created_at": now,
            "updated_at": now,
            "updated_by": "system-default",
        }
        for value in DEFAULT_DETECTION_RULES
    ]


def normalize_detection_rule(
    tenant_id: str,
    deployment_id: str,
    value: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
    actor_id: str,
) -> dict[str, Any]:
    allowed = {"rule_id", "name", "description", "detector_id", "enabled", "severity", "schedule", "thresholds"}
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unsupported detection rule fields: {sorted(unknown)}")
    now = utc_now()
    item = dict(existing or {})
    item.update(value)
    item["rule_id"] = _identifier(item.get("rule_id") or str(uuid.uuid4()), "rule_id")
    item["name"] = _text(item.get("name"), "name", maximum=160)
    item["description"] = _text(item.get("description", ""), "description", maximum=1000, required=False)
    item["detector_id"] = _identifier(item.get("detector_id"), "detector_id")
    if item["detector_id"] not in _DETECTOR_THRESHOLD_KEYS:
        raise ValueError("detector_id is not an available local detector")
    item["enabled"] = _boolean(item.get("enabled", True), "enabled")
    item["severity"] = str(item.get("severity", "dynamic")).strip().lower()
    if item["severity"] not in {"dynamic", "low", "medium", "high", "critical"}:
        raise ValueError("severity must be dynamic, low, medium, high, or critical")
    item["schedule"] = str(item.get("schedule", "behavior-1m")).strip()
    if item["schedule"] not in {"fast-10s", "behavior-1m", "tunneling-5m"}:
        raise ValueError("schedule is not supported")
    thresholds = item.get("thresholds", {})
    if not isinstance(thresholds, Mapping):
        raise ValueError("thresholds must be an object")
    unknown_thresholds = set(thresholds) - _DETECTOR_THRESHOLD_KEYS[item["detector_id"]]
    if unknown_thresholds:
        raise ValueError(f"unsupported thresholds for detector: {sorted(unknown_thresholds)}")
    normalized_thresholds: dict[str, float | int] = {}
    for key, threshold in thresholds.items():
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not math.isfinite(float(threshold)):
            raise ValueError(f"thresholds.{key} must be a finite number")
        if float(threshold) <= 0:
            raise ValueError(f"thresholds.{key} must be greater than zero")
        if key == "tunnel_score_threshold" and float(threshold) > 1:
            raise ValueError("thresholds.tunnel_score_threshold must not exceed 1")
        normalized_thresholds[key] = threshold
    item["thresholds"] = normalized_thresholds
    item.update({
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "builtin": bool(item.get("builtin", False)),
        "version": int(item.get("version", 0)) + 1,
        "created_at": str(item.get("created_at") or now),
        "updated_at": now,
        "updated_by": actor_id,
    })
    return item


def normalize_suppression(
    tenant_id: str,
    deployment_id: str,
    value: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
    actor_id: str,
) -> dict[str, Any]:
    allowed = {"suppression_id", "name", "description", "rule_id", "match", "reason", "enabled", "expires_at"}
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unsupported suppression fields: {sorted(unknown)}")
    now = utc_now()
    item = dict(existing or {})
    item.update(value)
    item["suppression_id"] = _identifier(item.get("suppression_id") or str(uuid.uuid4()), "suppression_id")
    item["name"] = _text(item.get("name"), "name", maximum=160)
    item["description"] = _text(item.get("description", ""), "description", maximum=1000, required=False)
    rule_id = str(item.get("rule_id", "*")).strip()
    item["rule_id"] = "*" if rule_id == "*" else _identifier(rule_id, "rule_id")
    item["reason"] = _text(item.get("reason"), "reason", maximum=500)
    item["enabled"] = _boolean(item.get("enabled", True), "enabled")
    item["expires_at"] = _timestamp(item.get("expires_at"), "expires_at", optional=True)
    match = item.get("match")
    if not isinstance(match, Mapping) or not match:
        raise ValueError("match must be a non-empty object")
    allowed_match = {"entity_id", "src_ip", "dst_ip", "protocol", "sensor_id"}
    unknown_match = set(match) - allowed_match
    if unknown_match:
        raise ValueError(f"unsupported suppression match fields: {sorted(unknown_match)}")
    item["match"] = {key: _text(target, f"match.{key}", maximum=255) for key, target in match.items()}
    item.update({
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "created_at": str(item.get("created_at") or now),
        "updated_at": now,
        "updated_by": actor_id,
    })
    return item


def normalize_integration(
    tenant_id: str,
    deployment_id: str,
    value: Mapping[str, Any],
    *,
    existing: Mapping[str, Any] | None = None,
    existing_secret: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    allowed = {
        "integration_id", "name", "kind", "endpoint_url", "enabled", "format", "auth_type",
        "secret", "username", "secret_header", "headers", "event_types", "minimum_severity", "verify_tls",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unsupported integration fields: {sorted(unknown)}")
    now = utc_now()
    item = dict(existing or {})
    item.update({key: target for key, target in value.items() if key not in {"secret", "username"}})
    item["integration_id"] = _identifier(item.get("integration_id") or str(uuid.uuid4()), "integration_id")
    item["name"] = _text(item.get("name"), "name", maximum=160)
    item["kind"] = str(item.get("kind", "webhook")).strip().lower()
    if item["kind"] not in {"webhook", "generic_siem"}:
        raise ValueError("kind must be webhook or generic_siem")
    endpoint = _text(item.get("endpoint_url"), "endpoint_url", maximum=2048)
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("endpoint_url must be an HTTPS URL without credentials or fragments")
    item["endpoint_url"] = endpoint
    item["enabled"] = _boolean(item.get("enabled", True), "enabled")
    item["verify_tls"] = _boolean(item.get("verify_tls", True), "verify_tls")
    if not item["verify_tls"]:
        raise ValueError("TLS certificate verification cannot be disabled")
    item["format"] = str(item.get("format", "json")).strip().lower()
    if item["format"] not in {"json", "cef"}:
        raise ValueError("format must be json or cef")
    item["auth_type"] = str(item.get("auth_type", "none")).strip().lower()
    if item["auth_type"] not in {"none", "bearer", "basic", "api_key"}:
        raise ValueError("auth_type is not supported")
    item["secret_header"] = _text(item.get("secret_header", "X-API-Key"), "secret_header", maximum=64)
    if not _HEADER_NAME.fullmatch(item["secret_header"]):
        raise ValueError("secret_header must be a valid HTTP header name")
    headers = item.get("headers", {})
    if not isinstance(headers, Mapping) or len(headers) > 20:
        raise ValueError("headers must be an object with at most 20 entries")
    public_headers: dict[str, str] = {}
    for name, target in headers.items():
        if not _HEADER_NAME.fullmatch(str(name)) or str(name).lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
            raise ValueError("headers contain a reserved or invalid name")
        public_headers[str(name)] = _text(target, f"headers.{name}", maximum=500, required=False)
    item["headers"] = public_headers
    event_types = item.get("event_types", ["alerts"])
    if not isinstance(event_types, list) or not event_types or len(event_types) > 10:
        raise ValueError("event_types must be a non-empty list")
    normalized_events = list(dict.fromkeys(str(target).strip().lower() for target in event_types))
    if set(normalized_events) - {"alerts", "cases"}:
        raise ValueError("event_types may contain alerts and cases")
    item["event_types"] = normalized_events
    item["minimum_severity"] = str(item.get("minimum_severity", "medium")).strip().lower()
    if item["minimum_severity"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("minimum_severity is invalid")
    secret = dict(existing_secret or {})
    if "secret" in value:
        supplied = _text(value.get("secret"), "secret", maximum=4096, required=item["auth_type"] != "none")
        secret["secret"] = supplied
    if "username" in value:
        secret["username"] = _text(value.get("username"), "username", maximum=256, required=item["auth_type"] == "basic")
    if item["auth_type"] == "none":
        secret = {}
    elif not secret.get("secret"):
        raise ValueError("secret is required for the selected authentication type")
    elif item["auth_type"] == "basic" and not secret.get("username"):
        raise ValueError("username is required for basic authentication")
    item.update({
        "tenant_id": tenant_id,
        "deployment_id": deployment_id,
        "secret_configured": bool(secret.get("secret")),
        "created_at": str(item.get("created_at") or now),
        "updated_at": now,
    })
    return item, secret


def normalize_system_settings(
    tenant_id: str,
    deployment_id: str,
    changes: Mapping[str, Any],
    *,
    current: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    unknown = set(changes) - set(DEFAULT_SYSTEM_SETTINGS)
    if unknown:
        raise ValueError(f"unsupported system settings: {sorted(unknown)}")
    item = {**DEFAULT_SYSTEM_SETTINGS, **dict(current or {}), **changes}
    bounds = {
        "event_retention_days": (1, 3650),
        "raw_evidence_retention_days": (1, 3650),
        "alert_retention_days": (30, 3650),
        "case_retention_days": (30, 3650),
        "audit_retention_days": (365, 36500),
        "support_bundle_ttl_hours": (1, 720),
    }
    for key, (minimum, maximum) in bounds.items():
        item[key] = _bounded_int(item[key], key, minimum, maximum)
    item["timezone"] = _text(item["timezone"], "timezone", maximum=64)
    if item["timezone"] != "UTC":
        raise ValueError("the MVP stores and displays system timestamps in UTC")
    item.update({"tenant_id": tenant_id, "deployment_id": deployment_id, "updated_at": utc_now()})
    return item


def public_integration(item: Mapping[str, Any], secret: Mapping[str, Any] | None = None) -> dict[str, Any]:
    result = {key: value for key, value in item.items() if key not in {"secret", "secret_json", "username"}}
    result["secret_configured"] = bool((secret or {}).get("secret", item.get("secret_configured", False)))
    return result


def suppression_matches(
    suppression: Mapping[str, Any],
    detector_id: str,
    entity_id: str,
    evidence: list[Mapping[str, Any]],
    *,
    at: datetime,
) -> bool:
    if not suppression.get("enabled", False):
        return False
    expires_at = suppression.get("expires_at")
    if expires_at:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if at.astimezone(expiry.tzinfo) >= expiry:
            return False
    rule_id = str(suppression.get("rule_id", "*"))
    if rule_id not in {"*", detector_id}:
        return False
    match = suppression.get("match", {})
    if not isinstance(match, Mapping):
        return False
    for field, expected_value in match.items():
        expected = str(expected_value)
        if field == "entity_id":
            if entity_id != expected:
                return False
            continue
        actual_values = {str(item.get(field, "")) for item in evidence}
        if field in {"src_ip", "dst_ip"} and "/" in expected:
            try:
                network = ipaddress.ip_network(expected, strict=False)
                if not any(value and ipaddress.ip_address(value) in network for value in actual_values):
                    return False
            except ValueError:
                return False
        elif expected not in actual_values:
            return False
    return True
