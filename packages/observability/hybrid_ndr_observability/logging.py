"""Structured JSON logging for product services.

Every record is a single JSON object written to stderr, so container log
collectors can parse events without custom formats. Fields are allowlisted and
bounded: request bodies, query strings, headers, credentials, event data, and
evidence are never logged. Messages are truncated to a fixed limit.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Mapping

MAX_MESSAGE_CHARACTERS = 500
_ALLOWED_KEYS = frozenset({
    "ts", "level", "event", "service", "request_id", "method", "route", "status",
    "duration_ms", "actor_type", "error_code", "error_type", "error_message",
    "detector_id", "schedule", "sensor_id", "job", "cycle", "events", "alerts_created",
    "elapsed_ms", "target_version", "channel", "action", "reason_code", "attempt",
})


def _service_name() -> str:
    value = os.environ.get("HYBRID_NDR_SERVICE", "").strip().lower()
    return value if value else "hybrid-ndr"


def _record(event: str, level: str, fields: Mapping[str, Any]) -> str:
    record: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "event": event,
        "service": _service_name(),
    }
    for key, value in fields.items():
        if key not in _ALLOWED_KEYS:
            continue
        if value is None:
            continue
        if isinstance(value, str):
            value = value[:MAX_MESSAGE_CHARACTERS]
        if not isinstance(value, (bool, int, float, str)):
            continue
        record[key] = value
    return json.dumps(record, separators=(",", ":"), ensure_ascii=True)


def log(level: str, event: str, **fields: Any) -> None:
    """Write one structured log line to stderr."""
    print(_record(event, level, fields), file=sys.stderr, flush=True)


def info(event: str, **fields: Any) -> None:
    log("info", event, **fields)


def warning(event: str, **fields: Any) -> None:
    log("warning", event, **fields)


def error(event: str, **fields: Any) -> None:
    log("error", event, **fields)


def exception(event: str, exc: BaseException, **fields: Any) -> None:
    """Log an unexpected failure with bounded, sanitized detail.

    The exception message can reflect customer-controlled input, so it is
    truncated but still useful for correlation; the full traceback is written
    only when HYBRID_NDR_DEBUG=1 is set for the process.
    """
    fields = dict(fields)
    fields.setdefault("error_type", type(exc).__name__)
    fields.setdefault("error_message", str(exc)[:MAX_MESSAGE_CHARACTERS])
    log("error", event, **fields)
    if os.environ.get("HYBRID_NDR_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}:
        import traceback

        traceback.print_exc()
