"""Customer-local, privacy-minimized product telemetry."""

from .logging import error, exception, info, log, warning
from .telemetry import Telemetry, sanitize_route, validate_collector_endpoint

__all__ = [
    "Telemetry",
    "error",
    "exception",
    "info",
    "log",
    "sanitize_route",
    "validate_collector_endpoint",
    "warning",
]
