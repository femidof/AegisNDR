from __future__ import annotations

import contextlib
import os
import re
import time
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit, urlunsplit


_SERVICE_NAME = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_SAFE_SEGMENTS = frozenset({
    "api", "v1", "healthz", "metrics", "overview", "alerts", "events", "search",
    "ingest", "entities", "timeline", "baseline", "investigations", "retry",
    "transmission", "transmissions", "cases", "comments", "sensors", "audit",
    "model-policy", "system", "support", "health",
})
_LOCAL_COLLECTOR_HOSTS = frozenset({"otel-collector", "localhost", "127.0.0.1", "::1"})


def validate_collector_endpoint(value: str) -> str:
    """Allow OTLP export only to the customer-local collector or loopback."""

    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("OTLP endpoint is not a valid URL") from exc
    if parsed.scheme != "http" or parsed.hostname not in _LOCAL_COLLECTOR_HOSTS:
        raise ValueError("OTLP endpoint must use HTTP to the customer-local collector")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("OTLP endpoint must not contain credentials, a query, or a fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("OTLP base endpoint must not contain a path")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def sanitize_route(path: str) -> str:
    """Produce a bounded route label without customer-controlled identifiers."""

    if not isinstance(path, str) or not path.startswith("/"):
        return "/unmatched"
    segments = [segment for segment in path.split("/") if segment][:8]
    if not segments:
        return "/"
    sanitized = [segment if segment in _SAFE_SEGMENTS else ":id" for segment in segments]
    return "/" + "/".join(sanitized)


class _NoopCounter:
    def add(self, _amount: int | float, _attributes: Mapping[str, Any] | None = None) -> None:
        return None


class _NoopHistogram:
    def record(self, _amount: int | float, _attributes: Mapping[str, Any] | None = None) -> None:
        return None


class _NoopSpan:
    def set_attribute(self, _name: str, _value: Any) -> None:
        return None


@contextlib.contextmanager
def _noop_span() -> Iterator[_NoopSpan]:
    yield _NoopSpan()


class Telemetry:
    """Minimal instrumentation facade backed by OpenTelemetry when installed.

    Only operational, bounded attributes are emitted. Request bodies, query
    strings, headers, tenant/deployment IDs, actors, event data, and evidence
    never become metrics or span attributes.
    """

    def __init__(self, service_name: str, environ: Mapping[str, str] | None = None) -> None:
        if not _SERVICE_NAME.fullmatch(service_name):
            raise ValueError("invalid OpenTelemetry service name")
        env = environ if environ is not None else os.environ
        self.service_name = service_name
        self.enabled = env.get("OTEL_SDK_DISABLED", "false").strip().lower() not in {
            "1", "true", "yes", "on",
        }
        self._tracer: Any = None
        self._request_count: Any = _NoopCounter()
        self._request_duration: Any = _NoopHistogram()
        self._detection_cycles: Any = _NoopCounter()
        self._detection_events: Any = _NoopCounter()
        self._detection_alerts: Any = _NoopCounter()
        self._detection_duration: Any = _NoopHistogram()
        if not self.enabled:
            return

        endpoint = validate_collector_endpoint(
            env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318").strip()
        )
        try:
            from opentelemetry import metrics, trace
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError:
            # Native unit-test runs intentionally have no optional telemetry
            # dependency. The production image installs the pinned SDK.
            self.enabled = False
            return

        resource = Resource.create({
            "service.name": service_name,
            "deployment.environment.name": "customer",
            "hybrid_ndr.data_classification": "operational-only",
        })
        trace_provider = TracerProvider(resource=resource)
        trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(
            endpoint=endpoint + "/v1/traces", timeout=2,
        )))
        trace.set_tracer_provider(trace_provider)
        self._tracer = trace.get_tracer("hybrid_ndr_observability", "1")

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=endpoint + "/v1/metrics", timeout=2),
            export_interval_millis=15_000,
            export_timeout_millis=2_000,
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter("hybrid_ndr_observability", "1")
        self._request_count = meter.create_counter(
            "hybrid_ndr.http.server.requests", unit="{request}",
            description="Completed product HTTP requests",
        )
        self._request_duration = meter.create_histogram(
            "hybrid_ndr.http.server.duration", unit="ms",
            description="Product HTTP request duration",
        )
        self._detection_cycles = meter.create_counter(
            "hybrid_ndr.detection.cycles", unit="{cycle}",
        )
        self._detection_events = meter.create_counter(
            "hybrid_ndr.detection.events_evaluated", unit="{event}",
        )
        self._detection_alerts = meter.create_counter(
            "hybrid_ndr.detection.alerts_created", unit="{alert}",
        )
        self._detection_duration = meter.create_histogram(
            "hybrid_ndr.detection.cycle.duration", unit="ms",
        )

    @contextlib.contextmanager
    def span(self, name: str) -> Iterator[Any]:
        if self._tracer is None:
            with _noop_span() as span:
                yield span
            return
        with self._tracer.start_as_current_span(name) as span:
            yield span

    def record_detection_cycle(
        self,
        stats: Mapping[str, int],
        duration_ms: float,
        *,
        succeeded: bool,
    ) -> None:
        attributes = {"job.kind": "scheduled", "job.success": succeeded}
        self._detection_cycles.add(1, attributes)
        self._detection_events.add(max(0, int(stats.get("events", 0))), attributes)
        self._detection_alerts.add(max(0, int(stats.get("alerts_created", 0))), attributes)
        self._detection_duration.record(max(0.0, float(duration_ms)), attributes)

    def wrap_wsgi(self, application: Callable[..., Any]) -> Callable[..., Any]:
        def observed(environ: Mapping[str, Any], start_response: Callable[..., Any]):
            started = time.monotonic()
            method = str(environ.get("REQUEST_METHOD", "GET")).upper()
            if method not in {"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}:
                method = "OTHER"
            route = sanitize_route(str(environ.get("PATH_INFO", "/")))
            status_code = 500

            def observed_start_response(status: str, headers: Any, exc_info: Any = None):
                nonlocal status_code
                try:
                    status_code = int(status.split(" ", 1)[0])
                except (ValueError, IndexError):
                    status_code = 500
                if exc_info is None:
                    return start_response(status, headers)
                return start_response(status, headers, exc_info)

            with self.span(f"{method} {route}") as span:
                try:
                    return application(environ, observed_start_response)
                finally:
                    attributes = {
                        "http.request.method": method,
                        "http.route": route,
                        "http.response.status_code": status_code,
                    }
                    duration_ms = (time.monotonic() - started) * 1000
                    self._request_count.add(1, attributes)
                    self._request_duration.record(duration_ms, attributes)
                    for key, value in attributes.items():
                        span.set_attribute(key, value)

        observed.api = getattr(application, "api", None)  # type: ignore[attr-defined]
        return observed
