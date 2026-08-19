from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Any, Mapping
from urllib.parse import parse_qs

from hybrid_ndr_agent import InvestigationRuntime
from hybrid_ndr_auth import (
    DEFAULT_ROLE_PERMISSIONS,
    AuthenticationError,
    Principal,
    build_authenticator,
)
from hybrid_ndr_contracts import ValidationError
from hybrid_ndr_gateway import DeterministicAssessmentProvider, ModelGateway
from hybrid_ndr_observability import Telemetry, exception as log_exception, info as log_info, sanitize_route
from hybrid_ndr_observability.ratelimit import FixedWindowLimiter
from hybrid_ndr_storage import LocalStore, NotFoundError

from .standalone import (
    StandaloneAuthError,
    issue_access_token,
    load_jwks,
    standalone_settings,
    verify_login_secret,
)


ROLE_PERMISSIONS = DEFAULT_ROLE_PERMISSIONS

# Reject request bodies above this size before any JSON parsing; the WSGI
# layer refuses oversized Content-Length without reading the stream.
MAX_BODY_BYTES = 1_000_000


class APIError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AuthContext:
    tenant_id: str
    deployment_id: str
    actor_id: str
    role: str
    permissions: frozenset[str]

    def require(self, permission: str) -> None:
        if "*" not in self.permissions and permission not in self.permissions:
            raise APIError(403, "permission_denied", f"Permission '{permission}' is required for this operation.")


@dataclass(frozen=True)
class APIResponse:
    status: int
    body: dict[str, Any] | list[Any] | None
    headers: tuple[tuple[str, str], ...] = ()


class LocalAPI:
    def __init__(
        self,
        store: LocalStore,
        runtime: InvestigationRuntime,
        *,
        allowed_origins: set[str] | None = None,
        authenticator: Any | None = None,
        persistence: Any | None = None,
    ) -> None:
        self.store = store
        self.runtime = runtime
        self.authenticator = authenticator or build_authenticator(role_permissions=ROLE_PERMISSIONS)
        self.persistence = persistence
        self._standalone = standalone_settings()
        self.rate_limiter = FixedWindowLimiter(
            max(1, int(os.environ.get("LOCAL_API_RATE_LIMIT_PER_MINUTE", "600")))
        )
        configured = os.environ.get("LOCAL_API_ALLOWED_ORIGINS", "")
        self.allowed_origins = allowed_origins or {
            item.strip()
            for item in configured.split(",")
            if item.strip()
        } or {
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        }

    def handle(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | Mapping[str, Any] | None = None,
        query: Mapping[str, list[str]] | None = None,
    ) -> APIResponse:
        request_id = str(uuid.uuid4())
        started = time.monotonic()
        route = sanitize_route(path)
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        origin = normalized_headers.get("origin")
        cors = self._cors(origin)
        if method.upper() == "OPTIONS":
            if origin and origin not in self.allowed_origins:
                return self._error(403, "origin_not_allowed", "The request origin is not allowed.", request_id, cors)
            return APIResponse(204, None, cors)
        status = 500
        try:
            payload = self._body(body)
            method = method.upper()
            query = query or {}
            if path in {"/healthz", "/api/v1/system/health"} and method == "GET":
                return APIResponse(200, self._health(), cors)
            if self._standalone is not None and path == "/api/v1/system/jwks" and method == "GET":
                try:
                    jwks = load_jwks(self._standalone["jwks_file"])
                except StandaloneAuthError:
                    status = 503
                    return self._error(503, "standalone_identity_unavailable", "The local identity JWKS is unavailable.", request_id, cors)
                status = 200
                return APIResponse(200, jwks, cors)
            if self._standalone is not None and path == "/api/v1/system/standalone-login" and method == "POST":
                if not self.rate_limiter.allow("standalone-login"):
                    status = 429
                    return self._error(429, "rate_limit_exceeded", "Too many login attempts; retry later.", request_id, cors)
                login_response = self._standalone_login(normalized_headers, payload, request_id, cors)
                status = login_response.status
                return login_response
            auth = self._authenticate(normalized_headers)
            if not self.rate_limiter.allow(f"{auth.tenant_id}:{auth.actor_id}"):
                retry_after = str(self.rate_limiter.retry_after(f"{auth.tenant_id}:{auth.actor_id}"))
                return self._error(
                    429, "rate_limit_exceeded",
                    "Too many requests; retry after the limit window resets.",
                    request_id, (*cors, ("Retry-After", retry_after)),
                )
            response = self._dispatch(method, path.rstrip("/") or "/", auth, payload, query, request_id)
            status = response.status
            return APIResponse(response.status, response.body, (*response.headers, *cors))
        except APIError as exc:
            status = exc.status
            return self._error(exc.status, exc.code, exc.message, request_id, cors)
        except NotFoundError as exc:
            status = 404
            return self._error(404, "not_found", str(exc).capitalize() + ".", request_id, cors)
        except (ValidationError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            status = 400
            return self._error(400, "invalid_request", str(exc) or "The request body is invalid.", request_id, cors)
        except Exception as exc:
            status = 500
            log_exception(
                "api.internal_error", exc,
                request_id=request_id, method=method.upper(), route=route,
            )
            return self._error(500, "internal_error", "The server could not complete the request.", request_id, cors)
        finally:
            log_info(
                "api.request.completed",
                request_id=request_id, method=method.upper(), route=route,
                status=status, duration_ms=int((time.monotonic() - started) * 1000),
            )

    def _dispatch(
        self,
        method: str,
        path: str,
        auth: AuthContext,
        body: dict[str, Any],
        query: Mapping[str, list[str]],
        request_id: str,
    ) -> APIResponse:
        if method == "POST" and path == "/api/v1/session/audit":
            self._audit(
                auth, "authentication.succeeded", "session", auth.actor_id, request_id,
                {"role": auth.role, "deployment_id": auth.deployment_id},
            )
            return APIResponse(204, None)
        if method == "GET" and path == "/api/v1/overview":
            auth.require("alerts:read")
            alerts = self.store.list_alerts(auth.tenant_id, deployment_id=auth.deployment_id, limit=500)
            events = self.store.search_events(auth.tenant_id, deployment_id=auth.deployment_id, limit=1000)
            investigations = self.store.list_investigations(auth.tenant_id, deployment_id=auth.deployment_id, limit=500)
            return APIResponse(200, {
                "events": len(events), "alerts": len(alerts), "open_alerts": sum(item["status"] == "open" for item in alerts),
                "critical_alerts": sum(item["severity"] == "critical" for item in alerts),
                "completed_investigations": sum(item["status"] == "completed" for item in investigations),
                "sensors": self.store.list_sensors(auth.tenant_id, auth.deployment_id),
            })
        if method == "GET" and path == "/api/v1/alerts":
            auth.require("alerts:read")
            items = self.store.list_alerts(
                auth.tenant_id, deployment_id=auth.deployment_id,
                status=self._first(query, "status"), severity=self._first(query, "severity"),
                limit=int(self._first(query, "limit") or 100),
            )
            return APIResponse(200, {"items": items, "count": len(items)})
        match = re.fullmatch(r"/api/v1/alerts/([^/]+)", path)
        if match and method == "GET":
            auth.require("alerts:read")
            return APIResponse(200, self._scoped(self.store.get_alert(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth))
        if match and method == "PATCH":
            auth.require("alerts:update")
            before = self._scoped(self.store.get_alert(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            item = self.store.update_alert(
                auth.tenant_id, match.group(1), body, deployment_id=auth.deployment_id
            )
            self._audit(auth, "alert.updated", "alert", match.group(1), request_id, {"before_status": before["status"], "after_status": item["status"]})
            return APIResponse(200, item)
        match = re.fullmatch(r"/api/v1/alerts/([^/]+)/investigate", path)
        if match and method == "POST":
            auth.require("investigations:create")
            result = self.runtime.investigate(
                tenant_id=auth.tenant_id, deployment_id=auth.deployment_id, alert_id=match.group(1),
                actor_id=auth.actor_id, request_id=request_id,
            )
            return APIResponse(201, result)
        if method == "POST" and path == "/api/v1/events/search":
            auth.require("events:search")
            allowed = {
                "query", "event_type", "entity_id", "source", "start_time", "end_time", "protocol",
                "src_ip", "dst_ip", "sensor_id", "event_id", "offset", "limit",
            }
            unknown = set(body) - allowed
            if unknown:
                raise APIError(400, "invalid_search", f"Unsupported event search fields: {sorted(unknown)}.")
            for field in allowed - {"offset", "limit"}:
                value = body.get(field)
                if value is not None and (not isinstance(value, str) or len(value) > 500):
                    raise APIError(400, "invalid_search", f"Search field '{field}' must be a string of at most 500 characters.")
            items = self.store.search_events(
                auth.tenant_id, deployment_id=auth.deployment_id, event_type=body.get("event_type"),
                entity_id=body.get("entity_id"), source=body.get("source"), query_text=body.get("query"),
                start_time=body.get("start_time"), end_time=body.get("end_time"), protocol=body.get("protocol"),
                src_ip=body.get("src_ip"), dst_ip=body.get("dst_ip"), sensor_id=body.get("sensor_id"),
                event_id=body.get("event_id"), offset=int(body.get("offset", 0)), limit=int(body.get("limit", 100)),
            )
            return APIResponse(200, {"items": items, "count": len(items), "offset": int(body.get("offset", 0)), "limit": int(body.get("limit", 100))})
        if method == "POST" and path == "/api/v1/events/ingest":
            auth.require("events:write")
            raw_events = body.get("events")
            if not isinstance(raw_events, list):
                raise APIError(400, "invalid_events", "The 'events' field must be a list.")
            for event in raw_events:
                if event.get("tenant_id") != auth.tenant_id or event.get("deployment_id") != auth.deployment_id:
                    raise APIError(403, "tenant_mismatch", "Every event must match the authenticated tenant and deployment.")
            items = self.store.insert_events(raw_events)
            return APIResponse(202, {"accepted": len(items)})
        match = re.fullmatch(r"/api/v1/entities/([^/]+)/timeline", path)
        if match and method == "GET":
            auth.require("events:search")
            items = self.store.search_events(auth.tenant_id, deployment_id=auth.deployment_id, entity_id=match.group(1), limit=200)
            return APIResponse(200, {"items": items, "count": len(items)})
        match = re.fullmatch(r"/api/v1/entities/([^/]+)/baseline", path)
        if match and method == "GET":
            auth.require("events:search")
            return APIResponse(200, self.store.get_baseline(auth.tenant_id, auth.deployment_id, match.group(1)))
        if method == "GET" and path == "/api/v1/investigations":
            auth.require("investigations:read")
            items = self.store.list_investigations(auth.tenant_id, deployment_id=auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        match = re.fullmatch(r"/api/v1/investigations/([^/]+)", path)
        if match and method == "GET":
            auth.require("investigations:read")
            return APIResponse(200, self._scoped(self.store.get_investigation(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth))
        match = re.fullmatch(r"/api/v1/investigations/([^/]+)/retry", path)
        if match and method == "POST":
            auth.require("investigations:create")
            previous = self._scoped(self.store.get_investigation(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            result = self.runtime.investigate(
                tenant_id=auth.tenant_id, deployment_id=auth.deployment_id, alert_id=previous["alert_id"],
                actor_id=auth.actor_id, request_id=request_id,
            )
            return APIResponse(201, result)
        match = re.fullmatch(r"/api/v1/investigations/([^/]+)/transmission", path)
        if match and method == "GET":
            auth.require("transmissions:read")
            return APIResponse(200, self._scoped(self.store.get_transmission(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth))
        if method == "GET" and path == "/api/v1/transmissions":
            auth.require("transmissions:read")
            items = self.store.list_transmissions(auth.tenant_id, deployment_id=auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "GET" and path == "/api/v1/cases":
            auth.require("alerts:read")
            items = self.store.list_cases(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "POST" and path == "/api/v1/cases":
            auth.require("cases:create")
            item = self.store.create_case(auth.tenant_id, auth.deployment_id, body)
            self._audit(auth, "case.created", "case", item["case_id"], request_id)
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/cases/([^/]+)", path)
        if match and method == "GET":
            auth.require("alerts:read")
            item = self._scoped(self.store.get_case(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            item["comments"] = self.store.list_comments(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            )
            return APIResponse(200, item)
        if match and method == "PATCH":
            auth.require("cases:update")
            self._scoped(self.store.get_case(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            item = self.store.update_case(
                auth.tenant_id, match.group(1), body, deployment_id=auth.deployment_id
            )
            self._audit(auth, "case.updated", "case", match.group(1), request_id)
            return APIResponse(200, item)
        match = re.fullmatch(r"/api/v1/cases/([^/]+)/comments", path)
        if match and method == "POST":
            auth.require("cases:update")
            self._scoped(self.store.get_case(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            item = self.store.add_case_comment(
                auth.tenant_id, match.group(1), auth.actor_id, str(body.get("body", "")),
                deployment_id=auth.deployment_id,
            )
            self._audit(auth, "case.comment.created", "case", match.group(1), request_id)
            return APIResponse(201, item)
        if match and method == "GET":
            auth.require("alerts:read")
            self._scoped(self.store.get_case(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            ), auth)
            items = self.store.list_comments(
                auth.tenant_id, match.group(1), deployment_id=auth.deployment_id
            )
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "GET" and path == "/api/v1/sensors":
            auth.require("alerts:read")
            items = self.store.list_sensors(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "GET" and path == "/api/v1/audit":
            auth.require("audit:read")
            items = self.store.audit.list(auth.tenant_id, auth.deployment_id, limit=int(self._first(query, "limit") or 200))
            return APIResponse(200, {"items": items, "count": len(items), "chain_valid": self.store.audit.verify(auth.tenant_id, auth.deployment_id)})
        if method == "GET" and path == "/api/v1/model-policy":
            auth.require("transmissions:read")
            return APIResponse(200, self.store.get_policy(auth.tenant_id, auth.deployment_id))
        if method == "PATCH" and path == "/api/v1/model-policy":
            auth.require("model-policy:manage")
            item = self.store.set_policy(auth.tenant_id, auth.deployment_id, body)
            self._audit(auth, "model_policy.updated", "model_policy", item["policy_id"], request_id)
            return APIResponse(200, item)
        if method == "GET" and path == "/api/v1/detection-rules":
            auth.require("rules:read")
            items = self.store.list_detection_rules(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "POST" and path == "/api/v1/detection-rules":
            auth.require("rules:manage")
            item = self.store.create_detection_rule(
                auth.tenant_id, auth.deployment_id, body, actor_id=auth.actor_id
            )
            self._audit(auth, "rule.created", "detection_rule", item["rule_id"], request_id)
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/detection-rules/([^/]+)", path)
        if match and method == "GET":
            auth.require("rules:read")
            return APIResponse(200, self.store.get_detection_rule(
                auth.tenant_id, auth.deployment_id, match.group(1)
            ))
        if match and method == "PATCH":
            auth.require("rules:manage")
            item = self.store.update_detection_rule(
                auth.tenant_id, auth.deployment_id, match.group(1), body, actor_id=auth.actor_id
            )
            self._audit(
                auth, "rule.updated", "detection_rule", item["rule_id"], request_id,
                {"fields": sorted(body)},
            )
            return APIResponse(200, item)
        if match and method == "DELETE":
            auth.require("rules:manage")
            item = self.store.delete_detection_rule(auth.tenant_id, auth.deployment_id, match.group(1))
            self._audit(auth, "rule.deleted", "detection_rule", item["rule_id"], request_id)
            return APIResponse(200, {"deleted": True, "item": item})
        if method == "GET" and path == "/api/v1/detection-suppressions":
            auth.require("rules:read")
            items = self.store.list_suppressions(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "POST" and path == "/api/v1/detection-suppressions":
            auth.require("rules:manage")
            item = self.store.create_suppression(
                auth.tenant_id, auth.deployment_id, body, actor_id=auth.actor_id
            )
            self._audit(auth, "suppression.created", "detection_suppression", item["suppression_id"], request_id)
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/detection-suppressions/([^/]+)", path)
        if match and method == "GET":
            auth.require("rules:read")
            return APIResponse(200, self.store.get_suppression(
                auth.tenant_id, auth.deployment_id, match.group(1)
            ))
        if match and method == "PATCH":
            auth.require("rules:manage")
            item = self.store.update_suppression(
                auth.tenant_id, auth.deployment_id, match.group(1), body, actor_id=auth.actor_id
            )
            self._audit(
                auth, "suppression.updated", "detection_suppression", item["suppression_id"], request_id,
                {"fields": sorted(body)},
            )
            return APIResponse(200, item)
        if match and method == "DELETE":
            auth.require("rules:manage")
            item = self.store.delete_suppression(auth.tenant_id, auth.deployment_id, match.group(1))
            self._audit(auth, "suppression.deleted", "detection_suppression", item["suppression_id"], request_id)
            return APIResponse(200, {"deleted": True, "item": item})
        if method == "GET" and path == "/api/v1/integrations":
            auth.require("integrations:manage")
            items = self.store.list_integrations(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {
                "items": items, "count": len(items),
                "forwarding_contract": {
                    "method": "POST", "transport": "https", "formats": ["json", "cef"],
                    "event_types": ["alerts", "cases"], "delivery": "at_least_once",
                    "authentication": ["none", "bearer", "basic", "api_key"],
                    "secret_handling": "write_only_customer_local",
                },
            })
        if method == "POST" and path == "/api/v1/integrations":
            auth.require("integrations:manage")
            item = self.store.create_integration(auth.tenant_id, auth.deployment_id, body)
            self._audit(
                auth, "integration.created", "integration", item["integration_id"], request_id,
                {"kind": item["kind"], "auth_type": item["auth_type"]},
            )
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/integrations/([^/]+)", path)
        if match and method == "GET":
            auth.require("integrations:manage")
            return APIResponse(200, self.store.get_integration(
                auth.tenant_id, auth.deployment_id, match.group(1)
            ))
        if match and method == "PATCH":
            auth.require("integrations:manage")
            item = self.store.update_integration(auth.tenant_id, auth.deployment_id, match.group(1), body)
            self._audit(
                auth, "integration.updated", "integration", item["integration_id"], request_id,
                {"fields": sorted(set(body) - {"secret", "username"}), "secret_rotated": "secret" in body},
            )
            return APIResponse(200, item)
        if match and method == "DELETE":
            auth.require("integrations:manage")
            item = self.store.delete_integration(auth.tenant_id, auth.deployment_id, match.group(1))
            self._audit(auth, "integration.deleted", "integration", item["integration_id"], request_id)
            return APIResponse(200, {"deleted": True, "item": item})
        if method == "GET" and path == "/api/v1/system/settings":
            auth.require("alerts:read")
            return APIResponse(200, self.store.get_system_settings(auth.tenant_id, auth.deployment_id))
        if method == "PATCH" and path == "/api/v1/system/settings":
            auth.require("deployments:manage")
            before = self.store.get_system_settings(auth.tenant_id, auth.deployment_id)
            item = self.store.update_system_settings(auth.tenant_id, auth.deployment_id, body)
            retention_fields = sorted(field for field in body if field.endswith("_retention_days"))
            if retention_fields:
                self._audit(
                    auth, "retention.updated", "system_settings", auth.deployment_id, request_id,
                    {"fields": retention_fields, "before": {field: before[field] for field in retention_fields},
                     "after": {field: item[field] for field in retention_fields}},
                )
            else:
                self._audit(auth, "system_settings.updated", "system_settings", auth.deployment_id, request_id, {"fields": sorted(body)})
            return APIResponse(200, item)
        if method == "GET" and path == "/api/v1/evidence/exports":
            auth.require("evidence:read")
            items = self.store.list_evidence_exports(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "POST" and path == "/api/v1/evidence/exports":
            auth.require("evidence:read")
            if body.get("alert_id"):
                self._scoped(self.store.get_alert(
                    auth.tenant_id, str(body["alert_id"]), deployment_id=auth.deployment_id
                ), auth)
            if body.get("investigation_id"):
                self._scoped(self.store.get_investigation(
                    auth.tenant_id, str(body["investigation_id"]), deployment_id=auth.deployment_id
                ), auth)
            evidence_ids = body.get("evidence_ids") if isinstance(body.get("evidence_ids"), list) else []
            events = self.store.get_events(auth.tenant_id, evidence_ids, deployment_id=auth.deployment_id)
            if len(events) != len(set(evidence_ids)):
                raise APIError(400, "invalid_evidence", "Every requested evidence identifier must exist in this deployment.")
            item = self.store.create_evidence_export(
                auth.tenant_id, auth.deployment_id, body, requested_by=auth.actor_id
            )
            self._audit(auth, "evidence_export.requested", "evidence_export", item["export_id"], request_id, {"evidence_count": len(events)})
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/evidence/exports/([^/]+)", path)
        if match and method == "GET":
            auth.require("evidence:read")
            return APIResponse(200, self.store.get_evidence_export(
                auth.tenant_id, auth.deployment_id, match.group(1)
            ))
        match = re.fullmatch(r"/api/v1/evidence/exports/([^/]+)/approve", path)
        if match and method == "POST":
            auth.require("evidence:export")
            if body.get("approved") is not True:
                raise APIError(400, "explicit_approval_required", "Set 'approved' to true to explicitly approve this export.")
            pending = self.store.get_evidence_export(auth.tenant_id, auth.deployment_id, match.group(1))
            events = self.store.get_events(
                auth.tenant_id, pending["evidence_ids"], deployment_id=auth.deployment_id
            )
            if len(events) != len(pending["evidence_ids"]):
                raise APIError(409, "evidence_unavailable", "The complete approved evidence set is no longer locally available.")
            document = {
                "schema_version": "hybrid-ndr-evidence-export/v1", "export_id": pending["export_id"],
                "tenant_id": auth.tenant_id, "deployment_id": auth.deployment_id,
                "alert_id": pending.get("alert_id"), "investigation_id": pending.get("investigation_id"),
                "requested_by": pending["requested_by"], "approved_by": auth.actor_id,
                "exported_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "reason": pending["reason"], "evidence": events,
            }
            item = self.store.approve_evidence_export(
                auth.tenant_id, auth.deployment_id, match.group(1), approved_by=auth.actor_id,
                justification=str(body.get("justification", "")), document=document,
            )
            self._audit(auth, "response.approved", "evidence_export", item["export_id"], request_id, {"approval_type": "evidence_export"})
            self._audit(auth, "evidence_export.approved", "evidence_export", item["export_id"], request_id, {"sha256": item["sha256"]})
            return APIResponse(200, item)
        match = re.fullmatch(r"/api/v1/evidence/exports/([^/]+)/download", path)
        if match and method == "GET":
            auth.require("evidence:export")
            document = self.store.get_evidence_export_document(auth.tenant_id, auth.deployment_id, match.group(1))
            item = self.store.mark_evidence_export_downloaded(auth.tenant_id, auth.deployment_id, match.group(1))
            self._audit(auth, "evidence_export.downloaded", "evidence_export", item["export_id"], request_id, {"sha256": item["sha256"]})
            return APIResponse(200, {
                "filename": f"evidence-{item['export_id']}.json", "content_type": "application/json",
                "sha256": item["sha256"], "document": document,
            })
        if method == "GET" and path == "/api/v1/support-bundles":
            auth.require("deployments:manage")
            items = self.store.list_support_bundles(auth.tenant_id, auth.deployment_id)
            return APIResponse(200, {"items": items, "count": len(items)})
        if method == "POST" and path == "/api/v1/support-bundles":
            auth.require("deployments:manage")
            allowed_options = {"include_health", "include_configuration", "include_audit"}
            if set(body) - allowed_options or any(not isinstance(value, bool) for value in body.values()):
                raise APIError(400, "invalid_bundle_options", "Support bundle options must be supported boolean flags.")
            options = {"include_health": True, "include_configuration": True, "include_audit": True, **body}
            settings = self.store.get_system_settings(auth.tenant_id, auth.deployment_id)
            document: dict[str, Any] = {
                "schema_version": "hybrid-ndr-support-bundle/v1", "tenant_id": auth.tenant_id,
                "deployment_id": auth.deployment_id, "generated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "generated_by": auth.actor_id, "software_version": os.environ.get("SOFTWARE_VERSION", "development"),
                "privacy": {"contains_secrets": False, "contains_event_content": False},
            }
            if options["include_health"]:
                document["health"] = self._health()
                document["sensors"] = self.store.list_sensors(auth.tenant_id, auth.deployment_id)
            if options["include_configuration"]:
                document["configuration"] = {
                    "system_settings": settings,
                    "detection_rules": self.store.list_detection_rules(auth.tenant_id, auth.deployment_id),
                    "suppression_count": len(self.store.list_suppressions(auth.tenant_id, auth.deployment_id)),
                    "integrations": [
                        {key: item.get(key) for key in ("integration_id", "name", "kind", "enabled", "format", "secret_configured")}
                        for item in self.store.list_integrations(auth.tenant_id, auth.deployment_id)
                    ],
                }
            if options["include_audit"]:
                document["audit"] = self.store.audit.list(auth.tenant_id, auth.deployment_id, limit=100)
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=settings["support_bundle_ttl_hours"])).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            item = self.store.create_support_bundle(
                auth.tenant_id, auth.deployment_id, document, requested_by=auth.actor_id,
                expires_at=expires_at, options=options,
            )
            self._audit(auth, "support_bundle.created", "support_bundle", item["bundle_id"], request_id, {"sha256": item["sha256"]})
            return APIResponse(201, item)
        match = re.fullmatch(r"/api/v1/support-bundles/([^/]+)", path)
        if match and method == "GET":
            auth.require("deployments:manage")
            return APIResponse(200, self.store.get_support_bundle(
                auth.tenant_id, auth.deployment_id, match.group(1)
            ))
        match = re.fullmatch(r"/api/v1/support-bundles/([^/]+)/download", path)
        if match and method == "GET":
            auth.require("deployments:manage")
            item = self.store.get_support_bundle(auth.tenant_id, auth.deployment_id, match.group(1))
            expiry = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) >= expiry:
                raise APIError(410, "support_bundle_expired", "The support bundle has expired and must be regenerated.")
            document = self.store.get_support_bundle_document(auth.tenant_id, auth.deployment_id, match.group(1))
            item = self.store.mark_support_bundle_downloaded(auth.tenant_id, auth.deployment_id, match.group(1))
            self._audit(auth, "support.accessed", "support_bundle", item["bundle_id"], request_id, {"sha256": item["sha256"]})
            return APIResponse(200, {
                "filename": f"support-{item['bundle_id']}.json", "content_type": "application/json",
                "sha256": item["sha256"], "document": document,
            })
        raise APIError(404, "route_not_found", f"No API route matches {method} {path}.")

    def _health(self) -> dict[str, Any]:
        try:
            if hasattr(self.store, "readiness"):
                database = "healthy" if self.store.readiness().ready else "unhealthy"
            else:
                self.store.connection.execute("SELECT 1").fetchone()
                database = "healthy"
        except Exception:
            database = "unhealthy"
        persistence = self.persistence.readiness() if self.persistence is not None else None
        dependencies_ready = persistence is None or persistence["ready"] or not persistence["required"]
        return {
            "status": "healthy" if database == "healthy" and dependencies_ready else "degraded",
            "service": "local-api",
            "database": database,
            "persistence": persistence,
            "detection_mode": "local-offline-capable",
            "model_dependency_required": False,
        }

    def _standalone_login(
        self,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        request_id: str,
        cors: tuple[tuple[str, str], ...],
    ) -> APIResponse:
        """Issue a short-lived local analyst token in air-gapped deployments."""
        assert self._standalone is not None
        authorization = headers.get("authorization", "").strip()
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not verify_login_secret(self._standalone, parts[1]):
            return self._error(401, "standalone_login_denied", "The standalone login credential is invalid.", request_id, cors)
        actor_id = str(payload.get("analyst", "")).strip()
        role = str(payload.get("role", "")).strip().lower().replace("-", "_")
        if not actor_id or len(actor_id) > 128:
            return self._error(400, "invalid_login", "Provide an analyst identifier of at most 128 characters.", request_id, cors)
        config = self.authenticator.config if hasattr(self.authenticator, "config") else None
        issuer = getattr(config, "issuer", "") or "https://hybrid-ndr.local/oidc"
        audience = getattr(config, "audience", "") or "https://hybrid-ndr.local/api"
        try:
            issued = issue_access_token(
                tenant_id=getattr(config, "expected_tenant_id", "") or os.environ.get("TENANT_ID", ""),
                deployment_id=getattr(config, "expected_deployment_id", "") or os.environ.get("DEPLOYMENT_ID", ""),
                actor_id=actor_id,
                role=role,
                issuer=issuer,
                audience=audience,
                jwks_path=self._standalone["jwks_file"],
                issuer_key_path=self._standalone["issuer_key_file"],
            )
        except StandaloneAuthError as exc:
            return self._error(400, "invalid_login", str(exc), request_id, cors)
        return APIResponse(200, issued, cors)

    @staticmethod
    def _body(body: bytes | str | Mapping[str, Any] | None) -> dict[str, Any]:
        if body is None or body == b"" or body == "":
            return {}
        if isinstance(body, Mapping):
            return dict(body)
        if isinstance(body, bytes):
            if len(body) > MAX_BODY_BYTES:
                raise APIError(413, "body_too_large", f"The request body must be at most {MAX_BODY_BYTES} bytes.")
            body = body.decode("utf-8")
        elif len(body) > MAX_BODY_BYTES:
            raise APIError(413, "body_too_large", f"The request body must be at most {MAX_BODY_BYTES} bytes.")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise APIError(400, "invalid_json", "The JSON request body must be an object.")
        return value

    def _authenticate(self, headers: Mapping[str, str]) -> AuthContext:
        try:
            principal: Principal = self.authenticator.authenticate(headers)
        except AuthenticationError as exc:
            raise APIError(exc.status, exc.code, exc.message) from exc
        return AuthContext(
            principal.tenant_id,
            principal.deployment_id,
            principal.actor_id,
            principal.role,
            principal.permissions,
        )

    @staticmethod
    def _scoped(item: dict[str, Any], auth: AuthContext) -> dict[str, Any]:
        if item.get("deployment_id") != auth.deployment_id:
            # Deliberately return a not-found shape so deployment membership is
            # not disclosed across a tenant's sites.
            raise NotFoundError("resource not found")
        return item

    def _cors(self, origin: str | None) -> tuple[tuple[str, str], ...]:
        common = (
            ("Vary", "Origin"),
            ("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Deployment-ID, X-Actor-ID, X-Role, X-Permissions, Idempotency-Key"),
            ("Access-Control-Max-Age", "600"),
        )
        if origin and origin in self.allowed_origins:
            return (("Access-Control-Allow-Origin", origin), *common)
        return common

    @staticmethod
    def _first(query: Mapping[str, list[str]], key: str) -> str | None:
        values = query.get(key, [])
        return values[0] if values else None

    def _audit(self, auth: AuthContext, action: str, resource_type: str, resource_id: str, request_id: str, metadata: Mapping[str, Any] | None = None) -> None:
        self.store.audit.append(
            tenant_id=auth.tenant_id, deployment_id=auth.deployment_id, actor_id=auth.actor_id,
            actor_type="human", action=action, resource_type=resource_type, resource_id=resource_id,
            request_id=request_id, metadata=metadata,
        )

    @staticmethod
    def _error(status: int, code: str, message: str, request_id: str, headers: tuple[tuple[str, str], ...]) -> APIResponse:
        return APIResponse(status, {"error": {"code": code, "message": message}, "request_id": request_id}, headers)


def create_application(store: LocalStore, *, authenticator: Any | None = None, persistence: Any | None = None):
    if authenticator is None:
        standalone = standalone_settings()
        if standalone is not None:
            # Air-gapped deployments validate bearer tokens against the local
            # JWKS directly (no network fetch) and require AUTH_MODE=jwt.
            from hybrid_ndr_auth import AuthConfig, JWTAuthenticator, StaticJWKSource

            config = AuthConfig.from_env()
            if config.mode != "jwt":
                raise RuntimeError("standalone authentication requires AUTH_MODE=jwt")
            try:
                jwks = load_jwks(standalone["jwks_file"])
            except StandaloneAuthError as exc:
                raise RuntimeError("standalone JWKS is unavailable") from exc
            authenticator = JWTAuthenticator(
                config, StaticJWKSource(jwks["keys"]), role_permissions=ROLE_PERMISSIONS
            )
    gateway = ModelGateway(
        DeterministicAssessmentProvider(), signing_key=b"local-demo-envelope-signing-key-0123456789"
    )
    runtime = InvestigationRuntime(store, gateway, token_key=b"local-demo-redaction-token-key")
    api = LocalAPI(store, runtime, authenticator=authenticator, persistence=persistence)

    def application(environ: Mapping[str, Any], start_response: Any):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        if length > MAX_BODY_BYTES:
            # Refuse oversized bodies before reading any of the stream so a
            # client cannot force unbounded memory use in the server.
            payload = json.dumps(
                {"error": {"code": "body_too_large", "message": f"The request body must be at most {MAX_BODY_BYTES} bytes."}},
                separators=(",", ":"),
            ).encode("utf-8")
            start_response("413 Request Entity Too Large", [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(payload)))])
            return [payload]
        body = environ["wsgi.input"].read(length) if length else b""
        headers = {
            key[5:].replace("_", "-"): value
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }
        if environ.get("CONTENT_TYPE"):
            headers["CONTENT-TYPE"] = environ["CONTENT_TYPE"]
        response = api.handle(
            environ["REQUEST_METHOD"], environ.get("PATH_INFO", "/"), headers=headers, body=body,
            query=parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True),
        )
        payload = b"" if response.body is None else json.dumps(response.body, separators=(",", ":")).encode("utf-8")
        response_headers = [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(payload))), *response.headers]
        start_response(f"{response.status} {HTTPStatus(response.status).phrase}", response_headers)
        return [payload]

    application.api = api  # type: ignore[attr-defined]
    return Telemetry("local-api").wrap_wsgi(application)
