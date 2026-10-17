from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Mapping
from urllib.parse import parse_qs

from hybrid_ndr_auth import AuthenticationError
from hybrid_ndr_gateway import GatewayPolicyError, ModelGateway, ModelUnavailable
from hybrid_ndr_observability import exception as log_exception, info as log_info, sanitize_route
from hybrid_ndr_observability.ratelimit import FixedWindowLimiter

from .portal_auth import PortalAuthenticator, PortalPrincipal
from .store import ControlError, ControlStore, canonical, now


# Reject request bodies above this size before any JSON parsing; the WSGI
# layer refuses oversized Content-Length without reading the stream.
MAX_BODY_BYTES = 1_000_000


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, Any] | None
    headers: tuple[tuple[str, str], ...] = ()


class APIError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


FORBIDDEN_CLOUD_KEYS = frozenset({
    "raw_event", "raw_events", "event", "events", "event_id", "event_ids",
    "evidence", "evidence_id", "evidence_ids", "packet", "packets", "pcap",
    "packet_capture", "log", "logs", "alert", "alerts", "case", "cases",
    "analyst_note", "analyst_notes", "prompt", "response", "src_ip", "dst_ip",
    "source_ip", "destination_ip", "hostname", "username", "credential", "credentials",
})


def reject_customer_content(value: Any) -> None:
    if isinstance(value, Mapping):
        forbidden = {str(key).strip().lower() for key in value} & FORBIDDEN_CLOUD_KEYS
        if forbidden:
            raise APIError(
                400,
                "customer_content_forbidden",
                "Customer event, evidence, credential, and investigation content is not accepted by the control plane.",
            )
        for nested in value.values():
            reject_customer_content(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            reject_customer_content(nested)


class ControlAPI:
    def __init__(
        self,
        store: ControlStore,
        gateway: ModelGateway | None = None,
        *,
        portal_authenticator: PortalAuthenticator | None = None,
        allowed_origins: set[str] | None = None,
        allow_insecure_fingerprint_header: bool = False,
    ) -> None:
        if allow_insecure_fingerprint_header and os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
            raise ValueError("insecure fingerprint header is forbidden when HYBRID_NDR_ENV=production")
        self.store, self.gateway = store, gateway
        self.portal_authenticator = portal_authenticator
        self.allow_insecure_fingerprint_header = allow_insecure_fingerprint_header
        self.rate_limiter = FixedWindowLimiter(
            max(1, int(os.environ.get("CONTROL_API_RATE_LIMIT_PER_MINUTE", "600")))
        )
        configured = os.environ.get("CONTROL_API_ALLOWED_ORIGINS", "")
        self.allowed_origins = allowed_origins or {item.strip() for item in configured.split(",") if item.strip()} or {
            "http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173"
        }

    def handle(self, method: str, path: str, *, headers: Mapping[str, str] | None = None, body: Any = None) -> Response:
        request_id = str(uuid.uuid4())
        started = time.monotonic()
        route = sanitize_route(path)
        headers = {key.lower(): value for key, value in (headers or {}).items()}
        cors = self._cors(headers.get("origin"))
        if method.upper() == "OPTIONS":
            return Response(204, None, cors)
        status = 500
        try:
            method, path = method.upper(), path.rstrip("/") or "/"
            payload = self._body(body)
            if method == "GET" and path in {"/healthz", "/v1/health"}:
                self.store.connection.execute("SELECT 1")
                return Response(200, {"status": "healthy", "service": "control-api", "evidence_retained": False}, cors)
            # Bound authenticated abuse without distinguishing shared network IPs.
            # Enterprise: pre-auth limiter must not trust a caller-supplied
            # tenant header (key rotation evasion); per-tenant limits apply
            # after mTLS authentication inside _authenticated().
            rate_key = "anonymous"
            if not self.rate_limiter.allow(rate_key):
                return Response(
                    429, {"error": {"code": "rate_limit_exceeded", "message": "Too many requests; retry after the limit window resets."}, "request_id": request_id},
                    (*cors, ("Retry-After", str(self.rate_limiter.retry_after(rate_key)))),
                )
            portal_response = self._handle_portal(method, path, headers, payload)
            if portal_response is not None:
                return Response(portal_response.status, portal_response.body, (*cors, *portal_response.headers))
            if method == "POST" and path == "/v1/enrollment/exchange":
                reject_customer_content(payload)
                key = self._idempotency(headers)
                cached = self.store.get_idempotent("enrollment.exchange", key)
                if cached:
                    return Response(200, cached, cors)
                result = self.store.exchange_enrollment(str(payload.get("enrollment_token", "")), str(payload.get("csr", "")))
                self.store.save_idempotent("enrollment.exchange", key, result)
                return Response(201, result, cors)
            match = re.fullmatch(r"/v1/deployments/([^/]+)/heartbeat", path)
            if match and method == "POST":
                reject_customer_content(payload)
                key, deployment = self._authenticated(headers, match.group(1), idempotent=True)
                cached = self.store.get_idempotent(f"heartbeat:{match.group(1)}", key)
                if cached:
                    return Response(200, cached, cors)
                result = self.store.heartbeat(deployment["tenant_id"], match.group(1), payload)
                self.store.save_idempotent(f"heartbeat:{match.group(1)}", key, result)
                return Response(200, result, cors)
            match = re.fullmatch(r"/v1/deployments/([^/]+)/usage", path)
            if match and method == "POST":
                reject_customer_content(payload)
                key, deployment = self._authenticated(headers, match.group(1), idempotent=True)
                cached = self.store.get_idempotent(f"usage:{match.group(1)}", key)
                if cached:
                    return Response(200, cached, cors)
                result = self.store.record_usage(deployment["tenant_id"], match.group(1), payload)
                self.store.save_idempotent(f"usage:{match.group(1)}", key, result)
                return Response(200, result, cors)
            match = re.fullmatch(r"/v1/deployments/([^/]+)/(entitlements|model-policy)", path)
            if match and method == "GET":
                _, deployment = self._authenticated(headers, match.group(1), idempotent=False)
                key = "model_policy" if match.group(2) == "model-policy" else "entitlements"
                return Response(200, deployment[key], cors)
            if method == "GET" and path == "/v1/updates/manifest":
                _, deployment = self._authenticated(headers, headers.get("x-deployment-id", ""), idempotent=False)
                return Response(200, self.store.update_manifest(deployment), cors)
            if method == "POST" and path == "/v1/model/investigate":
                if self.gateway is None:
                    raise APIError(
                        404,
                        "independent_model_gateway_required",
                        "Model requests must use the separately deployed model-gateway endpoint.",
                    )
                _, deployment = self._authenticated(headers, headers.get("x-deployment-id", ""), idempotent=False)
                result = self.gateway.investigate(
                    payload, tenant_id=deployment["tenant_id"], deployment_id=deployment["deployment_id"],
                    policy=deployment["model_policy"], entitlement_enabled=self.store.model_entitled(deployment),
                    deployment_authenticated=True,
                )
                return Response(200, result, cors)
            if method == "POST" and path == "/v1/certificates/rotate":
                reject_customer_content(payload)
                # Enterprise: authenticate before consulting the idempotency
                # cache. The cache key is namespaced by the authenticated
                # deployment so unauthenticated callers cannot probe/replay
                # another deployment's rotation response.
                requested_deployment = headers.get("x-deployment-id", "")
                _, deployment = self._authenticated(headers, requested_deployment, idempotent=False)
                key = self._idempotency(headers)
                cached = self.store.get_idempotent(f"certificate.rotate:{deployment['deployment_id']}", key)
                if cached:
                    return Response(200, cached, cors)
                result = self.store.rotate_certificate(deployment["tenant_id"], deployment["deployment_id"], str(payload.get("csr", "")))
                self.store.save_idempotent(f"certificate.rotate:{deployment['deployment_id']}", key, result)
                return Response(200, result, cors)
            raise APIError(404, "route_not_found", f"No API route matches {method} {path}.")
        except APIError as exc:
            status = exc.status
            return self._error(exc.status, exc.code, exc.message, request_id, cors)
        except AuthenticationError as exc:
            status = exc.status
            return self._error(exc.status, exc.code, exc.message, request_id, cors)
        except ControlError as exc:
            # Certificate authentication failures are unauthorized.  A malformed
            # CSR is client input validation and must not be reported as an auth
            # failure merely because its error code contains "certificate".
            status = (
                401
                if exc.code in {"invalid_deployment_certificate", "expired_deployment_certificate"}
                else 403
                if exc.code == "organization_binding_conflict"
                else 404
                if exc.code in {"deployment_not_found", "organization_not_found"}
                else 400
            )
            return self._error(status, exc.code, str(exc), request_id, cors)
        except GatewayPolicyError as exc:
            status = 403
            return self._error(403, "model_request_rejected", str(exc), request_id, cors)
        except ModelUnavailable:
            status = 503
            return self._error(503, "model_unavailable", "The model provider is currently unavailable; local detection remains operational.", request_id, cors)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            status = 400
            return self._error(400, "invalid_request", str(exc) or "The request is invalid.", request_id, cors)
        except Exception as exc:
            status = 500
            log_exception(
                "control_api.internal_error", exc,
                request_id=request_id, method=method, route=route,
            )
            return self._error(500, "internal_error", "The server could not complete the request.", request_id, cors)
        finally:
            log_info(
                "control_api.request.completed",
                request_id=request_id, method=method, route=route,
                status=status, duration_ms=int((time.monotonic() - started) * 1000),
            )

    def _handle_portal(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> Response | None:
        if not path.startswith("/v1/portal"):
            return None
        no_store = (("Cache-Control", "no-store"), ("Pragma", "no-cache"))
        if self.portal_authenticator is None:
            raise APIError(503, "portal_authentication_unavailable", "Cloud portal authentication is not configured.")

        if method == "GET" and path == "/v1/portal/session":
            principal = self._portal_principal(headers)
            organization = self.store.get_organization(principal.tenant_id, principal.organization_id)
            return Response(200, {
                "organization": self._organization_document(organization),
                "actor": {
                    "actor_id": principal.actor_id,
                    "role": principal.role,
                    "permissions": sorted(principal.permissions),
                },
                "privacy_boundary": {
                    "customer_event_content": "not_collected",
                    "customer_evidence_content": "not_collected",
                    "cloud_data_class": "operational_metadata_only",
                },
            }, no_store)

        if method == "GET" and path in {"/v1/portal/organization", "/v1/portal/organizations"}:
            principal = self._portal_principal(headers, "organizations:read")
            item = self._organization_document(
                self.store.get_organization(principal.tenant_id, principal.organization_id)
            )
            body: dict[str, Any] = {"items": [item], "count": 1} if path.endswith("organizations") else item
            return Response(200, body, no_store)

        if method == "PATCH" and path == "/v1/portal/organization":
            principal = self._portal_principal(headers, "organizations:manage")
            reject_customer_content(payload)
            updated = self.store.update_organization(
                principal.tenant_id, principal.organization_id, payload
            )
            self._audit(principal, "organization.updated", "organization", principal.organization_id)
            return Response(200, self._organization_document(updated), no_store)

        if method == "GET" and path == "/v1/portal/enrollments":
            principal = self._portal_principal(headers, "deployments:read")
            items = self.store.list_enrollments(principal.tenant_id)
            return Response(200, {"items": items, "count": len(items)}, no_store)

        if method == "GET" and path == "/v1/portal/deployments":
            principal = self._portal_principal(headers, "deployments:read")
            items = self.store.list_deployments(principal.tenant_id)
            return Response(200, {"items": items, "count": len(items)}, no_store)

        if method == "POST" and path == "/v1/portal/deployments":
            principal = self._portal_principal(headers, "deployments:manage")
            reject_customer_content(payload)
            if set(payload) - {"name", "update_channel"}:
                raise APIError(400, "invalid_deployment_metadata", "Only deployment name and update channel are accepted.")
            name = payload.get("name")
            channel = payload.get("update_channel", "stable")
            if not isinstance(name, str) or not 2 <= len(name.strip()) <= 120:
                raise APIError(400, "invalid_deployment_metadata", "Deployment name must contain 2-120 characters.")
            if not isinstance(channel, str):
                raise APIError(400, "invalid_deployment_metadata", "Update channel must be a string.")
            enrollment = self.store.create_portal_enrollment(
                principal.tenant_id,
                organization_id=principal.organization_id,
                deployment_name=name.strip(),
                update_channel=channel,
            )
            self._audit(principal, "enrollment.created", "enrollment", enrollment["enrollment_id"])
            return Response(201, enrollment, no_store)

        if method == "GET" and path == "/v1/portal/updates":
            principal = self._portal_principal(headers, "updates:read")
            deployments = self.store.list_deployments(principal.tenant_id)
            items = [
                {"deployment_id": item["deployment_id"], "name": item["name"], **item["software"]}
                for item in deployments
            ]
            return Response(200, {"items": items, "count": len(items)}, no_store)

        match = re.fullmatch(r"/v1/portal/deployments/([^/]+)", path)
        if match and method == "GET":
            principal = self._portal_principal(headers, "deployments:read")
            return Response(
                200,
                self.store.portal_deployment(principal.tenant_id, match.group(1)),
                no_store,
            )

        match = re.fullmatch(r"/v1/portal/deployments/([^/]+)/(usage|entitlements|model-policy|updates)", path)
        if match and method == "GET":
            deployment_id, resource = match.groups()
            permission = {
                "usage": "usage:read",
                "entitlements": "entitlements:read",
                "model-policy": "policy:read",
                "updates": "updates:read",
            }[resource]
            principal = self._portal_principal(headers, permission)
            deployment = self.store.portal_deployment(principal.tenant_id, deployment_id)
            key = "model_policy" if resource == "model-policy" else "software" if resource == "updates" else resource
            return Response(200, deployment[key], no_store)

        match = re.fullmatch(r"/v1/portal/deployments/([^/]+)/(entitlements|model-policy|update-channel)", path)
        if match and method == "PATCH":
            deployment_id, resource = match.groups()
            permission = {
                "entitlements": "entitlements:manage",
                "model-policy": "policy:manage",
                "update-channel": "updates:manage",
            }[resource]
            principal = self._portal_principal(headers, permission)
            reject_customer_content(payload)
            if resource == "entitlements":
                result = self.store.set_entitlements(principal.tenant_id, deployment_id, payload)
            elif resource == "model-policy":
                result = self.store.set_model_policy(principal.tenant_id, deployment_id, payload)
            else:
                if set(payload) != {"update_channel"} or not isinstance(payload.get("update_channel"), str):
                    raise APIError(400, "invalid_update_channel", "update_channel is required.")
                result = self.store.set_update_channel(
                    principal.tenant_id, deployment_id, str(payload["update_channel"])
                )
            self._audit(principal, f"deployment.{resource}.updated", "deployment", deployment_id)
            return Response(200, result, no_store)

        raise APIError(404, "route_not_found", f"No API route matches {method} {path}.")

    def _portal_principal(self, headers: Mapping[str, str], permission: str | None = None) -> PortalPrincipal:
        assert self.portal_authenticator is not None
        principal = self.portal_authenticator.authenticate(headers)
        if permission and permission not in principal.permissions and "*" not in principal.permissions:
            raise AuthenticationError(403, "permission_denied", f"The {permission} permission is required.")
        self.store.ensure_organization(principal.tenant_id, principal.organization_id)
        return principal

    @staticmethod
    def _organization_document(organization: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "tenant_id": organization["tenant_id"],
            "organization_id": organization["organization_id"],
            "name": organization["name"],
            "deployment_count": organization["deployment_count"],
            "support": dict(organization["support"]),
            "created_at": organization["created_at"],
            "updated_at": organization["updated_at"],
        }

    def _audit(
        self,
        principal: PortalPrincipal,
        action: str,
        resource_type: str,
        resource_id: str,
    ) -> None:
        self.store.record_control_audit(
            principal.tenant_id,
            principal.organization_id,
            principal.actor_id,
            action,
            resource_type,
            resource_id,
        )

    def _authenticated(self, headers: Mapping[str, str], deployment_id: str, *, idempotent: bool) -> tuple[str, dict[str, Any]]:
        tenant_id = headers.get("x-tenant-id", "")
        if not tenant_id or not deployment_id:
            raise APIError(401, "deployment_authentication_required", "X-Tenant-ID and X-Deployment-ID are required.")
        fingerprint = headers.get("x-verified-client-certificate-fingerprint", "")
        if not fingerprint and self.allow_insecure_fingerprint_header:
            if os.environ.get("HYBRID_NDR_ENV", "").strip().lower() == "production":
                raise APIError(401, "deployment_authentication_required", "Verified deployment certificate is required.")
            fingerprint = headers.get("x-client-certificate-fingerprint", "")
        deployment = self.store.authenticate(tenant_id, deployment_id, fingerprint)
        # Per-deployment rate limit on the verified identity (not the header).
        verified_key = f"{deployment['tenant_id']}:{deployment['deployment_id']}"
        if not self.rate_limiter.allow(verified_key):
            raise APIError(429, "rate_limit_exceeded", "Too many requests; retry after the limit window resets.")
        return (self._idempotency(headers) if idempotent else "", deployment)

    @staticmethod
    def _idempotency(headers: Mapping[str, str]) -> str:
        key = headers.get("idempotency-key", "").strip()
        if len(key) < 8 or len(key) > 200:
            raise APIError(400, "idempotency_key_required", "Idempotency-Key must contain 8-200 characters.")
        return key

    @staticmethod
    def _body(body: Any) -> dict[str, Any]:
        if body is None or body == b"" or body == "":
            return {}
        if isinstance(body, Mapping):
            return dict(body)
        if isinstance(body, bytes):
            if len(body) > MAX_BODY_BYTES:
                raise APIError(413, "body_too_large", f"The request body must be at most {MAX_BODY_BYTES} bytes.")
            body = body.decode()
        elif len(body) > MAX_BODY_BYTES:
            raise APIError(413, "body_too_large", f"The request body must be at most {MAX_BODY_BYTES} bytes.")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _cors(self, origin: str | None) -> tuple[tuple[str, str], ...]:
        headers = (
            ("Vary", "Origin"),
            ("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS"),
            (
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, X-Tenant-ID, X-Organization-ID, X-Deployment-ID, X-Client-Certificate-Fingerprint, Idempotency-Key",
            ),
        )
        return (("Access-Control-Allow-Origin", origin), *headers) if origin in self.allowed_origins else headers

    @staticmethod
    def _error(status: int, code: str, message: str, request_id: str, headers: tuple[tuple[str, str], ...]) -> Response:
        return Response(status, {"error": {"code": code, "message": message}, "request_id": request_id}, headers)


def create_application(
    store: ControlStore,
    gateway: ModelGateway | None = None,
    *,
    portal_authenticator: PortalAuthenticator | None = None,
    allow_insecure_fingerprint_header: bool = False,
):
    api = ControlAPI(
        store,
        gateway,
        portal_authenticator=portal_authenticator,
        allow_insecure_fingerprint_header=allow_insecure_fingerprint_header,
    )
    def application(environ: Mapping[str, Any], start_response: Any):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        if length > MAX_BODY_BYTES:
            # Refuse oversized bodies before reading any of the stream so a
            # client cannot force unbounded memory use in the server.
            encoded = json.dumps(
                {"error": {"code": "body_too_large", "message": f"The request body must be at most {MAX_BODY_BYTES} bytes."}},
                separators=(",", ":"),
            ).encode()
            start_response("413 Request Entity Too Large", [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(encoded)))])
            return [encoded]
        body = environ["wsgi.input"].read(length) if length else b""
        headers = {key[5:].replace("_", "-"): value for key, value in environ.items() if key.startswith("HTTP_")}
        # Never trust a caller-supplied "verified" header. Only the TLS server
        # can populate this WSGI value after a successful certificate handshake.
        headers.pop("X-VERIFIED-CLIENT-CERTIFICATE-FINGERPRINT", None)
        if environ.get("SSL_CLIENT_CERT_SHA256"):
            headers["X-VERIFIED-CLIENT-CERTIFICATE-FINGERPRINT"] = str(environ["SSL_CLIENT_CERT_SHA256"])
        response = api.handle(environ["REQUEST_METHOD"], environ.get("PATH_INFO", "/"), headers=headers, body=body)
        encoded = b"" if response.body is None else json.dumps(response.body, separators=(",", ":")).encode()
        start_response(f"{response.status} {HTTPStatus(response.status).phrase}", [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(encoded))), *response.headers])
        return [encoded]
    application.api = api  # type: ignore[attr-defined]
    return application
