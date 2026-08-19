from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Mapping

from hybrid_ndr_observability import exception as log_exception, info as log_info, sanitize_route

from .gateway import GatewayPolicyError, ModelGateway, ModelUnavailable


MAX_BODY_BYTES = 1_000_000


@dataclass(frozen=True)
class GatewayResponse:
    status: int
    body: dict[str, Any] | None


class GatewayAPI:
    """Standalone model ingress; it has no customer data-store dependencies."""

    def __init__(
        self,
        deployment_store: Any,
        gateway: ModelGateway,
        *,
        allow_insecure_fingerprint_header: bool = False,
    ) -> None:
        self.deployment_store = deployment_store
        self.gateway = gateway
        self.allow_insecure_fingerprint_header = allow_insecure_fingerprint_header

    def handle(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: Any = None,
    ) -> GatewayResponse:
        request_id = str(uuid.uuid4())
        started = time.monotonic()
        route = sanitize_route(path)
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        status = 500
        try:
            if method.upper() == "GET" and path.rstrip("/") in {"/healthz", "/v1/health"}:
                self.deployment_store.connection.execute("SELECT 1")
                status = 200
                return GatewayResponse(200, {
                    "status": "healthy",
                    "service": "model-gateway",
                    "provider": self.gateway.provider.name,
                    "zero_retention_verified": self.gateway.provider.zero_retention_verified,
                    "cache_disabled": self.gateway.provider.cache_disabled,
                    "evidence_retained": False,
                })
            if method.upper() != "POST" or path.rstrip("/") != "/v1/model/investigate":
                status = 404
                return self._error(404, "route_not_found", request_id)
            payload = self._body(body)
            tenant_id = normalized.get("x-tenant-id", "")
            deployment_id = normalized.get("x-deployment-id", "")
            if not tenant_id or not deployment_id:
                status = 401
                return self._error(401, "deployment_authentication_required", request_id)
            fingerprint = normalized.get("x-verified-client-certificate-fingerprint", "")
            if not fingerprint and self.allow_insecure_fingerprint_header:
                fingerprint = normalized.get("x-client-certificate-fingerprint", "")
            deployment = self.deployment_store.authenticate(tenant_id, deployment_id, fingerprint)
            result = self.gateway.investigate(
                payload,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                policy=deployment["model_policy"],
                entitlement_enabled=self.deployment_store.model_entitled(deployment),
                deployment_authenticated=True,
            )
            status = 200
            return GatewayResponse(200, result)
        except GatewayPolicyError as exc:
            status = 403
            return self._error(403, str(exc) or "model_request_rejected", request_id)
        except ModelUnavailable:
            status = 503
            return self._error(503, "model_unavailable", request_id)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            status = 400
            log_exception("gateway.invalid_request", exc, request_id=request_id, route=route)
            return self._error(400, "invalid_request", request_id)
        except Exception as exc:
            status = 500
            code = getattr(exc, "code", "internal_error")
            status = 401 if "certificate" in str(code) else 404 if code == "deployment_not_found" else 500
            log_exception("gateway.internal_error", exc, request_id=request_id, route=route)
            return self._error(status, str(code), request_id)
        finally:
            log_info(
                "gateway.request.completed",
                request_id=request_id, method=method.upper(), route=route,
                status=status, duration_ms=int((time.monotonic() - started) * 1000),
            )

    @staticmethod
    def _body(body: Any) -> dict[str, Any]:
        if isinstance(body, Mapping):
            return dict(body)
        if isinstance(body, bytes):
            if len(body) > MAX_BODY_BYTES:
                raise ValueError("request body too large")
            body = body.decode("utf-8")
        elif isinstance(body, str) and len(body) > MAX_BODY_BYTES:
            raise ValueError("request body too large")
        value = json.loads(body or "{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    @staticmethod
    def _error(status: int, code: str, request_id: str) -> GatewayResponse:
        # Error bodies are deliberately content-free and stable. In particular,
        # provider response bodies and exceptions are never reflected.
        return GatewayResponse(status, {"error": {"code": code}, "request_id": request_id})


def create_application(
    deployment_store: Any,
    gateway: ModelGateway,
    *,
    allow_insecure_fingerprint_header: bool = False,
):
    api = GatewayAPI(
        deployment_store,
        gateway,
        allow_insecure_fingerprint_header=allow_insecure_fingerprint_header,
    )

    def application(environ: Mapping[str, Any], start_response: Any):
        length = min(int(environ.get("CONTENT_LENGTH") or 0), 1_000_000)
        body = environ["wsgi.input"].read(length) if length else b""
        headers = {
            key[5:].replace("_", "-"): value
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }
        headers.pop("X-VERIFIED-CLIENT-CERTIFICATE-FINGERPRINT", None)
        if environ.get("SSL_CLIENT_CERT_SHA256"):
            headers["X-VERIFIED-CLIENT-CERTIFICATE-FINGERPRINT"] = str(environ["SSL_CLIENT_CERT_SHA256"])
        response = api.handle(
            environ["REQUEST_METHOD"],
            environ.get("PATH_INFO", "/"),
            headers=headers,
            body=body,
        )
        encoded = b"" if response.body is None else json.dumps(response.body, separators=(",", ":")).encode("utf-8")
        start_response(
            f"{response.status} {HTTPStatus(response.status).phrase}",
            [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(encoded)))],
        )
        return [encoded]

    application.api = api  # type: ignore[attr-defined]
    return application
