from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Mapping

from hybrid_ndr_contracts import EvidenceObservation, ModelRequest, ModelResponse, ValidationError, canonical_json
from hybrid_ndr_gateway import GatewayPolicyError, ModelUnavailable
from hybrid_ndr_redaction import RedactionError, Redactor
from hybrid_ndr_storage import LocalStore


class InvestigationRuntime:
    """Orchestrates bounded local evidence retrieval and an optional model assessment."""

    maximum_events = 100
    maximum_prompt_bytes = 50_000

    def __init__(self, store: LocalStore, model_gateway: Any, *, token_key: bytes) -> None:
        self.store = store
        self.model_gateway = model_gateway
        self.redactor = Redactor(token_key)

    def investigate(
        self,
        *,
        tenant_id: str,
        deployment_id: str,
        alert_id: str,
        actor_id: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        alert = self.store.get_alert(tenant_id, alert_id, deployment_id=deployment_id)
        if alert["deployment_id"] != deployment_id:
            raise PermissionError("alert is not assigned to this deployment")
        investigation = self.store.create_investigation(tenant_id, deployment_id, alert_id)
        investigation_id = investigation["investigation_id"]
        # The API layer correlation ID is threaded through the investigation,
        # transmission, and audit records so one request can be traced end to
        # end; direct calls generate one locally.
        request_id = request_id or str(uuid.uuid4())
        self.store.audit.append(
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            actor_id=actor_id,
            actor_type="human" if actor_id != "agent-runtime" else "service",
            action="investigation.created",
            resource_type="alert",
            resource_id=alert_id,
            request_id=request_id,
        )
        policy = self.store.get_policy(tenant_id, deployment_id)
        evidence = self.store.get_events(
            tenant_id, alert["evidence_ids"][: self.maximum_events], deployment_id=deployment_id
        )
        missing = set(alert["evidence_ids"][: self.maximum_events]) - {item["event_id"] for item in evidence}
        if missing:
            return self._fail(
                investigation_id, tenant_id, deployment_id, alert_id, actor_id, request_id,
                "invalid_local_evidence_reference", "rejected", payload={}, policy=policy,
            )
        observations = tuple(self._observation(item, alert) for item in evidence)
        request = ModelRequest(
            request_id=request_id,
            tenant_policy_id=policy["policy_id"],
            alert_type=alert["detector_id"],
            severity=alert["severity"],
            entity_type=alert["entity_type"],
            observations=observations,
            allowed_actions=("inspect_endpoint", "review_dns_history", "review_connection_history", "create_case"),
        )
        raw_payload = request.to_dict()
        try:
            report = self.redactor.redact(raw_payload, policy["level"])
            payload = report.payload
            if len(canonical_json(payload).encode("utf-8")) > self.maximum_prompt_bytes:
                raise RedactionError("minimized evidence exceeds prompt budget")
            # Re-parse the minimized request before it crosses the customer boundary.
            minimized_request = ModelRequest.from_dict(payload)
            started = time.monotonic()
            envelope = self.model_gateway.investigate(
                minimized_request.to_dict(),
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                policy=policy,
                entitlement_enabled=True,
                deployment_authenticated=True,
            )
            latency_ms = int((time.monotonic() - started) * 1000)
            response = ModelResponse.from_dict(
                envelope["response"],
                known_evidence_ids=minimized_request.evidence_ids,
                allowed_actions=minimized_request.allowed_actions,
            )
            response_payload = response.to_dict()
            transmission = self._transmission(
                investigation_id=investigation_id,
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                alert_id=alert_id,
                actor_id=actor_id,
                request_id=request_id,
                policy=policy,
                payload=payload,
                fields_included=report.fields_included,
                fields_removed=report.fields_removed,
                fields_tokenized=report.fields_tokenized,
                response=response_payload,
                usage=envelope.get("usage", {}),
                latency_ms=latency_ms,
                result="success",
            )
            self.store.save_transmission(transmission)
            finished = self.store.finish_investigation(
                tenant_id, investigation_id, status="completed", assessment=response_payload,
                deployment_id=deployment_id,
            )
            self.store.audit.append(
                tenant_id=tenant_id,
                deployment_id=deployment_id,
                actor_id="agent-runtime",
                actor_type="service",
                action="model.transmission.completed",
                resource_type="investigation",
                resource_id=investigation_id,
                request_id=request_id,
                metadata={"transmission_id": transmission["transmission_id"], "prompt_hash": transmission["prompt_hash"]},
            )
            return finished
        except ModelUnavailable:
            return self._fail(
                investigation_id, tenant_id, deployment_id, alert_id, actor_id, request_id,
                "provider_unavailable", "unavailable", payload=locals().get("payload", {}), policy=policy,
                report=locals().get("report"),
            )
        except (GatewayPolicyError, RedactionError, ValidationError, KeyError, TypeError, ValueError) as exc:
            code = str(exc) if str(exc) else "invalid_model_response"
            return self._fail(
                investigation_id, tenant_id, deployment_id, alert_id, actor_id, request_id,
                code[:120], "rejected", payload=locals().get("payload", {}), policy=policy,
                report=locals().get("report"),
            )

    @staticmethod
    def _observation(event: Mapping[str, Any], alert: Mapping[str, Any]) -> EvidenceObservation:
        details = dict(event.get("details", {}))
        context = {
            "event_type": event["event_type"],
            "source": event["source"],
            "src_ip": event.get("src_ip", ""),
            "dst_ip": event.get("dst_ip", ""),
            "dst_port": event.get("dst_port", 0),
            "query": details.get("query", ""),
            "query_type": details.get("query_type", ""),
            "signature": details.get("signature", ""),
        }
        observed = float(event.get("bytes_out", 0) + event.get("bytes_in", 0))
        feature = "network_bytes" if observed else "event_observed"
        baseline_p99 = alert.get("baseline", {}).get("p99")
        return EvidenceObservation(
            evidence_id=event["event_id"], feature=feature, observed=observed or True,
            baseline_p99=float(baseline_p99) if baseline_p99 is not None else None, context=context,
        )

    def _fail(
        self,
        investigation_id: str,
        tenant_id: str,
        deployment_id: str,
        alert_id: str,
        actor_id: str,
        request_id: str,
        error_code: str,
        status: str,
        *,
        payload: Mapping[str, Any],
        policy: Mapping[str, Any],
        report: Any = None,
    ) -> dict[str, Any]:
        transmission = self._transmission(
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            alert_id=alert_id,
            actor_id=actor_id,
            request_id=request_id,
            policy=policy,
            payload=dict(payload),
            fields_included=getattr(report, "fields_included", ()),
            fields_removed=getattr(report, "fields_removed", ()),
            fields_tokenized=getattr(report, "fields_tokenized", ()),
            response={}, usage={}, latency_ms=0, result="failure", error_code=error_code,
        )
        self.store.save_transmission(transmission)
        finished = self.store.finish_investigation(
            tenant_id, investigation_id, status=status, error_code=error_code,
            deployment_id=deployment_id,
        )
        self.store.audit.append(
            tenant_id=tenant_id,
            deployment_id=deployment_id,
            actor_id="agent-runtime",
            actor_type="service",
            action="model.transmission.failed",
            resource_type="investigation",
            resource_id=investigation_id,
            request_id=request_id,
            result="failure",
            metadata={"error_code": error_code},
        )
        return finished

    @staticmethod
    def _transmission(
        *, investigation_id: str, tenant_id: str, deployment_id: str, alert_id: str, actor_id: str,
        request_id: str, policy: Mapping[str, Any], payload: Mapping[str, Any], fields_included: Any,
        fields_removed: Any, fields_tokenized: Any, response: Mapping[str, Any], usage: Mapping[str, Any],
        latency_ms: int, result: str, error_code: str | None = None,
    ) -> dict[str, Any]:
        return {
            "transmission_id": str(uuid.uuid4()), "request_id": request_id, "investigation_id": investigation_id,
            "alert_id": alert_id, "tenant_id": tenant_id, "deployment_id": deployment_id, "actor_id": actor_id,
            "provider": str(policy.get("provider", "none")), "model": str(policy.get("model", "none")),
            "retention_mode": str(policy.get("retention_mode", "zero")), "region": str(policy.get("region", "none")),
            "fields_included": list(fields_included), "fields_removed": list(fields_removed),
            "fields_tokenized": list(fields_tokenized), "prompt_hash": hashlib.sha256(canonical_json(payload).encode()).hexdigest(),
            "response_hash": hashlib.sha256(canonical_json(response).encode()).hexdigest() if response else "",
            "input_tokens": int(usage.get("input_tokens", 0)), "output_tokens": int(usage.get("output_tokens", 0)),
            "latency_ms": latency_ms, "result": result, "error_code": error_code, "payload": dict(payload),
        }
