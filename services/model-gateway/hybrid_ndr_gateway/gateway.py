from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Callable, Mapping, Protocol

from hybrid_ndr_contracts import ModelRequest, ModelResponse, ValidationError, canonical_json, utc_now
from hybrid_ndr_redaction import Redactor, SensitiveDataError


class ModelUnavailable(RuntimeError):
    pass


class GatewayPolicyError(PermissionError):
    pass


class Provider(Protocol):
    name: str
    zero_retention_verified: bool
    cache_disabled: bool
    regions: frozenset[str]

    def assess(self, request: ModelRequest, model: str) -> Mapping[str, Any]: ...


class DeterministicAssessmentProvider:
    """A deterministic adapter available only through explicit test/demo setup."""

    name = "demo-zero-retention"
    zero_retention_verified = True
    cache_disabled = True
    regions = frozenset({"us", "eu"})

    def assess(self, request: ModelRequest, model: str) -> Mapping[str, Any]:
        classification = {
            "port-scan-v1": "likely_network_reconnaissance",
            "dns-volume-v1": "possible_dns_abuse",
            "dns-tunneling-v1": "likely_dns_tunneling",
            "traffic-spike-v1": "anomalous_data_transfer",
            "new-destination-v1": "novel_destination_requires_review",
            "suricata-conversion-v1": "signature_alert_requires_review",
        }.get(request.alert_type, "anomalous_network_activity")
        action_order = ["inspect_endpoint", "review_dns_history", "review_connection_history", "create_case", "escalate_to_soc"]
        actions = [action for action in action_order if action in request.allowed_actions][:2]
        technique = "T1071.004" if "dns" in request.alert_type else "T1046" if "scan" in request.alert_type else "T1071.001"
        return {
            "classification": classification,
            "severity": request.severity,
            "confidence": 0.87,
            "summary": "The cited local evidence is materially different from the supplied baseline and requires analyst review.",
            "supporting_evidence_ids": [item.evidence_id for item in request.observations[:3]],
            "mitre_techniques": [technique],
            "recommended_actions": actions,
            "requires_human_review": True,
        }


class OfflineProvider:
    # It represents an approved adapter whose upstream is unreachable, not an
    # unapproved provider. Keeping the configured provider name lets the
    # failure reach the availability path after policy checks pass.
    name = "demo-zero-retention"
    zero_retention_verified = True
    cache_disabled = True
    regions = frozenset({"us", "eu"})

    def assess(self, request: ModelRequest, model: str) -> Mapping[str, Any]:
        raise ModelUnavailable("model provider is unavailable")


class ModelGateway:
    """Provider-independent boundary that never persists evidence content."""

    def __init__(
        self,
        provider: Provider,
        *,
        signing_key: bytes,
        approved_models: set[str] | None = None,
        approved_regions: set[str] | None = None,
        maximum_request_bytes: int = 50_000,
        usage_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 bytes")
        self.provider = provider
        self.signing_key = signing_key
        if maximum_request_bytes < 1_024 or maximum_request_bytes > 1_000_000:
            raise ValueError("maximum_request_bytes is outside the supported range")
        self.approved_models = {"evidence-assessor-v1"} if approved_models is None else set(approved_models)
        self.approved_regions = {"us", "eu"} if approved_regions is None else set(approved_regions)
        self.maximum_request_bytes = maximum_request_bytes
        self.usage_sink = usage_sink

    def investigate(
        self,
        payload: Mapping[str, Any],
        *,
        tenant_id: str,
        deployment_id: str,
        policy: Mapping[str, Any],
        entitlement_enabled: bool = True,
        deployment_authenticated: bool = True,
    ) -> dict[str, Any]:
        request_id = str(payload.get("request_id", "unknown"))
        started = time.monotonic()
        metadata = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "deployment_id": deployment_id,
            "provider": self.provider.name,
            "model": str(policy.get("model", "")),
            "status": "rejected",
            "error_code": None,
            "timestamp": utc_now(),
            "input_tokens": 0,
            "output_tokens": 0,
            "latency_ms": 0,
        }
        try:
            self._enforce(policy, entitlement_enabled, deployment_authenticated)
            Redactor.assert_safe(payload)
            encoded = canonical_json(payload).encode("utf-8")
            if len(encoded) > self.maximum_request_bytes:
                raise GatewayPolicyError("evidence_package_too_large")
            request = ModelRequest.from_dict(payload)
            if request.tenant_policy_id != policy.get("policy_id"):
                raise GatewayPolicyError("tenant_policy_mismatch")
            try:
                raw_response = self.provider.assess(request, str(policy["model"]))
            except ModelUnavailable:
                raise
            except Exception:
                # Provider exceptions can contain response content, endpoints,
                # or authorization material. Normalize them at this boundary.
                raise ModelUnavailable("model provider is unavailable") from None
            try:
                response = ModelResponse.from_dict(
                    raw_response,
                    known_evidence_ids=request.evidence_ids,
                    allowed_actions=request.allowed_actions,
                )
            except (ValidationError, KeyError, TypeError, ValueError) as exc:
                raise GatewayPolicyError("invalid_model_response") from exc
            response_payload = response.to_dict()
            metadata.update(
                status="success",
                input_tokens=max(1, len(encoded) // 4),
                output_tokens=max(1, len(canonical_json(response_payload).encode("utf-8")) // 4),
            )
            envelope = {
                "request_id": request.request_id,
                "response": response_payload,
                "provider": self.provider.name,
                "model": policy["model"],
                "region": policy["region"],
                "retention_mode": "zero",
                "issued_at": utc_now(),
            }
            envelope["signature"] = hmac.new(
                self.signing_key, canonical_json(envelope).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            return {**envelope, "usage": {key: metadata[key] for key in ("input_tokens", "output_tokens")}}
        except ModelUnavailable:
            metadata.update(status="unavailable", error_code="provider_unavailable")
            raise
        except SensitiveDataError as exc:
            metadata["error_code"] = "sensitive_data_detected"
            raise GatewayPolicyError("sensitive_data_detected") from exc
        except (ValidationError, KeyError, TypeError) as exc:
            metadata["error_code"] = "invalid_evidence_schema"
            raise GatewayPolicyError("invalid_evidence_schema") from exc
        except GatewayPolicyError as exc:
            metadata["error_code"] = str(exc)
            raise
        finally:
            metadata["latency_ms"] = int((time.monotonic() - started) * 1000)
            if self.usage_sink:
                try:
                    self.usage_sink(dict(metadata))  # Contains metadata only, never prompt or response.
                except Exception:
                    # Metering availability cannot safely change a completed
                    # provider result into a retry that could double bill.
                    pass

    def verify_envelope(self, envelope: Mapping[str, Any]) -> bool:
        supplied = str(envelope.get("signature", ""))
        unsigned = {key: value for key, value in envelope.items() if key not in {"signature", "usage"}}
        expected = hmac.new(self.signing_key, canonical_json(unsigned).encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(supplied, expected)

    def _enforce(self, policy: Mapping[str, Any], entitled: bool, authenticated: bool) -> None:
        if authenticated is not True:
            raise GatewayPolicyError("deployment_certificate_invalid")
        if entitled is not True:
            raise GatewayPolicyError("model_entitlement_disabled")
        if policy.get("enabled") is not True or policy.get("level") == "disabled":
            raise GatewayPolicyError("model_policy_disabled")
        if policy.get("level") not in {"strict", "balanced", "investigative"}:
            raise GatewayPolicyError("model_policy_invalid")
        if policy.get("retention_mode") != "zero" or not self.provider.zero_retention_verified:
            raise GatewayPolicyError("zero_retention_unverified")
        if not self.provider.cache_disabled:
            raise GatewayPolicyError("prompt_cache_cannot_be_disabled")
        if policy.get("model") not in self.approved_models:
            raise GatewayPolicyError("model_not_approved")
        if policy.get("region") not in self.approved_regions:
            raise GatewayPolicyError("region_not_approved")
        provider_regions = getattr(self.provider, "regions", frozenset())
        if policy.get("region") not in provider_regions:
            raise GatewayPolicyError("provider_region_mismatch")
        if policy.get("provider") != self.provider.name:
            raise GatewayPolicyError("provider_not_approved")
