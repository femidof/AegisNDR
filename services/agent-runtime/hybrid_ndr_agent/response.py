"""Customer-local response authorization. Model assessments are never permissions."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone

from hybrid_ndr_contracts import canonical_json
from hybrid_ndr_storage.response import ResponseRepository


FAMILIES = {"firewall": "block_address", "edr": "isolate_endpoint", "agent": "isolate_endpoint"}
ACTIVE = ("queued", "executing", "verifying", "succeeded", "unknown", "release_queued",
          "releasing", "release_verifying", "release_unknown")
DEFAULT_POLICY = {
    "version": 0, "mode": "off", "emergency_stop": False,
    "allowed_groups": [], "allowed_families": [], "max_active": 1,
    "max_per_hour": 5, "max_duration_seconds": 900,
    "max_evidence_age_seconds": 900, "approval_ttl_seconds": 300,
    "autonomous_rules": [],
}


class ResponseDenied(ValueError):
    pass


class ResponseNotSubmitted(ResponseDenied):
    """A preflight rejected the action before any mutation request was sent."""


def now():
    return datetime.now(timezone.utc)


def timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def digest(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("invalid response identifier")
    return value


def fields(body, allowed):
    if not isinstance(body, dict) or set(body) - set(allowed):
        raise ValueError("unsupported response fields")


def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"expected integer between {minimum} and {maximum}")
    return value


class ResponseWorkflow:
    def __init__(self, store, *, adapters=None, execution_enabled=False, scope=None):
        self.store = store
        self.repository = ResponseRepository(store)
        self.repository.scope = scope
        # Adapters are supplied by trusted local configuration, never request bodies.
        self.adapters = adapters or {}
        self.execution_enabled = execution_enabled
        self.configuration_revision = None
        self.configuration_error = False

    def list(self, tenant, deployment, kind, *, limit=100, offset=0):
        if kind not in {"asset", "action", "journal"}:
            raise ValueError("unsupported response resource")
        with self.repository.transaction(tenant, deployment) as tx:
            return tx.list(kind, limit=limit, offset=offset)

    def get_action(self, tenant, deployment, action_id):
        with self.repository.transaction(tenant, deployment) as tx:
            return tx.get("action", identifier(action_id))

    def policy(self, tenant, deployment):
        with self.repository.transaction(tenant, deployment) as tx:
            return tx.get("policy", "current", dict(DEFAULT_POLICY))

    def capabilities(self, tenant=None, deployment=None):
        worker = {"healthy": False, "updated_at": None}
        if tenant and deployment:
            with self.repository.transaction(tenant, deployment) as tx:
                worker = tx.get("worker", "current", worker)
            worker["healthy"] = bool(worker.get("updated_at") and
                0 <= (now() - timestamp(worker["updated_at"])).total_seconds() < 30 and worker.get("healthy")
                and worker.get("configuration_revision") == self.configuration_revision)
        return {
            "execution_enabled": self.execution_enabled,
            "worker": worker,
            "configuration_error": self.configuration_error,
            "automatic_proposals": getattr(self, "automatic_proposals", False),
            "families": [{"family": family, "action": action,
                          "simulation": True,
                          "integrations": sorted(key for key, adapter in self.adapters.items()
                                                 if adapter.family == family)}
                         for family, action in FAMILIES.items()],
        }

    def record_denial(self, tenant, deployment, actor, route, reason):
        with self.repository.transaction(tenant, deployment) as tx:
            tx.journal(actor, "response.denied", route, {"reason": reason})

    def update_policy(self, tenant, deployment, actor, body):
        fields(body, DEFAULT_POLICY)
        with self.repository.transaction(tenant, deployment) as tx:
            previous = tx.get("policy", "current", dict(DEFAULT_POLICY))
            if type(body.get("version")) is not int or body["version"] != previous["version"]:
                raise ResponseDenied("policy version changed; reload before updating")
            policy = {**previous, **body, "version": previous["version"] + 1}
            if policy["mode"] not in {"off", "simulate", "approval_required", "autonomous"}:
                raise ValueError("invalid response policy mode")
            if type(policy["emergency_stop"]) is not bool:
                raise ValueError("emergency_stop must be boolean")
            for key, maximum in (("max_active", 100), ("max_per_hour", 100),
                                 ("max_duration_seconds", 3600), ("max_evidence_age_seconds", 3600),
                                 ("approval_ttl_seconds", 900)):
                integer(policy[key], 1, maximum)
            for key in ("allowed_groups", "allowed_families"):
                if not isinstance(policy[key], list) or len(policy[key]) > 50:
                    raise ValueError(f"{key} must be a bounded list")
                for item in policy[key]:
                    identifier(item)
            if set(policy["allowed_families"]) - set(FAMILIES):
                raise ValueError("unsupported response family")
            rules = policy["autonomous_rules"]
            if not isinstance(rules, list) or len(rules) > 50:
                raise ValueError("autonomous_rules must be a bounded list")
            for rule in rules:
                fields(rule, {"detector_id", "severity", "group", "family"})
                if set(rule) != {"detector_id", "severity", "group", "family"}:
                    raise ValueError("automatic rules require detector, severity, group, and family")
                identifier(rule["detector_id"])
                if (rule["severity"] not in {"high", "critical"}
                        or rule["group"] not in policy["allowed_groups"]
                        or rule["family"] not in policy["allowed_families"]):
                    raise ValueError("automatic rule is outside the allowed policy scope")
            # Configuring a policy is distinct from activating privileged execution.
            if policy["mode"] in {"approval_required", "autonomous"} and not self.execution_enabled:
                raise ResponseDenied("live execution is disabled in local configuration; use simulate")
            tx.put("policy", "current", policy)
            tx.journal(actor, "response.policy.updated", "current", {"policy": policy})
            return policy

    def register_asset(self, tenant, deployment, actor, body):
        fields(body, {"asset_id", "group", "critical", "platform", "addresses", "observed_at",
                      "valid_until", "source", "bindings", "revision"})
        asset = {key: body[key] for key in ("asset_id", "group", "critical", "platform", "addresses",
                                           "observed_at", "valid_until", "source", "bindings")}
        for key in ("asset_id", "group", "platform", "source"):
            identifier(asset[key])
        if type(asset["critical"]) is not bool:
            raise ValueError("critical must be boolean")
        start, end = timestamp(asset["observed_at"]), timestamp(asset["valid_until"])
        if not start <= now() < end or end - start > timedelta(hours=24):
            raise ValueError("asset assignment must be current and valid for at most 24 hours")
        if not isinstance(asset["addresses"], list) or not 1 <= len(asset["addresses"]) <= 16:
            raise ValueError("asset requires between 1 and 16 addresses")
        asset["addresses"] = sorted({str(ipaddress.ip_address(value)) for value in asset["addresses"]})
        if not isinstance(asset["bindings"], dict) or set(asset["bindings"]) - set(FAMILIES):
            raise ValueError("unsupported asset bindings")
        for binding in asset["bindings"].values():
            fields(binding, {"integration_id", "target_id"})
            identifier(binding["integration_id"])
            identifier(binding["target_id"])
        with self.repository.transaction(tenant, deployment) as tx:
            assets = tx.list("asset", limit=1001)
            if len(assets) > 1000 or (len(assets) == 1000 and not any(
                    item["asset_id"] == asset["asset_id"] for item in assets)):
                raise ResponseDenied("asset inventory exceeds this response engine's supported capacity")
            for other in assets:
                if (other["asset_id"] != asset["asset_id"] and timestamp(other["valid_until"]) > now()
                        and set(other["addresses"]) & set(asset["addresses"])):
                    raise ResponseDenied("address already belongs to another current asset; resolve ambiguity")
            previous_revision = tx.get("asset", asset["asset_id"], {"revision": 0})["revision"]
            if type(body.get("revision", 0)) is not int or body.get("revision", 0) != previous_revision:
                raise ResponseDenied("asset revision changed; reload the complete assignment before updating")
            asset["revision"] = previous_revision + 1
            tx.put("asset", asset["asset_id"], asset)
            tx.journal(actor, "response.asset.registered", asset["asset_id"], {"asset_hash": digest(asset)})
            return asset

    def _evidence(self, tenant, deployment, alert_id):
        alert = self.store.get_alert(tenant, alert_id, deployment_id=deployment)
        if alert["deployment_id"] != deployment or alert["tenant_id"] != tenant:
            raise ResponseDenied("alert scope mismatch")
        ids = alert.get("evidence_ids", [])
        if not ids or len(ids) > 100:
            raise ResponseDenied("response requires between 1 and 100 evidence records")
        events = self.store.get_events(tenant, ids, deployment_id=deployment)
        if {event["event_id"] for event in events} != set(ids):
            raise ResponseDenied("local evidence is missing")
        return alert, sorted(events, key=lambda event: event["event_id"])

    def _validate(self, policy, asset, family, address, alert, events):
        instant = now()
        target = ipaddress.ip_address(address)
        if target.is_loopback or target.is_unspecified or target.is_multicast or target.is_link_local:
            raise ResponseDenied("response target is not a unicast endpoint address")
        if policy["mode"] == "off" or policy["emergency_stop"]:
            raise ResponseDenied("response is off or the emergency stop is active")
        if asset["critical"] or asset["group"] not in policy["allowed_groups"]:
            raise ResponseDenied("asset is critical or its group is excluded")
        if family not in policy["allowed_families"] or family not in asset["bindings"]:
            raise ResponseDenied("response family is not permitted or has no asset binding")
        if address not in asset["addresses"] or not timestamp(asset["observed_at"]) <= instant < timestamp(asset["valid_until"]):
            raise ResponseDenied("asset address assignment is stale or does not match")
        if alert["status"] == "closed":
            raise ResponseDenied("closed alerts cannot authorize response")
        if alert["entity_id"] not in {address, asset["asset_id"]}:
            raise ResponseDenied("alert entity does not identify the proposed target")
        matched = False
        for event in events:
            observed = timestamp(event["event_time"])
            if not 0 <= (instant - observed).total_seconds() <= policy["max_evidence_age_seconds"]:
                raise ResponseDenied("response evidence is stale or future-dated")
            if address in {event.get("src_ip"), event.get("dst_ip")}:
                if not timestamp(asset["observed_at"]) <= observed < timestamp(asset["valid_until"]):
                    raise ResponseDenied("asset assignment does not cover evidence time")
                matched = True
        if not matched:
            raise ResponseDenied("target address is not present in local evidence")

    @staticmethod
    def _capacity(tx, policy, action=None):
        active = tx.list("action", states=ACTIVE, limit=1001)
        if action is not None:
            active = [item for item in active if item["action_id"] != action["action_id"]]
            if any(item["proposal"]["asset_id"] == action["proposal"]["asset_id"] for item in active):
                raise ResponseDenied("asset already has an active restriction or unresolved outcome")
        if len(active) >= policy["max_active"]:
            raise ResponseDenied("maximum active response actions reached")
        # Only authorizations in the last hour count, including released/failed actions.
        history = tx.list("authorization", limit=1001)
        recent = [record for record in history if now() - timestamp(record["created_at"]) < timedelta(hours=1)]
        if len(history) == 1001 and len(recent) == 1001:
            raise ResponseDenied("authorization history exceeds the bounded rate-check window")
        if sum((action is None or record["action_id"] != action["action_id"])
               for record in recent) >= policy["max_per_hour"]:
            raise ResponseDenied("hourly response authorization limit reached")

    def simulate_alerts(self, tenant, deployment, actor, body):
        fields(body, {"request_id", "limit"})
        batch_id = identifier(body["request_id"])
        limit = integer(body.get("limit", 20), 1, 50)
        policy = self.policy(tenant, deployment)
        if policy["mode"] != "simulate" or policy["emergency_stop"]:
            raise ResponseDenied("batch simulation requires simulate mode without emergency stop")
        with self.repository.transaction(tenant, deployment) as tx:
            assets = tx.list("asset", limit=1001)
        if len(assets) > 1000:
            raise ResponseDenied("asset inventory exceeds supported capacity")
        alerts = self.store.list_alerts(tenant, deployment_id=deployment, limit=limit)
        actions, excluded = [], []
        for alert in alerts:
            matches = [(asset, address) for asset in assets for address in asset["addresses"]
                       if alert["entity_id"] == address or (
                           alert["entity_id"] == asset["asset_id"] and len(asset["addresses"]) == 1)]
            if len(matches) != 1:
                excluded.append({"alert_id": alert["alert_id"], "reason": "no unambiguous registered asset assignment"})
                continue
            asset, address = matches[0]
            families = sorted(set(policy["allowed_families"]) & set(asset["bindings"]))
            if not families:
                excluded.append({"alert_id": alert["alert_id"], "reason": "no permitted family binding"})
            for family in families:
                proposal = {
                    "request_id": digest([batch_id, alert["alert_id"], asset["asset_id"], family]),
                    "asset_id": asset["asset_id"], "alert_id": alert["alert_id"],
                    "family": family, "address": address,
                    "duration_seconds": min(300, policy["max_duration_seconds"]),
                }
                try:
                    actions.append(self.propose(tenant, deployment, actor, proposal, simulation_only=True))
                except ResponseDenied as exc:
                    excluded.append({"alert_id": alert["alert_id"], "family": family, "reason": str(exc)})
        with self.repository.transaction(tenant, deployment) as tx:
            tx.journal(actor, "response.simulation.completed", batch_id,
                       {"action_count": len(actions), "exclusion_count": len(excluded), "enforcement_performed": False})
        return {"items": actions, "count": len(actions), "excluded": excluded, "enforcement_performed": False}

    def propose(self, tenant, deployment, actor, body, *, simulation_only=False, automatic_only=False):
        fields(body, {"request_id", "asset_id", "alert_id", "family", "address", "duration_seconds"})
        request_id = identifier(body["request_id"])
        family = body["family"]
        if family not in FAMILIES:
            raise ValueError("unsupported response family")
        asset_id, alert_id = identifier(body["asset_id"]), identifier(body["alert_id"])
        address = str(ipaddress.ip_address(body["address"]))
        duration = integer(body["duration_seconds"], 1, 3600)
        alert, events = self._evidence(tenant, deployment, alert_id)
        request_hash = digest({"actor_id": actor, "body": body})
        with self.repository.transaction(tenant, deployment) as tx:
            previous = tx.get("request", request_id, {"action_id": None})
            if previous["action_id"]:
                if previous["request_hash"] != request_hash:
                    raise ResponseDenied("request_id was already used for a different proposal")
                existing = tx.get("action", previous["action_id"])
                if simulation_only and existing["status"] != "simulated":
                    raise ResponseDenied("simulation request ID belongs to a non-simulation action")
                return existing
            policy = tx.get("policy", "current", dict(DEFAULT_POLICY))
            if automatic_only and policy["mode"] != "autonomous":
                raise ResponseDenied("automatic proposals require autonomous policy")
            if len(tx.list("action", states=("awaiting_approval",), limit=1001)) >= 1000:
                raise ResponseDenied("pending response approval capacity reached")
            if simulation_only and policy["mode"] != "simulate":
                raise ResponseDenied("policy changed; batch simulation cannot create live proposals")
            asset = tx.get("asset", asset_id)
            self._validate(policy, asset, family, address, alert, events)
            if duration > policy["max_duration_seconds"]:
                raise ResponseDenied("action duration exceeds local policy")
            action_id = str(uuid.uuid4())
            proposal = {
                "tenant_id": tenant, "deployment_id": deployment, "action_id": action_id,
                "asset_id": asset_id, "asset_hash": digest(asset), "alert_id": alert_id,
                "alert_hash": digest(alert),
                "platform": asset["platform"],
                "integration_revision": self._adapter_revision(asset["bindings"][family]["integration_id"]),
                "evidence_hash": digest(events), "evidence_ids": [item["event_id"] for item in events],
                "policy_version": policy["version"], "family": family, "action": FAMILIES[family],
                "address": address, "binding": asset["bindings"][family], "duration_seconds": duration,
                "direction": "both", "created_at": now().isoformat(),
                "authorization_expires_at": (now() + timedelta(seconds=policy["approval_ttl_seconds"])).isoformat(),
                "recovery": "enforcement_ttl" if family == "firewall" else "explicit_verified_release",
            }
            rule_match = {"detector_id": alert["detector_id"], "severity": alert["severity"],
                          "group": asset["group"], "family": family} in policy["autonomous_rules"]
            origin = tx.get("detector_origin", alert_id, {"unverified": True})
            origin_verified = origin.get("sha256") == digest({key: alert.get(key) for key in ("detector_id", "severity", "entity_type",
                               "entity_id", "evidence_ids", "created_at", "features", "baseline")})
            automatic = rule_match and origin_verified
            if automatic_only and not automatic:
                raise ResponseDenied("alert does not match an automatic policy rule")
            action = {"action_id": action_id, "proposal": proposal, "proposal_hash": digest(proposal),
                      "proposed_by": actor, "status": "awaiting_approval", "attempts": 0,
                      "created_at": proposal["created_at"], "authorization": None,
                      "provider_action_id": None, "effective_state": "not_verified"}
            self._capacity(tx, policy, action)
            if policy["mode"] == "simulate":
                action.update(status="simulated", simulation={"would_authorize_automatically": automatic,
                                                             "automatic_rule_match": rule_match,
                                                             "detector_origin_verified": origin_verified,
                                                             "would_require_approval": not automatic,
                                                             "enforcement_performed": False})
            elif policy["mode"] == "autonomous" and automatic:
                self._authorize(tx, action, "response-policy", "automatic")
            tx.put("action", action_id, action)
            tx.put("request", request_id, {"action_id": action_id, "request_hash": request_hash})
            tx.journal(actor, "response.proposed", action_id, {"proposal_hash": action["proposal_hash"],
                                                              "status": action["status"]})
            return action

    def emergency_stop(self, tenant, deployment, actor):
        with self.repository.transaction(tenant, deployment) as tx:
            policy = tx.get("policy", "current", dict(DEFAULT_POLICY))
            policy.update(emergency_stop=True, version=policy["version"] + 1)
            tx.put("policy", "current", policy)
            tx.journal(actor, "response.emergency_stop", "current", {"version": policy["version"]})
            return policy

    def _authorize(self, tx, action, actor, authorization_type):
        if not self.execution_enabled:
            raise ResponseDenied("live execution is disabled")
        if self.configuration_revision is not None:
            worker = tx.get("worker", "current", {"healthy": False})
            if (not worker.get("healthy") or worker.get("configuration_revision") != self.configuration_revision
                    or not worker.get("updated_at")
                    or not 0 <= (now() - timestamp(worker["updated_at"])).total_seconds() < 30):
                raise ResponseDenied("a healthy worker with matching configuration is required")
        proposal = action["proposal"]
        adapter = self.adapters.get(proposal["binding"]["integration_id"])
        if adapter is None or adapter.family != proposal["family"]:
            raise ResponseDenied("no configured response adapter supports this target")
        if (proposal["integration_revision"] is None or proposal["integration_revision"] !=
                self._adapter_revision(proposal["binding"]["integration_id"])):
            raise ResponseDenied("integration configuration changed; propose again")
        adapter.validate(proposal)
        action.update(status="queued", authorization={"actor_id": actor, "type": authorization_type,
                      "proposal_hash": action["proposal_hash"], "created_at": now().isoformat()})
        tx.journal(actor, "response.authorized", action["action_id"], action["authorization"])
        tx.put("authorization", action["action_id"], {"action_id": action["action_id"],
            "created_at": action["authorization"]["created_at"]})

    def schedule(self, tenant, deployment):
        policy = self.policy(tenant, deployment)
        if not self.execution_enabled or policy["mode"] != "autonomous" or policy["emergency_stop"]:
            return {"considered": 0, "excluded": 0}
        with self.repository.transaction(tenant, deployment) as tx:
            assets = tx.list("asset", limit=1001)
        if len(assets) > 1000:
            raise ResponseDenied("asset inventory exceeds supported capacity")
        stats = {"considered": 0, "excluded": 0}
        for alert in self.store.list_alerts(tenant, deployment_id=deployment, limit=50):
            matches = [(asset, address) for asset in assets for address in asset["addresses"]
                if alert["entity_id"] == address or (alert["entity_id"] == asset["asset_id"] and len(asset["addresses"]) == 1)]
            if len(matches) != 1:
                continue
            asset, address = matches[0]
            for family in sorted(set(policy["allowed_families"]) & set(asset["bindings"])):
                stats["considered"] += 1
                try:
                    self.propose(tenant, deployment, "response-policy", {
                        "request_id": digest(["automatic", alert["alert_id"], asset["asset_id"], family]),
                        "asset_id": asset["asset_id"], "alert_id": alert["alert_id"], "family": family,
                        "address": address, "duration_seconds": min(300, policy["max_duration_seconds"])}, automatic_only=True)
                except (ResponseDenied, ValueError, LookupError):
                    stats["excluded"] += 1
        return stats

    def _revalidate(self, tx, action, alert, events):
        proposal = action["proposal"]
        policy = tx.get("policy", "current", dict(DEFAULT_POLICY))
        asset = tx.get("asset", proposal["asset_id"])
        if (digest(proposal) != action["proposal_hash"] or digest(asset) != proposal["asset_hash"]
                or digest(alert) != proposal.get("alert_hash")
                or policy["version"] != proposal["policy_version"] or digest(events) != proposal["evidence_hash"]
                or now() >= timestamp(proposal["authorization_expires_at"])):
            raise ResponseDenied("proposal, asset, evidence, policy or authorization window changed; propose again")
        self._validate(policy, asset, proposal["family"], proposal["address"], alert, events)
        self._capacity(tx, policy, action)
        return policy

    def _adapter_revision(self, integration_id):
        adapter = self.adapters.get(integration_id)
        revision = getattr(adapter, "revision", None)
        if adapter is not None and (not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{64}", revision)):
            raise ResponseDenied("adapter requires a SHA-256 configuration revision")
        return revision

    def approve(self, tenant, deployment, actor, action_id, body):
        fields(body, {"proposal_hash"})
        snapshot = self.get_action(tenant, deployment, action_id)
        alert, events = self._evidence(tenant, deployment, snapshot["proposal"]["alert_id"])
        with self.repository.transaction(tenant, deployment) as tx:
            action = tx.get("action", action_id)
            if action["status"] != "awaiting_approval" or body.get("proposal_hash") != action["proposal_hash"]:
                raise ResponseDenied("action is not awaiting approval of this exact proposal")
            if actor == action["proposed_by"]:
                raise ResponseDenied("a different person must approve this action")
            self._revalidate(tx, action, alert, events)
            self._authorize(tx, action, actor, "human")
            return tx.put("action", action_id, action)

    def transition(self, tenant, deployment, actor, action_id, operation, body):
        fields(body, {"proposal_hash"})
        with self.repository.transaction(tenant, deployment) as tx:
            action = tx.get("action", action_id)
            if body.get("proposal_hash") != action["proposal_hash"]:
                raise ResponseDenied("proposal hash does not match")
            if operation == "cancel":
                if action["status"] not in {"awaiting_approval", "queued"}:
                    raise ResponseDenied("action has already started or is terminal")
                action["status"] = "cancelled"
            elif operation == "release":
                if action["status"] not in {"succeeded", "unknown", "verifying", "release_unknown"}:
                    raise ResponseDenied("action has no submitted restriction to release")
                if action.get("lease_until") and timestamp(action["lease_until"]) > now():
                    raise ResponseDenied("an observation is in progress; refresh before requesting release")
                action["status"] = "release_queued"
                action["release_requested_by"] = actor
                # Discard a late observer's result rather than overwriting recovery intent.
                action.update(lease_token=None, lease_until=None)
            else:
                raise ValueError("unsupported response transition")
            tx.put("action", action_id, action)
            tx.journal(actor, "response." + operation + ".requested", action_id,
                       {"proposal_hash": action["proposal_hash"]})
            return action
