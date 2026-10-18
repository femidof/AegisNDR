"""Leased response execution for explicitly installed, trusted local adapters.

An adapter implements validate(proposal), submit(action), observe(action), and
release(action). submit/release return a provider operation ID; observe returns
{state: pending|applied|released|absent|unknown, owned: bool}. Only an effective,
owned restriction can be marked succeeded. Adapters must reconcile by action ID
even if the submit response was lost, and remove only their own restriction.
"""
from __future__ import annotations

import uuid
from datetime import timedelta

from .response import ResponseDenied, digest, now, timestamp


WORK = ("queued", "executing", "verifying", "unknown", "release_queued", "releasing",
        "release_verifying", "release_unknown", "succeeded")


class ResponseWorker:
    def __init__(self, workflow):
        self.workflow = workflow

    def run_once(self, tenant, deployment):
        if not self.workflow.execution_enabled:
            return 0
        with self.workflow.repository.transaction(tenant, deployment) as tx:
            actions = tx.list("action", states=WORK, limit=101)
        if len(actions) > 100:
            raise ResponseDenied("worker capacity exceeded; operator reconciliation required")
        processed = 0
        for action in actions:
            processed += self._process(tenant, deployment, action)
        return processed

    def _process(self, tenant, deployment, snapshot):
        action_id, proposal = snapshot["action_id"], snapshot["proposal"]
        adapter = self.workflow.adapters.get(proposal["binding"]["integration_id"])
        if adapter is None or adapter.family != proposal["family"]:
            # Retain uncertainty / restrictions until the original adapter returns.
            return 0
        alert, events, validation_error = None, None, None
        if snapshot["status"] == "queued":
            try:
                alert, events = self.workflow._evidence(tenant, deployment, proposal["alert_id"])
            except Exception:
                validation_error = "local evidence unavailable; submit was not attempted"
        token = str(uuid.uuid4())
        with self.workflow.repository.transaction(tenant, deployment) as tx:
            action = tx.get("action", action_id)
            if action["status"] != snapshot["status"]:
                return 0
            if action.get("lease_until") and timestamp(action["lease_until"]) > now():
                return 0
            if action["status"] in {"executing", "releasing"}:
                # A crashed worker might have sent the command. Never submit it again.
                action["status"] = "unknown" if action["status"] == "executing" else "release_unknown"
                tx.put("action", action_id, action)
                tx.journal("response-worker", "response.outcome.unknown", action_id,
                           {"reason": "worker lease expired"})
                return 1
            if action["status"] == "succeeded":
                if proposal["family"] != "firewall" or now() < timestamp(action["restriction_expires_at"]):
                    return 0
                # Firewall TTL should expire at the enforcement point; verify expiry.
                operation = "observe"
            elif action["status"] == "queued":
                try:
                    if validation_error:
                        raise ResponseDenied(validation_error)
                    self.workflow._revalidate(tx, action, alert, events)
                    if action["authorization"]["proposal_hash"] != digest(proposal):
                        raise ResponseDenied("authorization is not bound to the proposal")
                    adapter.validate(proposal)
                except (ResponseDenied, ValueError, KeyError):
                    action.update(status="invalidated", effective_state="not_submitted")
                    tx.put("action", action_id, action)
                    tx.journal("response-worker", "response.invalidated", action_id,
                               {"reason": "authorization or evidence no longer valid"})
                    return 1
                action.update(status="executing", attempts=action["attempts"] + 1,
                              restriction_expires_at=(now() + timedelta(seconds=proposal["duration_seconds"])).isoformat())
                operation = "submit"
            elif action["status"] == "release_queued":
                # Emergency stop prevents new restrictions, never recovery of owned ones.
                action["status"] = "releasing"
                operation = "release"
            else:
                operation = "observe"
            action.update(lease_token=token, lease_until=(now() + timedelta(seconds=60)).isoformat())
            tx.put("action", action_id, action)
            tx.journal("response-worker", "response." + operation + ".started", action_id,
                       {"proposal_hash": action["proposal_hash"]})

        # Intent and lease are committed before any privileged remote operation.
        result, error = None, False
        try:
            result = getattr(adapter, operation)(action)
        except Exception:
            # Never persist provider exception text: it can contain tokens or evidence.
            error = True
        with self.workflow.repository.transaction(tenant, deployment) as tx:
            current = tx.get("action", action_id)
            if current.get("lease_token") != token:
                return 1
            recovering = current["status"] in {"releasing", "release_verifying", "release_unknown"}
            if operation in {"submit", "release"}:
                if error or not isinstance(result, str) or not result or len(result) > 256:
                    current["status"] = "release_unknown" if recovering else "unknown"
                else:
                    current["provider_action_id" if operation == "submit" else "release_provider_action_id"] = result
                    current["status"] = "release_verifying" if recovering else "verifying"
            else:
                state = result.get("state") if isinstance(result, dict) and not error else "unknown"
                owned = isinstance(result, dict) and result.get("owned") is True
                expired = (proposal["family"] == "firewall"
                           and now() >= timestamp(current["restriction_expires_at"]))
                if state in {"released", "absent"} and owned and (recovering or expired):
                    current.update(status="released", effective_state="released")
                elif state == "applied" and owned and not recovering and not expired:
                    current.update(status="succeeded", effective_state="applied")
                elif state == "pending":
                    current["status"] = "release_verifying" if recovering else "verifying"
                else:
                    current.update(status="release_unknown" if recovering else "unknown",
                                   effective_state="not_verified")
            current.update(lease_token=None, lease_until=None)
            tx.put("action", action_id, current)
            tx.journal("response-worker", "response.outcome", action_id,
                       {"status": current["status"], "effective_state": current["effective_state"]})
        return 1
