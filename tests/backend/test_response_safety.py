"""Response authorization and crash recovery checks; never contacts a provider."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import support
from hybrid_ndr_agent.response import ResponseDenied, ResponseNotSubmitted, ResponseWorkflow, digest, now
from hybrid_ndr_agent.response_worker import ResponseWorker
from hybrid_ndr_agent.response_adapters import EnforcerAdapter, DefenderAdapter, load_configuration
from hybrid_ndr_storage import LocalStore
from hybrid_ndr_auth import HeaderAuthenticator
from hybrid_ndr_local_api import create_application

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("response_enforcer", ROOT / "services/response-enforcer/enforcer.py")
enforcer_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enforcer_module)
Enforcer = enforcer_module.Enforcer


class Adapter:
    family, revision = "firewall", "a" * 64

    def __init__(self):
        self.submissions, self.releases = 0, 0
        self.observation = {"state": "applied", "owned": True}
        self.failure = None

    def validate(self, proposal):
        pass

    def submit(self, action):
        self.submissions += 1
        if self.failure:
            raise self.failure
        return "provider-1"

    def observe(self, action):
        return self.observation

    def release(self, action):
        self.releases += 1
        self.observation = {"state": "released", "owned": True}
        return "release-1"


class WorkflowSafetyTests(unittest.TestCase):
    def setUp(self):
        self.store = LocalStore(":memory:")
        self.adapter = Adapter()
        self.workflow = ResponseWorkflow(self.store, adapters={"gateway": self.adapter}, execution_enabled=True)
        self.scope = ("tenant", "deployment")
        instant = now()
        self.alert = dict(alert_id="alert-1", tenant_id="tenant", deployment_id="deployment", status="new",
                          detector_id="validated-rule", severity="high", entity_id="192.0.2.10", entity_type="ip",
                          evidence_ids=["event-1"], created_at=instant.isoformat(), features={}, baseline={})
        self.events = [dict(event_id="event-1", event_time=instant.isoformat(), src_ip="192.0.2.10")]
        self.workflow._evidence = lambda *args: (copy.deepcopy(self.alert), copy.deepcopy(self.events))
        self.asset = dict(asset_id="asset-1", group="lab", critical=False, platform="linux", addresses=["192.0.2.10"],
                          observed_at=(instant - timedelta(seconds=5)).isoformat(),
                          valid_until=(instant + timedelta(hours=1)).isoformat(), source="administrator",
                          bindings={"firewall": {"integration_id": "gateway", "target_id": "device-1"}})
        self.workflow.register_asset(*self.scope, "admin", self.asset)
        self.workflow.update_policy(*self.scope, "admin", dict(version=0, mode="approval_required",
            allowed_groups=["lab"], allowed_families=["firewall"]))
        self.body = dict(request_id="request-1", asset_id="asset-1", alert_id="alert-1", family="firewall",
                         address="192.0.2.10", duration_seconds=300)
        self.worker = ResponseWorker(self.workflow)

    def tearDown(self):
        self.store.close()

    def propose(self):
        return self.workflow.propose(*self.scope, "analyst", self.body)

    def authorize(self):
        action = self.propose()
        return self.workflow.approve(*self.scope, "approver", action["action_id"], {"proposal_hash": action["proposal_hash"]})

    def current(self, action):
        return self.workflow.get_action(*self.scope, action["action_id"])

    def mutate(self, action, **changes):
        with self.workflow.repository.transaction(*self.scope) as tx:
            current = tx.get("action", action["action_id"])
            current.update(changes)
            tx.put("action", action["action_id"], current)

    def test_proposal_is_idempotent_and_cannot_change_body(self):
        first = self.propose()
        self.assertEqual(first, self.propose())
        self.body["duration_seconds"] = 100
        with self.assertRaises(ResponseDenied):
            self.propose()

    def test_self_approval_and_wrong_hash_are_rejected(self):
        action = self.propose()
        for actor, proposal_hash in (("analyst", action["proposal_hash"]), ("approver", "b" * 64)):
            with self.assertRaises(ResponseDenied):
                self.workflow.approve(*self.scope, actor, action["action_id"], {"proposal_hash": proposal_hash})

    def test_stale_asset_update_cannot_overwrite_mapping(self):
        with self.assertRaises(ResponseDenied):
            self.workflow.register_asset(*self.scope, "admin", self.asset)
        self.assertEqual(self.workflow.list(*self.scope, "asset")[0]["revision"], 1)

    def test_critical_assets_and_stale_evidence_are_rejected(self):
        self.events[0]["event_time"] = (now() - timedelta(hours=1)).isoformat()
        with self.assertRaises(ResponseDenied):
            self.propose()
        self.events[0]["event_time"] = now().isoformat()
        self.workflow.register_asset(*self.scope, "admin", {**self.asset, "revision": 1, "critical": True})
        with self.assertRaises(ResponseDenied):
            self.propose()

    def test_policy_stop_invalidates_queued_work(self):
        action = self.authorize()
        self.workflow.emergency_stop(*self.scope, "admin")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "invalidated")
        self.assertEqual(self.adapter.submissions, 0)

    def test_changed_evidence_invalidates_authorization(self):
        action = self.authorize()
        self.events[0]["extra"] = "changed"
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "invalidated")

    def test_submit_timeout_is_observed_without_retry(self):
        action = self.authorize()
        self.adapter.failure = TimeoutError("secret must not reach journal")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "unknown")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "succeeded")
        self.assertEqual(self.adapter.submissions, 1)
        self.assertNotIn("secret must", json.dumps(self.workflow.list(*self.scope, "journal")))

    def test_known_preflight_failure_is_terminal(self):
        action = self.authorize()
        self.adapter.failure = ResponseNotSubmitted("preflight")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "failed")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.adapter.submissions, 1)

    def test_expired_execution_lease_never_resubmits(self):
        action = self.authorize()
        self.mutate(action, status="executing", lease_until=(now() - timedelta(seconds=1)).isoformat(),
                    restriction_expires_at=(now() + timedelta(minutes=5)).isoformat())
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "unknown")
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "succeeded")
        self.assertEqual(self.adapter.submissions, 0)

    def test_foreign_restriction_cannot_be_released(self):
        action = self.authorize()
        self.worker.run_once(*self.scope)
        self.adapter.observation = {"state": "applied", "owned": False}
        self.workflow.transition(*self.scope, "admin", action["action_id"], "release", {"proposal_hash": action["proposal_hash"]})
        self.worker.run_once(*self.scope)
        self.assertEqual(self.adapter.releases, 0)
        self.assertEqual(self.current(action)["status"], "release_unknown")

    def test_emergency_stop_still_allows_owned_release(self):
        action = self.authorize()
        self.worker.run_once(*self.scope)
        self.worker.run_once(*self.scope)
        self.workflow.emergency_stop(*self.scope, "admin")
        self.workflow.transition(*self.scope, "admin", action["action_id"], "release", {"proposal_hash": action["proposal_hash"]})
        self.worker.run_once(*self.scope)
        self.worker.run_once(*self.scope)
        self.assertEqual(self.current(action)["status"], "released")
        self.assertEqual(self.adapter.releases, 1)

    def test_live_worker_revision_is_required(self):
        self.workflow.configuration_revision = "c" * 64
        action = self.propose()
        with self.assertRaises(ResponseDenied):
            self.workflow.approve(*self.scope, "approver", action["action_id"], {"proposal_hash": action["proposal_hash"]})

    def test_automatic_rule_requires_detector_provenance(self):
        self.workflow.update_policy(*self.scope, "admin", dict(version=1, mode="autonomous", autonomous_rules=[
            dict(detector_id="validated-rule", severity="high", group="lab", family="firewall")]))
        first = self.propose()
        self.assertEqual(first["status"], "awaiting_approval")
        projection = {key: self.alert.get(key) for key in ("detector_id", "severity", "entity_type", "entity_id",
                      "evidence_ids", "created_at", "features", "baseline")}
        with self.workflow.repository.transaction(*self.scope) as tx:
            tx.put("detector_origin", "alert-1", {"sha256": digest(projection)})
        self.body["request_id"] = "verified"
        self.assertEqual(self.propose()["status"], "queued")

    def test_scope_and_transaction_rollback(self):
        self.workflow.repository.scope = self.scope
        with self.assertRaises(LookupError):
            self.workflow.list("other", "deployment", "action")
        with self.assertRaises(RuntimeError):
            with self.workflow.repository.transaction(*self.scope) as tx:
                tx.put("request", "rollback", {"value": 1})
                raise RuntimeError()
        with self.workflow.repository.transaction(*self.scope) as tx:
            self.assertEqual(tx.get("request", "rollback", {"missing": True}), {"missing": True})

    def test_active_lease_prevents_a_second_worker_claim(self):
        action = self.authorize()
        self.mutate(action, lease_until=(now() + timedelta(seconds=60)).isoformat())
        self.assertEqual(self.worker.run_once(*self.scope), 0)
        self.assertEqual(self.adapter.submissions, 0)

    def test_authorization_limit_is_independent_of_observation_journal_volume(self):
        action = self.authorize()
        self.mutate(action, status="released")
        self.workflow.update_policy(*self.scope, "admin", dict(version=1, max_per_hour=1))
        with self.workflow.repository.transaction(*self.scope) as tx:
            for index in range(1100):
                tx.journal("worker", "response.observed", action["action_id"], {"index": index})
        self.body["request_id"] = "second"
        with self.assertRaises(ResponseDenied):
            self.propose()

    def test_journal_forms_a_continuous_hash_chain(self):
        self.authorize()
        records = sorted(self.workflow.list(*self.scope, "journal"), key=lambda value: value["sequence"])
        previous = "0" * 64
        for sequence, record in enumerate(records, 1):
            self.assertEqual(record["sequence"], sequence)
            self.assertEqual(record["previous_hash"], previous)
            previous = record.pop("hash")
            self.assertEqual(digest(record), previous)

    def test_api_enforces_response_permissions_on_server(self):
        api = create_application(self.store, authenticator=HeaderAuthenticator()).api
        api.response = self.workflow
        for role in ("analyst", "auditor", "read_only", "deployment_agent"):
            headers = {"X-Tenant-ID": "tenant", "X-Deployment-ID": "deployment", "X-Actor-ID": "actor", "X-Role": role}
            result = api.handle("PATCH", "/api/v1/response/policy", headers=headers, body={"version": 1, "mode": "off"})
            self.assertEqual(result.status, 403, role)
        for role in ("read_only", "deployment_agent"):
            headers = {"X-Tenant-ID": "tenant", "X-Deployment-ID": "deployment", "X-Actor-ID": "actor", "X-Role": role}
            self.assertEqual(api.handle("GET", "/api/v1/response/actions", headers=headers).status, 403)
        self.assertEqual(self.workflow.policy(*self.scope)["mode"], "approval_required")

    def test_invalid_config_fails_closed_without_breaking_local_api(self):
        with patch.dict("os.environ", {"RESPONSE_CONFIG_FILE": "nonexistent-response-config.json"}):
            api = create_application(self.store, authenticator=HeaderAuthenticator()).api
        self.assertFalse(api.response.execution_enabled)
        self.assertTrue(api.response.configuration_error)


class FakeNft:
    def __init__(self):
        self.tables, self.applied = {}, 0

    def preflight(self, command, config):
        pass

    def inspect(self, name):
        return copy.deepcopy(self.tables.get(name))

    def apply(self, name, command, config):
        self.applied += 1
        self.tables[name] = {"nftables": [{"table": {"name": name, "comment": "aegisndr:" + command["action_id"] + ":" + command["proposal_hash"]}},
            {"set": {"name": "blocked", "elem": [{"elem": {"val": command["address"], "expires": 2500}}]}}]}
        return self.inspect(name)

    def release(self, name):
        del self.tables[name]


class EnforcerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.nft = FakeNft()
        self.config = json.loads((ROOT / "infra/response/gateway.example.json").read_text())
        self.enforcer = Enforcer(self.config, str(Path(self.directory.name) / "state.db"), nft=self.nft)
        self.action_id = str(uuid.uuid4())
        target, addresses = next(iter(self.config["targets"].items()))
        self.command = dict(action_id=self.action_id, tenant_id=self.config["tenant_id"], deployment_id=self.config["deployment_id"],
            integration_id=self.config["integration_id"], target_id=target, address=addresses[0], family="firewall", proposal_hash="b" * 64,
            remote_revision=self.enforcer.revision, command_expires_at=(now() + timedelta(minutes=5)).isoformat(),
            restriction_expires_at=(now() + timedelta(minutes=5)).isoformat())

    def tearDown(self):
        self.enforcer.connection.close()
        self.directory.cleanup()

    def test_prepare_does_not_restore_into_enforcement(self):
        self.enforcer.prepare(self.action_id, self.command)
        self.enforcer.restore()
        self.assertEqual(self.nft.applied, 0)
        self.assertEqual(self.enforcer.observe(self.action_id)["state"], "pending")

    def test_apply_release_and_replay_are_idempotent(self):
        self.assertEqual(self.enforcer.apply(self.action_id, self.command)["state"], "applied")
        self.enforcer.apply(self.action_id, self.command)
        self.assertEqual(self.nft.applied, 1)
        self.assertEqual(self.enforcer.release(self.action_id, self.command)["state"], "released")
        self.assertEqual(self.enforcer.apply(self.action_id, self.command)["state"], "released")
        self.assertEqual(self.nft.applied, 1)

    def test_changed_target_or_hash_cannot_reuse_id(self):
        self.enforcer.prepare(self.action_id, self.command)
        with self.assertRaises(ResponseDenied):
            self.enforcer.apply(self.action_id, {**self.command, "proposal_hash": "c" * 64})

    def test_rule_tampering_denies_release(self):
        self.enforcer.apply(self.action_id, self.command)
        self.nft.tables[self.enforcer._name(self.action_id)]["nftables"].append({"rule": {"expr": "foreign"}})
        self.assertFalse(self.enforcer.observe(self.action_id)["owned"])
        with self.assertRaises(ResponseDenied):
            self.enforcer.release(self.action_id)

    def test_missing_table_retains_durable_recovery_intent(self):
        self.enforcer.apply(self.action_id, self.command)
        self.nft.tables.clear()
        self.assertTrue(self.enforcer.observe(self.action_id)["requires_release"])
        self.enforcer.release(self.action_id)
        self.enforcer.restore()
        self.assertFalse(self.nft.tables)

    def test_scope_and_expiry_rejected_before_mutation(self):
        for key, value in (("tenant_id", "other"), ("remote_revision", "d" * 64),
                           ("command_expires_at", (now() - timedelta(seconds=1)).isoformat())):
            with self.assertRaises(ResponseDenied):
                self.enforcer.apply(self.action_id, {**self.command, key: value})
        self.assertEqual(self.nft.applied, 0)

    def test_controller_certificate_rotation_preserves_owned_recovery(self):
        self.enforcer.apply(self.action_id, self.command)
        original_revision = self.enforcer.revision
        self.enforcer.connection.close()
        rotated = {**self.config, "controller_fingerprints": ["c" * 64]}
        self.enforcer = Enforcer(rotated, str(Path(self.directory.name) / "state.db"), nft=self.nft)
        self.assertEqual(self.enforcer.revision, original_revision)
        self.enforcer.restore()
        self.assertEqual(self.enforcer.release(self.action_id)["state"], "released")
        changed = {**rotated, "management_networks": ["192.0.2.7/32"]}
        self.assertNotEqual(enforcer_module.configuration_revision(changed), original_revision)

    def test_http_headers_cannot_impersonate_controller_certificate(self):
        statuses = []
        result = self.enforcer.application({"PATH_INFO": "/v1/capabilities", "REQUEST_METHOD": "GET",
            "HTTP_SSL_CLIENT_CERT_SHA256": self.config["controller_fingerprints"][0]}, lambda status, headers: statuses.append(status))
        self.assertTrue(statuses[0].startswith("403"))

    @unittest.skipUnless(sys.platform == "linux", "Linux process lock")
    def test_local_recovery_cannot_race_the_running_service(self):
        sys.path.insert(0, str(ROOT / "services/response-enforcer"))
        app_spec = importlib.util.spec_from_file_location("response_enforcer_app", ROOT / "services/response-enforcer/app.py")
        application = importlib.util.module_from_spec(app_spec)
        app_spec.loader.exec_module(application)
        filename = str(Path(self.directory.name) / "state.db")
        lock = application.exclusive_state_lock(filename)
        try:
            with self.assertRaises(SystemExit):
                application.exclusive_state_lock(filename)
        finally:
            lock.close()
        application.exclusive_state_lock(filename).close()


class AdapterSafetyTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(id="defender", type="defender", platforms=["Windows11"], targets={"a" * 40: ["192.0.2.10"]},
                           requestor="application-id", device_groups=["1"], isolation_type="Full")
        self.adapter = DefenderAdapter(self.config, "tenant", "deployment")
        self.action = dict(action_id=str(uuid.uuid4()), proposal_hash="b" * 64, proposal=dict(
            tenant_id="tenant", deployment_id="deployment", family="edr", platform="Windows11",
            address="192.0.2.10", binding=dict(integration_id="defender", target_id="a" * 40)))
        self.original = dict(id="provider-id", machineId="a" * 40, type="Isolate", status="Succeeded",
            requestor="application-id", requestorComment=self.adapter._marker(self.action), creationDateTimeUtc=now().isoformat())

    def test_foreign_action_prevents_aggregate_release(self):
        foreign = {**self.original, "id": "foreign", "requestorComment": "operator restriction"}
        with patch.object(self.adapter, "_actions", return_value=[foreign, self.original]):
            self.assertEqual(self.adapter.observe(self.action), {"state": "unknown", "owned": False})
            with self.assertRaises(ResponseDenied):
                self.adapter.release(self.action)

    def test_provider_success_requires_independent_datapath_confirmation(self):
        with patch.object(self.adapter, "_actions", return_value=[self.original]), patch.object(self.adapter, "_probe", return_value=True):
            self.assertEqual(self.adapter.observe(self.action)["state"], "unknown")
        with patch.object(self.adapter, "_actions", return_value=[self.original]), patch.object(self.adapter, "_probe", return_value=False):
            self.assertEqual(self.adapter.observe(self.action)["state"], "applied")

    def test_pending_provider_operation_never_counts_as_applied(self):
        with patch.object(self.adapter, "_actions", return_value=[{**self.original, "status": "Pending"}]):
            self.assertEqual(self.adapter.observe(self.action)["state"], "pending")

    def test_preflight_failure_never_posts_isolation(self):
        with patch.object(self.adapter, "_prepare", side_effect=TimeoutError()), patch.object(self.adapter, "_call") as call:
            with self.assertRaises(ResponseNotSubmitted):
                self.adapter.submit(self.action)
            call.assert_not_called()

    def test_isolation_response_loss_is_uncertain(self):
        with patch.object(self.adapter, "_prepare", return_value=None), patch.object(self.adapter, "_call", side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):
                self.adapter.submit(self.action)

    def test_enforcer_preflight_failure_never_posts_apply(self):
        adapter = EnforcerAdapter({"type": "linux_endpoint"}, "tenant", "deployment")
        with patch.object(adapter, "_request", side_effect=TimeoutError()) as request:
            with self.assertRaises(ResponseNotSubmitted):
                adapter.submit(self.action)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(request.call_args.args[2], "prepare")

    def test_live_configuration_requires_a_concrete_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "response.json"
            config = dict(schema_version=1, enabled=False, tenant_id="tenant", deployment_id="deployment", integrations=[])
            filename.write_text(json.dumps(config))
            self.assertEqual(load_configuration(filename)[1], {})
            filename.write_text(json.dumps({**config, "enabled": True}))
            with self.assertRaises(ValueError):
                load_configuration(filename)


if __name__ == "__main__":
    unittest.main()
