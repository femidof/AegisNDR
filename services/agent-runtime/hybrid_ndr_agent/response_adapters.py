"""Concrete response adapters. Credentials are read only by worker operations."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlencode, urlparse

from hybrid_ndr_transport import JSONHTTPClient
from .response import ResponseDenied, ResponseNotSubmitted, ResponseWorkflow, digest, fields, now, timestamp


def document(filename):
    path = Path(filename)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise ValueError("response configuration must be a small regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("response configuration must be an object")
    return value


def tls_client(config):
    return JSONHTTPClient(config["endpoint"], ca_file=config["ca_file"],
        certificate_file=config["certificate_file"], private_key_file=config["private_key_file"],
        timeout_seconds=5, maximum_response_bytes=500_000)


class EnforcerAdapter:
    def __init__(self, config, tenant, deployment):
        self.config, self.tenant, self.deployment = config, tenant, deployment
        self.family = "firewall" if config["type"] == "nftables_gateway" else "agent"
        self.revision = digest(config)

    def validate(self, proposal):
        if (proposal["tenant_id"] != self.tenant or proposal["deployment_id"] != self.deployment
                or proposal["family"] != self.family or proposal["platform"] not in self.config["platforms"]
                or proposal["binding"]["integration_id"] != self.config["id"]
                or proposal["binding"]["target_id"] not in self.config["targets"]
                or proposal["address"] not in self.config["targets"][proposal["binding"]["target_id"]]):
            raise ResponseDenied("target is outside the configured adapter scope")

    def _request(self, action, method, operation):
        proposal = action["proposal"]
        self.validate(proposal)
        client = tls_client(self.config)
        capabilities = client.request("GET", "/v1/capabilities")
        if capabilities.get("revision") != self.config["remote_revision"]:
            raise ResponseDenied("enforcement service configuration revision changed")
        path = "/v1/actions/" + action["action_id"]
        if method == "GET":
            result = client.request(method, path)
        else:
            body = {"action_id": action["action_id"], "tenant_id": self.tenant,
                    "deployment_id": self.deployment, "integration_id": self.config["id"],
                    "target_id": proposal["binding"]["target_id"], "address": proposal["address"],
                    "family": self.family, "proposal_hash": action["proposal_hash"],
                    "remote_revision": self.config["remote_revision"],
                    "command_expires_at": proposal["authorization_expires_at"],
                    "restriction_expires_at": action["restriction_expires_at"]}
            result = client.request(method, path + "/" + operation, body=body)
        if result.get("action_id") != action["action_id"] or result.get("proposal_hash") != action["proposal_hash"]:
            raise ResponseDenied("enforcer returned an unrelated action")
        return result

    def submit(self, action):
        try:
            self._request(action, "POST", "prepare")
        except Exception:
            raise ResponseNotSubmitted("enforcer preflight was not confirmed") from None
        self._request(action, "POST", "apply")
        return action["action_id"]

    def observe(self, action):
        result = self._request(action, "GET", "observe")
        return {"state": result["state"], "owned": result["owned"],
                "requires_release": result.get("requires_release") is True}

    def release(self, action):
        self._request(action, "POST", "release")
        return "release-" + action["action_id"]


class DefenderAdapter:
    """Defender isolation with action correlation and independent mTLS probes.

    MachineActions are aggregate device state, so an exclusive managed device
    group is required. Ambiguous ownership or unavailable probes stay unknown.
    """
    family = "edr"

    def __init__(self, config, tenant, deployment):
        self.config, self.tenant, self.deployment = config, tenant, deployment
        self.revision = digest(config)

    def validate(self, proposal):
        if (proposal["tenant_id"] != self.tenant or proposal["deployment_id"] != self.deployment
                or proposal["family"] != "edr" or proposal["platform"] not in self.config["platforms"]
                or proposal["binding"]["integration_id"] != self.config["id"]
                or proposal["binding"]["target_id"] not in self.config["targets"]
                or proposal["address"] not in self.config["targets"][proposal["binding"]["target_id"]]):
            raise ResponseDenied("Defender target is outside the configured device group")

    def _call(self, method, path, body=None):
        token_path = Path(self.config["access_token_file"])
        if token_path.is_symlink() or not token_path.is_file() or token_path.stat().st_size > 16_384:
            raise ResponseDenied("Defender access token file is unavailable")
        token = token_path.read_text(encoding="utf-8").strip()
        if not token or any(char.isspace() for char in token):
            raise ResponseDenied("Defender access token is invalid")
        return JSONHTTPClient(self.config["endpoint"], timeout_seconds=5,
            maximum_response_bytes=500_000).request(method, path, body=body,
                headers={"Authorization": "Bearer " + token})

    @staticmethod
    def _marker(action, release=False):
        return "aegisndr:" + action["action_id"] + ":" + action["proposal_hash"] + (":release" if release else ":isolate")

    def _actions(self, action):
        target = action["proposal"]["binding"]["target_id"]
        query = urlencode({"$filter": "machineId eq '" + target + "'", "$top": 1000})
        result = self._call("GET", "/api/machineactions?" + query)
        if result.get("@odata.nextLink") or not isinstance(result.get("value"), list) or len(result["value"]) >= 1000:
            raise ResponseDenied("Defender action history cannot be reconciled within bounded scope")
        records = [item for item in result["value"] if item.get("machineId") == target
                   and item.get("type") in {"Isolate", "Unisolate"}]
        return sorted(records, key=lambda item: timestamp(item["creationDateTimeUtc"]), reverse=True)

    def _owned(self, record, action, release=False):
        return (record.get("requestorComment") == self._marker(action, release)
                and record.get("requestor") == self.config["requestor"])

    def _probe(self, action):
        config = self.config["verification"]
        nonce = os.urandom(16).hex()
        result = tls_client(config).request("GET", "/v1/probe?" + urlencode({"nonce": nonce}))
        if (result.get("nonce") != nonce or result.get("device_id") != action["proposal"]["binding"]["target_id"]
                or result.get("revision") != config["remote_revision"]
                or not 0 <= (now() - timestamp(result["observed_at"])).total_seconds() <= 15
                or type(result.get("reachable")) is not bool):
            raise ResponseDenied("independent device verification is unavailable or stale")
        return result["reachable"]

    def _prepare(self, action):
        proposal = action["proposal"]
        self.validate(proposal)
        records = self._actions(action)
        owned = [record for record in records if self._owned(record, action)]
        if owned:
            return owned[0]["id"]
        pending = {"Pending", "InProgress"}
        if any(record.get("status") in pending for record in records):
            raise ResponseDenied("Defender already has a pending isolation change")
        terminal = next((record for record in records if record.get("status") == "Succeeded"), None)
        if terminal and terminal["type"] == "Isolate":
            raise ResponseDenied("device already has an unrelated isolation")
        target = proposal["binding"]["target_id"]
        machine = self._call("GET", "/api/machines/" + target)
        if (machine.get("id") != target or str(machine.get("rbacGroupId")) not in self.config["device_groups"]
                or machine.get("osPlatform") not in self.config["platforms"]
                or machine.get("healthStatus") != "Active" or machine.get("deviceValue") == "High"
                or machine.get("lastIpAddress") != proposal["address"] or not self._probe(action)):
            raise ResponseDenied("Defender inventory, critical-asset check or baseline probe failed")
        return None

    def submit(self, action):
        try:
            existing = self._prepare(action)
        except Exception:
            raise ResponseNotSubmitted("Defender preflight was not confirmed") from None
        if existing:
            return existing
        target = action["proposal"]["binding"]["target_id"]
        result = self._call("POST", "/api/machines/" + target + "/isolate",
                            {"Comment": self._marker(action), "IsolationType": self.config["isolation_type"]})
        if not self._owned(result, action) or result.get("machineId") != target or result.get("type") != "Isolate":
            raise ResponseDenied("Defender submission could not be correlated")
        return result["id"]

    def observe(self, action):
        records = self._actions(action)
        owned = [record for record in records if self._owned(record, action)]
        if not owned:
            return {"state": "unknown", "owned": False}
        original = owned[0]
        # Any later foreign isolation intent makes aggregate release unsafe.
        if any(not self._owned(record, action) and not self._owned(record, action, True)
               and timestamp(record["creationDateTimeUtc"]) >= timestamp(original["creationDateTimeUtc"])
               for record in records):
            return {"state": "unknown", "owned": False}
        releases = [record for record in records if self._owned(record, action, True)]
        latest = releases[0] if releases else original
        if latest.get("status") in {"Pending", "InProgress"}:
            return {"state": "pending", "owned": True}
        if latest.get("status") != "Succeeded":
            return {"state": "unknown", "owned": True}
        reachable = self._probe(action)
        state = "released" if releases and reachable else "applied" if not releases and not reachable else "unknown"
        return {"state": state, "owned": True}

    def release(self, action):
        records = self._actions(action)
        releases = [record for record in records if self._owned(record, action, True)]
        if releases:
            return releases[0]["id"]
        if self.observe(action) != {"state": "applied", "owned": True}:
            raise ResponseDenied("Defender restriction is not verified as exclusively owned")
        target = action["proposal"]["binding"]["target_id"]
        result = self._call("POST", "/api/machines/" + target + "/unisolate", {"Comment": self._marker(action, True)})
        if not self._owned(result, action, True) or result.get("machineId") != target or result.get("type") != "Unisolate":
            raise ResponseDenied("Defender release could not be correlated")
        return result["id"]


def load_configuration(filename):
    config = document(filename)
    fields(config, {"schema_version", "enabled", "tenant_id", "deployment_id", "automatic_proposals", "integrations"})
    if (config.get("schema_version") != 1 or type(config.get("enabled")) is not bool
            or type(config.get("automatic_proposals", False)) is not bool
            or not isinstance(config.get("integrations"), list) or len(config["integrations"]) > 50):
        raise ValueError("invalid response configuration")
    from .response import identifier
    identifier(config["tenant_id"])
    identifier(config["deployment_id"])
    adapters = {}
    common = {"id", "type", "endpoint", "platforms", "targets"}
    for item in config["integrations"]:
        identifier(item["id"])
        if item["id"] in adapters:
            raise ValueError("duplicate response integration ID")
        if (not isinstance(item["platforms"], list) or not item["platforms"]
                or not isinstance(item["targets"], dict) or not 1 <= len(item["targets"]) <= 1000):
            raise ValueError("response integration requires explicit platforms and targets")
        for platform in item["platforms"]:
            identifier(platform)
        all_addresses = [address for addresses in item["targets"].values() for address in addresses]
        if len(all_addresses) != len(set(all_addresses)):
            raise ValueError("shared target addresses require disambiguation before response")
        for target, addresses in item["targets"].items():
            identifier(target)
            if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
                raise ValueError("response targets require bounded addresses")
            for address in addresses:
                if str(ipaddress.ip_address(address)) != address:
                    raise ValueError("response addresses must be canonical IP literals")
        parsed = urlparse(item["endpoint"])
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("response integration requires an HTTPS origin")
        if item["type"] in {"nftables_gateway", "linux_endpoint"}:
            fields(item, common | {"ca_file", "certificate_file", "private_key_file", "remote_revision"})
            for key in ("ca_file", "certificate_file", "private_key_file"):
                if not isinstance(item.get(key), str) or not item[key]:
                    raise ValueError("mTLS file configuration is required")
            if not re.fullmatch(r"[a-f0-9]{64}", item.get("remote_revision", "")):
                raise ValueError("remote configuration revision must be pinned")
            if item["type"] == "linux_endpoint" and item["platforms"] != ["linux"]:
                raise ValueError("native endpoint isolation supports Linux only")
            adapter = EnforcerAdapter(item, config["tenant_id"], config["deployment_id"])
        elif item["type"] == "defender":
            fields(item, common | {"access_token_file", "requestor", "device_groups", "isolation_type", "exclusive_device_group", "verification"})
            if (parsed.hostname != "api.security.microsoft.com" or parsed.port not in {None, 443}
                    or item.get("exclusive_device_group") is not True or not item.get("requestor")
                    or item.get("isolation_type") not in {"Full", "Selective"}
                    or not isinstance(item.get("device_groups"), list) or not item["device_groups"]
                    or not isinstance(item.get("access_token_file"), str)):
                raise ValueError("Defender requires scoped credentials, exclusive groups and an isolation type")
            if set(item["platforms"]) - {"Windows10", "Windows11"}:
                raise ValueError("Defender adapter supports Windows 10/11; use the native endpoint adapter for Linux")
            if any(not isinstance(group, str) or not group.isdigit() for group in item["device_groups"]):
                raise ValueError("Defender device groups must be explicit numeric IDs")
            if any(not re.fullmatch(r"[a-fA-F0-9]{40}", target) for target in item["targets"]):
                raise ValueError("Defender requires stable hexadecimal machine IDs")
            verification = item["verification"]
            fields(verification, {"endpoint", "ca_file", "certificate_file", "private_key_file", "remote_revision"})
            for key in ("ca_file", "certificate_file", "private_key_file"):
                if not isinstance(verification.get(key), str) or not verification[key]:
                    raise ValueError("verification requires explicit mTLS credential paths")
            # Validate TLS origin without loading private credentials in the API.
            verify_url = urlparse(verification["endpoint"])
            if verify_url.scheme != "https" or not verify_url.hostname or verify_url.username or verify_url.password or verify_url.query or verify_url.fragment or verify_url.path not in {"", "/"}:
                raise ValueError("verification requires a fixed HTTPS origin")
            if not re.fullmatch(r"[a-f0-9]{64}", verification.get("remote_revision", "")):
                raise ValueError("verification service revision must be pinned")
            adapter = DefenderAdapter(item, config["tenant_id"], config["deployment_id"])
        else:
            raise ValueError("unsupported response integration type")
        adapters[item["id"]] = adapter
    if config["enabled"] and not adapters:
        raise ValueError("live response requires a concrete configured adapter")
    return config, adapters


def configured_workflow(store, environ=None):
    env = os.environ if environ is None else environ
    filename = env.get("RESPONSE_CONFIG_FILE", "").strip()
    if not filename:
        return ResponseWorkflow(store)
    config, adapters = load_configuration(filename)
    expected = (env.get("TENANT_ID", env.get("AUTH_TENANT_ID")),
                env.get("DEPLOYMENT_ID", env.get("AUTH_DEPLOYMENT_ID")))
    if expected != (config["tenant_id"], config["deployment_id"]):
        raise ValueError("response configuration does not match the installed deployment")
    workflow = ResponseWorkflow(store, adapters=adapters, execution_enabled=config["enabled"],
                                scope=(config["tenant_id"], config["deployment_id"]))
    workflow.configuration_revision = digest(config)
    workflow.automatic_proposals = config.get("automatic_proposals", False)
    return workflow
