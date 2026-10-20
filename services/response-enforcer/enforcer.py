"""Small mTLS-controlled Linux nftables enforcer and portable probe service.

Only action-owned tables are created/deleted. No caller-provided command is run.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import socket
import sqlite3
import subprocess
import threading
import uuid
from urllib.parse import parse_qs

from hybrid_ndr_agent.response import ResponseDenied, digest, fields, now, timestamp


def validate_config(config):
    fields(config, {"schema_version", "mode", "tenant_id", "deployment_id", "integration_id",
                    "device_id", "targets", "management_networks", "zone_interface",
                    "controller_fingerprints", "probe_destinations"})
    if config.get("schema_version") != 1 or config.get("mode") not in {"gateway", "endpoint", "probe"}:
        raise ValueError("unsupported enforcer configuration")
    from hybrid_ndr_agent.response import identifier
    for key in ("tenant_id", "deployment_id", "integration_id", "device_id"):
        identifier(config[key])
    pins = config.get("controller_fingerprints")
    if not isinstance(pins, list) or not pins or any(not re.fullmatch(r"[a-f0-9]{64}", pin) for pin in pins):
        raise ValueError("controller certificate fingerprints must be pinned")
    if config["mode"] != "probe":
        targets = config.get("targets")
        if not isinstance(targets, dict) or not 1 <= len(targets) <= 1000:
            raise ValueError("explicit target assignments are required")
        for target, addresses in targets.items():
            identifier(target)
            if not isinstance(addresses, list) or not 1 <= len(addresses) <= 16:
                raise ValueError("invalid target address assignment")
            for value in addresses:
                address = ipaddress.ip_address(value)
                if str(address) != value or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                    raise ValueError("invalid target address")
        all_addresses = [value for addresses in targets.values() for value in addresses]
        if len(all_addresses) != len(set(all_addresses)):
            raise ValueError("shared target addresses are not supported by this enforcer")
        networks = config.get("management_networks")
        if not isinstance(networks, list) or not networks or len(networks) > 32:
            raise ValueError("explicit management networks are required")
        for network in networks:
            if ipaddress.ip_network(network).prefixlen == 0:
                raise ValueError("management exception cannot allow all traffic")
        if config["mode"] == "gateway" and not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", config.get("zone_interface", "")):
            raise ValueError("gateway requires a fixed forwarding interface")
        if config["mode"] == "endpoint" and (set(targets) != {config["device_id"]}):
            raise ValueError("endpoint configuration must target only its own device")
    if config["mode"] == "probe":
        destinations = config.get("probe_destinations")
        if not isinstance(destinations, list) or not 2 <= len(destinations) <= 4:
            raise ValueError("probe service requires two to four fixed canary destinations")
        for destination in destinations:
            fields(destination, {"address", "port"})
            address = ipaddress.ip_address(destination["address"])
            if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                raise ValueError("invalid canary address")
            if type(destination["port"]) is not int or not 1 <= destination["port"] <= 65535:
                raise ValueError("invalid canary port")
        if len({item["address"] for item in destinations}) != len(destinations):
            raise ValueError("canary destinations must be distinct")


def topology(value):
    if isinstance(value, dict):
        return {key: topology(item) for key, item in value.items()
                if key not in {"handle", "metainfo", "elem", "expires", "packets", "bytes"}}
    if isinstance(value, list):
        return [topology(item) for item in value if not isinstance(item, dict) or "metainfo" not in item]
    return value


class Nftables:
    def preflight(self, command, config):
        if config["mode"] == "gateway":
            version = ipaddress.ip_address(command["address"]).version
            path = "/proc/sys/net/ipv4/ip_forward" if version == 4 else "/proc/sys/net/ipv6/conf/all/forwarding"
            with open(path, encoding="ascii") as source:
                if source.read().strip() != "1":
                    raise ResponseDenied("gateway forwarding is not enabled")
            socket.if_nametoindex(config["zone_interface"])
        else:
            result = subprocess.run(["/usr/sbin/ip", "-j", "address", "show"], capture_output=True,
                text=True, timeout=5, check=True, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
            addresses = {str(ipaddress.ip_address(info["local"])) for interface in json.loads(result.stdout)
                         for info in interface.get("addr_info", []) if "local" in info}
            if command["address"] not in addresses:
                raise ResponseDenied("endpoint address is no longer assigned locally")

    def _run(self, arguments, script=None):
        result = subprocess.run(["/usr/sbin/nft", *arguments], input=script, text=True,
            capture_output=True, timeout=5, check=False, env={"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})
        if result.returncode:
            if script is None and "No such file or directory" in result.stderr and "Operation not permitted" not in result.stderr:
                return None
            raise ResponseDenied("nftables operation failed")
        return result.stdout

    def inspect(self, name):
        raw = self._run(["-j", "list", "table", "inet", name])
        return json.loads(raw) if raw is not None else None

    def apply(self, name, command, config):
        address = ipaddress.ip_address(command["address"])
        marker = "aegisndr:" + command["action_id"] + ":" + command["proposal_hash"]
        script = [f"create table inet {name} {{ comment {json.dumps(marker)}; }}"]
        if config["mode"] == "gateway":
            seconds = math.floor((timestamp(command["restriction_expires_at"]) - now()).total_seconds())
            if not 1 <= seconds <= 3600:
                raise ResponseDenied("firewall expiration is outside the permitted window")
            kind, proto = ("ipv4_addr", "ip") if address.version == 4 else ("ipv6_addr", "ip6")
            interface = json.dumps(config["zone_interface"])
            script.extend([
                f"add set inet {name} blocked {{ type {kind}; flags timeout; elements = {{ {address} timeout {seconds}s }}; }}",
                f"add chain inet {name} guard {{ type filter hook forward priority -10; policy accept; }}",
                f"add rule inet {name} guard iifname {interface} {proto} saddr @blocked drop",
                f"add rule inet {name} guard oifname {interface} {proto} daddr @blocked drop",
            ])
        else:
            for hook in ("input", "output", "forward"):
                script.append(f"add chain inet {name} {hook}_guard {{ type filter hook {hook} priority -10; policy accept; }}")
                chain = f"inet {name} {hook}_guard"
                if hook != "forward":
                    script.append(f"add rule {chain} {'iifname' if hook == 'input' else 'oifname'} \"lo\" accept")
                for network in config["management_networks"]:
                    proto = "ip" if ipaddress.ip_network(network).version == 4 else "ip6"
                    for direction in (("saddr", "daddr") if hook == "forward" else ("saddr",) if hook == "input" else ("daddr",)):
                        script.append(f"add rule {chain} {proto} {direction} {network} accept")
                # Preserve IPv6 neighbour/router discovery without opening data sessions.
                script.append(f"add rule {chain} meta l4proto ipv6-icmp icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept")
                script.append(f"add rule {chain} drop")
        self._run(["-f", "-"], "\n".join(script) + "\n")
        return self.inspect(name)

    def release(self, name):
        self._run(["-f", "-"], f"delete table inet {name}\n")


class Enforcer:
    def __init__(self, config, database, *, nft=None):
        validate_config(config)
        self.config, self.revision = config, digest(config)
        self.nft = nft or Nftables()
        self.connection = sqlite3.connect(database, check_same_thread=False, timeout=10)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("CREATE TABLE IF NOT EXISTS commands (action_id TEXT PRIMARY KEY, command_json TEXT NOT NULL, state TEXT NOT NULL, topology_hash TEXT)")
        self.connection.commit()
        self.lock = threading.RLock()

    def _row(self, action_id):
        return self.connection.execute("SELECT command_json,state,topology_hash FROM commands WHERE action_id=?", (action_id,)).fetchone()

    def _name(self, action_id):
        return "aegis_" + digest([self.config["tenant_id"], self.config["deployment_id"], action_id])[:24]

    def _validate(self, command, action_id):
        fields(command, {"action_id", "tenant_id", "deployment_id", "integration_id", "target_id", "address", "family",
                         "proposal_hash", "remote_revision", "command_expires_at", "restriction_expires_at"})
        if (str(uuid.UUID(action_id)) != action_id or command["action_id"] != action_id
                or not re.fullmatch(r"[a-f0-9]{64}", command["proposal_hash"])):
            raise ValueError("invalid command identity")
        for key in ("tenant_id", "deployment_id", "integration_id"):
            if command[key] != self.config[key]:
                raise ResponseDenied("enforcer scope mismatch")
        family = "firewall" if self.config["mode"] == "gateway" else "agent"
        if (self.config["mode"] == "probe" or command["family"] != family or command["remote_revision"] != self.revision
                or command["address"] not in self.config["targets"].get(command["target_id"], [])):
            raise ResponseDenied("enforcer target or configuration mismatch")
        address = ipaddress.ip_address(command["address"])
        if family == "firewall" and any(address in ipaddress.ip_network(value) for value in self.config["management_networks"]):
            raise ResponseDenied("management address cannot be blocked")

    def _save(self, action_id, command, state, topology_hash=None):
        self.connection.execute("INSERT INTO commands VALUES (?,?,?,?) ON CONFLICT(action_id) DO UPDATE SET state=excluded.state,topology_hash=excluded.topology_hash",
                                (action_id, json.dumps(command, sort_keys=True), state, topology_hash))
        self.connection.commit()

    def _result(self, command, state, owned=True, requires_release=False):
        return {"action_id": command["action_id"], "proposal_hash": command["proposal_hash"],
                "state": state, "owned": owned, "revision": self.revision, "requires_release": requires_release}

    def observe(self, action_id):
        with self.lock:
            row = self._row(action_id)
            if row is None:
                raise KeyError("unknown enforcement action")
            command, state, expected = json.loads(row[0]), row[1], row[2]
            if command["remote_revision"] != self.revision:
                return self._result(command, "unknown", False)
            actual = self.nft.inspect(self._name(action_id))
            if actual is None:
                if state == "prepared" and (now() - timestamp(command["command_expires_at"])).total_seconds() < 60:
                    return self._result(command, "pending")
                return self._result(command, "released" if state == "released" else "absent",
                                    requires_release=state not in {"released", "prepared", "not_submitted"})
            if expected is None or digest(topology(actual)) != expected:
                return self._result(command, "unknown", False)
            if command["family"] == "firewall":
                sets = [item["set"] for item in actual["nftables"] if "set" in item]
                elements = sets[0].get("elem", []) if len(sets) == 1 else [None, None]
                values = [item if isinstance(item, str) else item.get("elem", {}).get("val") for item in elements if item is not None]
                if not elements and now() >= timestamp(command["restriction_expires_at"]):
                    return self._result(command, "released")
                if values != [command["address"]]:
                    return self._result(command, "unknown", False)
            return self._result(command, "applied")

    def apply(self, action_id, command):
        with self.lock:
            self._validate(command, action_id)
            row = self._row(action_id)
            if row:
                if json.loads(row[0]) != command:
                    raise ResponseDenied("action ID was already used for another command")
                if row[1] != "prepared":
                    return self.observe(action_id)
            if not 0 < (timestamp(command["command_expires_at"]) - now()).total_seconds() <= 900:
                raise ResponseDenied("command expired or exceeds the acceptance window")
            if not 0 < (timestamp(command["restriction_expires_at"]) - now()).total_seconds() <= 3600:
                raise ResponseDenied("restriction deadline is invalid")
            self.expire()
            active = self.connection.execute("SELECT command_json FROM commands WHERE state IN ('applying','applied','releasing')").fetchall()
            if len(active) >= (1 if self.config["mode"] == "endpoint" else 100):
                raise ResponseDenied("enforcer active action limit reached")
            if any(json.loads(item[0])["target_id"] == command["target_id"] for item in active):
                raise ResponseDenied("target already has an unresolved enforcement command")
            name = self._name(action_id)
            if self.nft.inspect(name) is not None:
                raise ResponseDenied("action table already exists without a durable ownership record")
            self.nft.preflight(command, self.config)
            self._save(action_id, command, "applying")
            actual = self.nft.apply(name, command, self.config)
            if actual is None:
                raise ResponseDenied("nftables read-back failed")
            self._save(action_id, command, "applied", digest(topology(actual)))
            return self.observe(action_id)

    def prepare(self, action_id, command):
        with self.lock:
            self._validate(command, action_id)
            if not 0 < (timestamp(command["command_expires_at"]) - now()).total_seconds() <= 900:
                raise ResponseDenied("command acceptance window is invalid")
            self.nft.preflight(command, self.config)
            row = self._row(action_id)
            if row and json.loads(row[0]) != command:
                raise ResponseDenied("action ID was already used for another command")
            if row is None:
                # Reserve the immutable command before mutation. Restart never
                # treats a mere preflight reservation as an isolation request.
                self._save(action_id, command, "prepared")
            return self._result(command, "ready", False)

    def release(self, action_id, command=None):
        with self.lock:
            row = self._row(action_id)
            if row is None:
                raise KeyError("unknown enforcement action")
            original = json.loads(row[0])
            if command is not None:
                self._validate(command, action_id)
                if command != original:
                    raise ResponseDenied("release command differs from original intent")
            if original["remote_revision"] != self.revision:
                raise ResponseDenied("restore the original enforcement configuration before recovery")
            observed = self.observe(action_id)
            if not observed["owned"]:
                raise ResponseDenied("restriction ownership cannot be verified")
            self._save(action_id, original, "releasing", row[2])
            if self.nft.inspect(self._name(action_id)) is not None:
                self.nft.release(self._name(action_id))
            self._save(action_id, original, "released", row[2])
            return self.observe(action_id)

    def restore(self):
        """Recover durable endpoint isolation; gateway timeout never extends on restart."""
        with self.lock:
            for action_id, raw, state, expected in self.connection.execute("SELECT * FROM commands").fetchall():
                command = json.loads(raw)
                if state in {"released", "prepared", "not_submitted"}:
                    continue
                if command["remote_revision"] != self.revision:
                    raise ResponseDenied("unresolved commands require the original configuration")
                if state == "releasing":
                    self.release(action_id)
                    continue
                actual = self.nft.inspect(self._name(action_id))
                if actual is not None:
                    marker = "aegisndr:" + action_id + ":" + command["proposal_hash"]
                    tables = [item["table"] for item in actual["nftables"] if "table" in item]
                    if len(tables) != 1 or tables[0].get("comment") != marker:
                        raise ResponseDenied("nftables ownership marker changed")
                    if expected is not None and digest(topology(actual)) != expected:
                        raise ResponseDenied("nftables rules changed outside the enforcer")
                    self._save(action_id, command, "applied", digest(topology(actual)))
                elif command["family"] == "firewall" and now() >= timestamp(command["restriction_expires_at"]):
                    self._save(action_id, command, "released", expected)
                else:
                    actual = self.nft.apply(self._name(action_id), command, self.config)
                    self._save(action_id, command, "applied", digest(topology(actual)))
            self.expire()

    def expire(self):
        with self.lock:
            for action_id, raw in self.connection.execute("SELECT action_id,command_json FROM commands WHERE state NOT IN ('released','not_submitted')").fetchall():
                command = json.loads(raw)
                row = self._row(action_id)
                if row[1] == "prepared":
                    if (now() - timestamp(command["command_expires_at"])).total_seconds() >= 60 and self.nft.inspect(self._name(action_id)) is None:
                        self._save(action_id, command, "not_submitted")
                    continue
                if command["family"] == "firewall" and now() >= timestamp(command["restriction_expires_at"]):
                    observed = self.observe(action_id)
                    if observed["owned"] and observed["state"] in {"released", "absent"}:
                        self.release(action_id)

    def probe(self, nonce):
        if self.config["mode"] != "probe" or not re.fullmatch(r"[a-f0-9]{32}", nonce):
            raise ResponseDenied("probe is not configured")
        outcomes = []
        for destination in self.config["probe_destinations"]:
            try:
                with socket.create_connection((destination["address"], destination["port"]), timeout=1):
                    outcomes.append(True)
            except OSError:
                outcomes.append(False)
        return {"nonce": nonce, "device_id": self.config["device_id"], "revision": self.revision,
                "reachable": True if all(outcomes) else False if not any(outcomes) else None,
                "observed_at": now().isoformat()}

    def application(self, environ, start_response):
        status, result = 200, {}
        try:
            if environ.get("SSL_CLIENT_CERT_SHA256") not in self.config["controller_fingerprints"]:
                status, result = 403, {"error": "controller certificate not authorized"}
            elif environ["PATH_INFO"] == "/v1/capabilities" and environ["REQUEST_METHOD"] == "GET":
                result = {"revision": self.revision, "mode": self.config["mode"]}
            elif environ["PATH_INFO"] == "/v1/probe" and environ["REQUEST_METHOD"] == "GET":
                result = self.probe(parse_qs(environ.get("QUERY_STRING", "")).get("nonce", [""])[0])
            else:
                match = re.fullmatch(r"/v1/actions/([a-f0-9-]{36})(?:/(apply|prepare|release))?", environ["PATH_INFO"])
                if not match:
                    raise KeyError("unknown route")
                action_id, operation = match.groups()
                if environ["REQUEST_METHOD"] == "GET" and operation is None:
                    result = self.observe(action_id)
                elif environ["REQUEST_METHOD"] == "POST" and operation:
                    length = int(environ.get("CONTENT_LENGTH", "0"))
                    if not 1 <= length <= 8192:
                        raise ValueError("command body must be between 1 and 8192 bytes")
                    command = json.loads(environ["wsgi.input"].read(length))
                    if operation in {"apply", "prepare"} and self.config["mode"] == "endpoint":
                        peer = ipaddress.ip_address(environ["REMOTE_ADDR"])
                        if not any(peer in ipaddress.ip_network(network) for network in self.config["management_networks"]):
                            raise ResponseDenied("controller path is outside preserved management networks")
                    result = getattr(self, operation)(action_id, command)
                else:
                    raise ValueError("unsupported request method")
        except KeyError:
            status, result = 404, {"error": "enforcement resource not found"}
        except (ValueError, TypeError):
            status, result = 409, {"error": "enforcement request rejected"}
        except Exception:
            status, result = 503, {"error": "enforcement state unavailable"}
        encoded = json.dumps(result).encode()
        start_response(f"{status} response", [("Content-Type", "application/json"), ("Content-Length", str(len(encoded))), ("Cache-Control", "no-store")])
        return [encoded]
