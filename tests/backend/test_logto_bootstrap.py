from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import support


MODULE_PATH = support.ROOT / "infra" / "logto" / "bootstrap.py"
SPEC = importlib.util.spec_from_file_location("hybrid_ndr_logto_bootstrap", MODULE_PATH)
bootstrap = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = bootstrap
SPEC.loader.exec_module(bootstrap)


class FakeLogtoClient:
    endpoint = "http://localhost:3011"

    def __init__(self):
        self.keys = [{"id": "ec-1", "status": "Current", "signingKeyAlgorithm": "EC"}]
        self.resources = []
        self.scopes = []
        self.roles = []
        self.role_scope_ids = {}
        self.organizations = []
        self.applications = []
        self.organization_applications = []
        self.organization_application_roles = {}
        self.calls = []
        self.customizers = {}
        self._counter = 0

    def _id(self, prefix):
        self._counter += 1
        return f"{prefix}-{self._counter}"

    def list(self, path, *, query=""):
        if path == "/api/resources":
            values = self.resources
        elif path.startswith("/api/resources/") and path.endswith("/scopes"):
            resource_id = path.split("/")[3]
            values = [item for item in self.scopes if item["resourceId"] == resource_id]
        elif path == "/api/organization-roles":
            values = self.roles
        elif path == "/api/organizations":
            values = self.organizations
        elif path == "/api/applications":
            values = self.applications
        elif path.startswith("/api/organizations/") and path.endswith("/applications"):
            values = self.organization_applications
        else:
            raise AssertionError(path)
        if not query:
            return [dict(item) for item in values]
        return [dict(item) for item in values if query in str(item)]

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if (method, path) == ("GET", "/api/configs/oidc/private-keys"):
            return [dict(item) for item in self.keys]
        if (method, path) == ("POST", "/api/configs/oidc/private-keys/rotate"):
            self.keys = [{"id": "rsa-1", "status": "Current", "signingKeyAlgorithm": "RSA"}]
            return [dict(item) for item in self.keys]
        if method == "POST" and path == "/api/resources":
            item = {"id": self._id("resource"), **payload}
            self.resources.append(item)
            return dict(item)
        if method == "PATCH" and path.startswith("/api/resources/") and "/scopes/" not in path:
            item = next(value for value in self.resources if path.endswith(value["id"]))
            item.update(payload)
            return dict(item)
        if method == "POST" and path.startswith("/api/resources/") and path.endswith("/scopes"):
            resource_id = path.split("/")[3]
            item = {"id": self._id("scope"), "resourceId": resource_id, **payload}
            self.scopes.append(item)
            return dict(item)
        if method == "PATCH" and "/scopes/" in path:
            item = next(value for value in self.scopes if path.endswith(value["id"]))
            item.update(payload)
            return dict(item)
        if method == "POST" and path == "/api/organization-roles":
            item = {"id": self._id("role"), **payload}
            self.roles.append(item)
            self.role_scope_ids[item["id"]] = list(payload["resourceScopeIds"])
            return dict(item)
        if method == "PATCH" and path.startswith("/api/organization-roles/"):
            item = next(value for value in self.roles if path.endswith(value["id"]))
            item.update(payload)
            return dict(item)
        if method == "PUT" and path.endswith("/resource-scopes"):
            role_id = path.split("/")[3]
            self.role_scope_ids[role_id] = list(payload["scopeIds"])
            return None
        if method == "POST" and path == "/api/organizations":
            item = {"id": self._id("organization"), **payload}
            self.organizations.append(item)
            return dict(item)
        if method == "PATCH" and path.startswith("/api/organizations/"):
            self.organizations[0].update(payload)
            return dict(self.organizations[0])
        if method == "POST" and path == "/api/applications":
            item = {"id": self._id("application"), **payload}
            self.applications.append(item)
            return dict(item)
        if method == "PATCH" and path.startswith("/api/applications/"):
            item = next(value for value in self.applications if path.endswith(value["id"]))
            item.update(payload)
            return dict(item)
        if method == "POST" and path.startswith("/api/organizations/") and path.endswith("/applications"):
            for application_id in payload["applicationIds"]:
                application = next(value for value in self.applications if value["id"] == application_id)
                if not any(value["id"] == application_id for value in self.organization_applications):
                    self.organization_applications.append(dict(application))
            return payload
        if method == "PUT" and "/applications/" in path and path.endswith("/roles"):
            application_id = path.split("/")[5]
            self.organization_application_roles[application_id] = list(payload["organizationRoleIds"])
            return None
        if method == "PUT" and path.startswith("/api/configs/jwt-customizer/"):
            self.customizers[path.rsplit("/", 1)[-1]] = payload
            return payload
        raise AssertionError((method, path, payload))


class LogtoBootstrapTests(unittest.TestCase):
    def manifest(self):
        return json.loads((support.ROOT / "infra" / "logto" / "manifest.json").read_text())

    def test_manifest_reconciliation_is_idempotent_and_rotates_rsa_once(self):
        manifest = self.manifest()
        customizer = (support.ROOT / "infra" / "logto" / "custom-access-token.js").read_text()
        bootstrap.validate_manifest(manifest)
        client = FakeLogtoClient()
        first = bootstrap.reconcile(client, manifest, customizer)
        counts = tuple(map(len, (client.resources, client.scopes, client.roles, client.organizations, client.applications)))
        second = bootstrap.reconcile(client, manifest, customizer)
        self.assertEqual(
            counts,
            tuple(map(len, (client.resources, client.scopes, client.roles, client.organizations, client.applications))),
        )
        self.assertEqual(counts[0], 2)
        self.assertEqual(counts[2], 7)
        self.assertEqual(counts[4], 3)
        self.assertEqual(sum(path.endswith("private-keys/rotate") for _, path, _ in client.calls), 1)
        self.assertEqual(first["application_id"], second["application_id"])
        self.assertEqual(first["control_application_id"], second["control_application_id"])
        self.assertEqual(first["organization_id"], second["organization_id"])
        self.assertEqual(first["signing_key_algorithm"], "RSA")
        self.assertEqual(first["deployment_application_id"], second["deployment_application_id"])
        self.assertEqual(set(client.customizers), {"access-token", "client-credentials"})
        self.assertTrue(client.customizers["access-token"]["blockIssuanceOnError"])
        self.assertEqual(len(client.organization_applications), 1)
        self.assertEqual(set(first["audiences"]), {"local_api", "control_api"})
        self.assertNotIn("offline_access", first["application_scopes"]["local_dashboard"])
        self.assertTrue(first["refresh_tokens"]["session_bound"])

        for application in client.applications[:2]:
            metadata = application["customClientMetadata"]
            self.assertTrue(metadata["alwaysIssueRefreshToken"])
            self.assertTrue(metadata["rotateRefreshToken"])
            binding = application["customData"]["hybrid_ndr_binding"]
            self.assertEqual(binding["organization_id"], first["organization_id"])
        self.assertNotIn("secret", json.dumps(first).lower())

    def test_manifest_rejects_unknown_role_permissions_and_missing_spec_permission(self):
        manifest = self.manifest()
        manifest["organization_roles"]["analyst"]["resource_scopes"]["local_api"].append("shell:execute")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_manifest(manifest)

        manifest = self.manifest()
        del manifest["api_resources"]["local_api"]["scopes"]["evidence:export"]
        for role in manifest["organization_roles"].values():
            role["resource_scopes"]["local_api"] = [
                scope for scope in role["resource_scopes"]["local_api"] if scope != "evidence:export"
            ]
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_manifest(manifest)

    def test_environment_rendering_uses_explicit_https_browser_origins(self):
        rendered = bootstrap.render_manifest(self.manifest(), {
            "DASHBOARD_PUBLIC_ORIGIN": "https://ndr.customer.example",
            "CLOUD_PORTAL_PUBLIC_ORIGIN": "https://console.vendor.example",
            "TENANT_ID": "tenant-customer",
            "DEPLOYMENT_ID": "deployment-site-a",
        })
        bootstrap.validate_manifest(rendered)
        dashboard = rendered["applications"]["local_dashboard"]
        portal = rendered["applications"]["cloud_portal"]
        self.assertEqual(dashboard["redirect_uris"], ["https://ndr.customer.example/callback"])
        self.assertEqual(dashboard["cors_allowed_origins"], ["https://ndr.customer.example"])
        self.assertEqual(portal["post_logout_redirect_uris"], ["https://console.vendor.example"])
        self.assertEqual(rendered["organization"]["tenant_id"], "tenant-customer")
        self.assertEqual(rendered["organization"]["deployment_ids"], ["deployment-site-a"])

        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.render_manifest(self.manifest(), {"DASHBOARD_PUBLIC_ORIGIN": "http://192.168.1.50"})

    def test_local_management_seed_keeps_secret_off_process_arguments_and_cleans_up(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            compose = Path(temporary) / "compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            seeder = bootstrap.LocalManagementSeeder(compose, runner=run)
            secret = "A" * 43
            seeder.seed(secret)
            seeder.remove()

        self.assertEqual(len(calls), 2)
        self.assertNotIn(secret, " ".join(calls[0][0]))
        self.assertIn(secret, calls[0][1]["input"])
        self.assertNotIn(secret, calls[1][1]["input"])
        self.assertIn("15 minutes", calls[0][1]["input"])
        self.assertIn("hybridNdrBootstrap", calls[1][1]["input"])


if __name__ == "__main__":
    unittest.main()
