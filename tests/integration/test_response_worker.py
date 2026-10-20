"""Read-only worker supervision check inside the disposable production TLS stack."""
from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/backend"))
import support
from hybrid_ndr_agent.response_adapters import configured_workflow
from hybrid_ndr_storage import PersistenceSettings, build_store


@unittest.skipUnless(os.environ.get("RUN_RESPONSE_WORKER_TESTS") == "1", "requires response TLS acceptance stack")
class ResponseWorkerAcceptanceTests(unittest.TestCase):
    def test_supervised_worker_health_matches_the_api_configuration(self):
        settings = PersistenceSettings.from_env()
        self.assertEqual(settings.profile, "production")
        self.assertTrue(settings.ca_file)
        store = build_store(settings)
        self.addCleanup(store.close)
        workflow = configured_workflow(store)
        self.assertFalse(workflow.execution_enabled)
        self.assertFalse(workflow.automatic_proposals)
        self.assertFalse(workflow.adapters)
        expected = os.environ.get("RESPONSE_EXPECT_HEALTHY", "1") == "1"
        deadline = time.monotonic() + 35
        while True:
            capabilities = workflow.capabilities(os.environ["TENANT_ID"], os.environ["DEPLOYMENT_ID"])
            if capabilities["worker"]["healthy"] == expected or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        self.assertEqual(capabilities["worker"]["healthy"], expected)
        self.assertEqual(capabilities["worker"]["configuration_revision"], workflow.configuration_revision)
