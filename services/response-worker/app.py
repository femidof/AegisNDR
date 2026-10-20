#!/usr/bin/env python3
"""Supervised customer-local response worker. No privileged host network access."""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for dependency in ("packages/contracts-python", "packages/audit", "packages/storage", "packages/transport",
                   "packages/auth", "packages/redaction", "packages/observability", "services/model-gateway",
                   "services/agent-runtime"):
    sys.path.insert(0, str(ROOT / dependency))

from hybrid_ndr_agent.response import now
from hybrid_ndr_agent.response_adapters import configured_workflow
from hybrid_ndr_agent.response_worker import ResponseWorker
from hybrid_ndr_storage import PersistenceSettings, build_store


def main():
    filename = os.environ.get("RESPONSE_CONFIG_FILE", "").strip()
    if not filename:
        raise SystemExit("RESPONSE_CONFIG_FILE is required")
    tenant, deployment = os.environ["TENANT_ID"], os.environ["DEPLOYMENT_ID"]
    settings = PersistenceSettings.from_env()
    if settings.profile != "production":
        raise SystemExit("supervised response worker requires production PostgreSQL persistence")
    store = build_store(settings)
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_args: stop.set())
    health_path = Path(os.environ.get("RESPONSE_HEALTH_FILE", "/tmp/response-worker-health.json"))
    workflow = None
    healthy = False

    def heartbeat():
        if workflow is not None:
            record = {"updated_at": now().isoformat(), "healthy": healthy,
                      "configuration_revision": workflow.configuration_revision}
            with workflow.repository.transaction(tenant, deployment) as tx:
                tx.put("worker", "current", record)
            temporary = health_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(record), encoding="utf-8")
            temporary.replace(health_path)

    try:
        while not stop.is_set():
            try:
                candidate = configured_workflow(store)
                workflow, healthy = candidate, True
                heartbeat()
                if workflow.automatic_proposals:
                    workflow.schedule(tenant, deployment)
                ResponseWorker(workflow, on_progress=heartbeat).run_once(tenant, deployment)
                heartbeat()
            except Exception:
                # Do not log provider responses, token paths, credentials or evidence.
                print(json.dumps({"event": "response.worker.degraded"}), flush=True)
                healthy = False
                if workflow is not None:
                    workflow.execution_enabled = False
                    try:
                        heartbeat()
                        ResponseWorker(workflow, on_progress=heartbeat).run_once(tenant, deployment)
                    except Exception:
                        pass
            stop.wait(5)
    finally:
        healthy = False
        try:
            if workflow is not None:
                heartbeat()
        finally:
            store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
