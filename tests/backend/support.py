from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "redaction",
    ROOT / "packages" / "audit",
    ROOT / "packages" / "auth",
    ROOT / "packages" / "storage",
    ROOT / "packages" / "transport",
    ROOT / "packages" / "observability",
    ROOT / "services" / "detection-engine",
    ROOT / "services" / "operations-agent",
    ROOT / "services" / "model-gateway",
    ROOT / "services" / "deployment-connector",
    ROOT / "services" / "update-agent",
    ROOT / "services" / "agent-runtime",
    ROOT / "apps" / "local-api",
    ROOT / "apps" / "control-api",
):
    sys.path.insert(0, str(path))


def analyst_headers(tenant: str = "demo-tenant", deployment: str = "demo-deployment") -> dict[str, str]:
    return {
        "X-Tenant-ID": tenant,
        "X-Deployment-ID": deployment,
        "X-Actor-ID": "analyst-01",
        "X-Role": "analyst",
    }
