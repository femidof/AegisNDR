#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "packages" / "contracts-python", ROOT / "packages" / "redaction", ROOT / "packages" / "audit",
    ROOT / "packages" / "auth", ROOT / "packages" / "storage", ROOT / "packages" / "transport",
    ROOT / "packages" / "observability", ROOT / "services" / "model-gateway", ROOT / "services" / "agent-runtime",
    ROOT / "apps" / "local-api",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_local_api.__main__ import main

if __name__ == "__main__":
    main()
