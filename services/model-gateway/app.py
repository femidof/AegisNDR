#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "packages" / "contracts-python",
    ROOT / "packages" / "redaction",
    ROOT / "packages" / "transport",
    ROOT / "packages" / "auth",
    ROOT / "packages" / "observability",
    ROOT / "services" / "model-gateway",
    ROOT / "apps" / "control-api",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_gateway.__main__ import main

if __name__ == "__main__":
    main()
