#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
for package in (ROOT / "packages/audit", ROOT / "packages/observability", ROOT / "services/update-agent"):
    sys.path.insert(0, str(package))

from hybrid_ndr_update.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
