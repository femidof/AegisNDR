#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "packages" / "transport",
    ROOT / "services" / "deployment-connector",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_connector.__main__ import main

if __name__ == "__main__":
    main()
