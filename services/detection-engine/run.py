#!/usr/bin/env python3
"""Evaluate a JSON event fixture without any cloud dependency."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "contracts-python"))
sys.path.insert(0, str(ROOT / "services" / "detection-engine"))

from hybrid_ndr_detection import DetectionEngine  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    document = json.loads(args.fixture.read_text(encoding="utf-8"))
    events = document["events"] if isinstance(document, dict) else document
    baselines = document.get("baselines", {}) if isinstance(document, dict) else {}
    print(json.dumps([result.__dict__ for result in DetectionEngine().run(events, baselines)], indent=2, default=list))


if __name__ == "__main__":
    main()
