#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"

bash -n installer/*.sh installer/lib/*.sh scripts/build-offline-bundle.sh scripts/verify-offline-bundle.sh
python3 -m unittest discover -s tests/installer -p 'test_*.py' -v
