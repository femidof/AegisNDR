#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export PYTHONPATH="packages/contracts-python:packages/redaction:packages/audit:packages/auth:packages/storage:packages/transport:packages/observability:services/detection-engine:services/operations-agent:services/deployment-connector:services/model-gateway:services/agent-runtime:apps/local-api:apps/control-api"
export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/hybrid-ndr-pycache"
python3 -m compileall -q apps/local-api apps/control-api packages services
python3 -m unittest discover -s tests/backend -p 'test_*.py' -v
