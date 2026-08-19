#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd "$script_dir/.." && pwd)

# The update agent itself is part of the signed release. Preserve only the
# caller's ordinary process environment here; the agent uses a strict allowlist
# when it starts an installer so credentials cannot flow into child commands.
export PYTHONPATH="$project_dir/services/update-agent:$project_dir/packages/audit:$project_dir/packages/observability${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m hybrid_ndr_update "$@"
