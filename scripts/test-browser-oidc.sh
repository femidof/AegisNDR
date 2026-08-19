#!/usr/bin/env bash
set -euo pipefail
# Run the joined browser OIDC acceptance journey against the composed Logto
# identity plane, the customer dashboard, and the cloud portal.
#
# Prerequisites (this script provisions them):
#   1. `docker compose ... --profile vendor up -d logto-postgres logto`
#   2. `infra/logto/bootstrap.py` reconciled the identity manifest
#   3. A browser-capable Playwright image and a Playwright node package.
#
# Usage:
#   bash scripts/test-browser-oidc.sh
#
# This script is intended to be re-run after the environment has been reset or
# upgraded. It is idempotent: bootstrap reconciliation and user/role assignment
# are skipped when already present.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export LOGTO_PUBLIC_ENDPOINT="${LOGTO_PUBLIC_ENDPOINT:-http://localhost:3011}"
export DASHBOARD_PUBLIC_ORIGIN="${DASHBOARD_PUBLIC_ORIGIN:-http://localhost:4173}"
export CLOUD_PORTAL_PUBLIC_ORIGIN="${CLOUD_PORTAL_PUBLIC_ORIGIN:-http://localhost:4180}"
export LOGTO_REDIRECT_URI="${LOGTO_REDIRECT_URI:-http://localhost:4173/callback}"
export LOGTO_POST_LOGOUT_URI="${LOGTO_POST_LOGOUT_URI:-http://localhost:4173}"
export LOGTO_CLOUD_PORTAL_REDIRECT_URI="${LOGTO_CLOUD_PORTAL_REDIRECT_URI:-http://localhost:4180/callback}"
export LOGTO_CLOUD_PORTAL_POST_LOGOUT_URI="${LOGTO_CLOUD_PORTAL_POST_LOGOUT_URI:-http://localhost:4180}"

compose=(docker compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env)

step() { printf '\n== %s ==\n' "$*"; }

step "waiting for Logto"
"${compose[@]}" --profile vendor up -d logto-postgres logto >/dev/null
for _ in $(seq 1 60); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' hybrid-ndr-logto-1 2>/dev/null || true)
  [[ "$status" == healthy ]] && break
  sleep 10
done
[[ "$status" == healthy ]] || { echo "Logto did not become healthy" >&2; exit 1; }

step "reconciling identity manifest"
python3 infra/logto/bootstrap.py \
  --management-endpoint http://127.0.0.1:3011 \
  --issuer http://localhost:3011/oidc \
  --compose-env-file infra/compose/.env.example \
  --output .data/logto-bootstrap-state.json >.data/bootstrap.log 2>&1

step "rendering dashboard/portal runtime config from bootstrap state"
python3 - <<'PY'
import json
from pathlib import Path
state = json.loads(Path(".data/logto-bootstrap-state.json").read_text())
values = {
    "LOGTO_DASHBOARD_CLIENT_ID": state["applications"]["local_dashboard"],
    "LOGTO_CLOUD_PORTAL_CLIENT_ID": state["applications"]["cloud_portal"],
    "LOGTO_ORGANIZATION_ID": state["organization_id"],
    "LOGTO_CLOUD_PORTAL_ORGANIZATION_ID": state["organization_id"],
    "AUTH_ALLOWED_ORGANIZATION_IDS": state["organization_id"],
    "CONTROL_PORTAL_AUTH_ALLOWED_ORGANIZATION_IDS": state["organization_id"],
    "LOGTO_DASHBOARD_SCOPES": " ".join(state["application_scopes"]["local_dashboard"]),
    "LOGTO_CLOUD_PORTAL_SCOPES": " ".join(state["application_scopes"]["cloud_portal"]),
}
Path(".data/runtime.env").write_text(
    "\n".join(f"{key}={value}" for key, value in values.items()) + "\n",
    encoding="ascii",
)
print("rendered runtime values for", sorted(values))
PY

step "recreating dashboard with OIDC config"
"${compose[@]}" --profile customer up -d --no-deps --force-recreate dashboard >/dev/null

step "running browser OIDC sign-in"
mkdir -p .data/browser-screens
docker run --rm --network host \
  -v "$repo_root/.data/browser-screens:/tmp/screens" \
  -v "$repo_root/scripts:/repo/scripts:ro" \
  -v /tmp/hybrid-browser-qa:/work \
  mcr.microsoft.com/playwright:v1.55.0-noble \
  sh -c 'cd /work && NODE_PATH=/work/node_modules PLAYWRIGHT_BROWSERS_PATH=/ms-playwright node /repo/scripts/browser-oidc-acceptance.cjs'

echo
echo "browser OIDC acceptance passed"
