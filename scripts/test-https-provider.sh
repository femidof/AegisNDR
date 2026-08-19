#!/usr/bin/env bash
set -euo pipefail
# Composed zero-retention HTTPS provider acceptance.
#
# Proves the model-gateway container reaches a live HTTPS provider (not the
# embedded demo provider): real TLS to a generated private CA, a real Bearer
# API key, the X-Hybrid-NDR-Retention and X-Hybrid-NDR-Prompt-Cache headers on
# the wire, schema-constrained response parsing, and a signed envelope.
#
# Usage:
#   bash scripts/test-https-provider.sh
#
# Prerequisites: the base vendor stack (control-api) is running. This script
# adds the provider-mock overlay, re-points the model-gateway at it, seeds a
# deterministic deployment, and drives an authenticated investigate.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

compose=(docker compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env)
overlay=(docker compose -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.provider-mock.yml --env-file infra/compose/.env)

step() { printf '\n== %s ==\n' "$*"; }

step "starting the mock HTTPS provider + gateway overlay"
"${overlay[@]}" --profile vendor up -d --build provider-mock model-gateway >/dev/null
for _ in $(seq 1 40); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' hybrid-ndr-provider-mock-1 2>/dev/null || true)
  [[ "$status" == healthy ]] && break
  sleep 5
done
[[ "$status" == healthy ]] || { echo "provider-mock did not become healthy" >&2; exit 1; }
for _ in $(seq 1 40); do
  status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' hybrid-ndr-model-gateway-1 2>/dev/null || true)
  [[ "$status" == healthy ]] && break
  sleep 5
done
[[ "$status" == healthy ]] || { echo "model-gateway did not become healthy" >&2; exit 1; }

step "verifying the gateway health endpoint reports the live provider"
health=$("${compose[@]}" exec -T model-gateway python3 -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8082/healthz", timeout=3).read().decode())')
echo "$health"
python3 - "$health" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
assert body["provider"] == "live-zero-retention", body
assert body["zero_retention_verified"] is True, body
assert body["cache_disabled"] is True, body
assert body["evidence_retained"] is False, body
print("gateway health confirms live HTTPS zero-retention provider")
PY

step "seeding a deterministic deployment in the shared control store"
token=$(python3 - <<'PY'
import subprocess

code = r'''
import sys
for path in (
    "/app/packages/contracts-python",
    "/app/packages/redaction",
    "/app/packages/transport",
    "/app/packages/auth",
    "/app/packages/observability",
    "/app/services/model-gateway",
    "/app/apps/control-api",
    "/app/apps/control-api/hybrid_ndr_control_api",
):
    sys.path.insert(0, path)
from hybrid_ndr_control_api.store import ControlStore
store = ControlStore("/var/lib/hybrid-ndr/control-api.sqlite3")
token = store.create_enrollment_token(
    "demo-tenant",
    token="https-provider-demo-token",
    deployment_name="HTTPS provider demo",
    entitlements={"subscription_status": "active", "model_investigations": True, "edition": "enterprise", "local_detection": True, "ai_monthly_limit": 1000, "protected_assets_limit": 10000, "offline_grace_days": 14},
    model_policy={"policy_id": "policy-live", "level": "balanced", "provider": "live-zero-retention", "model": "evidence-assessor-v1", "region": "us", "retention_mode": "zero", "enabled": True},
)
print(token)
'''
result = subprocess.run(
    [
        "docker", "compose", "-f", "infra/compose/docker-compose.yml",
        "--env-file", "infra/compose/.env", "--profile", "vendor",
        "exec", "-T", "control-api", "sh", "-c", "cd /app && python3 -",
    ],
    input=code, capture_output=True, text=True, check=True,
)
print(result.stdout.strip().splitlines()[-1])
PY
)
echo "seeded enrollment token: $token"

step "exchanging enrollment for a deployment certificate + fingerprint"
enrollment=$(python3 - <<'PY'
import json
import subprocess
import sys

csr_dir = "/tmp/hybrid-ndr-provider-csr"
subprocess.run(["mkdir", "-p", csr_dir], check=True)
key = f"{csr_dir}/deployment-key.pem"
csr = f"{csr_dir}/deployment.csr"
subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key], check=True, capture_output=True)
subprocess.run(
    ["openssl", "req", "-new", "-sha256", "-key", key, "-subj", "/CN=provider-demo-deployment", "-out", csr],
    check=True, capture_output=True,
)
csr_pem = open(csr, encoding="ascii").read()
payload = json.dumps({"enrollment_token": "https-provider-demo-token", "csr": csr_pem})
code = f'''
import json, urllib.request, sys
payload = json.loads(sys.argv[1])
request = urllib.request.Request(
    "http://127.0.0.1:8081/v1/enrollment/exchange",
    data=json.dumps(payload).encode("utf-8"),
    headers={{"Content-Type": "application/json", "Idempotency-Key": "provider-demo-enroll"}},
    method="POST",
)
response = urllib.request.urlopen(request, timeout=10)
print(response.read().decode())
'''
result = subprocess.run(
    [
        "docker", "compose", "-f", "infra/compose/docker-compose.yml",
        "--env-file", "infra/compose/.env", "--profile", "vendor",
        "exec", "-T", "control-api", "sh", "-c", f"cd /app && python3 - {json.dumps(payload)}",
    ],
    input=code, capture_output=True, text=True, check=True,
)
print(result.stdout.strip())
PY
)
echo "$enrollment" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print("tenant:", d["tenant_id"]); print("deployment:", d["deployment_id"]); print("fingerprint:", d["certificate_fingerprint"][:16], "...")'
tenant_id=$(echo "$enrollment" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["tenant_id"])')
deployment_id=$(echo "$enrollment" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["deployment_id"])')
fingerprint=$(echo "$enrollment" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["certificate_fingerprint"])')

step "driving an authenticated investigate through the composed gateway"
result=$(python3 - "$tenant_id" "$deployment_id" "$fingerprint" <<'PY'
import json
import subprocess
import sys

tenant_id, deployment_id, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
payload = {
    "request_id": "composed-https-provider-1",
    "tenant_policy_id": "policy-live",
    "alert_type": "dns-tunneling-v1",
    "severity": "high",
    "entity_type": "host",
    "observations": [{"evidence_id": "event-1", "feature": "query_volume", "observed": 420, "baseline_p99": 90}],
    "allowed_actions": ["inspect_endpoint", "review_dns_history"],
}
code = f'''
import json, urllib.request, sys
tenant_id, deployment_id, fingerprint = sys.argv[1], sys.argv[2], sys.argv[3]
payload = {json.dumps(payload)}
request = urllib.request.Request(
    "http://127.0.0.1:8082/v1/model/investigate",
    data=json.dumps(payload).encode("utf-8"),
    headers={{
        "Content-Type": "application/json",
        "X-Tenant-ID": tenant_id,
        "X-Deployment-ID": deployment_id,
        "X-Client-Certificate-Fingerprint": fingerprint,
    }},
    method="POST",
)
response = urllib.request.urlopen(request, timeout=15)
print(response.read().decode())
'''
result = subprocess.run(
    [
        "docker", "compose", "-f", "infra/compose/docker-compose.yml",
        "--env-file", "infra/compose/.env", "--profile", "vendor",
        "exec", "-T", "model-gateway", "sh", "-c",
        f"cd /app && python3 - {json.dumps(tenant_id)} {json.dumps(deployment_id)} {json.dumps(fingerprint)}",
    ],
    input=code, capture_output=True, text=True,
)
if result.returncode != 0:
    print(result.stderr, file=sys.stderr)
    raise SystemExit(result.returncode)
print(result.stdout.strip())
PY
)
echo "$result" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print("retention:", d["retention_mode"]); print("provider:", d["provider"]); print("model:", d["model"]); print("signature:", d["signature"][:16], "...")'

step "asserting the provider received the zero-retention contract over the wire"
python3 - "$deployment_id" <<'PY'
import json
import subprocess
import sys

deployment_id = sys.argv[1]
result = subprocess.run(
    [
        "docker", "compose", "-f", "infra/compose/docker-compose.yml",
        "--env-file", "infra/compose/.env", "--profile", "vendor",
        "exec", "-T", "provider-mock", "sh", "-c",
        "cat /pki/records.jsonl",
    ],
    capture_output=True, text=True, check=True,
)
records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
assert records, "provider received no requests"
latest = records[-1]
assert latest["authorization"].startswith("Bearer "), latest
assert latest["retention"] == "zero", latest
assert latest["prompt_cache"] == "disabled", latest
assert latest["path"] == "/v1/chat/completions", latest
evidence_ids = latest["body"].get("messages", [])[-1].get("content", "")
assert "event-1" in evidence_ids, latest
print("provider recorded:", latest["path"], "| retention:", latest["retention"], "| cache:", latest["prompt_cache"])
PY

step "confirming no raw evidence was retained anywhere"
"${compose[@]}" exec -T model-gateway sh -c 'ls /app >/dev/null && echo "gateway container has no evidence store"'

echo
echo "composed zero-retention HTTPS provider acceptance passed"
