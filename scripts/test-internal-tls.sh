#!/usr/bin/env bash
set -euo pipefail
# Live proof that the internal data-plane hops are TLS-encrypted and verified.
#
# Brings up the customer profile with the internal-TLS overlay (PostgreSQL SSL,
# ClickHouse HTTPS, MinIO TLS), then verifies the product flow still works over
# the encrypted internal hops and that plaintext credential listeners are gone.
#
# Usage:
#   bash scripts/test-internal-tls.sh
#
# The script is safe to re-run: it generates fresh internal certs and recreates
# the affected services. Volumes persist across runs.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export HYBRID_NDR_INTERNAL_TLS_DIR="${HYBRID_NDR_INTERNAL_TLS_DIR:-$repo_root/.runtime/internal-tls}"
export HYBRID_NDR_INTERNAL_TLS_DIR="${HYBRID_NDR_INTERNAL_TLS_DIR#./}"
[[ "$HYBRID_NDR_INTERNAL_TLS_DIR" == /* ]] || HYBRID_NDR_INTERNAL_TLS_DIR="$repo_root/$HYBRID_NDR_INTERNAL_TLS_DIR"
env_file=${ENV_FILE:-infra/compose/.env}
export HYBRID_NDR_INTERNAL_TLS_GID="${HYBRID_NDR_INTERNAL_TLS_GID:-$(id -g)}"
compose=(docker compose -f infra/compose/docker-compose.yml --env-file "$env_file" --profile customer)
overlay=(docker compose -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.internal-tls.yml --env-file "$env_file" --profile customer)
if [[ -n "${COMPOSE_TEST_OVERRIDE:-}" ]]; then
  compose+=(-f "$COMPOSE_TEST_OVERRIDE")
  overlay+=(-f "$COMPOSE_TEST_OVERRIDE")
fi
if [[ "${RESPONSE_ACCEPTANCE:-0}" == 1 ]]; then
  export RESPONSE_CONFIG_DIR="$repo_root/.runtime/response-acceptance-config"
  export RESPONSE_SECRETS_DIR="$repo_root/.runtime/response-acceptance-secrets"
  mkdir -p "$RESPONSE_SECRETS_DIR" "$RESPONSE_CONFIG_DIR"
  "${compose[@]}" config --format json | python3 -c '
import json,sys
env=json.load(sys.stdin)["services"]["local-api"]["environment"]
print(json.dumps(dict(schema_version=1,enabled=False,automatic_proposals=False,
    tenant_id=env["TENANT_ID"],deployment_id=env["DEPLOYMENT_ID"],integrations=[])))
' > "$RESPONSE_CONFIG_DIR/response.json"
  overlay+=(-f infra/compose/docker-compose.response.yml --profile response)
fi

step() { printf '\n== %s ==\n' "$*"; }

step "provisioning the internal data-plane CA and server certificates"
bash infra/internal-tls/provision-internal-certs.sh "$HYBRID_NDR_INTERNAL_TLS_DIR"

step "bringing up the customer stack with the internal-TLS overlay"
"${overlay[@]}" --profile customer up -d --build >/dev/null

step "waiting for required services"
required=(postgres clickhouse minio suricata zeek vector detection-engine local-api operations-agent prometheus grafana blackbox-exporter)
if [[ "${RESPONSE_ACCEPTANCE:-0}" == 1 ]]; then required+=(response-worker); fi
deadline=$((SECONDS + 240))
for service in "${required[@]}"; do
  while :; do
    container_id=$("${overlay[@]}" ps -q "$service")
    [[ -n "$container_id" ]] || { echo "missing container: $service" >&2; exit 1; }
    state=$(docker inspect --format '{{.State.Status}}' "$container_id")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")
    if [[ "$state" == running && ("$health" == healthy || "$health" == none) ]]; then
      break
    fi
    if (( SECONDS >= deadline )); then
      "${overlay[@]}" logs --no-color --tail=60 "$service" >&2
      echo "service did not become ready: $service ($state/$health)" >&2
      exit 1
    fi
    sleep 3
  done
done

step "verifying the monitoring probes use trusted TLS endpoints"
"${overlay[@]}" exec -T local-api python3 - <<'PY'
from urllib.parse import urlencode
from urllib.request import urlopen

def probe(target, module):
    url = "http://blackbox-exporter:9115/probe?" + urlencode({"target": target, "module": module})
    with urlopen(url, timeout=10) as response:
        lines = response.read(100000).decode().splitlines()
    return next(line for line in lines if line.startswith("probe_success "))

assert probe("https://minio:9000/minio/health/ready", "http_2xx") == "probe_success 1"
assert probe("clickhouse:9440", "tcp_connect") == "probe_success 1"
assert probe("http://minio:9000/minio/health/ready", "http_2xx") == "probe_success 0"
assert probe("clickhouse:9000", "tcp_connect") == "probe_success 0"
print("MinIO HTTPS and ClickHouse native TLS probes passed; plaintext probes failed as expected")
PY

step "verifying minio-init completed the TLS bucket provisioning"
for _ in $(seq 1 30); do
  minio_init_id=$("${overlay[@]}" ps --all -q minio-init)
  state=$(docker inspect --format '{{.State.Status}}' "$minio_init_id" 2>/dev/null || echo "missing")
  [[ "$state" == exited ]] && break
  sleep 3
done
exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$minio_init_id" 2>/dev/null || echo "1")
[[ "$exit_code" == 0 ]] || { echo "minio-init did not complete successfully (exit $exit_code)" >&2; exit 1; }
echo "minio-init completed TLS bucket provisioning"

step "verifying Postgres requires verified TLS"
"${overlay[@]}" exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql "host=postgres port=5432 dbname=$POSTGRES_DB user=$POSTGRES_USER sslmode=disable" -c "SELECT 1" >/dev/null 2>&1 && { echo "plaintext Postgres connection unexpectedly succeeded" >&2; exit 1; } || echo "plaintext Postgres connection rejected (expected)"'
"${overlay[@]}" exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" PGSSLROOTCERT=/run/internal-tls/ca-cert.pem psql "host=postgres port=5432 dbname=$POSTGRES_DB user=$POSTGRES_USER sslmode=verify-full" -Atqc "SELECT 1"' >/dev/null
echo "verified-TLS Postgres connection succeeded"

step "verifying ClickHouse serves HTTPS and rejects plaintext credentials"
"${overlay[@]}" exec -T local-api python3 - <<'PY'
import socket
for port in (8123, 9000):
    with socket.socket() as connection:
        connection.settimeout(3)
        assert connection.connect_ex(("clickhouse", port)) != 0, (port, "plaintext listener active")
PY
"${overlay[@]}" exec -T local-api python3 -c "import ssl, urllib.request; context = ssl.create_default_context(cafile='/run/internal-tls/ca-cert.pem'); urllib.request.urlopen('https://clickhouse:8443/ping', context=context, timeout=5).read()"
echo "verified-TLS ClickHouse HTTPS succeeded"

step "verifying MinIO serves TLS"
"${overlay[@]}" exec -T minio sh -c 'curl -sf "https://127.0.0.1:9000/minio/health/ready" --cacert /run/internal-tls/CAs/ca-cert.pem -o /dev/null'
echo "verified-TLS MinIO health succeeded"

step "verifying the product flow works over the encrypted internal hops"
health_json=$("${overlay[@]}" exec -T local-api python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5).read().decode())")
python3 - "$health_json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
assert d["status"] == "healthy", d
assert d["persistence"]["profile"] == "production", d
assert d["persistence"]["ready"] is True, d
assert all(d["persistence"]["product_io"].values()), d
for name in ("metadata", "events", "evidence"):
    assert d["persistence"]["adapters"][name]["ready"], (name, d)
print("local-api reports production persistence ready over TLS")
PY

event_count=$("${overlay[@]}" exec -T clickhouse sh -c 'clickhouse-client --secure --host clickhouse --port 9440 --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM hybrid_ndr.network_events"')
[[ "$event_count" -ge 15 ]] || { echo "expected at least 15 normalized events, got $event_count" >&2; exit 1; }
echo "ClickHouse retained $event_count normalized events"

"${overlay[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.schema_migrations WHERE version=1")" = 1'
"${overlay[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts WHERE payload_json::jsonb->>\$\$detector_id\$\$=\$\$suricata-conversion-v1\$\$")" -ge 1'
echo "Postgres alert/evidence persisted over verified TLS"

step "verifying operations-agent health over encrypted hops"
"${overlay[@]}" exec -T operations-agent sh -c 'python3 -c "import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:9108/healthz\", timeout=3)"' >/dev/null
echo "operations-agent healthy"

"${overlay[@]}" run --rm --no-deps --entrypoint python3 \
  -e RUN_POSTGRES_DETECTION_TESTS=1 -e RUN_PRODUCTION_PERSISTENCE_TESTS=1 \
  -v "$repo_root/tests:/app/tests:ro" local-api \
  -m unittest discover -s tests/integration -p test_production_persistence.py
if [[ "${RESPONSE_ACCEPTANCE:-0}" == 1 ]]; then
  "${overlay[@]}" exec -T response-worker python3 -c "import os,json; d=json.load(open('/tmp/response-worker-health.json')); assert os.geteuid()!=0; assert d['healthy']; print('unprivileged response worker healthy over verified persistence TLS')"
  check_worker() {
    "${overlay[@]}" run --rm --no-deps --entrypoint python3 \
      -e RUN_RESPONSE_WORKER_TESTS=1 -e "RESPONSE_EXPECT_HEALTHY=$1" \
      -e "RESPONSE_EXPECT_AUTOMATIC=${2:-0}" \
      -v "$repo_root/tests:/app/tests:ro" local-api \
      -m unittest discover -s tests/integration -p test_response_worker.py
  }
  check_worker 1
  # Replacing the host file must be visible through the directory bind mount.
  # Execution stays disabled; this toggles only the inert scheduler flag.
  for automatic in 1 0; do
    python3 - "$RESPONSE_CONFIG_DIR/response.json" "$automatic" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1])
config=json.loads(path.read_text())
assert config["enabled"] is False
config["automatic_proposals"]=sys.argv[2] == "1"
temporary=path.with_suffix(".tmp")
temporary.write_text(json.dumps(config))
temporary.replace(path)
PY
    check_worker 1 "$automatic"
  done
  "${overlay[@]}" stop response-worker
  check_worker 0
  "${overlay[@]}" start response-worker
  check_worker 1
  echo "response worker supervision, recovery and API readiness verified"
fi

echo
echo "internal data-plane TLS acceptance passed: all credential-bearing hops encrypted and the product flow verified"
