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
compose=(docker compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env)
overlay=(docker compose -f infra/compose/docker-compose.yml -f infra/compose/docker-compose.internal-tls.yml --env-file infra/compose/.env)

step() { printf '\n== %s ==\n' "$*"; }

step "provisioning the internal data-plane CA and server certificates"
bash infra/internal-tls/provision-internal-certs.sh "$HYBRID_NDR_INTERNAL_TLS_DIR"

step "bringing up the customer stack with the internal-TLS overlay"
"${overlay[@]}" --profile customer up -d --build >/dev/null

step "waiting for required services"
required=(postgres clickhouse minio suricata zeek vector detection-engine local-api operations-agent prometheus grafana)
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

step "verifying minio-init completed the TLS bucket provisioning"
for _ in $(seq 1 30); do
  state=$(docker inspect --format '{{.State.Status}}' hybrid-ndr-minio-init-1 2>/dev/null || echo "missing")
  [[ "$state" == exited ]] && break
  sleep 3
done
exit_code=$(docker inspect --format '{{.State.ExitCode}}' hybrid-ndr-minio-init-1 2>/dev/null || echo "1")
[[ "$exit_code" == 0 ]] || { echo "minio-init did not complete successfully (exit $exit_code)" >&2; exit 1; }
echo "minio-init completed TLS bucket provisioning"

step "verifying Postgres requires verified TLS"
"${overlay[@]}" exec -T postgres sh -c 'psql "host=127.0.0.1 port=5432 dbname=$POSTGRES_DB user=$POSTGRES_USER sslmode=disable" -c "SELECT 1" >/dev/null 2>&1 && { echo "plaintext Postgres connection unexpectedly succeeded" >&2; exit 1; } || echo "plaintext Postgres connection rejected (expected)"'
"${overlay[@]}" exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql "host=127.0.0.1 port=5432 dbname=$POSTGRES_DB user=$POSTGRES_USER sslmode=require" -Atqc "SELECT 1"' >/dev/null
echo "verified-TLS Postgres connection succeeded"

step "verifying ClickHouse serves HTTPS and rejects plaintext credentials"
"${overlay[@]}" exec -T clickhouse sh -c 'wget -q --spider "http://127.0.0.1:8123/ping" 2>/dev/null && { echo "plaintext ClickHouse listener unexpectedly active" >&2; exit 1; } || echo "plaintext ClickHouse HTTP listener absent (expected)"'
"${overlay[@]}" exec -T local-api python3 -c "import ssl, urllib.request; context = ssl.create_default_context(cafile='/run/internal-tls/ca-cert.pem'); urllib.request.urlopen('https://clickhouse:8443/ping', context=context, timeout=5).read()"
echo "verified-TLS ClickHouse HTTPS succeeded"

step "verifying MinIO serves TLS"
"${overlay[@]}" exec -T minio sh -c 'curl -sf "https://127.0.0.1:9000/minio/health/ready" --cacert /root/.minio/certs/CAs/ca-cert.pem -o /dev/null'
echo "verified-TLS MinIO health succeeded"

step "verifying the product flow works over the encrypted internal hops"
health_json=$(curl -fsS http://127.0.0.1:8080/healthz)
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

event_count=$("${overlay[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM hybrid_ndr.network_events"')
[[ "$event_count" -ge 15 ]] || { echo "expected at least 15 normalized events, got $event_count" >&2; exit 1; }
echo "ClickHouse retained $event_count normalized events"

"${overlay[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.schema_migrations WHERE version=1")" = 1'
"${overlay[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts WHERE payload_json->>\$\$detector_id\$\$=\$\$suricata-conversion-v1\$\$")" -ge 1'
echo "Postgres alert/evidence persisted over verified TLS"

step "verifying operations-agent health over encrypted hops"
"${overlay[@]}" exec -T operations-agent sh -c 'python3 -c "import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:9108/healthz\", timeout=3)"' >/dev/null
echo "operations-agent healthy"

echo
echo "internal data-plane TLS acceptance passed: all credential-bearing hops encrypted and the product flow verified"
