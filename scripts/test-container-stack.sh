#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repo_root/infra/compose/docker-compose.yml"
env_file=${ENV_FILE:-$repo_root/infra/compose/.env.example}
compose=(docker compose -f "$compose_file" --env-file "$env_file" --profile customer)

cd "$repo_root"

"${compose[@]}" config --quiet
"${compose[@]}" up -d --build

required=(postgres clickhouse minio suricata zeek vector detection-engine deployment-connector operations-agent local-api dashboard prometheus grafana)
deadline=$((SECONDS + 180))
for service in "${required[@]}"; do
  while :; do
    container_id=$("${compose[@]}" ps -q "$service")
    [[ -n "$container_id" ]] || { echo "missing container: $service" >&2; exit 1; }
    state=$(docker inspect --format '{{.State.Status}}' "$container_id")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id")
    if [[ "$state" == running && ("$health" == healthy || "$health" == none) ]]; then
      break
    fi
    if (( SECONDS >= deadline )); then
      "${compose[@]}" logs --no-color --tail=100 "$service" >&2
      echo "service did not become ready: $service ($state/$health)" >&2
      exit 1
    fi
    sleep 2
  done
done

health_json=$(curl -fsS http://127.0.0.1:8080/healthz)
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="healthy"; assert d["persistence"]["profile"]=="production"; assert d["persistence"]["ready"] is True; assert all(d["persistence"]["product_io"].values())' <<<"$health_json"
curl -fsS http://127.0.0.1:4173/ >/dev/null
# Grafana is not published on the host in the base Compose; verify through the
# container that its provisioning (database) is healthy.
"${compose[@]}" exec -T grafana sh -c 'wget -q -O - http://127.0.0.1:3000/api/health | grep -q "\"database\": \"ok\""'

# Read the ClickHouse credentials from the rendered container environment so
# this gate does not echo them or depend on shell-sourcing an operator file.
event_count=$("${compose[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM hybrid_ndr.network_events"')
[[ "$event_count" -ge 15 ]] || { echo "expected at least 15 normalized events, got $event_count" >&2; exit 1; }
tenant_id=$("${compose[@]}" exec -T local-api printenv AUTH_TENANT_ID)
deployment_id=$("${compose[@]}" exec -T local-api printenv AUTH_DEPLOYMENT_ID)
fixture_result=$("${compose[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --param_tenant="$1" --param_deployment="$2" --query "SELECT count(), uniqExact(source) FROM hybrid_ndr.network_events WHERE tenant_id={tenant:UUID} AND deployment_id={deployment:UUID}"' -- "$tenant_id" "$deployment_id")
read -r fixture_count fixture_sources <<<"$fixture_result"
[[ "$fixture_count" -ge 15 && "$fixture_sources" == 2 ]] || { echo "expected the configured tenant/deployment to contain both sensor sources and at least 15 events, got $fixture_result" >&2; exit 1; }

"${compose[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.schema_migrations WHERE version=1")" = 1'
"${compose[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts WHERE payload_json->>\$\$detector_id\$\$=\$\$suricata-conversion-v1\$\$")" -ge 1'
"${compose[@]}" exec -T postgres sh -c 'test "$(psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alert_evidence WHERE source=\$\$suricata\$\$")" -ge 1'

echo "customer container acceptance passed: $event_count retained events; sensor detection alert/evidence persisted; all required services ready"
