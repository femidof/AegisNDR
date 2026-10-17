#!/usr/bin/env bash
set -euo pipefail

# Survivability acceptance: prove the customer-resident stack keeps capturing,
# ingesting, detecting, and retaining evidence while vendor services are
# unavailable.
#
# The deterministic sensor PCAP is replayed once; this gate then:
#   1. stops the outbound deployment connector (control plane unreachable),
#   2. waits through several detection cycles,
#   3. proves the detection loop still advances its checkpoint,
#   4. proves ingested events, alerts, investigations, and cases are retained,
#   5. proves the local API and dashboard remain healthy.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/infra/compose/docker-compose.yml"
env_file=${ENV_FILE:-$repo_root/infra/compose/.env.example}
compose=(docker compose -f "$compose_file" --env-file "$env_file" --profile customer)
if [[ -n "${COMPOSE_TEST_OVERRIDE:-}" ]]; then
  compose+=(-f "$COMPOSE_TEST_OVERRIDE")
fi

cd "$repo_root"

"${compose[@]}" config --quiet
"${compose[@]}" run --rm --no-deps vector validate --skip-healthchecks /etc/vector/vector.yaml
if ! "${compose[@]}" up -d --build; then
  "${compose[@]}" ps --all >&2
  "${compose[@]}" logs --no-color --tail=60 suricata zeek vector operations-agent detection-engine >&2
  exit 1
fi

required=(postgres clickhouse minio suricata zeek vector detection-engine operations-agent local-api dashboard prometheus grafana deployment-connector)
deadline=$((SECONDS + 240))
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

# Exercise concurrent alert claims against PostgreSQL, including FK enforcement.
"${compose[@]}" run --rm --no-deps --entrypoint python3 \
  -e RUN_POSTGRES_DETECTION_TESTS=1 -v "$repo_root/tests:/app/tests:ro" local-api \
  -m unittest discover -s tests/integration -p test_production_persistence.py

# Prove the expected fixture records arrived from BOTH sensors, rather than
# relying on a total that changes with diagnostic/stats events in sensor images.
fixture_query="SELECT
  countIf(source = 'suricata' AND signature = 'HYBRID NDR deterministic HTTP sensor acceptance') >= 1
  AND countIf(source = 'suricata' AND signature = 'HYBRID NDR deterministic DNS sensor acceptance') >= 1
  AND countIf(source = 'zeek' AND event_type = 'network.connection') >= 2
  AND countIf(source = 'zeek' AND event_type = 'network.dns') >= 1
  AND countIf(source = 'zeek' AND event_type = 'network.http') >= 1
  FROM hybrid_ndr.network_events"
deadline=$((SECONDS + 90))
while :; do
  fixture_ready=$("${compose[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "$1"' fixture-check "$fixture_query")
  alerts_before=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts"')
  if [[ "$fixture_ready" == 1 && "$alerts_before" -ge 1 ]]; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "baseline fixture incomplete: expected_records=$fixture_ready alerts=$alerts_before" >&2
    "${compose[@]}" logs --no-color --tail=60 vector detection-engine >&2
    exit 1
  fi
  sleep 2
done
events_before=$("${compose[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM hybrid_ndr.network_events"')
alerts_before=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts"')
checkpoint_before=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT completed_at FROM local_state.detection_checkpoints WHERE job_name=\$\$fast-10s\$\$"')
investigations_before=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.investigations"')
cases_before=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.cases"')
echo "baseline: events=$events_before alerts=$alerts_before investigations=$investigations_before cases=$cases_before"

# Pull the plug on the vendor control plane. The outbound connector is the
# only customer-profile service that talks to the vendor.
"${compose[@]}" stop deployment-connector
echo "deployment-connector stopped (control plane unavailable)"

# Let the detection loop run several fast-10s cycles while offline.
sleep 30

checkpoint_after=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT completed_at FROM local_state.detection_checkpoints WHERE job_name=\$\$fast-10s\$\$"')
[[ -n "$checkpoint_before" && -n "$checkpoint_after" && "$checkpoint_after" > "$checkpoint_before" ]] || {
  echo "detection checkpoint did not advance while offline ($checkpoint_before -> $checkpoint_after)" >&2
  exit 1
}
echo "detection checkpoint advanced while offline: $checkpoint_before -> $checkpoint_after"

events_after=$("${compose[@]}" exec -T clickhouse sh -c 'clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "SELECT count() FROM hybrid_ndr.network_events"')
alerts_after=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.alerts"')
investigations_after=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.investigations"')
cases_after=$("${compose[@]}" exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT count(*) FROM local_state.cases"')
[[ "$events_after" -ge "$events_before" && "$alerts_after" -ge "$alerts_before" \
   && "$investigations_after" -ge "$investigations_before" && "$cases_after" -ge "$cases_before" ]] || {
  echo "evidence was lost while offline (events $events_before->$events_after, alerts $alerts_before->$alerts_after)" >&2
  exit 1
}
echo "evidence retained while offline: events=$events_after alerts=$alerts_after investigations=$investigations_after cases=$cases_after"

# The customer-resident surfaces stay healthy without the control plane.
health_json=$(curl -fsS http://127.0.0.1:8080/healthz)
python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="healthy"; assert d["model_dependency_required"] is False' <<<"$health_json"
curl -fsS http://127.0.0.1:4173/ >/dev/null
dashboard_state=$(docker inspect --format '{{.State.Status}}' "$("${compose[@]}" ps -q dashboard)")
[[ "$dashboard_state" == running ]] || { echo "dashboard is not running while offline" >&2; exit 1; }

echo "offline resilience acceptance passed: local capture, ingestion, detection, retention, and dashboards survive control-plane loss"
