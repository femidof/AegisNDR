#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose_file="$repository_root/infra/compose/docker-compose.yml"
project_name=${SENSOR_TEST_PROJECT:-hybrid-ndr-sensor-acceptance-$$}

export TENANT_ID=${TENANT_ID:-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}
export DEPLOYMENT_ID=${DEPLOYMENT_ID:-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}
export SURICATA_SENSOR_ID=${SURICATA_SENSOR_ID:-sensor-suricata-acceptance}
export ZEEK_SENSOR_ID=${ZEEK_SENSOR_ID:-sensor-zeek-acceptance}
export CLICKHOUSE_USER=${CLICKHOUSE_USER:-hybrid_ndr}
export CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:-hybrid-ndr-sensor-acceptance}
export POSTGRES_DB=${POSTGRES_DB:-hybrid_ndr}
export POSTGRES_USER=${POSTGRES_USER:-hybrid_ndr}
export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-hybrid-ndr-postgres-acceptance}
export SENSOR_CAPTURE_MODE=pcap
export SENSOR_NETWORK_MODE=none
export CAPTURE_INTERFACE=lo
export DETECTION_POLL_SECONDS=1
export DETECTION_FAST_INTERVAL_SECONDS=2
export DETECTION_HEALTH_TTL_SECONDS=15

compose() {
  docker compose --project-name "$project_name" --file "$compose_file" "$@"
}

cleanup() {
  if [ "${KEEP_SENSOR_TEST_STACK:-false}" != "true" ]; then
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

echo "Validating sensor Compose topology"
compose config --quiet

echo "Starting isolated sensor pipeline project: $project_name"
compose up --detach --wait --wait-timeout 180 detection-engine

attempt=0
result=""
while [ "$attempt" -lt 30 ]; do
  result=$(compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --query "
    SELECT
      countIf(source = 'suricata') AS suricata_events,
      countIf(source = 'zeek') AS zeek_events,
      countIf(source = 'suricata' AND event_type = 'network.alert') AS suricata_alerts,
      countIf(source = 'zeek' AND event_type = 'network.connection') AS zeek_connections,
      countIf(tenant_id = toUUID('$TENANT_ID')) AS tenant_matches,
      countIf(deployment_id = toUUID('$DEPLOYMENT_ID')) AS deployment_matches,
      (SELECT count() FROM (
        SELECT community_id
        FROM hybrid_ndr.network_events
        WHERE community_id != ''
        GROUP BY community_id
        HAVING uniqExact(source) = 2
      )) AS cross_sensor_flows
    FROM hybrid_ndr.network_events
    FORMAT TSVRaw
  ")
  set -- $result
  if [ "${1:-0}" -gt 0 ] && [ "${2:-0}" -gt 0 ] && [ "${3:-0}" -gt 0 ] && [ "${4:-0}" -gt 0 ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done

set -- $result
suricata_events=${1:-0}
zeek_events=${2:-0}
suricata_alerts=${3:-0}
zeek_connections=${4:-0}
tenant_matches=${5:-0}
deployment_matches=${6:-0}
cross_sensor_flows=${7:-0}
total_events=$((suricata_events + zeek_events))

if [ "$suricata_events" -le 0 ] || [ "$suricata_alerts" -le 0 ]; then
  echo "Suricata events or deterministic alerts did not reach ClickHouse" >&2
  compose logs --no-color suricata vector clickhouse >&2
  exit 1
fi
if [ "$zeek_events" -le 0 ] || [ "$zeek_connections" -le 0 ]; then
  echo "Zeek events or connection records did not reach ClickHouse" >&2
  compose logs --no-color zeek vector clickhouse >&2
  exit 1
fi
if [ "$tenant_matches" -ne "$total_events" ] || [ "$deployment_matches" -ne "$total_events" ]; then
  echo "At least one normalized row has the wrong tenant or deployment identifier" >&2
  exit 1
fi
if [ "$cross_sensor_flows" -le 0 ]; then
  echo "Suricata and Zeek events did not correlate on a shared Community ID" >&2
  exit 1
fi

echo "Verifying normalized sensor alert detection and PostgreSQL evidence persistence"
attempt=0
persisted=""
while [ "$attempt" -lt 30 ]; do
  persisted=$(compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F " " -c "
    SELECT
      (SELECT count(*) FROM local_state.alerts
       WHERE tenant_id = '\''$1'\'' AND deployment_id = '\''$2'\''
         AND payload_json->>'\''detector_id'\'' = '\''suricata-conversion-v1'\''),
      (SELECT count(*) FROM local_state.alert_evidence
       WHERE tenant_id = '\''$1'\'' AND deployment_id = '\''$2'\'' AND source = '\''suricata'\'')
  "' -- "$TENANT_ID" "$DEPLOYMENT_ID")
  set -- $persisted
  if [ "${1:-0}" -gt 0 ] && [ "${2:-0}" -gt 0 ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 2
done
set -- $persisted
persisted_alerts=${1:-0}
persisted_evidence=${2:-0}
if [ "$persisted_alerts" -le 0 ] || [ "$persisted_evidence" -le 0 ]; then
  echo "Detection service did not persist the sensor alert and evidence in PostgreSQL" >&2
  compose logs --no-color detection-engine postgres clickhouse vector >&2
  exit 1
fi

# The detector has only the internal customer data network. There is no cloud,
# model gateway, or outbound-control attachment in this acceptance run.
detection_container=$(compose ps -q detection-engine)
if docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$detection_container" \
  | grep -q 'outbound-control'; then
  echo "Detection service must not be attached to the cloud/outbound network" >&2
  exit 1
fi

compose exec -T vector wget -qO- http://127.0.0.1:9598/metrics \
  | grep -q 'vector_component_received_events_total'

echo "Verifying Vector checkpoint persistence across restart"
compose restart vector >/dev/null
attempt=0
while [ "$attempt" -lt 20 ]; do
  if compose exec -T vector wget -qO- http://127.0.0.1:8686/health >/dev/null 2>&1; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 1
done
sleep 3
events_after_restart=$(compose exec -T clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" \
  --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT count() FROM hybrid_ndr.network_events")
if [ "$events_after_restart" -ne "$total_events" ]; then
  echo "Vector replayed already-checkpointed files after restart: before=$total_events after=$events_after_restart" >&2
  exit 1
fi

echo "Sensor pipeline acceptance passed"
echo "  tenant_id=$TENANT_ID"
echo "  deployment_id=$DEPLOYMENT_ID"
echo "  suricata_events=$suricata_events (alerts=$suricata_alerts)"
echo "  zeek_events=$zeek_events (connections=$zeek_connections)"
echo "  cross_sensor_flows=$cross_sensor_flows"
echo "  checkpointed_events=$events_after_restart"
echo "  postgres_alerts=$persisted_alerts (evidence=$persisted_evidence)"
echo "  vector_metrics=http://vector:9598/metrics"
