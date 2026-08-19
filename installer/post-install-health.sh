#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

project_dir=""
compose_file=""
https_compose_file=""
release_compose_file=""
env_file=""
project_name=hybrid-ndr-customer
timeout=300
interval=${HYBRID_NDR_HEALTH_INTERVAL:-5}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir) project_dir=${2:?}; shift 2 ;;
    --compose-file) compose_file=${2:?}; shift 2 ;;
    --https-compose-file) https_compose_file=${2:?}; shift 2 ;;
    --release-compose-file) release_compose_file=${2:?}; shift 2 ;;
    --env-file) env_file=${2:?}; shift 2 ;;
    --project-name) project_name=${2:?}; shift 2 ;;
    --timeout) timeout=${2:?}; shift 2 ;;
    --help|-h)
      echo "usage: $0 --project-dir DIR --compose-file FILE --env-file FILE [--https-compose-file FILE] [--release-compose-file FILE] [--project-name NAME] [--timeout SECONDS]"
      exit 0
      ;;
    *) hybrid_ndr_die "unknown argument: $1" ;;
  esac
done

[[ -d "$project_dir" && -f "$compose_file" && -f "$env_file" ]] || hybrid_ndr_die "health check paths are incomplete"
[[ -n "$https_compose_file" ]] || https_compose_file="$project_dir/infra/compose/docker-compose.https.yml"
[[ -f "$https_compose_file" && ! -L "$https_compose_file" ]] || hybrid_ndr_die "HTTPS Compose file is missing or is a symlink"
if [[ -n "$release_compose_file" ]]; then
  release_compose_file=$(hybrid_ndr_realpath_m "$release_compose_file")
  hybrid_ndr_require_release_image_pins "$release_compose_file"
fi
[[ "$timeout" =~ ^[0-9]+$ && "$interval" =~ ^[0-9]+$ ]] || hybrid_ndr_die "health timeout/interval must be numeric"

compose=()
compose_overrides=()
[[ -z "$release_compose_file" ]] || compose_overrides+=("$release_compose_file")
internal_tls_compose_file="$(dirname -- "$compose_file")/docker-compose.internal-tls.yml"
[[ -f "$internal_tls_compose_file" && ! -L "$internal_tls_compose_file" ]] || hybrid_ndr_die "internal TLS Compose overlay is missing or is a symlink"
compose_overrides+=("$internal_tls_compose_file")
compose_overrides+=("$https_compose_file")
hybrid_ndr_compose_base compose "$project_dir" "$compose_file" "$env_file" "$project_name" "${compose_overrides[@]}"
services=$(hybrid_ndr_customer_services compose)
hybrid_ndr_require_https_ingress "$services"
deadline=$((SECONDS + timeout))
pending=""

while (( SECONDS < deadline )); do
  pending=""
  while IFS= read -r service; do
    case "$service" in
      minio-init|sensor-fixture|*-init) continue ;;
    esac
    container_id=$("${compose[@]}" ps --quiet "$service" 2>/dev/null || true)
    if [[ -z "$container_id" ]]; then
      pending+=" $service(no-container)"
      continue
    fi
    container_state=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
    case "$container_state" in
      healthy|running) ;;
      *) pending+=" $service(${container_state:-unknown})" ;;
    esac
  done <<<"$services"

  if [[ -z "$pending" ]]; then
    break
  fi
  sleep "$interval"
done

if [[ -n "$pending" ]]; then
  "${compose[@]}" ps --all >&2 || true
  hybrid_ndr_die "post-install container health deadline exceeded:$pending"
fi

lan_host=$(hybrid_ndr_read_env "$env_file" CUSTOMER_LAN_HOST)
bind_address=$(hybrid_ndr_read_env "$env_file" CUSTOMER_BIND_ADDRESS)
tls_ca_file=$(hybrid_ndr_read_env "$env_file" HYBRID_NDR_TLS_CA_FILE)
[[ -n "$lan_host" && -n "$bind_address" ]] || hybrid_ndr_die "HTTPS health configuration is incomplete"
if [[ -n "$tls_ca_file" ]]; then
  [[ -f "$tls_ca_file" && ! -L "$tls_ca_file" ]] || hybrid_ndr_die "HTTPS health CA file is invalid"
fi
if [[ "$bind_address" == 0.0.0.0 ]]; then
  connect_address=127.0.0.1
else
  connect_address=$bind_address
fi

curl_tls=(--fail --silent --show-error --connect-timeout 3 --max-time 10
  --proto '=https' --tlsv1.2
  --resolve "$lan_host:443:$connect_address")
[[ -z "$tls_ca_file" ]] || curl_tls+=(--cacert "$tls_ca_file")
origin="https://$lan_host"
endpoints=("$origin/_health/api" "$origin/_health/dashboard" "$origin/grafana/api/health")
for endpoint in "${endpoints[@]}"; do
  curl "${curl_tls[@]}" "$endpoint" >/dev/null || hybrid_ndr_die "post-install HTTPS endpoint check failed: $endpoint"
done

hybrid_ndr_log "post-install HTTPS health validation passed for $origin"
