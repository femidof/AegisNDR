#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

project_dir=$(cd "$script_dir/.." && pwd)
compose_file=""
https_compose_file=""
release_compose_file=""
config_dir=${HYBRID_NDR_CONFIG_DIR:-/etc/hybrid-ndr}
state_dir=${HYBRID_NDR_STATE_DIR:-/var/lib/hybrid-ndr}
project_name=${HYBRID_NDR_COMPOSE_PROJECT:-hybrid-ndr-customer}

usage() {
  cat <<'EOF'
Usage: uninstall.sh [options]

Stops and removes only customer-profile containers and networks. Named volumes,
configuration, deployment identity, certificates, audit records, and evidence
are always preserved.

Options:
  --project-dir DIR
  --compose-file FILE
  --https-compose-file FILE
  --release-compose-file FILE
  --config-dir DIR
  --state-dir DIR
  --project-name NAME
  --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir) project_dir=${2:?}; shift 2 ;;
    --compose-file) compose_file=${2:?}; shift 2 ;;
    --https-compose-file) https_compose_file=${2:?}; shift 2 ;;
    --release-compose-file) release_compose_file=${2:?}; shift 2 ;;
    --config-dir) config_dir=${2:?}; shift 2 ;;
    --state-dir) state_dir=${2:?}; shift 2 ;;
    --project-name) project_name=${2:?}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) hybrid_ndr_die "unknown argument: $1" ;;
  esac
done

project_dir=$(hybrid_ndr_realpath_m "$project_dir")
config_dir=$(hybrid_ndr_realpath_m "$config_dir")
state_dir=$(hybrid_ndr_realpath_m "$state_dir")
[[ -n "$compose_file" ]] || compose_file="$project_dir/infra/compose/docker-compose.yml"
compose_file=$(hybrid_ndr_realpath_m "$compose_file")
[[ -n "$https_compose_file" ]] || https_compose_file="$project_dir/infra/compose/docker-compose.https.yml"
https_compose_file=$(hybrid_ndr_realpath_m "$https_compose_file")
if [[ -z "$release_compose_file" && -f "$project_dir/infra/compose/docker-compose.release.yml" ]]; then
  release_compose_file="$project_dir/infra/compose/docker-compose.release.yml"
elif [[ -n "$release_compose_file" ]]; then
  release_compose_file=$(hybrid_ndr_realpath_m "$release_compose_file")
fi
env_file="$config_dir/customer.env"

[[ -f "$compose_file" && ! -L "$compose_file" ]] || hybrid_ndr_die "Compose file is missing or is a symlink"
[[ -f "$https_compose_file" && ! -L "$https_compose_file" ]] || hybrid_ndr_die "HTTPS Compose file is missing or is a symlink"
[[ -z "$release_compose_file" ]] || hybrid_ndr_require_release_image_pins "$release_compose_file"
[[ -f "$env_file" && ! -L "$env_file" ]] || hybrid_ndr_die "customer environment file is missing"
compose=()
compose_overrides=()
[[ -z "$release_compose_file" ]] || compose_overrides+=("$release_compose_file")
compose_overrides+=("$https_compose_file")
hybrid_ndr_compose_base compose "$project_dir" "$compose_file" "$env_file" "$project_name" "${compose_overrides[@]}"
services=$(hybrid_ndr_customer_services compose)
hybrid_ndr_require_https_ingress "$services"

# Deliberately omit --volumes, --rmi, and any filesystem deletion.
"${compose[@]}" down --remove-orphans --timeout 30

hybrid_ndr_log "customer-resident services were removed"
hybrid_ndr_log "preserved named volumes, configuration at $config_dir, and customer data at $state_dir"
hybrid_ndr_log "evidence destruction requires a separate, explicitly approved retention procedure"
