#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"

capture_interface=""
config_dir=${HYBRID_NDR_CONFIG_DIR:-/etc/hybrid-ndr}
state_dir=${HYBRID_NDR_STATE_DIR:-/var/lib/hybrid-ndr}
bind_address=${HYBRID_NDR_BIND_ADDRESS:-0.0.0.0}
skip_port_checks=0
allow_loopback=0
quiet=0
minimum_cpu=${HYBRID_NDR_MIN_CPU:-4}
minimum_memory_mb=${HYBRID_NDR_MIN_MEMORY_MB:-8192}
minimum_disk_gb=${HYBRID_NDR_MIN_DISK_GB:-20}
minimum_docker_version=${HYBRID_NDR_MIN_DOCKER_VERSION:-24.0.0}
minimum_compose_version=${HYBRID_NDR_MIN_COMPOSE_VERSION:-2.24.0}
ports=${HYBRID_NDR_REQUIRED_PORTS:-"80 443"}
sys_class_net=${HYBRID_NDR_SYS_CLASS_NET:-/sys/class/net}

usage() {
  cat <<'EOF'
Usage: preflight.sh --interface INTERFACE [options]

Options:
  --config-dir DIR         Configuration directory (default: /etc/hybrid-ndr)
  --state-dir DIR          Customer data directory (default: /var/lib/hybrid-ndr)
  --bind-address IPV4      Address used by the HTTPS ingress (default: 0.0.0.0)
  --skip-port-checks       Intended only for an upgrade of this same deployment
  --allow-loopback         Permit lo as a capture interface for local testing
  --quiet                  Print only failures
  --help                   Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) [[ $# -ge 2 ]] || hybrid_ndr_die "--interface requires a value"; capture_interface=$2; shift 2 ;;
    --config-dir) [[ $# -ge 2 ]] || hybrid_ndr_die "--config-dir requires a value"; config_dir=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || hybrid_ndr_die "--state-dir requires a value"; state_dir=$2; shift 2 ;;
    --bind-address) [[ $# -ge 2 ]] || hybrid_ndr_die "--bind-address requires a value"; bind_address=$2; shift 2 ;;
    --skip-port-checks) skip_port_checks=1; shift ;;
    --allow-loopback) allow_loopback=1; shift ;;
    --quiet) quiet=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) hybrid_ndr_die "unknown argument: $1" ;;
  esac
done

[[ -n "$capture_interface" ]] || { usage >&2; exit 2; }
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$bind_address" 2>/dev/null || hybrid_ndr_die "bind address must be a valid IPv4 address"
[[ "$(uname -s)" == Linux ]] || hybrid_ndr_die "the customer appliance installer supports Linux only"
case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) hybrid_ndr_die "unsupported CPU architecture: $(uname -m)" ;;
esac

for command_name in docker openssl curl python3 sha256sum awk sed df uname realpath install grep; do
  hybrid_ndr_require_command "$command_name"
done

version_at_least() {
  local actual=$1 required=$2 first
  first=$(printf '%s\n%s\n' "$required" "$actual" | sort -V | head -n 1)
  [[ "$first" == "$required" ]]
}

docker compose version >/dev/null 2>&1 || hybrid_ndr_die "Docker Compose v2 is required"
docker info >/dev/null 2>&1 || hybrid_ndr_die "the Docker daemon is unavailable to the current user"
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
compose_version=$(docker compose version --short 2>/dev/null)
version_at_least "$docker_version" "$minimum_docker_version" || hybrid_ndr_die "Docker $minimum_docker_version or newer is required (found $docker_version)"
version_at_least "$compose_version" "$minimum_compose_version" || hybrid_ndr_die "Docker Compose $minimum_compose_version or newer is required (found $compose_version)"

[[ "$capture_interface" =~ ^[A-Za-z0-9_.:-]{1,64}$ ]] || hybrid_ndr_die "capture interface contains invalid characters"
[[ -d "$sys_class_net/$capture_interface" ]] || hybrid_ndr_die "capture interface does not exist: $capture_interface"
if [[ "$capture_interface" == lo && "$allow_loopback" != 1 ]]; then
  hybrid_ndr_die "the loopback interface is not accepted for network capture; use --allow-loopback only for testing"
fi
if [[ -r "$sys_class_net/$capture_interface/operstate" ]]; then
  interface_state=$(<"$sys_class_net/$capture_interface/operstate")
  case "$interface_state" in
    up|unknown) ;;
    *) hybrid_ndr_die "capture interface is not up: $capture_interface ($interface_state)" ;;
  esac
fi

cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
[[ "$cpu_count" =~ ^[0-9]+$ ]] || hybrid_ndr_die "could not determine available CPU count"
(( cpu_count >= minimum_cpu )) || hybrid_ndr_die "at least $minimum_cpu CPU cores are required (found $cpu_count)"

memory_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[[ "$memory_kb" =~ ^[0-9]+$ ]] || hybrid_ndr_die "could not determine available memory"
memory_mb=$((memory_kb / 1024))
(( memory_mb >= minimum_memory_mb )) || hybrid_ndr_die "at least $minimum_memory_mb MiB memory is required (found $memory_mb MiB)"

disk_probe=$state_dir
while [[ ! -e "$disk_probe" && "$disk_probe" != / ]]; do
  disk_probe=$(dirname -- "$disk_probe")
done
available_kb=$(df -Pk -- "$disk_probe" | awk 'NR == 2 {print $4}')
[[ "$available_kb" =~ ^[0-9]+$ ]] || hybrid_ndr_die "could not determine free storage"
minimum_kb=$((minimum_disk_gb * 1024 * 1024))
(( available_kb >= minimum_kb )) || hybrid_ndr_die "at least $minimum_disk_gb GiB free storage is required"

if (( skip_port_checks == 0 )); then
  for port in $ports; do
    [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || hybrid_ndr_die "invalid required port: $port"
    if ! python3 - "$bind_address" "$port" <<'PY'
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    sock.bind((address, port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
    then
      hybrid_ndr_die "required ingress port is unavailable on $bind_address: $port"
    fi
  done
fi

if (( quiet == 0 )); then
  hybrid_ndr_log "preflight passed: ${cpu_count} CPU, ${memory_mb} MiB RAM, interface ${capture_interface}"
fi
