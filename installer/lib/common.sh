#!/usr/bin/env bash

# Shared installer helpers. This file is sourced; callers must enable strict mode.

hybrid_ndr_log() {
  printf '[hybrid-ndr] %s\n' "$*"
}

hybrid_ndr_warn() {
  printf '[hybrid-ndr] warning: %s\n' "$*" >&2
}

hybrid_ndr_die() {
  printf '[hybrid-ndr] error: %s\n' "$*" >&2
  exit 1
}

hybrid_ndr_require_command() {
  command -v "$1" >/dev/null 2>&1 || hybrid_ndr_die "missing required command: $1"
}

hybrid_ndr_realpath_m() {
  realpath -m -- "$1"
}

hybrid_ndr_secure_directory() {
  local directory=$1
  install -d -m 0700 -- "$directory"
  chmod 0700 -- "$directory"
}

hybrid_ndr_secure_file() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || hybrid_ndr_die "expected a regular file: $path"
  chmod 0600 -- "$path"
}

hybrid_ndr_random_hex() {
  openssl rand -hex "${1:-32}"
}

hybrid_ndr_validate_identifier() {
  local value=$1
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]
}

hybrid_ndr_validate_sha256() {
  [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]
}

hybrid_ndr_upsert_env() {
  local path=$1
  local key=$2
  local value=$3
  local directory temporary line found=0

  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || hybrid_ndr_die "invalid environment key: $key"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || hybrid_ndr_die "environment value for $key contains a newline"

  directory=$(dirname -- "$path")
  temporary=$(mktemp "$directory/.env.tmp.XXXXXX")
  chmod 0600 -- "$temporary"
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "$key="* ]]; then
      printf '%s=%s\n' "$key" "$value" >>"$temporary"
      found=1
    else
      printf '%s\n' "$line" >>"$temporary"
    fi
  done <"$path"
  if (( found == 0 )); then
    printf '%s=%s\n' "$key" "$value" >>"$temporary"
  fi
  mv -f -- "$temporary" "$path"
  chmod 0600 -- "$path"
}

hybrid_ndr_read_env() {
  local path=$1 key=$2
  awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' "$path"
}

hybrid_ndr_compose_base() {
  local -n target=$1
  local project_dir=$2
  local compose_file=$3
  local env_file=$4
  local project_name=$5
  shift 5
  target=(docker compose
    --project-name "$project_name"
    --project-directory "$project_dir"
    --file "$compose_file")
  local additional_file
  for additional_file in "$@"; do
    [[ -f "$additional_file" && ! -L "$additional_file" ]] || hybrid_ndr_die "additional Compose file is missing or is a symlink: $additional_file"
    target+=(--file "$additional_file")
  done
  target+=(--env-file "$env_file" --profile customer)
}

hybrid_ndr_require_https_ingress() {
  local services=$1
  grep -Fxq ingress <<<"$services" || hybrid_ndr_die "production customer profile is missing the HTTPS ingress"
}

hybrid_ndr_require_release_image_pins() {
  local release_compose_file=$1
  [[ -f "$release_compose_file" && ! -L "$release_compose_file" ]] || hybrid_ndr_die "release image override is missing or is a symlink"
  python3 - "$release_compose_file" <<'PY' || hybrid_ndr_die "release image override contains a mutable or malformed image reference"
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
services = set()
images = {}
current = None
for line in text.splitlines():
    match = re.fullmatch(r"  ([a-z0-9][a-z0-9-]{0,62}):", line)
    if match:
        current = match.group(1)
        services.add(current)
        continue
    match = re.fullmatch(r"    image: (sha256:[0-9a-f]{64})", line)
    if match and current:
        images[current] = match.group(1)
if not services or set(images) != services:
    raise SystemExit(1)
PY
}

hybrid_ndr_customer_services() {
  local -n compose_ref=$1
  local services service forbidden required found
  services=$("${compose_ref[@]}" config --services) || hybrid_ndr_die "customer Compose configuration is invalid"
  [[ -n "$services" ]] || hybrid_ndr_die "customer Compose profile selected no services"

  for forbidden in logto logto-postgres control-api; do
    if grep -Fxq "$forbidden" <<<"$services"; then
      hybrid_ndr_die "customer profile contains forbidden vendor service: $forbidden"
    fi
  done

  for required in postgres clickhouse minio suricata zeek vector detection-engine deployment-connector update-agent operations-agent local-api dashboard prometheus grafana otel-collector; do
    grep -Fxq "$required" <<<"$services" || hybrid_ndr_die "customer profile is missing required service: $required"
  done

  found=0
  for service in deployment-connector connector outbound-connector customer-connector; do
    if grep -Fxq "$service" <<<"$services"; then
      found=1
      break
    fi
  done
  if (( found == 0 )); then
    hybrid_ndr_warn "customer profile has no outbound connector service; enrollment is stored locally and cloud heartbeat/rotation remain deferred"
  fi
  printf '%s\n' "$services"
}
