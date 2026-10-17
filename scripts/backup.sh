#!/usr/bin/env bash
# Enterprise backup/restore for Hybrid NDR customer deployments.
# Backs up Postgres (pg_dump), local/control SQLite, connector state, and
# identity metadata (no private keys leave the host unencrypted).
# Usage:
#   BACKUP_PASSPHRASE='<strong>' ./backup.sh /var/lib/hybrid-ndr /etc/hybrid-ndr ./backups
#   BACKUP_PASSPHRASE='<strong>' ./backup.sh restore ./backups/hybrid-ndr-YYYYMMDDTHHMMSSZ.enc /var/lib/hybrid-ndr
set -euo pipefail

mode="${1:-backup}"
if [[ "$mode" == "restore" ]]; then
  archive="$2"
  state_dir="${3:-/var/lib/hybrid-ndr}"
  [[ -n "${BACKUP_PASSPHRASE:-}" ]] || { echo "BACKUP_PASSPHRASE is required" >&2; exit 1; }
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  openssl enc -d -aes-256-gcm -pbkdf2 -iter 200000 -in "$archive" -out "$work/bundle.tar" -pass env:BACKUP_PASSPHRASE
  tar -xf "$work/bundle.tar" -C "$work"
  sha256sum -c "$work/MANIFEST.sha256" --status --quiet --chdir "$work" || { echo "backup integrity check failed" >&2; exit 1; }
  mkdir -p "$state_dir"
  cp -a "$work/state/." "$state_dir/"
  chmod 0700 "$state_dir"
  echo "restore complete to $state_dir (restart the stack to apply)"
  exit 0
fi

state_dir="${1:-/var/lib/hybrid-ndr}"
config_dir="${2:-/etc/hybrid-ndr}"
out_dir="${3:-./backups}"
[[ -n "${BACKUP_PASSPHRASE:-}" ]] || { echo "BACKUP_PASSPHRASE is required" >&2; exit 1; }
mkdir -p "$out_dir"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/state"

# Postgres logical backup (via compose service when running).
if docker compose --project-directory "$(dirname "$0")/../.." ps postgres --format json 2>/dev/null | grep -q postgres; then
  docker compose --project-directory "$(dirname "$0")/../.." exec -T postgres \
    pg_dump -U "${POSTGRES_USER:-hybrid_ndr}" -d "${POSTGRES_DB:-hybrid_ndr}" >"$work/state/postgres.sql" || true
fi
# SQLite + connector state + non-secret identity metadata.
for f in local-api.sqlite3 control-api.sqlite3 connector/state.sqlite3; do
  [[ -f "$state_dir/$f" ]] && cp -a "$state_dir/$f" "$work/state/$(echo "$f" | tr '/' '_')"
done
[[ -f "$config_dir/customer.env" ]] && grep -v -E 'PASSWORD|SECRET|TOKEN|API_KEY' "$config_dir/customer.env" >"$work/state/customer.env.redacted" || true
cp -a "$state_dir/identity/tenant-id" "$work/state/tenant-id" 2>/dev/null || true
cp -a "$state_dir/identity/deployment-id" "$work/state/deployment-id" 2>/dev/null || true
(cd "$work" && sha256sum state/* >MANIFEST.sha256)
tar -cf "$work/bundle.tar" -C "$work" state MANIFEST.sha256
stamp=$(date -u +%Y%m%dT%H%M%SZ)
openssl enc -e -aes-256-gcm -pbkdf2 -iter 200000 -in "$work/bundle.tar" -out "$out_dir/hybrid-ndr-$stamp.enc" -pass env:BACKUP_PASSPHRASE
chmod 0600 "$out_dir/hybrid-ndr-$stamp.enc"
echo "backup written to $out_dir/hybrid-ndr-$stamp.enc"
echo "schedule via cron/systemd timer; test restores quarterly; retain per 30/365d policy"
