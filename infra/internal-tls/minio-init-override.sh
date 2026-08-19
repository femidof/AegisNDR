#!/bin/sh
set -eu

# Same bucket provisioning as the base script, but over the MinIO TLS endpoint
# with TLS verification pinned to the internal CA, so the whole MinIO
# credential-bearing path is encrypted and verified. The `mc` binary reads the
# internal CA from the mc trust directory mounted by the overlay.
: "${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
: "${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
: "${MINIO_RAW_BUCKET:?MINIO_RAW_BUCKET is required}"
: "${MINIO_CASE_BUCKET:?MINIO_CASE_BUCKET is required}"
: "${MINIO_EXPORT_BUCKET:?MINIO_EXPORT_BUCKET is required}"
: "${MINIO_RAW_RETENTION_DAYS:?MINIO_RAW_RETENTION_DAYS is required}"
: "${MINIO_CASE_RETENTION_DAYS:?MINIO_CASE_RETENTION_DAYS is required}"
: "${MINIO_EXPORT_RETENTION_DAYS:?MINIO_EXPORT_RETENTION_DAYS is required}"

validate_bucket() {
  case "$1" in
    ''|*[!a-z0-9.-]*|.*|*.)
      echo "Invalid bucket name: $1" >&2
      exit 1
      ;;
  esac
}

validate_days() {
  case "$1" in
    ''|*[!0-9]*)
      echo "Retention must be an integer number of days: $1" >&2
      exit 1
      ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 3650 ]; then
    echo "Retention must be between 1 and 3650 days: $1" >&2
    exit 1
  fi
}

ensure_locked_bucket() {
  bucket="$1"
  retention_days="$2"
  validate_bucket "$bucket"
  validate_days "$retention_days"
  mc mb --ignore-existing --with-lock "local/$bucket"
  mc version enable "local/$bucket"
  mc anonymous set none "local/$bucket"
  mc retention set --default GOVERNANCE "${retention_days}d" "local/$bucket"
  printf '{"Rules":[{"ID":"hybrid-ndr-retention","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":%s},"NoncurrentVersionExpiration":{"NoncurrentDays":%s}}]}\n' \
    "$retention_days" "$retention_days" | mc ilm rule import "local/$bucket"
}

until mc alias set local https://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
  --api S3v4 >/dev/null 2>&1 \
  && mc ready local >/dev/null 2>&1; do
  attempts=$(( ${attempts:-0} + 1 ))
  if [ "$attempts" -ge 60 ]; then
    echo "MinIO TLS endpoint did not become ready" >&2
    exit 1
  fi
  sleep 2
done

ensure_locked_bucket "$MINIO_RAW_BUCKET" "$MINIO_RAW_RETENTION_DAYS"
ensure_locked_bucket "$MINIO_CASE_BUCKET" "$MINIO_CASE_RETENTION_DAYS"
ensure_locked_bucket "$MINIO_EXPORT_BUCKET" "$MINIO_EXPORT_RETENTION_DAYS"

# MinIO cluster metrics are protected by MINIO_PROMETHEUS_AUTH_TYPE=private.
# Generate the scrape JWT for Prometheus (shared via the prometheus-data
# volume) so storage telemetry is not readable without a token. The --json
# form is parsed with shell parameter expansion (no field-count dependence on
# the mc CLI output layout), and an unusable token fails loudly instead of
# silently leaving Prometheus without a scrape credential.
if command -v mc >/dev/null 2>&1 && [ -d /prometheus-data ]; then
  json=$(mc admin prometheus generate local --json 2>/dev/null | tr -d '\n ' || true)
  rest=${json#*'"bearerToken":"'}
  token=${rest%%'"'*}
  case "$token" in
    eyJ[A-Za-z0-9_-]*.[A-Za-z0-9_-]*.[A-Za-z0-9_-]*)
      printf '%s\n' "$token" >/prometheus-data/minio-prometheus.jwt
      # Owner-readable only: the JWT alone unlocks MinIO metrics, so it must
      # not be world-readable on the shared volume.
      chmod 0640 /prometheus-data/minio-prometheus.jwt
      ;;
    *)
      echo "mc admin prometheus generate produced no usable scrape JWT; MinIO metrics will be unavailable" >&2
      exit 1
      ;;
  esac
fi

echo "MinIO TLS evidence buckets are private, versioned, retention protected, and lifecycle scheduled."
