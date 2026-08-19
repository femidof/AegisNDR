#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "$script_dir/lib/common.sh"
# shellcheck source=lib/tls.sh
source "$script_dir/lib/tls.sh"

project_dir=$(cd "$script_dir/.." && pwd)
compose_file=""
https_compose_file=""
release_compose_file=""
config_dir=${HYBRID_NDR_CONFIG_DIR:-/etc/hybrid-ndr}
state_dir=${HYBRID_NDR_STATE_DIR:-/var/lib/hybrid-ndr}
compose_project=${HYBRID_NDR_COMPOSE_PROJECT:-hybrid-ndr-customer}
capture_interface=""
customer_bind_address=${HYBRID_NDR_BIND_ADDRESS:-0.0.0.0}
lan_host=${HYBRID_NDR_LAN_HOST:-}
tls_certificate=""
tls_private_key=""
tls_ca=""
control_plane_url=${HYBRID_NDR_CONTROL_PLANE_URL:-}
control_plane_ca=""
enrollment_token_file=""
token_from_stdin=0
legacy_token=""
allow_insecure_control_plane=0
allow_loopback=0
offline_images=""
offline_images_sha256=""
health_timeout=${HYBRID_NDR_HEALTH_TIMEOUT:-300}
release_version=${HYBRID_NDR_RELEASE_VERSION:-}
allow_downgrade=0
non_interactive=0
standalone=0
lock_dir=""
work_dir=""
remove_token_after_success=""

usage() {
  cat <<'EOF'
Usage: install.sh --interface INTERFACE [enrollment option] [options]

Initial enrollment (choose one):
  --enrollment-token-file FILE  Read the one-time token from a mode-0600 file.
                                The file is deleted after a successful exchange.
  --enrollment-token-stdin      Read the one-time token as one line from stdin.

Options:
  --control-plane-url URL       Vendor enrollment endpoint base URL (HTTPS required)
  --control-plane-ca FILE       Private CA bundle for the HTTPS endpoint
  --project-dir DIR             Verified/extracted release directory
  --compose-file FILE           Compose file within the verified release
  --https-compose-file FILE     Additive HTTPS ingress Compose file
  --release-compose-file FILE   Signed digest-only image override from a release bundle
  --project-name NAME           Stable Docker Compose project name
  --bind-address IPV4           Operator service bind address (default: 0.0.0.0)
  --lan-host HOST_OR_IPV4       Trusted browser hostname/IP (default: bind IP,
                                or hybrid-ndr.local when binding all interfaces)
  --tls-cert FILE               Supplied PEM server certificate/full chain
  --tls-key FILE                Supplied unencrypted PEM server private key
  --tls-ca FILE                 Optional PEM CA bundle for the supplied cert
  --config-dir DIR              Private configuration directory
  --state-dir DIR               Customer data/runtime directory
  --offline-images FILE         Preloaded images.tar from a verified offline bundle
  --offline-images-sha256 HASH  Required SHA-256 for --offline-images
  --health-timeout SECONDS      Post-install health deadline (default: 300)
  --release-version VERSION     Version recorded for upgrade ordering
  --allow-insecure-control-plane
                                Permit HTTP loopback for local development only
  --allow-loopback              Permit lo as the capture interface for testing
  --allow-downgrade             Explicitly allow an older release version
  --standalone                  Provision fully local identity with no control
                                plane or enrollment token (air-gapped mode)
  --non-interactive             Confirm that no prompts may be used
  --help                        Show this help

An already-enrolled deployment upgrades idempotently without another token.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface) [[ $# -ge 2 ]] || hybrid_ndr_die "--interface requires a value"; capture_interface=$2; shift 2 ;;
    --enrollment-token-file) [[ $# -ge 2 ]] || hybrid_ndr_die "--enrollment-token-file requires a value"; enrollment_token_file=$2; shift 2 ;;
    --enrollment-token-stdin) token_from_stdin=1; shift ;;
    --enrollment-token)
      [[ $# -ge 2 ]] || hybrid_ndr_die "--enrollment-token requires a value"
      legacy_token=$2
      hybrid_ndr_warn "--enrollment-token can leak through shell history; prefer --enrollment-token-file or --enrollment-token-stdin"
      shift 2
      ;;
    --control-plane-url) [[ $# -ge 2 ]] || hybrid_ndr_die "--control-plane-url requires a value"; control_plane_url=$2; shift 2 ;;
    --control-plane-ca) [[ $# -ge 2 ]] || hybrid_ndr_die "--control-plane-ca requires a value"; control_plane_ca=$2; shift 2 ;;
    --project-dir) [[ $# -ge 2 ]] || hybrid_ndr_die "--project-dir requires a value"; project_dir=$2; shift 2 ;;
    --compose-file) [[ $# -ge 2 ]] || hybrid_ndr_die "--compose-file requires a value"; compose_file=$2; shift 2 ;;
    --https-compose-file) [[ $# -ge 2 ]] || hybrid_ndr_die "--https-compose-file requires a value"; https_compose_file=$2; shift 2 ;;
    --release-compose-file) [[ $# -ge 2 ]] || hybrid_ndr_die "--release-compose-file requires a value"; release_compose_file=$2; shift 2 ;;
    --project-name) [[ $# -ge 2 ]] || hybrid_ndr_die "--project-name requires a value"; compose_project=$2; shift 2 ;;
    --bind-address) [[ $# -ge 2 ]] || hybrid_ndr_die "--bind-address requires a value"; customer_bind_address=$2; shift 2 ;;
    --lan-host) [[ $# -ge 2 ]] || hybrid_ndr_die "--lan-host requires a value"; lan_host=$2; shift 2 ;;
    --tls-cert) [[ $# -ge 2 ]] || hybrid_ndr_die "--tls-cert requires a value"; tls_certificate=$2; shift 2 ;;
    --tls-key) [[ $# -ge 2 ]] || hybrid_ndr_die "--tls-key requires a value"; tls_private_key=$2; shift 2 ;;
    --tls-ca) [[ $# -ge 2 ]] || hybrid_ndr_die "--tls-ca requires a value"; tls_ca=$2; shift 2 ;;
    --config-dir) [[ $# -ge 2 ]] || hybrid_ndr_die "--config-dir requires a value"; config_dir=$2; shift 2 ;;
    --state-dir) [[ $# -ge 2 ]] || hybrid_ndr_die "--state-dir requires a value"; state_dir=$2; shift 2 ;;
    --offline-images) [[ $# -ge 2 ]] || hybrid_ndr_die "--offline-images requires a value"; offline_images=$2; shift 2 ;;
    --offline-images-sha256) [[ $# -ge 2 ]] || hybrid_ndr_die "--offline-images-sha256 requires a value"; offline_images_sha256=$2; shift 2 ;;
    --health-timeout) [[ $# -ge 2 ]] || hybrid_ndr_die "--health-timeout requires a value"; health_timeout=$2; shift 2 ;;
    --release-version) [[ $# -ge 2 ]] || hybrid_ndr_die "--release-version requires a value"; release_version=$2; shift 2 ;;
    --allow-insecure-control-plane) allow_insecure_control_plane=1; shift ;;
    --allow-loopback) allow_loopback=1; shift ;;
    --allow-downgrade) allow_downgrade=1; shift ;;
    --standalone) standalone=1; shift ;;
    --non-interactive) non_interactive=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) hybrid_ndr_die "unknown argument: $1" ;;
  esac
done

[[ -n "$capture_interface" ]] || { usage >&2; exit 2; }
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$customer_bind_address" 2>/dev/null || hybrid_ndr_die "bind address must be a valid IPv4 address"
if [[ -z "$lan_host" ]]; then
  if [[ "$customer_bind_address" == 0.0.0.0 ]]; then
    lan_host=hybrid-ndr.local
  else
    lan_host=$customer_bind_address
  fi
fi
lan_host=$(hybrid_ndr_normalize_lan_host "$lan_host") || hybrid_ndr_die "LAN host must be a valid DNS hostname or non-wildcard IPv4 address"
[[ "$compose_project" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || hybrid_ndr_die "Compose project name is invalid"
dashboard_public_origin="https://$lan_host"
[[ "$health_timeout" =~ ^[0-9]+$ ]] && (( health_timeout >= 10 && health_timeout <= 3600 )) || hybrid_ndr_die "health timeout must be between 10 and 3600 seconds"
(( token_from_stdin + (${#enrollment_token_file} > 0) + (${#legacy_token} > 0) <= 1 )) || hybrid_ndr_die "select only one enrollment token input"
(( (${#tls_certificate} > 0) == (${#tls_private_key} > 0) )) || hybrid_ndr_die "--tls-cert and --tls-key must be supplied together"

project_dir=$(hybrid_ndr_realpath_m "$project_dir")
config_dir=$(hybrid_ndr_realpath_m "$config_dir")
state_dir=$(hybrid_ndr_realpath_m "$state_dir")
if [[ -z "$compose_file" ]]; then
  compose_file="$project_dir/infra/compose/docker-compose.yml"
else
  compose_file=$(hybrid_ndr_realpath_m "$compose_file")
fi
if [[ -z "$https_compose_file" ]]; then
  https_compose_file="$project_dir/infra/compose/docker-compose.https.yml"
else
  https_compose_file=$(hybrid_ndr_realpath_m "$https_compose_file")
fi
if [[ -z "$release_compose_file" && -f "$project_dir/infra/compose/docker-compose.release.yml" ]]; then
  release_compose_file="$project_dir/infra/compose/docker-compose.release.yml"
elif [[ -n "$release_compose_file" ]]; then
  release_compose_file=$(hybrid_ndr_realpath_m "$release_compose_file")
fi
[[ -d "$project_dir" ]] || hybrid_ndr_die "project directory does not exist: $project_dir"
[[ -f "$compose_file" && ! -L "$compose_file" ]] || hybrid_ndr_die "Compose file is missing or is a symlink: $compose_file"
[[ -f "$https_compose_file" && ! -L "$https_compose_file" ]] || hybrid_ndr_die "HTTPS Compose file is missing or is a symlink: $https_compose_file"
if [[ -n "$release_compose_file" ]]; then
  hybrid_ndr_require_release_image_pins "$release_compose_file"
fi
[[ -f "$project_dir/installer/process-enrollment.py" ]] || hybrid_ndr_die "verified release is missing its enrollment processor"

if [[ -z "$release_version" ]]; then
  if [[ -s "$project_dir/RELEASE_VERSION" ]]; then
    release_version=$(<"$project_dir/RELEASE_VERSION")
  elif [[ -s "$project_dir/package.json" ]]; then
    release_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("version", "0.0.0"))' "$project_dir/package.json")
  else
    release_version=0.0.0
  fi
fi
[[ "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || hybrid_ndr_die "release version is not valid: $release_version"

if [[ -n "$offline_images" || -n "$offline_images_sha256" ]]; then
  [[ -n "$offline_images" && -n "$offline_images_sha256" ]] || hybrid_ndr_die "offline image path and SHA-256 must be supplied together"
  offline_images=$(realpath -- "$offline_images")
  [[ -f "$offline_images" && ! -L "$offline_images" ]] || hybrid_ndr_die "offline image archive must be a regular non-symlink file"
  hybrid_ndr_validate_sha256 "$offline_images_sha256" || hybrid_ndr_die "offline image SHA-256 is invalid"
  actual_images_sha256=$(sha256sum -- "$offline_images" | awk '{print $1}')
  [[ "$actual_images_sha256" == "${offline_images_sha256,,}" ]] || hybrid_ndr_die "offline image archive checksum verification failed"
  [[ -n "$release_compose_file" ]] || hybrid_ndr_die "offline images require the signed digest-only release Compose override"
fi

preflight_args=(--interface "$capture_interface" --config-dir "$config_dir" --state-dir "$state_dir" --bind-address "$customer_bind_address")
[[ -f "$config_dir/install-state" ]] && preflight_args+=(--skip-port-checks)
(( allow_loopback == 1 )) && preflight_args+=(--allow-loopback)
"$script_dir/preflight.sh" "${preflight_args[@]}"

hybrid_ndr_secure_directory "$config_dir"
hybrid_ndr_secure_directory "$config_dir/secrets"
hybrid_ndr_secure_directory "$state_dir"
hybrid_ndr_secure_directory "$state_dir/identity"
hybrid_ndr_secure_directory "$state_dir/evidence"
hybrid_ndr_secure_directory "$state_dir/updates"

# Provision the private internal data-plane CA and server certificates. Every
# credential-bearing hop (PostgreSQL, ClickHouse, MinIO, exporters, vector,
# Grafana) is encrypted with verified TLS when the internal-tls Compose overlay
# is applied below. The CA and keys stay inside the root-owned state directory.
internal_tls_dir=${HYBRID_NDR_INTERNAL_TLS_DIR:-"$state_dir/internal-tls"}
hybrid_ndr_secure_directory "$internal_tls_dir"
if ! bash "$script_dir/../infra/internal-tls/provision-internal-certs.sh" "$internal_tls_dir"; then
  hybrid_ndr_die "internal TLS certificate provisioning failed"
fi

lock_dir="$config_dir/.installer.lock"
if ! mkdir -m 0700 -- "$lock_dir" 2>/dev/null; then
  hybrid_ndr_die "another install/upgrade appears to be active ($lock_dir exists)"
fi
printf '%s\n' "$$" >"$lock_dir/pid"
chmod 0600 -- "$lock_dir/pid"

cleanup() {
  local status=$?
  if [[ -n "$work_dir" && -d "$work_dir" && "$work_dir" == "$state_dir/identity/"* ]]; then
    rm -rf -- "$work_dir"
  fi
  if [[ -n "$lock_dir" && -d "$lock_dir" ]]; then
    rm -f -- "$lock_dir/pid"
    rmdir -- "$lock_dir" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

env_file="$config_dir/customer.env"
if [[ ! -e "$env_file" ]]; then
  tenant_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
  deployment_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
  postgres_password=$(hybrid_ndr_random_hex 32)
  postgres_exporter_password=$(hybrid_ndr_random_hex 32)
  grafana_postgres_password=$(hybrid_ndr_random_hex 32)
  clickhouse_password=$(hybrid_ndr_random_hex 32)
  minio_password=$(hybrid_ndr_random_hex 32)
  grafana_password=$(hybrid_ndr_random_hex 32)
  logto_password=$(hybrid_ndr_random_hex 32)
  temporary_env=$(mktemp "$config_dir/.customer.env.XXXXXX")
  chmod 0600 -- "$temporary_env"
  {
    printf 'TENANT_ID=%s\n' "$tenant_id"
    printf 'DEPLOYMENT_ID=%s\n' "$deployment_id"
    printf 'CAPTURE_INTERFACE=%s\n' "$capture_interface"
    printf 'SENSOR_CAPTURE_MODE=live\n'
    printf 'SENSOR_NETWORK_MODE=host\n'
    printf 'CUSTOMER_BIND_ADDRESS=%s\n' "$customer_bind_address"
    printf 'CUSTOMER_LAN_HOST=%s\n' "$lan_host"
    printf 'DASHBOARD_MODE=api\nDASHBOARD_AUTH_MODE=oidc\nDASHBOARD_ALLOW_INSECURE_HTTP=false\n'
    printf 'DASHBOARD_PUBLIC_ORIGIN=%s\n' "$dashboard_public_origin"
    printf 'LOGTO_REDIRECT_URI=%s/callback\nLOGTO_POST_LOGOUT_URI=%s\n' "$dashboard_public_origin" "$dashboard_public_origin"
    printf 'HYBRID_NDR_CONFIG_DIR=%s\n' "$config_dir"
    printf 'HYBRID_NDR_STATE_DIR=%s\n' "$state_dir"
    printf 'CONTROL_PLANE_URL=%s\n' "$control_plane_url"
    printf 'CONTROL_PLANE_CA_FILE=\n'
    printf 'CONNECTOR_ENABLED=true\n'
    printf 'CONTROL_PLANE_ALLOW_INSECURE_LOOPBACK=%s\n' "$([[ $allow_insecure_control_plane == 1 ]] && printf true || printf false)"
    printf 'HYBRID_NDR_RELEASE_VERSION=%s\n' "$release_version"
    printf 'CONNECTOR_HEARTBEAT_SECONDS=60\nCONNECTOR_USAGE_SECONDS=300\nCONNECTOR_CONFIGURATION_SECONDS=300\n'
    printf 'CONNECTOR_UPDATE_SECONDS=3600\nCONNECTOR_CERTIFICATE_CHECK_SECONDS=21600\nCONNECTOR_CERTIFICATE_ROTATE_BEFORE_DAYS=30\n'
    printf 'CONNECTOR_UPDATE_MANIFEST_FILE=/var/lib/hybrid-ndr/updates/available-manifest.json\n'
    printf 'UPDATE_AGENT_MONITOR_SECONDS=30\n'
    printf 'POSTGRES_DB=hybrid_ndr\nPOSTGRES_USER=hybrid_ndr\nPOSTGRES_PASSWORD=%s\n' "$postgres_password"
    printf 'POSTGRES_EXPORTER_USER=ndr_metrics\nPOSTGRES_EXPORTER_PASSWORD=%s\n' "$postgres_exporter_password"
    printf 'GRAFANA_POSTGRES_USER=ndr_grafana\nGRAFANA_POSTGRES_PASSWORD=%s\n' "$grafana_postgres_password"
    printf 'CLICKHOUSE_DATABASE=hybrid_ndr\nCLICKHOUSE_USER=hybrid_ndr\nCLICKHOUSE_PASSWORD=%s\n' "$clickhouse_password"
    printf 'MINIO_ROOT_USER=hybrid_ndr\nMINIO_ROOT_PASSWORD=%s\n' "$minio_password"
    printf 'MINIO_RAW_BUCKET=ndr-raw-evidence\nMINIO_CASE_BUCKET=ndr-case-evidence\nMINIO_EXPORT_BUCKET=ndr-investigation-exports\n'
    printf 'MINIO_RAW_RETENTION_DAYS=30\nMINIO_CASE_RETENTION_DAYS=365\nMINIO_EXPORT_RETENTION_DAYS=30\n'
    printf 'GRAFANA_ADMIN_USER=ndr-admin\nGRAFANA_ADMIN_PASSWORD=%s\n' "$grafana_password"
    printf 'PROMETHEUS_RETENTION_TIME=15d\nPROMETHEUS_RETENTION_SIZE=10GB\n'
    printf 'MODEL_POLICY=balanced\nMODEL_GATEWAY_AVAILABLE=true\nOFFLINE_GRACE_DAYS=14\n'
    printf 'DETECTION_POLL_SECONDS=2\nDETECTION_FAST_INTERVAL_SECONDS=10\nDETECTION_BEHAVIOR_INTERVAL_SECONDS=60\n'
    printf 'DETECTION_TUNNELING_INTERVAL_SECONDS=300\nDETECTION_BASELINE_INTERVAL_SECONDS=3600\n'
    printf 'DETECTION_BASELINE_WINDOW_DAYS=7\nDETECTION_BASELINE_EXCLUSION_SECONDS=300\n'
    printf 'DETECTION_BOOTSTRAP_LOOKBACK_SECONDS=86400\nDETECTION_MAX_EVENTS_PER_WINDOW=10000\n'
    printf 'DETECTION_BACKEND_TIMEOUT_SECONDS=10\nDETECTION_HEALTH_TTL_SECONDS=30\n'
    printf 'DETECTION_MODEL_RETRAIN_INTERVAL_SECONDS=86400\n'
    printf 'OPERATIONS_POLL_SECONDS=15\nOPERATIONS_HEALTH_SNAPSHOT_SECONDS=3600\n'
    printf 'RETENTION_INTERVAL_SECONDS=86400\nCLICKHOUSE_EVENT_RETENTION_DAYS=30\nPOSTGRES_EVENT_RETENTION_DAYS=30\n'
    printf 'OPERATIONAL_HISTORY_RETENTION_DAYS=90\nOTEL_SDK_DISABLED=false\n'
    printf 'AUTH_MODE=jwt\nAUTH_AUDIENCE=https://hybrid-ndr.local/api\nAUTH_ALLOWED_ORGANIZATION_IDS=\n'
    # Vendor-profile variables are populated only so Compose interpolation is deterministic.
    # The installer rejects that profile and never starts these services.
    printf 'LOGTO_POSTGRES_DB=logto\nLOGTO_POSTGRES_USER=logto\nLOGTO_POSTGRES_PASSWORD=%s\n' "$logto_password"
    printf 'LOGTO_DATABASE_STATEMENT_TIMEOUT=5000\nLOGTO_ENDPOINT=http://disabled.invalid\nLOGTO_ADMIN_ENDPOINT=http://disabled.invalid\n'
  } >"$temporary_env"
  mv -- "$temporary_env" "$env_file"
fi
hybrid_ndr_secure_file "$env_file"
hybrid_ndr_upsert_env "$env_file" CAPTURE_INTERFACE "$capture_interface"
hybrid_ndr_upsert_env "$env_file" SENSOR_CAPTURE_MODE live
hybrid_ndr_upsert_env "$env_file" SENSOR_NETWORK_MODE host
hybrid_ndr_upsert_env "$env_file" CUSTOMER_BIND_ADDRESS "$customer_bind_address"
hybrid_ndr_upsert_env "$env_file" CUSTOMER_LAN_HOST "$lan_host"
hybrid_ndr_upsert_env "$env_file" DASHBOARD_MODE api
hybrid_ndr_upsert_env "$env_file" DASHBOARD_AUTH_MODE oidc
hybrid_ndr_upsert_env "$env_file" DASHBOARD_ALLOW_INSECURE_HTTP false
hybrid_ndr_upsert_env "$env_file" DASHBOARD_PUBLIC_ORIGIN "$dashboard_public_origin"
hybrid_ndr_upsert_env "$env_file" LOGTO_REDIRECT_URI "$dashboard_public_origin/callback"
hybrid_ndr_upsert_env "$env_file" LOGTO_POST_LOGOUT_URI "$dashboard_public_origin"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_CONFIG_DIR "$config_dir"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_STATE_DIR "$state_dir"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_INTERNAL_TLS_DIR "$internal_tls_dir"
hybrid_ndr_upsert_env "$env_file" CONNECTOR_ENABLED true

# Prometheus scrape token for the operations-agent metrics endpoint. Persisted
# so upgrades keep the same token (and the rendered environment stays stable).
operations_metrics_token_file="$config_dir/secrets/operations-metrics-token"
if [[ ! -s "$operations_metrics_token_file" ]]; then
  hybrid_ndr_random_hex 32 >"$operations_metrics_token_file"
  hybrid_ndr_secure_file "$operations_metrics_token_file"
fi
hybrid_ndr_upsert_env "$env_file" OPERATIONS_METRICS_TOKEN "$(<"$operations_metrics_token_file")"
hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_ALLOW_INSECURE_LOOPBACK "$([[ $allow_insecure_control_plane == 1 ]] && printf true || printf false)"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_RELEASE_VERSION "$release_version"
hybrid_ndr_upsert_env "$env_file" CONNECTOR_UPDATE_MANIFEST_FILE /var/lib/hybrid-ndr/updates/available-manifest.json
hybrid_ndr_upsert_env "$env_file" UPDATE_AGENT_MONITOR_SECONDS 30
[[ -n "$control_plane_url" ]] && hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_URL "$control_plane_url"

tls_dir="$config_dir/tls"
hybrid_ndr_prepare_tls "$tls_dir" "$lan_host" "$tls_certificate" "$tls_private_key" "$tls_ca"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_TLS_CERT_FILE "$tls_dir/server-cert.pem"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_TLS_KEY_FILE "$tls_dir/server-key.pem"
hybrid_ndr_upsert_env "$env_file" HYBRID_NDR_TLS_CA_FILE "$(hybrid_ndr_tls_health_ca "$tls_dir")"

grafana_password_file="$config_dir/secrets/grafana-admin-password"
if [[ ! -s "$grafana_password_file" ]]; then
  awk -F= '$1 == "GRAFANA_ADMIN_PASSWORD" {print substr($0, index($0, "=") + 1)}' "$env_file" >"$grafana_password_file"
fi
hybrid_ndr_secure_file "$grafana_password_file"

identity_dir="$state_dir/identity"
private_key="$identity_dir/deployment-key.pem"
csr_file="$identity_dir/deployment.csr.pem"
certificate_file="$identity_dir/deployment-cert.pem"
if [[ ! -s "$private_key" ]]; then
  temporary_key=$(mktemp "$identity_dir/.deployment-key.XXXXXX")
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$temporary_key" >/dev/null 2>&1
  chmod 0600 -- "$temporary_key"
  openssl pkey -in "$temporary_key" -check -noout >/dev/null 2>&1 || hybrid_ndr_die "generated deployment private key failed validation"
  mv -- "$temporary_key" "$private_key"
fi
hybrid_ndr_secure_file "$private_key"
openssl pkey -in "$private_key" -check -noout >/dev/null 2>&1 || hybrid_ndr_die "stored deployment private key is invalid"
openssl pkey -in "$private_key" -text -noout 2>/dev/null | grep -q 'ASN1 OID: prime256v1' || hybrid_ndr_die "stored deployment key is not ECDSA P-256"

if [[ ! -s "$csr_file" ]]; then
  temporary_csr=$(mktemp "$identity_dir/.deployment-csr.XXXXXX")
  openssl req -new -sha256 -key "$private_key" -subj "/CN=hybrid-ndr-customer-deployment" -out "$temporary_csr"
  chmod 0600 -- "$temporary_csr"
  openssl req -in "$temporary_csr" -verify -noout >/dev/null 2>&1 || hybrid_ndr_die "generated CSR failed validation"
  mv -- "$temporary_csr" "$csr_file"
fi
hybrid_ndr_secure_file "$csr_file"
printf '%s\n' "$capture_interface" >"$identity_dir/capture-interface"
hybrid_ndr_secure_file "$identity_dir/capture-interface"

if [[ -s "$certificate_file" ]]; then
  [[ -z "$enrollment_token_file" && "$token_from_stdin" == 0 && -z "$legacy_token" ]] || hybrid_ndr_die "this deployment is already enrolled; do not supply another enrollment token"
elif (( standalone == 1 )); then
  [[ -z "$enrollment_token_file" && "$token_from_stdin" == 0 && -z "$legacy_token" ]] || hybrid_ndr_die "--standalone cannot be combined with an enrollment token"
  [[ -z "$control_plane_url" ]] || hybrid_ndr_die "--standalone cannot be combined with --control-plane-url"
  hybrid_ndr_log "provisioning standalone air-gapped identity (no control plane required)"
  printf '%s\n' "$(python3 -c 'import uuid; print(uuid.uuid4())')" >"$identity_dir/tenant-id"
  printf '%s\n' "$(python3 -c 'import uuid; print(uuid.uuid4())')" >"$identity_dir/deployment-id"
  hybrid_ndr_secure_file "$identity_dir/tenant-id"
  hybrid_ndr_secure_file "$identity_dir/deployment-id"

  # A locally generated CA signs the deployment certificate; no vendor is
  # involved and the identity is stable across upgrades.
  local_ca_key="$identity_dir/local-ca-key.pem"
  local_ca_cert="$identity_dir/local-ca-cert.pem"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$local_ca_key" >/dev/null 2>&1
  openssl req -x509 -new -sha256 -days 3650 -key "$local_ca_key" \
    -subj '/CN=Hybrid NDR Standalone Deployment CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -out "$local_ca_cert"
  temporary_cert=$(mktemp "$identity_dir/.deployment-cert.XXXXXX")
  certificate_extensions="$identity_dir/.certificate-extensions.cnf"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth,serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' >"$certificate_extensions"
  openssl x509 -req -sha256 -days 825 -in "$csr_file" -CA "$local_ca_cert" -CAkey "$local_ca_key" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -extfile "$certificate_extensions" \
    -out "$temporary_cert"
  rm -f -- "$certificate_extensions"
  mv -- "$temporary_cert" "$certificate_file"
  hybrid_ndr_secure_file "$certificate_file"
  openssl x509 -in "$certificate_file" -noout >/dev/null 2>&1 || hybrid_ndr_die "standalone deployment certificate failed validation"
  certificate_fingerprint=$(openssl x509 -in "$certificate_file" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  printf '%s\n' "$certificate_fingerprint" >"$identity_dir/certificate-fingerprint"
  hybrid_ndr_secure_file "$identity_dir/certificate-fingerprint"

  # Local issuer key + JWKS + update-signing key + identity document.
  python3 "$project_dir/installer/process-enrollment.py" standalone "$identity_dir" "https://$lan_host"

  tenant_id=$(<"$identity_dir/tenant-id")
  deployment_id=$(<"$identity_dir/deployment-id")
  hybrid_ndr_validate_identifier "$tenant_id" || hybrid_ndr_die "persisted tenant identifier is invalid"
  hybrid_ndr_validate_identifier "$deployment_id" || hybrid_ndr_die "persisted deployment identifier is invalid"
  hybrid_ndr_upsert_env "$env_file" TENANT_ID "$tenant_id"
  hybrid_ndr_upsert_env "$env_file" DEPLOYMENT_ID "$deployment_id"

  # Local identity environment: the local API serves the JWKS and issues
  # short-lived analyst tokens; the connector and vendor Logto stay disabled.
  hybrid_ndr_upsert_env "$env_file" AUTH_ISSUER "https://$lan_host/oidc"
  hybrid_ndr_upsert_env "$env_file" AUTH_JWKS_URL "https://$lan_host/api/v1/system/jwks"
  hybrid_ndr_upsert_env "$env_file" AUTH_ALLOWED_ORGANIZATION_IDS standalone
  hybrid_ndr_upsert_env "$env_file" LOGTO_ENDPOINT "https://$lan_host"
  hybrid_ndr_upsert_env "$env_file" LOGTO_PUBLIC_ENDPOINT "https://$lan_host"
  hybrid_ndr_upsert_env "$env_file" LOGTO_DASHBOARD_CLIENT_ID local-standalone
  hybrid_ndr_upsert_env "$env_file" LOGTO_ORGANIZATION_ID standalone
  hybrid_ndr_upsert_env "$env_file" LOGTO_DASHBOARD_SCOPES "openid profile urn:logto:scope:organizations urn:logto:scope:organization_roles"
  hybrid_ndr_upsert_env "$env_file" CONNECTOR_ENABLED false
  hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_URL ""
  hybrid_ndr_upsert_env "$env_file" AUTH_STANDALONE_ISSUER_KEY_FILE /var/lib/hybrid-ndr/identity/local-issuer-key.pem
  hybrid_ndr_upsert_env "$env_file" AUTH_STANDALONE_JWKS_FILE /var/lib/hybrid-ndr/identity/local-jwks.json
  standalone_login_secret_file="$config_dir/secrets/standalone-login-secret"
  if [[ ! -s "$standalone_login_secret_file" ]]; then
    hybrid_ndr_random_hex 32 >"$standalone_login_secret_file"
    hybrid_ndr_secure_file "$standalone_login_secret_file"
  fi
  standalone_login_secret=$(<"$standalone_login_secret_file")
  hybrid_ndr_upsert_env "$env_file" AUTH_STANDALONE_LOGIN_SECRET "$standalone_login_secret"
else
  [[ -n "$control_plane_url" ]] || hybrid_ndr_die "--control-plane-url is required for initial enrollment"
  if [[ "$control_plane_url" == https://* ]]; then
    :
  elif (( allow_insecure_control_plane == 1 )) && [[ "$control_plane_url" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]]; then
    hybrid_ndr_warn "using an insecure loopback control-plane endpoint for local development"
  else
    hybrid_ndr_die "the control-plane URL must use HTTPS (HTTP is permitted only for explicit loopback development)"
  fi
  control_plane_url=${control_plane_url%/}
  hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_URL "$control_plane_url"

  work_dir=$(mktemp -d "$identity_dir/.enrollment.XXXXXX")
  chmod 0700 -- "$work_dir"
  token_work_file="$work_dir/token"
  if [[ -n "$enrollment_token_file" ]]; then
    enrollment_token_file=$(realpath -- "$enrollment_token_file")
    [[ -f "$enrollment_token_file" && ! -L "$enrollment_token_file" ]] || hybrid_ndr_die "enrollment token must be a regular non-symlink file"
    token_mode=$(stat -c '%a' -- "$enrollment_token_file")
    (( (8#$token_mode & 077) == 0 )) || hybrid_ndr_die "enrollment token file must not be readable by group or others"
    cp -- "$enrollment_token_file" "$token_work_file"
    remove_token_after_success=$enrollment_token_file
  elif (( token_from_stdin == 1 )); then
    IFS= read -r token_line || hybrid_ndr_die "could not read enrollment token from stdin"
    printf '%s\n' "$token_line" >"$token_work_file"
    unset token_line
  elif [[ -n "$legacy_token" ]]; then
    printf '%s\n' "$legacy_token" >"$token_work_file"
    unset legacy_token
  else
    hybrid_ndr_die "initial enrollment requires --enrollment-token-file or --enrollment-token-stdin"
  fi
  chmod 0600 -- "$token_work_file"

  idempotency_file="$identity_dir/enrollment-idempotency-key"
  if [[ ! -s "$idempotency_file" ]]; then
    hybrid_ndr_random_hex 16 >"$idempotency_file"
  fi
  hybrid_ndr_secure_file "$idempotency_file"
  idempotency_key=$(<"$idempotency_file")
  [[ "$idempotency_key" =~ ^[0-9a-f]{32}$ ]] || hybrid_ndr_die "stored enrollment idempotency key is invalid"

  request_file="$work_dir/request.json"
  response_file="$work_dir/response.json"
  python3 "$project_dir/installer/process-enrollment.py" request "$token_work_file" "$csr_file" "$request_file"
  curl_args=(--silent --show-error --request POST
    --connect-timeout 15 --max-time 60
    --header 'Content-Type: application/json'
    --header "Idempotency-Key: $idempotency_key"
    --data-binary "@$request_file"
    --output "$response_file"
    --write-out '%{http_code}')
  if [[ "$control_plane_url" == https://* ]]; then
    curl_args+=(--proto '=https' --tlsv1.2)
  fi
  if [[ -n "$control_plane_ca" ]]; then
    control_plane_ca=$(realpath -- "$control_plane_ca")
    [[ -f "$control_plane_ca" && ! -L "$control_plane_ca" ]] || hybrid_ndr_die "control-plane CA must be a regular non-symlink file"
    curl_args+=(--cacert "$control_plane_ca")
  fi
  http_status=$(curl "${curl_args[@]}" "$control_plane_url/v1/enrollment/exchange") || hybrid_ndr_die "enrollment exchange could not reach the control plane"
  [[ "$http_status" =~ ^2[0-9][0-9]$ ]] || hybrid_ndr_die "enrollment exchange failed with HTTP status $http_status"
  staged_identity="$work_dir/issued"
  python3 "$project_dir/installer/process-enrollment.py" persist "$response_file" "$staged_identity"
  staged_certificate="$staged_identity/deployment-cert.pem"

  if openssl x509 -in "$staged_certificate" -noout >/dev/null 2>&1; then
    key_public_hash=$(openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    cert_public_hash=$(openssl x509 -in "$staged_certificate" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    [[ "$key_public_hash" == "$cert_public_hash" ]] || hybrid_ndr_die "issued deployment certificate does not match the local private key"
  elif (( allow_insecure_control_plane == 1 )); then
    hybrid_ndr_warn "development control plane returned a non-X.509 demo certificate"
  else
    hybrid_ndr_die "control plane returned an invalid X.509 certificate"
  fi

  for identity_name in deployment-cert.pem certificate-fingerprint tenant-id deployment-id enrollment.json; do
    install -m 0600 -- "$staged_identity/$identity_name" "$identity_dir/$identity_name"
  done

  tenant_id=$(<"$identity_dir/tenant-id")
  deployment_id=$(<"$identity_dir/deployment-id")
  hybrid_ndr_validate_identifier "$tenant_id" || hybrid_ndr_die "persisted tenant identifier is invalid"
  hybrid_ndr_validate_identifier "$deployment_id" || hybrid_ndr_die "persisted deployment identifier is invalid"
  hybrid_ndr_upsert_env "$env_file" TENANT_ID "$tenant_id"
  hybrid_ndr_upsert_env "$env_file" DEPLOYMENT_ID "$deployment_id"

  rm -f -- "$token_work_file" "$request_file" "$response_file"
  if [[ -n "$remove_token_after_success" ]]; then
    rm -f -- "$remove_token_after_success"
    hybrid_ndr_log "single-use enrollment token consumed and its source file removed"
  fi
  hybrid_ndr_log "deployment enrollment completed"
fi

# Identity bootstrap data is signed into the one-time enrollment response by
# the vendor control plane. Revalidate the persisted metadata on every install
# or upgrade, then copy only the fixed OIDC keys understood by the customer
# services into Compose's environment file. Standalone deployments already
# wrote their local identity environment and skip this vendor-only step.
if (( standalone != 1 )); then
identity_environment="$identity_dir/logto.env"
python3 "$project_dir/installer/process-enrollment.py" render-identity-env \
  "$identity_dir/enrollment.json" "$identity_environment"
identity_environment_count=0
while IFS='=' read -r identity_key identity_value; do
  case "$identity_key" in
    AUTH_ISSUER|AUTH_JWKS_URL|AUTH_ALLOWED_ORGANIZATION_IDS|LOGTO_ENDPOINT|LOGTO_PUBLIC_ENDPOINT|LOGTO_DASHBOARD_CLIENT_ID|LOGTO_ORGANIZATION_ID|LOGTO_DASHBOARD_SCOPES)
      hybrid_ndr_upsert_env "$env_file" "$identity_key" "$identity_value"
      identity_environment_count=$((identity_environment_count + 1))
      ;;
    *) hybrid_ndr_die "enrollment identity environment contains an unexpected key" ;;
  esac
done <"$identity_environment"
(( identity_environment_count == 8 )) || hybrid_ndr_die "enrollment identity environment is incomplete"
fi

# The enrollment channel provisions the release-verification key once. Pin its
# DER digest in the root-owned configuration directory so a changed identity
# document cannot silently replace update trust on a later upgrade.
update_signing_key="$identity_dir/update-signing-public.pem"
if [[ ! -s "$update_signing_key" ]]; then
  python3 "$project_dir/installer/process-enrollment.py" render-update-key \
    "$identity_dir/enrollment.json" "$update_signing_key"
fi
hybrid_ndr_secure_file "$update_signing_key"
update_key_text=$(openssl pkey -pubin -in "$update_signing_key" -text -noout 2>&1) || hybrid_ndr_die "enrollment update-signing public key is invalid"
[[ "$update_key_text" == *prime256v1* || "$update_key_text" == *P-256* ]] || hybrid_ndr_die "update-signing public key must use ECDSA P-256"
update_key_sha256=$(openssl pkey -pubin -in "$update_signing_key" -outform DER | sha256sum | awk '{print $1}')
update_key_pin="$config_dir/update-signing-key.sha256"
if [[ -s "$update_key_pin" ]]; then
  persisted_update_key_sha256=$(<"$update_key_pin")
  [[ "$persisted_update_key_sha256" == "$update_key_sha256" ]] || hybrid_ndr_die "update-signing public key does not match the customer trust pin"
else
  temporary_update_key_pin=$(mktemp "$config_dir/.update-signing-key.XXXXXX")
  chmod 0600 -- "$temporary_update_key_pin"
  printf '%s\n' "$update_key_sha256" >"$temporary_update_key_pin"
  mv -- "$temporary_update_key_pin" "$update_key_pin"
fi
hybrid_ndr_secure_file "$update_key_pin"

# Persist an explicitly supplied private CA inside the connector's read-only
# identity mount. It is never fetched from the control plane it authenticates.
if [[ -n "$control_plane_ca" ]]; then
  control_plane_ca=$(realpath -- "$control_plane_ca")
  [[ -f "$control_plane_ca" && ! -L "$control_plane_ca" ]] || hybrid_ndr_die "control-plane CA must be a regular non-symlink file"
  openssl crl2pkcs7 -nocrl -certfile "$control_plane_ca" 2>/dev/null | openssl pkcs7 -print_certs -noout >/dev/null 2>&1 || hybrid_ndr_die "control-plane CA bundle is invalid"
  install -m 0600 -- "$control_plane_ca" "$identity_dir/control-plane-ca.pem"
  hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_CA_FILE /var/lib/hybrid-ndr/identity/control-plane-ca.pem
elif [[ -f "$identity_dir/control-plane-ca.pem" ]]; then
  hybrid_ndr_upsert_env "$env_file" CONTROL_PLANE_CA_FILE /var/lib/hybrid-ndr/identity/control-plane-ca.pem
fi

# The connector image runs as this unprivileged UID/GID. Keeping the private
# directory mode 0700 and files mode 0600 prevents access by other host users.
if (( EUID == 0 )); then
  chown -R 65532:65532 -- "$identity_dir"
  chown 65532:65532 -- "$state_dir/updates"
else
  hybrid_ndr_warn "not running as root; retained current identity ownership for development"
fi

if [[ -f "$config_dir/install-state" ]]; then
  installed_version=$(awk -F= '$1 == "VERSION" {print substr($0, index($0, "=") + 1); exit}' "$config_dir/install-state")
  if [[ -n "$installed_version" && "$installed_version" != "$release_version" && "$allow_downgrade" != 1 ]]; then
    first_version=$(printf '%s\n%s\n' "$installed_version" "$release_version" | sort -V | head -n 1)
    [[ "$first_version" == "$installed_version" ]] || hybrid_ndr_die "refusing downgrade from $installed_version to $release_version without --allow-downgrade"
  fi
fi

compose=()
compose_overrides=()
[[ -z "$release_compose_file" ]] || compose_overrides+=("$release_compose_file")
internal_tls_compose_file="$(dirname -- "$compose_file")/docker-compose.internal-tls.yml"
[[ -f "$internal_tls_compose_file" && ! -L "$internal_tls_compose_file" ]] || hybrid_ndr_die "internal TLS Compose overlay is missing or is a symlink"
compose_overrides+=("$internal_tls_compose_file")
compose_overrides+=("$https_compose_file")
hybrid_ndr_compose_base compose "$project_dir" "$compose_file" "$env_file" "$compose_project" "${compose_overrides[@]}"
services=$(hybrid_ndr_customer_services compose)
hybrid_ndr_require_https_ingress "$services"
hybrid_ndr_log "validated customer-only profile ($(wc -w <<<"$services") services)"

if [[ -n "$offline_images" ]]; then
  hybrid_ndr_log "loading verified offline container images"
  docker image load --input "$offline_images" >/dev/null
  "${compose[@]}" up --detach --no-build --pull never --remove-orphans
else
  "${compose[@]}" pull --ignore-buildable
  "${compose[@]}" up --detach --build --pull missing --remove-orphans
fi

health_arguments=(
  --project-dir "$project_dir"
  --compose-file "$compose_file"
  --https-compose-file "$https_compose_file"
  --env-file "$env_file"
  --project-name "$compose_project"
  --timeout "$health_timeout"
)
[[ -z "$release_compose_file" ]] || health_arguments+=(--release-compose-file "$release_compose_file")
"$script_dir/post-install-health.sh" "${health_arguments[@]}"

temporary_state=$(mktemp "$config_dir/.install-state.XXXXXX")
chmod 0600 -- "$temporary_state"
{
  printf 'VERSION=%s\n' "$release_version"
  printf 'PROJECT_DIR=%s\n' "$project_dir"
  printf 'COMPOSE_FILE=%s\n' "$compose_file"
  printf 'HTTPS_COMPOSE_FILE=%s\n' "$https_compose_file"
  printf 'RELEASE_COMPOSE_FILE=%s\n' "$release_compose_file"
  # Persist the verified offline image archive so the update agent can reload
  # exactly these images when it automatically rolls back a failed candidate.
  printf 'IMAGES_FILE=%s\n' "${offline_images:-}"
  printf 'IMAGES_SHA256=%s\n' "${offline_images_sha256,,}"
  printf 'COMPOSE_PROJECT=%s\n' "$compose_project"
  printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$temporary_state"
mv -- "$temporary_state" "$config_dir/install-state"
hybrid_ndr_secure_file "$config_dir/install-state"

hybrid_ndr_log "customer-resident deployment $release_version is installed and healthy"
hybrid_ndr_log "configuration: $config_dir; customer data: $state_dir"
