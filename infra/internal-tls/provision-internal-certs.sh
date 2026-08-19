#!/usr/bin/env bash
set -euo pipefail

# Generate a private internal CA and server certificates for the customer data
# plane (PostgreSQL, ClickHouse, MinIO) so every internal credential-bearing
# hop is TLS-encrypted and verified by clients that pin the internal CA.
#
# Usage:
#   bash infra/internal-tls/provision-internal-certs.sh OUTPUT_DIR

output_dir=${1:?usage: provision-internal-certs.sh OUTPUT_DIR}
mkdir -p "$output_dir"

if [[ -s "$output_dir/ca-cert.pem" && -s "$output_dir/postgres-cert.pem" \
      && -s "$output_dir/clickhouse-cert.pem" && -s "$output_dir/minio-cert.pem" ]]; then
  echo "internal TLS material already present in $output_dir (reusing stable CA)"
  exit 0
fi

work=$(mktemp -d "$output_dir/.internal-tls.XXXXXX")
chmod 0700 "$work"

trap 'rm -rf -- "$work"' EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/ca-key.pem" >/dev/null 2>&1
openssl req -x509 -new -sha256 -days 3650 \
  -key "$work/ca-key.pem" \
  -subj '/CN=Hybrid NDR Internal Data Plane CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out "$work/ca-cert.pem"

issue() {
  local service=$1
  local key="$work/$service-key.pem"
  local csr="$work/$service.csr"
  local cert="$work/$service-cert.pem"
  local extensions="$work/$service-ext.cnf"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key" >/dev/null 2>&1
  openssl req -new -sha256 -key "$key" -subj "/CN=$service" -out "$csr"
  {
    printf '[server]\n'
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' "$service"
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid,issuer\n'
  } >"$extensions"
  openssl x509 -req -sha256 -days 825 \
    -in "$csr" -CA "$work/ca-cert.pem" -CAkey "$work/ca-key.pem" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -extfile "$extensions" -extensions server \
    -out "$cert"
}

for service in postgres clickhouse minio; do
  issue "$service"
done

install -m 0644 "$work/ca-cert.pem" "$output_dir/ca-cert.pem"
for service in postgres clickhouse minio; do
  install -m 0640 "$work/$service-key.pem" "$output_dir/$service-key.pem"
  install -m 0644 "$work/$service-cert.pem" "$output_dir/$service-cert.pem"
done

echo "internal TLS material written to $output_dir (CA + postgres/clickhouse/minio certs)"
