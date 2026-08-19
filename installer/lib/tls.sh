#!/usr/bin/env bash

# Private-LAN HTTPS certificate helpers. This file is sourced after common.sh;
# callers enable strict mode and create the private configuration directory.

hybrid_ndr_normalize_lan_host() {
  python3 - "$1" <<'PY'
import ipaddress
import re
import sys

value = sys.argv[1].strip().lower()
if not value or len(value) > 253 or value.endswith("."):
    raise SystemExit(1)
try:
    address = ipaddress.ip_address(value)
except ValueError:
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise SystemExit(1)
else:
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise SystemExit(1)
print(value)
PY
}

hybrid_ndr_lan_san() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
try:
    ipaddress.IPv4Address(value)
except ValueError:
    print(f"DNS:{value}")
else:
    print(f"IP:{value}")
PY
}

hybrid_ndr_validate_tls_pair() {
  local certificate=$1 private_key=$2 lan_host=$3 ca_file=${4:-}
  local key_hash certificate_hash

  [[ -f "$certificate" && ! -L "$certificate" ]] || hybrid_ndr_die "TLS certificate must be a regular non-symlink file"
  [[ -f "$private_key" && ! -L "$private_key" ]] || hybrid_ndr_die "TLS private key must be a regular non-symlink file"
  openssl x509 -in "$certificate" -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS certificate is not valid PEM X.509"
  openssl pkey -in "$private_key" -passin pass: -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS private key must be valid, PEM encoded, and unencrypted"
  openssl x509 -in "$certificate" -checkend 86400 -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS certificate is expired or expires within 24 hours"

  if [[ "$(hybrid_ndr_lan_san "$lan_host")" == IP:* ]]; then
    openssl x509 -in "$certificate" -checkip "$lan_host" -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS certificate does not cover LAN IP $lan_host"
  else
    openssl x509 -in "$certificate" -checkhost "$lan_host" -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS certificate does not cover LAN hostname $lan_host"
  fi

  key_hash=$(openssl pkey -in "$private_key" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  certificate_hash=$(openssl x509 -in "$certificate" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$key_hash" && "$key_hash" == "$certificate_hash" ]] || hybrid_ndr_die "TLS certificate does not match its private key"

  if [[ -n "$ca_file" ]]; then
    [[ -f "$ca_file" && ! -L "$ca_file" ]] || hybrid_ndr_die "TLS CA bundle must be a regular non-symlink file"
    openssl crl2pkcs7 -nocrl -certfile "$ca_file" 2>/dev/null | openssl pkcs7 -print_certs -noout >/dev/null 2>&1 || hybrid_ndr_die "TLS CA bundle is invalid"
    openssl verify -CAfile "$ca_file" "$certificate" >/dev/null 2>&1 || hybrid_ndr_die "TLS certificate does not verify against the supplied CA bundle"
  fi
}

hybrid_ndr_atomic_copy() {
  local source=$1 destination=$2 mode=${3:-0600}
  local temporary
  temporary=$(mktemp "$(dirname -- "$destination")/.${destination##*/}.XXXXXX")
  install -m "$mode" -- "$source" "$temporary"
  mv -f -- "$temporary" "$destination"
  chmod "$mode" -- "$destination"
}

hybrid_ndr_generate_tls_leaf() {
  local tls_dir=$1 lan_host=$2 ca_key=$3 ca_certificate=$4
  local work_dir san extension_file

  work_dir=$(mktemp -d "$tls_dir/.tls-generation.XXXXXX")
  chmod 0700 -- "$work_dir"
  san=$(hybrid_ndr_lan_san "$lan_host")
  extension_file="$work_dir/server-extensions.cnf"
  {
    printf '[server_ext]\n'
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature,keyEncipherment\n'
    printf 'extendedKeyUsage=serverAuth\n'
    printf 'subjectAltName=%s\n' "$san"
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid,issuer\n'
  } >"$extension_file"
  chmod 0600 -- "$extension_file"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work_dir/server-key.pem" >/dev/null 2>&1
  openssl req -new -sha256 -key "$work_dir/server-key.pem" -subj "/CN=$lan_host" -out "$work_dir/server.csr.pem"
  openssl x509 -req -sha256 -days 825 \
    -in "$work_dir/server.csr.pem" \
    -CA "$ca_certificate" -CAkey "$ca_key" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -extfile "$extension_file" -extensions server_ext \
    -out "$work_dir/server-cert.pem"

  hybrid_ndr_validate_tls_pair "$work_dir/server-cert.pem" "$work_dir/server-key.pem" "$lan_host" "$ca_certificate"
  hybrid_ndr_atomic_copy "$work_dir/server-key.pem" "$tls_dir/server-key.pem"
  hybrid_ndr_atomic_copy "$work_dir/server-cert.pem" "$tls_dir/server-cert.pem"
  rm -rf -- "$work_dir"
}

hybrid_ndr_prepare_tls() {
  local tls_dir=$1 lan_host=$2 supplied_certificate=${3:-} supplied_key=${4:-} supplied_ca=${5:-}
  local ca_key="$tls_dir/ca-key.pem" ca_certificate="$tls_dir/ca-cert.pem"
  local server_key="$tls_dir/server-key.pem" server_certificate="$tls_dir/server-cert.pem"
  local source_file="$tls_dir/certificate-source" source_type="" validation_ca="" work_dir

  hybrid_ndr_secure_directory "$tls_dir"
  if [[ -n "$supplied_certificate" || -n "$supplied_key" || -n "$supplied_ca" ]]; then
    [[ -n "$supplied_certificate" && -n "$supplied_key" ]] || hybrid_ndr_die "--tls-cert and --tls-key must be supplied together"
    [[ -f "$supplied_certificate" && ! -L "$supplied_certificate" ]] || hybrid_ndr_die "TLS certificate must be a regular non-symlink file"
    [[ -f "$supplied_key" && ! -L "$supplied_key" ]] || hybrid_ndr_die "TLS private key must be a regular non-symlink file"
    [[ -z "$supplied_ca" || ( -f "$supplied_ca" && ! -L "$supplied_ca" ) ]] || hybrid_ndr_die "TLS CA bundle must be a regular non-symlink file"
    supplied_certificate=$(realpath -- "$supplied_certificate")
    supplied_key=$(realpath -- "$supplied_key")
    [[ -z "$supplied_ca" ]] || supplied_ca=$(realpath -- "$supplied_ca")
    hybrid_ndr_validate_tls_pair "$supplied_certificate" "$supplied_key" "$lan_host" "$supplied_ca"
    hybrid_ndr_atomic_copy "$supplied_certificate" "$server_certificate"
    hybrid_ndr_atomic_copy "$supplied_key" "$server_key"
    if [[ -n "$supplied_ca" ]]; then
      hybrid_ndr_atomic_copy "$supplied_ca" "$ca_certificate"
      source_type=supplied-ca
      validation_ca=$ca_certificate
    else
      # With no private CA bundle, post-install health uses the host's public CA
      # trust. The certificate file may still contain its intermediate chain.
      source_type=supplied-system-trust
    fi
    printf '%s\n' "$source_type" >"$source_file"
    chmod 0600 -- "$source_file"
  elif [[ -s "$server_certificate" && -s "$server_key" ]]; then
    source_type=$(<"$source_file")
    case "$source_type" in
      generated|supplied-ca) validation_ca=$ca_certificate ;;
      supplied-system-trust) validation_ca="" ;;
      *) hybrid_ndr_die "stored TLS certificate source metadata is invalid" ;;
    esac
    if (hybrid_ndr_validate_tls_pair "$server_certificate" "$server_key" "$lan_host" "$validation_ca") 2>/dev/null; then
      :
    elif [[ "$source_type" == generated && -s "$ca_key" && -s "$ca_certificate" ]]; then
      hybrid_ndr_log "renewing the generated LAN certificate for $lan_host"
      hybrid_ndr_generate_tls_leaf "$tls_dir" "$lan_host" "$ca_key" "$ca_certificate"
    else
      hybrid_ndr_die "stored supplied TLS material is invalid for $lan_host; provide a replacement with --tls-cert and --tls-key"
    fi
  else
    work_dir=$(mktemp -d "$tls_dir/.tls-ca-generation.XXXXXX")
    chmod 0700 -- "$work_dir"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work_dir/ca-key.pem" >/dev/null 2>&1
    openssl req -x509 -new -sha256 -days 3650 \
      -key "$work_dir/ca-key.pem" \
      -subj '/CN=Hybrid NDR Private LAN CA' \
      -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' \
      -addext 'subjectKeyIdentifier=hash' \
      -out "$work_dir/ca-cert.pem"
    hybrid_ndr_atomic_copy "$work_dir/ca-key.pem" "$ca_key"
    hybrid_ndr_atomic_copy "$work_dir/ca-cert.pem" "$ca_certificate"
    rm -rf -- "$work_dir"
    hybrid_ndr_generate_tls_leaf "$tls_dir" "$lan_host" "$ca_key" "$ca_certificate"
    printf 'generated\n' >"$source_file"
    chmod 0600 -- "$source_file"
    source_type=generated
    validation_ca=$ca_certificate
    hybrid_ndr_log "generated a private LAN CA and HTTPS certificate for $lan_host"
  fi

  [[ -n "$source_type" ]] || source_type=$(<"$source_file")
  if [[ -z "$validation_ca" && "$source_type" != supplied-system-trust ]]; then
    validation_ca=$ca_certificate
  fi
  hybrid_ndr_validate_tls_pair "$server_certificate" "$server_key" "$lan_host" "$validation_ca"
  hybrid_ndr_secure_file "$server_key"
  hybrid_ndr_secure_file "$server_certificate"
  [[ ! -s "$validation_ca" ]] || hybrid_ndr_secure_file "$validation_ca"
}

hybrid_ndr_tls_health_ca() {
  local tls_dir=$1 source_type
  source_type=$(<"$tls_dir/certificate-source")
  case "$source_type" in
    generated|supplied-ca) printf '%s\n' "$tls_dir/ca-cert.pem" ;;
    supplied-system-trust) ;;
    *) hybrid_ndr_die "stored TLS certificate source metadata is invalid" ;;
  esac
}
