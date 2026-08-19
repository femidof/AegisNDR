#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: verify-release.sh [--public-key FILE] RELEASE CHECKSUM_FILE SIGNATURE_FILE

PRODUCT_RELEASE_PUBLIC_KEY defaults to /etc/hybrid-ndr/trust/release-public.pem.
Set PRODUCT_RELEASE_PUBLIC_KEY_SHA256 to pin the SHA-256 of the public key's DER form.
EOF
}

public_key_path=${PRODUCT_RELEASE_PUBLIC_KEY:-/etc/hybrid-ndr/trust/release-public.pem}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) [[ $# -ge 2 ]] || { usage; exit 2; }; public_key_path=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    --) shift; break ;;
    -*) usage; exit 2 ;;
    *) break ;;
  esac
done

[[ $# -eq 3 ]] || { usage; exit 2; }
for command_name in openssl sha256sum realpath awk wc; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "missing required command: $command_name" >&2; exit 1; }
done

release_path=$(realpath -- "$1")
checksum_path=$(realpath -- "$2")
signature_path=$(realpath -- "$3")
public_key_path=$(realpath -- "$public_key_path")

[[ -f "$release_path" && ! -L "$release_path" ]] || { echo "release must be a regular non-symlink file" >&2; exit 1; }
[[ -f "$checksum_path" && ! -L "$checksum_path" ]] || { echo "checksum must be a regular non-symlink file" >&2; exit 1; }
[[ -f "$signature_path" && ! -L "$signature_path" ]] || { echo "signature must be a regular non-symlink file" >&2; exit 1; }
[[ -f "$public_key_path" && ! -L "$public_key_path" ]] || { echo "trusted public key must be a regular non-symlink file" >&2; exit 1; }

release_name=$(basename -- "$release_path")
[[ "$release_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$ ]] || { echo "release filename is not permitted" >&2; exit 1; }
[[ $(wc -l <"$checksum_path") -eq 1 ]] || { echo "checksum file must contain exactly one record" >&2; exit 1; }
checksum_record=$(<"$checksum_path")
[[ "$checksum_record" =~ ^([0-9a-fA-F]{64})\ \ ([A-Za-z0-9][A-Za-z0-9._-]{0,200})$ ]] || { echo "checksum record has an invalid format" >&2; exit 1; }
expected_hash=${BASH_REMATCH[1],,}
expected_name=${BASH_REMATCH[2]}
[[ "$expected_name" == "$release_name" ]] || { echo "checksum record does not name the selected release" >&2; exit 1; }
actual_hash=$(sha256sum -- "$release_path" | awk '{print $1}')
[[ "$actual_hash" == "$expected_hash" ]] || { echo "release checksum verification failed" >&2; exit 1; }

openssl pkey -pubin -in "$public_key_path" -noout >/dev/null 2>&1 || { echo "trusted release public key is invalid" >&2; exit 1; }
if [[ -n "${PRODUCT_RELEASE_PUBLIC_KEY_SHA256:-}" ]]; then
  [[ "$PRODUCT_RELEASE_PUBLIC_KEY_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "PRODUCT_RELEASE_PUBLIC_KEY_SHA256 is invalid" >&2; exit 1; }
  public_key_hash=$(openssl pkey -pubin -in "$public_key_path" -outform DER | sha256sum | awk '{print $1}')
  [[ "$public_key_hash" == "${PRODUCT_RELEASE_PUBLIC_KEY_SHA256,,}" ]] || { echo "release public key pin verification failed" >&2; exit 1; }
fi

openssl dgst -sha256 -verify "$public_key_path" -signature "$signature_path" "$release_path" >/dev/null || {
  echo "release signature verification failed" >&2
  exit 1
}
echo "release verified: $release_name"
