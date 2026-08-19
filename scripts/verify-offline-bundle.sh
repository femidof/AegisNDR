#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd "$script_dir/.." && pwd)
public_key=""
extract_to=""

usage() {
  echo "usage: $0 --public-key FILE [--extract-to EMPTY_DIR] BUNDLE CHECKSUM SIGNATURE" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key) public_key=${2:?}; shift 2 ;;
    --extract-to) extract_to=${2:?}; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    -*) usage; exit 2 ;;
    *) break ;;
  esac
done
[[ $# -eq 3 && -n "$public_key" ]] || { usage; exit 2; }
bundle=$1
checksum=$2
signature=$3

# Verification happens before extraction and this script never elevates privileges.
"$project_dir/installer/verify-release.sh" --public-key "$public_key" "$bundle" "$checksum" "$signature"
arguments=("$bundle")
[[ -n "$extract_to" ]] && arguments+=(--extract-to "$extract_to")
python3 "$project_dir/installer/verify-bundle.py" "${arguments[@]}"
