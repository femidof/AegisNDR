#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
default_source=$(cd "$script_dir/.." && pwd)
source_dir=$default_source
output_dir=""
version=""
signing_key=""
skip_images=0
force=0
source_date_epoch=${SOURCE_DATE_EPOCH:-0}

usage() {
  cat <<'EOF'
Usage: build-offline-bundle.sh --output-dir DIR --version X.Y.Z --signing-key FILE [options]

Options:
  --source-dir DIR   Release source (default: repository root)
  --skip-images      Build a code-only test bundle; not suitable for offline install
  --force            Replace artifacts of the same version
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir) source_dir=${2:?}; shift 2 ;;
    --output-dir) output_dir=${2:?}; shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --signing-key) signing_key=${2:?}; shift 2 ;;
    --skip-images) skip_images=1; shift ;;
    --force) force=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$output_dir" && -n "$version" && -n "$signing_key" ]] || { usage >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo "invalid release version" >&2; exit 1; }
source_dir=$(realpath -- "$source_dir")
signing_key=$(realpath -- "$signing_key")
output_dir=$(realpath -m -- "$output_dir")
[[ -f "$source_dir/installer/install.sh" && -f "$source_dir/infra/compose/docker-compose.yml" && -f "$source_dir/infra/compose/docker-compose.https.yml" ]] || { echo "source is not a Hybrid NDR release tree" >&2; exit 1; }
[[ -f "$signing_key" && ! -L "$signing_key" ]] || { echo "signing key must be a regular non-symlink file" >&2; exit 1; }
openssl pkey -in "$signing_key" -noout >/dev/null 2>&1 || { echo "signing key is invalid" >&2; exit 1; }

mkdir -p -- "$output_dir"
bundle_name="hybrid-ndr-${version}-offline.tar.gz"
bundle_path="$output_dir/$bundle_name"
checksum_path="$bundle_path.sha256"
signature_path="$bundle_path.sig"
if (( force == 0 )) && [[ -e "$bundle_path" || -e "$checksum_path" || -e "$signature_path" ]]; then
  echo "release artifacts already exist; use --force to replace this exact version" >&2
  exit 1
fi

work_dir=$(mktemp -d)
cleanup() {
  [[ -n "${work_dir:-}" && -d "$work_dir" && "$work_dir" == /tmp/* ]] && rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM
payload_dir="$work_dir/bundle/payload/hybrid-ndr"
mkdir -p -- "$payload_dir"

tar -C "$source_dir" \
  --exclude='./.git' \
  --exclude='./.data' \
  --exclude='./.runtime' \
  --exclude='./.env' \
  --exclude='./node_modules' \
  --exclude='./dist' \
  --exclude='./runtime' \
  --exclude='./infra/compose/.env' \
  --exclude='./infra/compose/secrets' \
  --exclude='*/secrets' \
  --exclude='*/__pycache__' \
  --exclude='*.key' \
  --exclude='*.p12' \
  --exclude='*.pfx' \
  --exclude='*.token' \
  --exclude='*.pyc' \
  -cf - . | tar -C "$payload_dir" -xf -
printf '%s\n' "$version" >"$payload_dir/RELEASE_VERSION"

images_included=false
images_sha256=""
image_services_file="$work_dir/image-services.json"
image_sboms_file="$work_dir/image-sboms.json"
printf '{}\n' >"$image_services_file"
printf '[]\n' >"$image_sboms_file"
if (( skip_images == 0 )); then
  # shellcheck source=../installer/lib/common.sh
  source "$source_dir/installer/lib/common.sh"
  env_file="$source_dir/infra/compose/.env.example"
  [[ -f "$env_file" ]] || { echo "Compose environment example is missing" >&2; exit 1; }
  compose=()
  hybrid_ndr_compose_base compose "$source_dir" "$source_dir/infra/compose/docker-compose.yml" "$env_file" hybrid-ndr-customer "$source_dir/infra/compose/docker-compose.https.yml"
  services=$(hybrid_ndr_customer_services compose)
  hybrid_ndr_require_https_ingress "$services"
  "${compose[@]}" pull --ignore-buildable
  "${compose[@]}" build --pull
  compose_config="$work_dir/customer-compose.json"
  "${compose[@]}" config --format json >"$compose_config"
  python3 - "$compose_config" "$payload_dir/infra/compose/docker-compose.release.yml" "$image_services_file" "$work_dir/images.list" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

config_path, override_path, mapping_path, list_path = map(Path, sys.argv[1:])
configuration = json.loads(config_path.read_text(encoding="utf-8"))
services = configuration.get("services")
if not isinstance(services, dict) or not services:
    raise SystemExit("customer Compose configuration has no services")
mapping = {}
images = set()
buildable = set()
for service, body in sorted(services.items()):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", service) or not isinstance(body, dict):
        raise SystemExit("customer Compose service metadata is invalid")
    image = body.get("image")
    if not isinstance(image, str) or not image or any(character.isspace() for character in image):
        raise SystemExit(f"customer service {service} has no concrete image")
    inspected = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", inspected):
        raise SystemExit(f"customer service {service} did not resolve to a local content digest")
    mapping[service] = inspected
    images.add(image)
    if "build" in body:
        buildable.add(service)

lines = ["# Generated only inside a signed image-bearing release bundle.", "services:"]
for service, digest in mapping.items():
    lines.extend((f"  {service}:", f"    image: {digest}"))
    if service in buildable:
        lines.append("    build: !reset null")
override_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
mapping_path.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
list_path.write_text("\n".join(sorted(images)) + "\n", encoding="utf-8")
PY
  mapfile -t images <"$work_dir/images.list"
  (( ${#images[@]} > 0 )) || { echo "customer profile resolved no images" >&2; exit 1; }
  for image in "${images[@]}"; do
    docker image inspect "$image" >/dev/null
  done
  docker image save --output "$work_dir/bundle/images.tar" "${images[@]}"
  images_sha256=$(sha256sum "$work_dir/bundle/images.tar" | awk '{print $1}')
  command -v syft >/dev/null 2>&1 || { echo "syft is required to generate image SBOMs for a production bundle" >&2; exit 1; }
  mkdir -p -- "$work_dir/bundle/sbom/images"
  python3 - "$image_services_file" "$work_dir/unique-image-digests.list" <<'PY'
import json
import sys
from pathlib import Path

mapping = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text("\n".join(sorted(set(mapping.values()))) + "\n", encoding="ascii")
PY
  while IFS= read -r image_digest; do
    [[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid local image digest" >&2; exit 1; }
    image_hex=${image_digest#sha256:}
    syft "$image_digest" -o "cyclonedx-json=$work_dir/bundle/sbom/images/$image_hex.cdx.json" >/dev/null
  done <"$work_dir/unique-image-digests.list"
  python3 - "$work_dir/bundle/sbom/images" "$image_sboms_file" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

directory, output = map(Path, sys.argv[1:])
records = []
for path in sorted(directory.glob("*.cdx.json")):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    records.append({
        "image": "sha256:" + path.name.removesuffix(".cdx.json"),
        "path": "sbom/images/" + path.name,
        "sha256": digest,
        "format": "CycloneDX-1.6",
    })
output.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  images_included=true
else
  echo "warning: building a code-only bundle without container images" >&2
fi

mkdir -p -- "$work_dir/bundle/sbom"
python3 "$script_dir/generate-sbom.py" \
  --source "$payload_dir" \
  --output "$work_dir/bundle/sbom/source.cdx.json" \
  --version "$version"
source_sbom_sha256=$(sha256sum "$work_dir/bundle/sbom/source.cdx.json" | awk '{print $1}')

python3 - "$work_dir/bundle/BUNDLE-MANIFEST.json" "$version" "$images_included" "$images_sha256" "$source_sbom_sha256" "$image_services_file" "$image_sboms_file" <<'PY'
import datetime
import json
import sys

path, version, included, digest, source_sbom_digest, services_path, image_sboms_path = sys.argv[1:]
manifest = {
    "schema_version": 1,
    "product": "hybrid-ndr",
    "version": version,
    "compose_profile": "customer",
    "payload": "payload/hybrid-ndr",
    "images": {
        "included": included == "true",
        "path": "images.tar" if included == "true" else None,
        "sha256": digest or None,
        "services": json.load(open(services_path, encoding="utf-8")) if included == "true" else {},
    },
    "sbom": {
        "path": "sbom/source.cdx.json",
        "sha256": source_sbom_digest,
        "format": "CycloneDX-1.6",
        "images": json.load(open(image_sboms_path, encoding="utf-8")),
    },
    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
}
with open(path, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

temporary_bundle="$output_dir/.${bundle_name}.tmp.$$"
tar -C "$work_dir/bundle" --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@$source_date_epoch" -czf "$temporary_bundle" .
chmod 0644 -- "$temporary_bundle"
mv -f -- "$temporary_bundle" "$bundle_path"
bundle_hash=$(sha256sum -- "$bundle_path" | awk '{print $1}')
printf '%s  %s\n' "$bundle_hash" "$bundle_name" >"$checksum_path"
openssl dgst -sha256 -sign "$signing_key" -out "$signature_path" "$bundle_path"
chmod 0644 -- "$bundle_path" "$checksum_path" "$signature_path"

echo "offline bundle: $bundle_path"
echo "checksum: $checksum_path"
echo "signature: $signature_path"
