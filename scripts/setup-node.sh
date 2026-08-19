#!/usr/bin/env bash
set -euo pipefail

required_node="22.14.0"
if ! command -v node >/dev/null 2>&1; then
  printf 'Node.js %s or newer is required. Install it with nvm or your OS package manager.\n' "$required_node" >&2
  exit 1
fi

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if (( node_major < 22 )); then
  printf 'Node.js %s or newer is required; found %s.\n' "$required_node" "$(node --version)" >&2
  exit 1
fi

npm install
printf 'Node.js toolchain ready: %s / %s\n' "$(node --version)" "$(npm --version)"
