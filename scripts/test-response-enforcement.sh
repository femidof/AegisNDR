#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# A unique project prevents interference with production or another lab run.
project="aegis-response-lab-${RANDOM}-${RANDOM}"
compose=(docker compose -p "$project" -f infra/response/docker-compose.lab.yml)
trap '"${compose[@]}" down --volumes --remove-orphans' EXIT
"${compose[@]}" build
"${compose[@]}" up -d canary far-canary
"${compose[@]}" run --rm acceptance
