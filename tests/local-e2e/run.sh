#!/usr/bin/env bash
# Run a clean-file scan through Azurite, the actual scanner image, and its result queue.
set -euo pipefail

cd "$(dirname "$0")"
trap 'docker compose down --volumes --remove-orphans' EXIT

docker compose up --build --detach azurite
docker compose run --rm setup
docker compose run --rm scanner
docker compose run --rm verify
