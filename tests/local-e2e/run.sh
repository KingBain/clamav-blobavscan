#!/usr/bin/env bash
# Run a clean-file scan through Azurite, the actual scanner image, and its result queue.
set -euo pipefail

cd "$(dirname "$0")"
cleanup() {
  status=$?

  if [ "${status}" -ne 0 ]; then
    docker compose logs --no-color || true
  fi

  docker compose down --volumes --remove-orphans
  exit "${status}"
}

trap cleanup EXIT

docker compose up --build --detach azurite
docker compose run --rm setup
docker compose run --rm scanner
docker compose run --rm verify
