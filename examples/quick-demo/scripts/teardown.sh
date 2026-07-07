#!/usr/bin/env bash
# Tears down the quick-demo stack + volumes.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose down -v
echo "[teardown] stack removed."
