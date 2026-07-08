#!/usr/bin/env bash
# Boots the quick-demo stack. Idempotent: if already healthy, exits immediately.
set -euo pipefail

cd "$(dirname "$0")/.."

# Idempotency: if vAPI is already serving, we're up.
if curl -sf --max-time 3 http://127.0.0.1:8000/vapi >/dev/null 2>&1; then
  echo "[up] stack already healthy, skipping build."
else
  echo "[up] building + starting stack (first build is slow)..."
  docker compose up -d --build --wait
fi

# Health poll on the direct (raw vAPI) target.
echo "[up] waiting for vAPI on :8000..."
deadline=$(( $(date +%s) + 120 ))
until curl -sf --max-time 3 http://127.0.0.1:8000/vapi >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "[up] FATAL: vAPI not healthy after 120s." >&2
    docker compose ps || true
    docker compose logs --tail=20 vapi coraza kong 2>/dev/null || true
    exit 1
  fi
  sleep 2
done

echo "[up] stack healthy."
echo "  Direct (raw vAPI):    http://127.0.0.1:8000/vapi"
echo "  Coraza-only:          http://127.0.0.1:8080/vapi"
echo "  Indirect (full chain):http://127.0.0.1:18000/vapi"
