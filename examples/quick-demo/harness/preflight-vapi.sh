#!/bin/sh
# preflight-vapi.sh — wraps vAPI's CMD (`php artisan serve`; see compose).
#
# Two issues this fixes at the compose layer (no vAPI image mods):
#
#   1. The image-baked .env ships with DB_HOST=db. Laravel's config:cache
#      resolves it from the file, not env vars, so a compose-level
#      `environment:` override is ignored. We sed-rewrite the baked .env in
#      place and re-clear the config cache.
#
#   2. Laravel boots before MySQL has finished initializing on first run.
#      We wait for vapi-db:3306 with a bounded retry instead of letting the
#      artisan dev server crashloop.
set -eu

DB_HOST_TARGET="${DB_HOST:-vapi-db}"
DB_PORT_TARGET="${DB_PORT:-3306}"
ENV_FILE="/var/www/html/vapi/.env"

echo "[vapi-preflight] waiting for ${DB_HOST_TARGET}:${DB_PORT_TARGET}"
i=0
# vAPI's base image is Debian — bash exposes /dev/tcp, dash/sh does not.
# Try bash's /dev/tcp first, fall back to a tiny python probe if needed.
while [ "${i}" -lt 60 ]; do
  if bash -c "exec 3<>/dev/tcp/${DB_HOST_TARGET}/${DB_PORT_TARGET}" >/dev/null 2>&1; then
    break
  fi
  if command -v python3 >/dev/null 2>&1 && \
     python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('${DB_HOST_TARGET}',${DB_PORT_TARGET}))==0 else 1)" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
if [ "${i}" -ge 60 ]; then
  echo "[vapi-preflight] FATAL: ${DB_HOST_TARGET}:${DB_PORT_TARGET} never came up" >&2
  exit 21
fi
echo "[vapi-preflight] db reachable after ${i}s"

if [ -f "${ENV_FILE}" ]; then
  # Idempotent rewrite. Only touches DB_HOST so other operator edits stick.
  if grep -qE "^DB_HOST=" "${ENV_FILE}"; then
    sed -i "s/^DB_HOST=.*/DB_HOST=${DB_HOST_TARGET}/" "${ENV_FILE}"
  else
    echo "DB_HOST=${DB_HOST_TARGET}" >> "${ENV_FILE}"
  fi
  echo "[vapi-preflight] .env DB_HOST pinned to ${DB_HOST_TARGET}"

  # config:clear (not :cache) so the next request re-reads .env. Best-effort —
  # vAPI ships without `php artisan` in some build flavors.
  if [ -x /var/www/html/vapi/artisan ] || [ -f /var/www/html/vapi/artisan ]; then
    (cd /var/www/html/vapi && php artisan config:clear 2>&1) || \
      echo "[vapi-preflight] config:clear non-fatal failure (ok if no bootstrap/cache)"
  fi
fi

echo "[vapi-preflight] handing off to vAPI CMD (php artisan serve)"
exec "$@"
