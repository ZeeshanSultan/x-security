#!/bin/sh
# preflight-coraza.sh — runs as the modsec-nginx container CMD wrapper.
#
# Today's image owns /etc/modsecurity.d/modsecurity-override.conf and
# rewrites it from /etc/nginx/modsecurity.d/*.conf on every restart
# (see 90-copy-modsecurity-config.sh inside the image). Editing the
# override file in place does not survive `docker compose restart`.
#
# Survival path: the bundled setup.conf already Includes
# `/etc/modsecurity.d/owasp-crs/rules/*.conf`. We mount our compiled
# rules (as zzz-x-security.conf) into that glob via the compose `volumes:` block.
# This preflight only sanity-checks the mount before exec'ing the
# image's own entrypoint, so a missing mount fails loud instead of
# silently running with no x-security rules.
set -eu

RULE_FILE="/etc/modsecurity.d/owasp-crs/rules/zzz-x-security.conf"

echo "[x-security-preflight] verifying include mount at ${RULE_FILE}"
if [ ! -s "${RULE_FILE}" ]; then
  echo "[x-security-preflight] FATAL: ${RULE_FILE} missing or empty." >&2
  echo "[x-security-preflight] mount your x-security include there in compose." >&2
  exit 11
fi

# Marker grep so we can prove our compiled rules (not CRS) are the source of
# the rules loaded at startup. The image's nginx-entrypoint will load the file
# via the *.conf glob; if our marker rule (id:408999) is missing the file was wrong.
if ! grep -q "id:408999" "${RULE_FILE}"; then
  echo "[x-security-preflight] FATAL: marker rule id:408999 missing from ${RULE_FILE}" >&2
  exit 12
fi

echo "[x-security-preflight] ok — handing off to image entrypoint"

# nginx resolves `upstream vapi` at config-parse time. If vapi's Apache
# hasn't bound :80 yet the worker aborts with `host not found in upstream`.
# Wait for the upstream port to be reachable before exec'ing the image
# entrypoint, so we never crash on a known-transient race.
i=0
while [ "${i}" -lt 90 ]; do
  if getent hosts vapi >/dev/null 2>&1; then break; fi
  i=$((i + 1)); sleep 1
done
echo "[x-security-preflight] upstream vapi resolvable after ${i}s"

exec /docker-entrypoint.sh "$@"
