#!/bin/sh
# kong-consumer-provisioner.sh — one-shot sidecar.
#
# Runs in an `alpine:3.19` container (compose adds curl+jq+openssl via apk),
# reads consumers.json that the CLI's Kong generator emits next to kong.yml,
# and POSTs each consumer/credential/acl entry to Kong's admin API. Exits 0
# on success so runtime add/revoke tests have a deterministic starting state
# without depending on declarative-config reloads.
#
# Declarative kong.yml already covers the bootstrap consumers; this
# sidecar is the runtime path that complements it. Idempotent — Kong's
# 409 on duplicate is treated as ok.
set -eu

KONG_ADMIN="${KONG_ADMIN:-http://kong:8001}"
CONSUMERS_FILE="${CONSUMERS_FILE:-/kong/consumers.json}"

echo "[provisioner] target=${KONG_ADMIN} file=${CONSUMERS_FILE}"

# Wait for Kong admin to be reachable.
i=0
while [ "${i}" -lt 60 ]; do
  if curl -sf -o /dev/null "${KONG_ADMIN}/status"; then break; fi
  i=$((i + 1)); sleep 1
done
if [ "${i}" -ge 60 ]; then
  echo "[provisioner] FATAL: kong admin never came up at ${KONG_ADMIN}" >&2
  exit 31
fi

if [ ! -f "${CONSUMERS_FILE}" ]; then
  echo "[provisioner] no consumers.json — declarative kong.yml is authoritative; exiting 0"
  exit 0
fi

# DB-less Kong rejects admin-API mutations with 405 ("cannot create
# 'consumers' entities when not using a database"). In that mode the
# declarative kong.yml is the only source of truth and this sidecar is a
# no-op — exit clean so the chain doesn't appear broken.
if curl -sf "${KONG_ADMIN}/" | grep -q '"database":"off"'; then
  echo "[provisioner] kong is DB-less — declarative kong.yml is authoritative."
  echo "[provisioner] consumers.json is for the runtime-mutation mode only; skipping."
  exit 0
fi

# jq is apk-installed by the compose entrypoint (see docker-compose.yml).
# Schema (matches what the kong generator already emits in kong.yml):
#   { "consumers":[{"username":"role_admin"}],
#     "jwt_secrets":[{"consumer":"role_admin","key":"x#admin",
#                     "algorithm":"HS256","secret":"..."}],
#     "acls":[{"consumer":"role_admin","group":"admin"}] }

post() {
  path="$1"; body="$2"
  code=$(curl -sS -o /tmp/resp -w '%{http_code}' \
    -H 'Content-Type: application/json' -X POST "${KONG_ADMIN}${path}" -d "${body}")
  case "${code}" in
    2*) echo "[provisioner] POST ${path} ok (${code})" ;;
    409) echo "[provisioner] POST ${path} already exists (409) — ok" ;;
    *)  echo "[provisioner] POST ${path} failed code=${code} body=$(cat /tmp/resp)" >&2; return 1 ;;
  esac
}

jq -c '.consumers[]?' "${CONSUMERS_FILE}" | while read -r c; do
  post "/consumers" "${c}"
done

jq -c '.jwt_secrets[]?' "${CONSUMERS_FILE}" | while read -r j; do
  consumer=$(echo "${j}" | jq -r '.consumer')
  body=$(echo "${j}" | jq 'del(.consumer)')
  post "/consumers/${consumer}/jwt" "${body}"
done

jq -c '.acls[]?' "${CONSUMERS_FILE}" | while read -r a; do
  consumer=$(echo "${a}" | jq -r '.consumer')
  body=$(echo "${a}" | jq 'del(.consumer)')
  post "/consumers/${consumer}/acls" "${body}"
done

jq -c '.hmacauth_credentials[]?' "${CONSUMERS_FILE}" | while read -r h; do
  consumer=$(echo "${h}" | jq -r '.consumer')
  body=$(echo "${h}" | jq 'del(.consumer)')
  post "/consumers/${consumer}/hmac-auth" "${body}"
done

echo "[provisioner] done"

# Mint an HS256 token for role_user keyed on the jwt_secrets[*].key/secret
# already pushed above, and write it to a known path the harness can
# `docker exec ... cat`. The token's sub = "alice"; the BOLA test then
# attempts to read user 999's record, which the pre-function rejects
# (alice != owner of 999).
#
# Minting is openssl-only — no extra deps. Header/payload are static so the
# only variable is the HMAC over base64url(header).base64url(payload).
mint_jwt() {
  key="$1"; sub="$2"; secret="$3"
  hdr='{"alg":"HS256","typ":"JWT"}'
  # Use far-future exp so the token survives long-running test sessions.
  payload="{\"iss\":\"${key}\",\"sub\":\"${sub}\",\"exp\":4102444800}"
  b64() { printf '%s' "$1" | openssl base64 -A | tr -- '+/' '-_' | tr -d '='; }
  h=$(b64 "${hdr}"); p=$(b64 "${payload}")
  sig=$(printf '%s' "${h}.${p}" | openssl dgst -sha256 -hmac "${secret}" -binary | openssl base64 -A | tr -- '+/' '-_' | tr -d '=')
  printf '%s.%s.%s' "${h}" "${p}" "${sig}"
}

if [ -f "${CONSUMERS_FILE}" ]; then
  USER_KEY=$(jq -r '.jwt_secrets[] | select(.consumer=="role_user") | .key' "${CONSUMERS_FILE}" | head -1)
  USER_SECRET=$(jq -r '.jwt_secrets[] | select(.consumer=="role_user") | .secret' "${CONSUMERS_FILE}" | head -1)
  if [ -n "${USER_KEY}" ] && [ -n "${USER_SECRET}" ]; then
    TOK=$(mint_jwt "${USER_KEY}" "alice" "${USER_SECRET}")
    printf '%s' "${TOK}" > /tmp/role_user_jwt.txt
    echo "[provisioner] minted role_user JWT to /tmp/role_user_jwt.txt (sub=alice)"
  fi
fi
