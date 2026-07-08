#!/usr/bin/env bash
# Regenerates policy/kong.yml + policy/coraza/* from openapi.yaml via the lazy CLI.
# Run after editing openapi.yaml. Commits nothing — review + commit by hand.
#
# Env vars: the four below have canonical fixture defaults (synthetic test
# values, not real secrets) so a fresh regen reproduces the committed
# policy/kong.yml byte-for-byte.
# Override by exporting them before invoking.
#
# IMPORTANT — coraza confs are a PINNED snapshot, not a live mirror:
# the committed policy/coraza/x-security-include.conf is the exact ruleset
# that produced the validated EXPECTED.md ground truth. A fresh
# `lazy generate --target coraza` from the current generator may emit a
# DIFFERENT ruleset (the generator evolves) and therefore change what Coraza
# blocks. So regenerating coraza is a re-baseline, not a refresh: only commit
# a regenerated conf together with a re-run of scripts/demo.sh and a recapture
# of EXPECTED.md. Review the coraza diff carefully before doing either.
#
# Coraza note: the committed policy/coraza/x-security-include.conf is the
# file the compose mounts at /etc/modsecurity.d/owasp-crs/rules/zzz-x-security.conf
# and harness/preflight-coraza.sh greps it for the marker rule id:408999.
# `lazy generate --target coraza` does NOT emit that marker — it was hand-
# appended during integration. So we regenerate x-security.conf and append the
# marker block to produce x-security-include.conf.
set -euo pipefail
cd "$(dirname "$0")/.."

LAZY="${LAZY:-../../cli/packages/cli/dist/bin/lazy.js}"
[ -f "$LAZY" ] || { echo "[regen] lazy CLI not found at $LAZY (build it: cd ../../cli && pnpm --filter @x-security/cli build)" >&2; exit 1; }

: "${JWKS_URI:=https://idp.example.com/.well-known/jwks.json}"
: "${JWT_ISSUER:=https://idp.example.com}"
: "${TURNSTILE_SECRET:=realsecret_xyz123}"
: "${UPSTREAM_HMAC_SECRET:=hmac_real_secret_456}"
export JWKS_URI JWT_ISSUER TURNSTILE_SECRET UPSTREAM_HMAC_SECRET

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "[regen] kong (--kong-deployment with-coraza)..."
node "$LAZY" generate openapi.yaml --target kong --kong-deployment with-coraza --out "$tmp/kong"
mv "$tmp/kong/kong.yml" policy/kong.yml

echo "[regen] coraza (--coraza-engine modsec-nginx)..."
node "$LAZY" generate openapi.yaml --target coraza --coraza-engine modsec-nginx --out "$tmp/coraza"
# Generator emits x-security.conf, x-security-include.conf, nginx-server.conf, WARNINGS.md.
[ -f "$tmp/coraza/x-security.conf" ] || { echo "[regen] FATAL: $tmp/coraza/x-security.conf not emitted" >&2; exit 1; }

mkdir -p policy/coraza

# x-security-include.conf = generated x-security.conf + the id:408999 preflight marker.
# The marker is NOT produced by the generator; it was added during integration so
# harness/preflight-coraza.sh can prove x-security (not CRS) rules loaded at boot.
# Do not drop the marker — the preflight exits 12 and the coraza container won't start.
cp "$tmp/coraza/x-security.conf" policy/coraza/x-security-include.conf
cat >> policy/coraza/x-security-include.conf <<'MARKER'


# x-security-preflight marker (added during integration to satisfy harness check)
SecAction "id:408999,phase:1,pass,nolog,tag:x-security/marker"
MARKER

echo "[regen] verify chain routing..."
# `grep -c` exits 1 on 0 matches; neutralize so set -e doesn't abort the check.
n_coraza="$(grep -c 'url: http://coraza:8080' policy/kong.yml || true)"
n_vapi="$(grep -c 'url: http://vapi:80' policy/kong.yml || true)"
echo "[regen] kong services -> coraza: $n_coraza, -> vapi (should be 0): $n_vapi"
[ "$n_coraza" -gt 0 ] || { echo "[regen] FATAL: no kong services route through coraza." >&2; exit 1; }
[ "$n_vapi" -eq 0 ] || { echo "[regen] FATAL: some kong services still bypass Coraza." >&2; exit 1; }

echo "[regen] verify coraza preflight marker..."
grep -q 'id:408999' policy/coraza/x-security-include.conf \
  || { echo "[regen] FATAL: id:408999 marker missing from x-security-include.conf" >&2; exit 1; }

echo "[regen] done. review + git add policy/."
