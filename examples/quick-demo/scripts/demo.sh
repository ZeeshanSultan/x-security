#!/usr/bin/env bash
# examples/quick-demo/scripts/demo.sh
#
# The headline one-command entrypoint. Boots the stack, runs the curated
# 8-attack suite in DIRECT (raw vAPI) and INDIRECT (Kong->Coraza->vAPI, policy
# enforced) modes, prints a before/after table, and exits 0 only if the run's
# verdicts match the structural contract.
#
# Exit contract (honest, per CLAUDE.md Rule D-1):
#   exit 0 iff every attack that LANDED in direct mode was BLOCKED in indirect
#   mode, AND no attack regressed (landed in indirect but not direct).
#
#   Attacks that did NOT land in direct mode are reported as "n/a-direct" and
#   do NOT fail the contract. Rationale: an attack that isn't exploitable
#   without the gateway/policy path isn't a "secured" outcome (we make no
#   claim about it) and isn't a "reproducibility failure" either (the vuln
#   class may simply require a gateway to manifest — e.g. CORS-preflight needs
#   a CORS plugin to reflect, and the direct target has none). Calling those
#   rows "secured" would overclaim; calling them "not-reproducible" would
#   mislabel an honest non-exploitable state as a test failure. "n/a-direct"
#   says exactly what's true: this attack class doesn't reproduce against the
#   raw target, so direct-vs-indirect enforcement can't be demonstrated for it
#   here. The contract therefore only gates on the attacks that DID land.
#
# Tool deps: bash 4+, jq, docker, curl (transitively via up.sh / exploit.sh).

set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  echo "[demo] FATAL: Docker is not running." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[demo] FATAL: jq is required but not on PATH." >&2
  exit 1
fi

echo "=== booting stack ==="
./scripts/up.sh

echo
echo "=== DIRECT mode (client -> raw vAPI, no policy) ==="
direct="$(./scripts/exploit.sh direct 2>/dev/null)"

echo
echo "=== INDIRECT mode (client -> Kong -> Coraza -> vAPI, policy enforced) ==="
indirect="$(./scripts/exploit.sh indirect 2>/dev/null)"

echo
echo "=== before / after ==="
printf '%-34s %-6s %-10s %-12s %s\n' "ATTACK" "OWASP" "DIRECT" "INDIRECT" "VERDICT"
printf '%-72s\n' "$(printf '%.0s-' {1..72})"

# Join direct + indirect on attack name via jq. Attack set is identical across
# modes (exploit.sh runs the same 8 in both), so iterating direct's list covers
# every row.
mapfile -t attacks < <(printf '%s\n' "$direct" | jq -r '.attack')
# Guard against a silent-empty exploit.sh (exits 0 but emits no JSON): without
# this, the loop is skipped, rc stays 0, and demo.sh would print a false
# "contract met" beside an empty table.
(( ${#attacks[@]} )) || { echo "[demo] FATAL: exploit.sh (direct) emitted no attacks." >&2; exit 1; }
rc=0
for a in "${attacks[@]}"; do
  owasp="$(printf '%s\n' "$direct"   | jq -r --arg a "$a" 'select(.attack==$a).owasp'            | head -1)"
  d_ok="$(printf '%s\n' "$direct"    | jq -r --arg a "$a" 'select(.attack==$a).exploit_succeeded' | head -1)"
  i_ok="$(printf '%s\n' "$indirect"  | jq -r --arg a "$a" 'select(.attack==$a).exploit_succeeded' | head -1)"

  if [ "$d_ok" = "true" ];  then d="LANDED";  else d="blocked"; fi
  if [ "$i_ok" = "true" ];  then i="LANDED";  else i="BLOCKED"; fi

  # Verdict matrix. The two rc=1 cases are genuine enforcement failures
  # (landed in direct but slipped through indirect; or landed in indirect
  # despite being blocked in direct — a policy regression). The n/a-direct
  # case is informational and does NOT fail the contract (see header comment).
  if   [ "$d_ok" = "true"  ] && [ "$i_ok" = "false" ]; then verdict="secured"
  elif [ "$d_ok" = "true"  ] && [ "$i_ok" = "true"  ]; then verdict="UNBLOCKED"; rc=1
  elif [ "$d_ok" = "false" ] && [ "$i_ok" = "true"  ]; then verdict="REGRESSION"; rc=1
  elif [ "$d_ok" = "false" ] && [ "$i_ok" = "false" ]; then verdict="n/a-direct"
  else verdict="?"; rc=1
  fi

  printf '%-34s %-6s %-10s %-12s %s\n' "$a" "$owasp" "$d" "$i" "$verdict"
done

echo
if [ "$rc" -ne 0 ]; then
  echo "[demo] DIVERGENCE from expected contract. rc=$rc" >&2
  exit "$rc"
fi
echo "[demo] contract met: every attack that landed in direct was blocked in indirect."
echo "[demo] secured without touching app source."
