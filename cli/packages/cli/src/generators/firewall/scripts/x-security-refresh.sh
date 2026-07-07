#!/bin/sh
# x-security-refresh.sh — periodic re-resolution + apply for XSecurity rules.
#
# Designed to run from a systemd timer (every 5 min by default). On each
# tick:
#   1. Resolve /etc/x-security/rules.template via x-security-resolve.sh
#      into /etc/x-security/rules.current.
#   2. Diff against /etc/x-security/rules.applied — if unchanged, no-op.
#   3. If changed, apply via `iptables-restore` and snapshot
#      /etc/x-security/rules.applied.
#   4. Flap detection: if the resolved output changes more than
#      $X_SECURITY_FLAP_MAX times within $X_SECURITY_FLAP_WINDOW seconds,
#      hold the previous rules (do NOT apply the new ones) and warn.
#      This protects against DNS instability (round-robin churn,
#      misconfigured TTLs, or active DNS attacks).
#
# Fail-closed: if the resolver fails or flap-throttling engages, the
# previously-applied ruleset stays in force. That ruleset already has the
# default-deny terminator, so the worst case is "stale allowlist" not "open
# firewall".

set -eu

CONF_DIR="${X_SECURITY_CONF_DIR:-/etc/x-security}"
TEMPLATE="${CONF_DIR}/rules.template"
TEMPLATE6="${CONF_DIR}/rules6.template"
CURRENT="${CONF_DIR}/rules.current"
CURRENT6="${CONF_DIR}/rules6.current"
APPLIED="${CONF_DIR}/rules.applied"
APPLIED6="${CONF_DIR}/rules6.applied"
FLAP_LOG="${CONF_DIR}/.flap-history"
LOG_FILE="${X_SECURITY_LOG:-/var/log/x-security-resolve.log}"

# Flap thresholds.
FLAP_MAX="${X_SECURITY_FLAP_MAX:-5}"
FLAP_WINDOW="${X_SECURITY_FLAP_WINDOW:-900}"  # 15 minutes default

RESOLVER="${X_SECURITY_RESOLVER:-/usr/local/sbin/x-security-resolve.sh}"
IPTABLES_RESTORE="${IPTABLES_RESTORE:-/sbin/iptables-restore}"
IP6TABLES_RESTORE="${IP6TABLES_RESTORE:-/sbin/ip6tables-restore}"

log() {
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '%s [refresh] %s\n' "$ts" "$*" >> "$LOG_FILE" 2>/dev/null || \
    printf '%s [refresh] %s\n' "$ts" "$*" >&2
}

[ -r "$TEMPLATE" ] || { log "FATAL: missing template at $TEMPLATE"; exit 1; }

mkdir -p "$CONF_DIR"

# --- Flap detection ------------------------------------------------------
# History format: one unix-timestamp per line. We prune entries older than
# $FLAP_WINDOW and count what remains.
now=$(date +%s)
cutoff=$((now - FLAP_WINDOW))
if [ -f "$FLAP_LOG" ]; then
  awk -v c="$cutoff" '$1 >= c' "$FLAP_LOG" > "${FLAP_LOG}.tmp" || true
  mv "${FLAP_LOG}.tmp" "$FLAP_LOG"
else
  : > "$FLAP_LOG"
fi
flap_count=$(wc -l < "$FLAP_LOG" 2>/dev/null | tr -d ' ' || echo 0)

if [ "$flap_count" -ge "$FLAP_MAX" ]; then
  log "WARN: flap threshold exceeded ($flap_count changes in ${FLAP_WINDOW}s); holding previous ruleset"
  exit 0
fi

# --- Resolve -------------------------------------------------------------
if ! "$RESOLVER" --rules-file "$TEMPLATE" --out "$CURRENT"; then
  log "ERROR: resolver failed for v4 template; holding previous ruleset"
  exit 0  # fail-closed: previous rules remain
fi
if [ -r "$TEMPLATE6" ]; then
  if ! "$RESOLVER" --rules-file "$TEMPLATE6" --out "$CURRENT6"; then
    log "ERROR: resolver failed for v6 template; holding previous ruleset"
    exit 0
  fi
fi

# --- Diff + apply --------------------------------------------------------
apply_if_changed() {
  cur="$1"; applied="$2"; restore_bin="$3"; label="$4"
  [ -r "$cur" ] || return 0
  if [ -r "$applied" ] && cmp -s "$cur" "$applied"; then
    return 0  # no change, no-op
  fi
  log "INFO: applying refreshed $label ruleset"
  if "$restore_bin" < "$cur"; then
    cp "$cur" "$applied"
    printf '%s\n' "$now" >> "$FLAP_LOG"
    log "INFO: $label ruleset applied successfully"
  else
    log "ERROR: $restore_bin failed for $label; previous ruleset retained"
    return 1
  fi
}

apply_if_changed "$CURRENT"  "$APPLIED"  "$IPTABLES_RESTORE"  "v4" || exit 0
apply_if_changed "$CURRENT6" "$APPLIED6" "$IP6TABLES_RESTORE" "v6" || exit 0

exit 0
