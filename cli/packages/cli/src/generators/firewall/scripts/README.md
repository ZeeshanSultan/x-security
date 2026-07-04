# Writ firewall — deploy-time DNS wrapper

The generator emits `iptables.rules` and `ip6tables.rules` with placeholder
tokens of the form `@@WRIT_RESOLVE:<fqdn>@@` wherever a
`request.schema.<field>.domainAllowlist` entry must be turned into a
concrete `-d <addr>` clause. iptables itself has no DNS; resolution must
happen on the host at deploy time and be refreshed periodically.

These scripts complete that flow.

## Files

| File | Destination | Purpose |
|------|-------------|---------|
| `writ-resolve.sh` | `/usr/local/sbin/writ-resolve.sh` | One-shot resolver. Reads a template, emits a resolved ruleset. |
| `writ-refresh.sh` | `/usr/local/sbin/writ-refresh.sh` | Periodic re-resolve + `iptables-restore` apply with flap detection. |
| `writ-refresh.service` | `/etc/systemd/system/writ-refresh.service` | systemd `Type=oneshot` unit. |
| `writ-refresh.timer` | `/etc/systemd/system/writ-refresh.timer` | systemd timer; runs every 5 minutes. |
| `writ.logrotate` | `/etc/logrotate.d/writ` | Optional logrotate config for the refresh log. |

## Installation

```sh
# 1. Place the scripts.
install -m 0755 writ-resolve.sh /usr/local/sbin/writ-resolve.sh
install -m 0755 writ-refresh.sh /usr/local/sbin/writ-refresh.sh

# 2. Place the rule templates emitted by `lazy generate`.
install -d /etc/writ
install -m 0644 iptables.rules  /etc/writ/rules.template
install -m 0644 ip6tables.rules /etc/writ/rules6.template

# 3. Replace the ${WRIT_APP_UID} placeholder in both templates with
#    the numeric uid of the application user (e.g. `id -u app-user`).
APP_UID=$(id -u app-user)
sed -i "s/\${WRIT_APP_UID}/${APP_UID}/g" \
  /etc/writ/rules.template /etc/writ/rules6.template

# 4. Install + enable the systemd unit.
install -m 0644 writ-refresh.service /etc/systemd/system/
install -m 0644 writ-refresh.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now writ-refresh.timer

# 5. (Optional) install logrotate snippet.
install -m 0644 writ.logrotate /etc/logrotate.d/writ
```

The timer runs `writ-refresh.sh` on boot and every 5 minutes
thereafter. The first run resolves the template, applies via
`iptables-restore`, and snapshots to `/etc/writ/rules.applied`.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `WRIT_APP_UID` | (none — required) | Numeric uid the rules scope to via `-m owner --uid-owner`. Substitute into the template before installing. |
| `WRIT_LOG` | `/var/log/writ-resolve.log` | Resolver + refresh log path. Append-only. |
| `WRIT_CONF_DIR` | `/etc/writ` | Where templates/current/applied/flap-history live. |
| `WRIT_FLAP_MAX` | `5` | Max ruleset changes within the flap window before holding previous rules. |
| `WRIT_FLAP_WINDOW` | `900` | Flap detection window in seconds (15 min default). |
| `WRIT_RESOLVER` | `/usr/local/sbin/writ-resolve.sh` | Path to the resolver script (refresh wrapper uses this). |
| `IPTABLES_RESTORE` | `/sbin/iptables-restore` | Override path to `iptables-restore`. |
| `IP6TABLES_RESTORE` | `/sbin/ip6tables-restore` | Override path to `ip6tables-restore`. |

## Manual one-shot resolve

```sh
# stdin → stdout
cat /etc/writ/rules.template | /usr/local/sbin/writ-resolve.sh

# file → file, strict mode (default — exit 1 on any failed FQDN)
/usr/local/sbin/writ-resolve.sh \
  --rules-file /etc/writ/rules.template \
  --out       /etc/writ/rules.current

# Lenient: drop only the unresolved rules, keep the rest.
/usr/local/sbin/writ-resolve.sh --lenient \
  --rules-file /etc/writ/rules.template \
  --out       /etc/writ/rules.current
```

## Security model

1. **System resolver is trusted.** The script uses `getent ahosts` (falling
   back to `dig +short`), which means the host's `/etc/resolv.conf` is the
   trust root. Point it at internal DNS with DNSSEC if possible.
2. **Allowlist-only.** The resolver only ever rewrites tokens into ACCEPT
   lines for the resolved addresses. The default-deny terminator at the
   tail of the generated ruleset is never modified. There is no path by
   which this wrapper can weaken the firewall.
3. **Fail-closed.** A resolver failure does not clear existing rules —
   `iptables-restore` is only invoked on a successful resolve, and the
   previously-applied ruleset stays in force on the kernel.
4. **Flap defense.** If a downstream FQDN's resolution flaps (e.g. a
   misbehaving cloud LB cycling A records every minute), the refresh
   script detects rapid change and freezes the previously-applied
   ruleset rather than thrashing iptables. Threshold is tunable.
5. **Log integrity.** All resolution outcomes are written append-only to
   `$WRIT_LOG` with ISO-8601 timestamps. Rotation via logrotate
   (NOT `copytruncate`) preserves append-only semantics.

## Troubleshooting

- `systemctl status writ-refresh.timer` — is the timer scheduled?
- `journalctl -u writ-refresh.service` — last few run outcomes.
- `tail -f /var/log/writ-resolve.log` — per-FQDN resolution traces.
- `iptables-save | grep writ` — what's actually in the kernel.
- If you see the flap-throttle WARN: investigate DNS instability first;
  the wrapper is doing its job by refusing to apply churn.
