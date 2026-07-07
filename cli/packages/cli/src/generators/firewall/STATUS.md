# firewall generator — STATUS

Scope: PRD R2.5 — host-firewall SSRF protection.

## Implemented

- `firewallGenerator` (`Generator` interface) emits two artifacts:
  - `firewall/iptables.rules`   (IPv4, `iptables-restore` format)
  - `firewall/ip6tables.rules`  (IPv6, `ip6tables-restore` format)
- Cloud-metadata DROP rules always emitted: 169.254.169.254/32 (IMDS),
  169.254.170.2/32 (ECS), 100.100.100.200/32 (Alibaba), fd00:ec2::254/128 (IMDSv6).
- RFC1918 + CGNAT + link-local + loopback DROPs always emitted (v4 + v6).
- Per-endpoint ACCEPT rules for `request.schema.<field>.domainAllowlist`
  when `type === 'url'`, emitted with `@@X_SECURITY_RESOLVE:<fqdn>@@`
  tokens that the deploy wrapper substitutes after a fresh DNS lookup.
- All rules scoped by `-m owner --uid-owner ${X_SECURITY_APP_UID}` so
  system processes (DNS, ssh, package manager) are unaffected.
- Every rule preceded by a `# x-security: <endpoint> <field> -- <label>`
  provenance comment, plus an inline `-m comment --comment` that survives
  `iptables-save` round-trips.
- Fail-closed default-deny terminator appended at chain end.
- All blocks use `-j DROP` — never `REJECT` (REJECT would leak signal to
  the application and aid SSRF probing).
- Capability matrix: only `request.schema.*.domainAllowlist` reported as
  `full`. Every other policy field is `unsupported` (host firewall is L3/L4).

## Deploy-time DNS wrapper (shipped)

iptables has no DNS support, so `domainAllowlist` FQDNs cannot be resolved
at generate time. The generator emits `@@X_SECURITY_RESOLVE:<fqdn>@@`
placeholder tokens in `firewall/iptables.rules` and ships a wrapper
toolchain alongside the rulesets — emitted as additional `ConfigArtifact`
entries under `firewall/scripts/`:

- `x-security-resolve.sh`        — POSIX shell. Reads a template, runs
  `getent ahosts` (fallback `dig +short`), and rewrites each token into
  one resolved `-d <addr>` line per A/AAAA record. Strict by default
  (any failed FQDN → exit 1); `--lenient` flag drops only the
  unresolved rules. Append-only logging to `/var/log/x-security-resolve.log`.
- `x-security-refresh.sh`        — periodic re-resolve + diff +
  `iptables-restore` apply. Includes flap detection: if the resolved
  output changes more than `X_SECURITY_FLAP_MAX` (default 5) times
  within `X_SECURITY_FLAP_WINDOW` seconds (default 900), the previous
  ruleset is held in place rather than thrashed.
- `x-security-refresh.service`   — systemd `Type=oneshot` unit.
- `x-security-refresh.timer`     — fires every 5 minutes (plus 30s
  after boot).
- `x-security.logrotate`         — sample logrotate snippet preserving
  append-only semantics.
- `README.md`                    — install + tuning + troubleshooting.

Fail-closed properties preserved end-to-end:
- Resolver failure ⇒ refresh wrapper exits 0 without applying ⇒ previous
  ruleset (with its default-deny terminator) stays in force.
- Flap throttle engaged ⇒ refresh wrapper holds previous rules and warns.
- Unresolved FQDN in `--lenient` mode ⇒ rule for that FQDN is dropped
  (its destination remains unreachable), not silently widened.
- Wrapper only ever inserts ACCEPT lines for resolved IPs; it cannot
  weaken the default-deny terminator.

Installation summary (full instructions in `scripts/README.md`):

```sh
install -m 0755 x-security-resolve.sh /usr/local/sbin/
install -m 0755 x-security-refresh.sh /usr/local/sbin/
install -d /etc/x-security
install -m 0644 iptables.rules  /etc/x-security/rules.template
install -m 0644 ip6tables.rules /etc/x-security/rules6.template
sed -i "s/\${X_SECURITY_APP_UID}/$(id -u app-user)/g" \
  /etc/x-security/rules*.template
install -m 0644 x-security-refresh.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now x-security-refresh.timer
```

## Deferred / Out of scope

- **`nftables` flavor (`--firewall-flavor=nftables`).** Surface area
  documented here but not implemented. nftables would emit an `nft`
  ruleset instead of `iptables-restore` format; the high-level structure
  (allow-list ACCEPTs → metadata DROPs → RFC1918 DROPs → default-deny)
  carries over unchanged. Tracked for a follow-up.
- **Per-endpoint uid scoping.** All rules currently scope by a single
  app uid. A future enhancement could allocate one uid per endpoint to
  prevent one compromised endpoint from reaching another endpoint's
  allowed destinations — but this requires the runtime to drop privs
  per-request, which is out of generator scope.
- **`--firewall-allow-internal` flag** to exempt specific RFC1918 CIDRs
  (e.g. an internal database). Not yet implemented; STATUS only.
- **Provenance line numbers.** `ConfigArtifact.provenance[].line` is set
  to `0` because precise line mapping is already encoded inline in
  per-rule `# x-security:` comments and the file is short enough that
  human scanning suffices. A future pass can populate exact line numbers.

## Files

- `index.ts`            — `firewallGenerator` (Generator export)
- `iptables.ts`         — v4/v6 ruleset builders + render
- `metadata-blocks.ts`  — SSRF-protection constants (readonly tuples)
- `../../test/generators/firewall.test.ts`            — 13 tests, all passing
- `../../../../fixtures/configs/firewall/example.expected.rules` — golden output

## Verification

```
pnpm --filter @x-security/cli build   # passes
pnpm --filter @x-security/cli test    # firewall suite: 19/19 pass
```

E2E harness (`e2e/fixtures/chain-firewall-vapi/`) confirms rule application
end-to-end on alpine/busybox. Wave-7 attack matrix recorded packet-counter
deltas on every expected-fire rule (allow=6 pkts, IMDS drop=5 pkts,
RFC1918 drop=5 pkts, loopback drop=5 pkts, default-deny=5 pkts), plus a
root-uid control that bypassed the chain as designed.

(Unrelated pre-existing failures in `openappsec` block `pnpm --filter
@x-security/cli build` until that package is fixed; the firewall TS
sources compile clean in isolation and the firewall script-copy step
runs after tsc.)

## Wave-7 fixes (`x-security-resolve.sh`)

Three latent bugs in the shipped resolver wrapper blocked it from
producing a loadable ruleset under busybox/alpine. All three were
discovered while bringing up `chain-firewall-vapi` and are fixed in this
file:

1. **Header-comment FQDN leak.** Pass-1 token extraction scanned every
   line including the generator's header comment, which documents the
   token format with a literal `@@X_SECURITY_RESOLVE:<fqdn>@@` example.
   The resolver tried to DNS-resolve `<fqdn>`, failed, and exited strict.
   Fix: Pass-1 now skips comment lines (`grep -v '^[[:space:]]*#'`).
2. **`grep -c` arithmetic break.** `FAILED=$(grep -c PAT FILE || echo 0)`
   produced "0\n0" on zero matches because `grep -c` prints "0" AND
   exits 1. `$((TOTAL - FAILED))` then choked on the multi-line value.
   Fix: use `wc -l | tr -d ' \n'` and an explicit `[ -z "$FAILED" ]`
   default.
3. **busybox awk `in` side-effect.** `addrs[f[1]] = (f[1] in addrs ?
   addrs[f[1]] "\n" f[2] : f[2])` created a phantom empty entry on
   first insert under busybox awk, so `split()` later produced a stray
   empty element and the resolver emitted `-A OUTPUT -d  -m owner ...`
   (literal empty `-d`) which iptables rejects with "Bad argument
   `owner`". Fix: track presence via an explicit `seen[]` flag.
