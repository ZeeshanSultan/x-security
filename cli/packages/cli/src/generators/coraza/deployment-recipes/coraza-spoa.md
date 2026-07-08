# Deploying x-security rules on Coraza-SPOA (HAProxy bridge)

[coraza-spoa](https://github.com/corazawaf/coraza-spoa) is a SPOE agent
that speaks the HAProxy Stream Processing Offload Protocol and embeds
Coraza WAF v3 internally. HAProxy fronts traffic and delegates the WAF
decision to the SPOA daemon over SPOP (TCP/9000), then enforces the
verdict (allow / deny / redirect / drop).

## Topology

```
client → HAProxy:80 ─┐
                      ├─ SPOP ─→ coraza-spoa:9000 (rule eval, Coraza v3)
                      └─ HTTP ─→ upstream:80
```

## Generate

```bash
lazy generate \
  --target coraza \
  --coraza-engine coraza-spoa \
  --out ./out/coraza \
  spec.yaml
```

Produces `out/coraza/coraza.yml` — a YAML file with `directives: |`
holding the SecRules.

## Wire it in

Coraza-SPOA reads a thin `coraza-spoa.yaml` whose `directives:` block can
either inline the rules or `Include` a flat `.conf` file. Including a
flat file keeps the SPOA config tiny and human-diffable. Extract the
generator's directives block on the host:

```bash
python3 - <<'PY' out/coraza/coraza.yml /etc/coraza/x-security.conf
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f: doc = yaml.safe_load(f)
with open(dst, "w") as f: f.write(doc["directives"])
PY
```

Then `coraza-spoa.yaml`:

```yaml
bind: 0.0.0.0:9000
log_level: info
log_file: /dev/stdout
log_format: json
default_application: api

applications:
  - name: api
    directives: |
      Include /etc/coraza/x-security.conf
    response_check: false
    transaction_ttl_ms: 60000
    log_level: info
    log_file: /dev/stdout
    log_format: json
```

HAProxy needs an SPOE config (`coraza.cfg`) and a frontend wired to it.
The canonical wiring is in this repo at
`e2e/fixtures/chain-coraza-spoa-vapi/haproxy/` — see `haproxy.cfg` and
`coraza.cfg`. The key directives:

```haproxy
frontend default
    mode http
    bind *:80
    http-request set-var(txn.coraza.app) str(api)
    filter spoe engine coraza config /usr/local/etc/haproxy/coraza.cfg
    http-request send-spoe-group coraza coraza-req
    http-request deny deny_status 403 hdr waf-block "request" if { var(txn.coraza.action) -m str deny }
    http-request deny deny_status 500 if { var(txn.coraza.error) -m int gt 0 }
    default_backend api_backend
```

## Verify

The SPOA daemon emits JSON logs to stdout. On boot:

```
{"level":"info","time":"...","message":"Starting coraza-spoa"}
```

A fatal `failed to compile the directive "secrule"` means the rules
file has syntax the Coraza Go library rejects — re-run the generator
and check `WARNINGS.md` for hints.

Per-request denials are logged with the rule id, e.g.:

```
{"level":"error","message":"[client \"...\"] Coraza: Access denied (phase 1).
  x-security: missing Authorization header [file \"/etc/coraza/x-security.conf\"]
  [line \"46\"] [id \"265333\"] ..."}
```

HAProxy's access log also surfaces the rule id when the SPOE message
exports it (`exportRuleIDs=bool(true)` in `coraza.cfg`):

```
... waf-status=401 ruleid=265333 rules-hit=-
```

## Capability surface

Coraza-SPOA shares its rule engine with `coraza-go` (same Go library).
**Both engines apply the same downgrade as `modsec-nginx` for counter-
based rate-limits:** Coraza v3's `setvar` action only accepts the `TX`
collection (see `corazawaf/coraza` `internal/actions/setvar.go` —
*"invalid arguments, expected collection TX"*). The generator routes
`ip` / `user-id` / `api-key` / `header:*` rate-limit identifiers
through `TX`, which means counters are per-transaction, not cross-
request. `WARNINGS.md` flags this as a `downgrade` for every affected
endpoint with the recommendation to move rate-limiting to HAProxy
stick-tables for true cross-request enforcement.

Body parsing: phase:2 schema rules require the body to be parsed into
`ARGS`. SPOE forwards the raw body to coraza-spoa, but JSON parsing
must be enabled with `ctl:requestBodyProcessor=JSON` for `ARGS`
population. Same constraint as `coraza-go`.

End-to-end verification harness: `e2e/fixtures/chain-coraza-spoa-vapi/`.
