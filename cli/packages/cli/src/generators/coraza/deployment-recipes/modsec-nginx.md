# Deploying x-security rules on `owasp/modsecurity-crs:nginx` (modsec-nginx)

The default `--coraza-engine` target. Emits `x-security.conf` (plain
ModSecurity directives) plus a `x-security-include.conf` snippet.

## Generate

```bash
lazy generate \
  --target coraza \
  --coraza-engine modsec-nginx \
  --out ./out/coraza \
  spec.yaml
```

Produces:

```
out/coraza/x-security.conf          # the rules
out/coraza/x-security-include.conf  # the include directive
out/coraza/WARNINGS.md              # only if downgrades occurred
```

## Mount path (THIS MATTERS — see REPORT-v3 §3.1)

The `owasp/modsecurity-crs:nginx` image regenerates `setup.conf` and
`modsecurity-override.conf` at every container start, so you cannot
durably persist an `Include` line by mounting those files directly. The
correct strategy is to mount `x-security.conf` into `/etc/modsecurity.d/`
and add the `Include` AFTER the template regeneration runs — via a thin
entrypoint wrapper:

```yaml
services:
  waf:
    image: owasp/modsecurity-crs:nginx
    volumes:
      - ./out/coraza/x-security.conf:/etc/modsecurity.d/x-security.conf:ro
      - ./entrypoint-x-security.sh:/usr/local/bin/entrypoint-x-security.sh:ro
    entrypoint: /usr/local/bin/entrypoint-x-security.sh
    environment:
      BACKEND: http://upstream:8080
```

`entrypoint-x-security.sh`:

```sh
#!/bin/sh
set -e
for f in /docker-entrypoint.d/*.sh; do sh "$f"; done
echo "" >> /etc/modsecurity.d/setup.conf
echo "Include /etc/modsecurity.d/x-security.conf" >> /etc/modsecurity.d/setup.conf
exec nginx -g 'daemon off;'
```

**DO NOT** mount into `/etc/nginx/conf.d/` — that directory is auto-included
by nginx itself, and ModSecurity directives like `SecRule` are not valid
nginx config syntax. Doing this crashes the worker with
`unexpected end of file, expecting ";" or "}"`.

**DO NOT** mount into `/etc/modsecurity.d/modsecurity-override.conf`
directly — that file is regenerated from a template at every container
start, so your `Include` line gets wiped on restart and the rules
silently stop loading (REPORT-v3 §3.1).

## Verify the rules actually loaded

Status codes alone aren't proof — they can come from CRS PL1 anomaly
scores, vAPI's own errors, or auth deflection. Read the error log:

```bash
docker compose logs waf 2>&1 | grep -E "(Rules error|modsecurity|x-security)"
```

A clean load shows zero `Rules error` lines. To confirm a specific rule
fires, tail the audit log and look for the `ruleId:` you generated:

```bash
docker compose exec waf tail -F /var/log/modsec_audit.log | grep 'ruleId:'
```

## Known limitations (modsec-nginx vs coraza-go)

| Field | modsec-nginx | coraza-go |
|---|---|---|
| `rateLimit.identifier=user-id` | downgrade → `global` collection | full `user` collection |
| `rateLimit.identifier=api-key` | downgrade → `global` collection | full `user` collection |
| `rateLimit.identifier=header:X` | downgrade → `global` collection | full `user` collection |
| Engine globals | NOT emitted (crs-setup.conf owns them) | emitted |
| `SecDefaultAction` | NOT emitted (would crash the load) | emitted |
| Body-allowlist JSON parser | explicit `ctl:requestBodyProcessor=JSON` | implicit |

The downgrade is loud: every affected rule is listed in `WARNINGS.md`
and on stderr at generate time.
