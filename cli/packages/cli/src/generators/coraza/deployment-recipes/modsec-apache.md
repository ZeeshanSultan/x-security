# Deploying x-security rules on Apache httpd + ModSecurity (modsec-apache)

Same libmodsecurity3 backend as `modsec-nginx`. Identical directive surface,
different loading mechanism.

## Generate

```bash
x-security generate \
  --target coraza \
  --coraza-engine modsec-apache \
  --out ./out/coraza \
  spec.yaml
```

## Mount + load

```apache
# /etc/apache2/mods-enabled/security2.conf
<IfModule security2_module>
    SecRuleEngine On
    Include /etc/modsecurity/x-security.conf
</IfModule>
```

Drop `x-security.conf` into `/etc/modsecurity/` (or wherever your distro's
ModSecurity vhost include points). Reload Apache: `apachectl -t && apachectl graceful`.

## Verify

```bash
tail -F /var/log/apache2/error.log | grep -E "(ModSecurity|x-security)"
tail -F /var/log/apache2/modsec_audit.log | grep 'ruleId:'
```

`apachectl -t` returns 0 with a clean rule load. Any `ModSecurity: ... error`
lines are parse failures — fix them before bouncing the worker.

## Limitations

Same as `modsec-nginx` (downgrade `user-id`/`api-key`/`header:X` to `global`
collection; skip engine globals). Check `WARNINGS.md` for the list.
