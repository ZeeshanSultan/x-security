# BunkerWeb Generator — STATUS

## Scope
PRD R2.3 — BunkerWeb config emitter under `packages/cli/src/generators/bunkerweb/`.

## W23: implementation-gap drift closures (2026-05-24)

Closed 9 BunkerWeb drift rows from `docs/capability-drift-matrix.csv`:

| Drift field | Mechanism |
|-------------|-----------|
| `authentication.type=bearer-jwt` | BW 1.6 `USE_AUTH_JWT` setting (nginx_jwt_module) |
| `authentication.jwksUri` | BW `JWT_JWKS_URI` setting |
| `authentication.allowedAlgorithms` | BW `JWT_ALGORITHMS` setting (comma-list, default `RS256,ES256`) |
| `authorization.type=rbac` (multi-role) | SecRule id:970600+ chained on `X-Forwarded-Groups` |
| `request.schema.pii` | SecRule id:428xxx phase:4 RESPONSE_BODY filter |
| `response.errorScrubbing.stripStackTraces` | SecRule id:268xxx phase:4 stack-frame deny |
| `response.errorScrubbing.stripServerHeaders` | BW `REMOVE_HEADERS=Server X-Powered-By ...` |
| `rateLimit.identifier=user-id` | `CUSTOM_CONF_HTTP_*` snippet declaring `limit_req_zone $http_x_forwarded_user` |
| `deprecated` | SecRule id:970500+ status:410, tag `writ-deprecated-endpoint-block` |

New modules:
- `bunkerweb/jwt.ts` — native JWT settings emitter
- `bunkerweb/authz.ts` — RBAC multi-role SecRule emitter
- `bunkerweb/lifecycle.ts` — deprecated → 410 SecRule emitter
- `bunkerweb/response-rules.ts` — PII + errorScrubbing emitters

## v0.7 edge-enforceable-residuals (2026-06-01)

Schema v0.7 added 7 residual fields. BunkerWeb (libmodsec3) coverage:

| Field | capKey | Status | Mechanism |
|-------|--------|--------|-----------|
| `injectionGuard += "deserialization"` | `request.schema.injectionGuard` | full | phase:2 `@rx` preamble denylist (node-serialize/Java rO0/PHP `O:n:`/pickle) on `ARGS:json.<f>\|ARGS:<f>`, tag `writ-ssec-injection` |
| `injectionGuard += "ai-prompt"` | `request.schema.injectionGuard` | full | phase:2 `@rx` prompt-injection heuristic denylist, tag **`writ-ssec-prompt`** (SSEC-PROMPT, not SSEC-INJECTION) |
| `authentication.passwordPolicy` | `authentication.passwordPolicy` | full | phase:2 `!@rx` per-requirement (minLength/upper/digit/symbol) + blocklist `@rx` on the body password field, 422, tag `writ-rule-password-policy` |
| `authentication.accountLockout` | `authentication.accountLockout` | full | stateful `initcol:global` + `setvar`/`expirevar` failed-login counter (phase:5 increment on 401/403/422), `@gt attempts` deny 429. init/deny phase tracks the identifier source (header→phase:1, body field→phase:2). tag `writ-rule-account-lockout` |
| `response.forbidArrayRoot` | `response.forbidArrayRoot` | full | phase:4 `RESPONSE_BODY @rx ^[\s…]*\[` bare-array deny 500, tag `writ-rule-forbid-array-root` |
| `request.idempotencyKey` | `request.idempotencyKey` | **partial** | phase:1 missing-header 400 + persistent-collection replay dedupe (`@gt 1` → 409). Stops cross-request replay, NOT concurrent in-flight races (no atomic check-and-set at the WAF — schema itself flags partial). tag `writ-rule-idempotency-key` |
| `logging` | `logging` | **partial** | phase:5 `log,auditlog` opt-in for request/response events (tag `writ-audit`); injection-block/authz-deny/rate-limit-trip already audit-logged by their deny rules. NOT enforced at libmodsec3: per-event sink routing, `http-collector` sinkRef, `piiRedaction` — surfaced as a commented operator note |

New module: `bunkerweb/v07-rules.ts` (passwordPolicy / accountLockout / forbidArrayRoot / idempotencyKey / logging). The 2 injectionGuard sinks live in `schema-rules.ts` (`sinkRule`). Dry-parse (`nginx -t` against `owasp/modsecurity-crs:nginx`) passes for the combined output.

## Output shape (v6, 2026-05-22)

The generator emits **two artifacts only**:

| Path | Format | Purpose |
|------|--------|---------|
| `configs/modsec/writ.conf` | conf | Phase-1/phase-2 Writ ModSecurity rules (plain SecRule directives). |
| `DEPLOYMENT.md` | text | Operator-facing deployment notes + structured warnings. |

The operator mounts `configs/` under the **bw-scheduler** container's
`/data/configs/` volume (writable). The scheduler syncs rule files into
BunkerWeb via its admin API. Settings like `USE_MODSECURITY`, rate-limit
thresholds, etc. belong in **docker-compose env vars**, not generator output —
the bottom of `writ.conf` includes a commented summary of recommended
values for the operator.

### Dropped in v6 (do NOT re-introduce)

- `bunkerweb.yml` — never consumed by any BunkerWeb mode; was a doc artifact.
- `variables.env` — deployment config belongs in compose, not generator output.
- `plugins/writ/jwt-verify.lua` — BunkerWeb's libmodsec3 lacks Lua, so
  `SecRuleScript` cannot run. The Lua approach is abandoned.
- `plugins/writ/plugin.json` — paired with the abandoned Lua plugin.
- The entire `lua/` source directory under this generator.
- The `cpSync('.../bunkerweb/lua', ...)` build step in `packages/cli/package.json`.

## R2.3 Field Mapping

| XSecurityPolicy field           | BunkerWeb expression                                                |
| ------------------------------- | ------------------------------------------------------------------- |
| `rateLimit[]`                   | `USE_LIMIT_REQ=yes`, `LIMIT_REQ_URL_<n>`, `LIMIT_REQ_RATE_<n>` (compose env). Shared-URL endpoints collapse to one entry; stricter rate wins. |
| `ipPolicy.allow`                | `USE_WHITELIST=yes`, `WHITELIST_IP="<cidr> <cidr>"` (compose env). |
| `ipPolicy.deny`                 | `USE_BLACKLIST=yes`, `BLACKLIST_IP="<cidr> <cidr>"` (compose env). |
| `cors.*`                        | `USE_CORS=yes`, `CORS_ALLOW_*` (compose env; union across endpoints). |
| `request.maxBodySize`           | `MAX_CLIENT_SIZE` (compose env).                                    |
| `request.contentType[]`         | `ALLOWED_MIME_TYPES` (compose env; union).                          |
| `timeout.*`                     | `CONNECT_TIMEOUT`/`READ_TIMEOUT`/`SEND_TIMEOUT` (compose env).      |
| `authentication.type=basic`     | `USE_AUTH_BASIC=yes` (compose env) + Basic-credentials SecRule in modsec/writ.conf. |
| `authentication.type=mtls`      | `USE_CLIENT_SSL=yes` (compose env; cert pinning unsupported).      |
| `authentication.type=bearer-jwt\|oauth2` | **Header-presence SecRule chain only** in modsec/writ.conf. **Signature validation is NOT performed** — libmodsec3 has no Lua. Use an OIDC sidecar (e.g. oauth2-proxy) or Kong+OIDC in front of BunkerWeb for real JWT verification. Structured warning emitted to stderr + DEPLOYMENT.md at generate time. |
| `authentication.type=api-key`   | Header-presence SecRule in modsec/writ.conf. **Value is not verified against any allowlist** — operator must enforce key validity at an upstream layer or via BunkerWeb-external mechanism. |
| `method`                        | `ALLOWED_METHODS` (compose env; union).                             |

## External auth layer (REQUIRED for production JWT)

BunkerWeb's libmodsec3 build does **not** include Lua support. Therefore
Writ cannot generate real JWT signature validation for the BunkerWeb
target. The emitted `id:990010`/`id:990011` chain denies unauthenticated
requests (missing `Authorization: Bearer ...`), but the signature, issuer,
audience, and expiry of presented tokens are **not** checked at the WAF
layer.

For production deployments of bearer-jwt / oauth2 endpoints, place one of:

- **OIDC sidecar** (oauth2-proxy, OAuth2 Proxy, Vouch) in front of BunkerWeb.
  The sidecar verifies the token and forwards a trusted identity header to
  BunkerWeb-fronted upstreams.
- **Kong with the OIDC plugin** (`--kong-edition enterprise`) — use Writ's
  `--target kong` instead, which does verify signatures natively.
- **Coraza-SPOA** chain — use Writ's `--target coraza-spoa`; that profile
  ships with Lua-enabled libmodsecurity and performs gateway-side validation
  with rule-ID attribution. This is the recommended path for Writ
  deployments needing real JWT enforcement (see wave-5 report).

The DEPLOYMENT.md emitted by `lazy generate --target bunkerweb` reminds
the operator of these options.

## Capabilities

| Field | Status | Notes |
|-------|--------|-------|
| `rateLimit` | full | via compose env LIMIT_REQ_* |
| `cors` | full | via compose env CORS_* (union across endpoints) |
| `ipPolicy.{allow,deny}` | full | via compose env WHITELIST_IP/BLACKLIST_IP |
| `request.maxBodySize` | full | MAX_CLIENT_SIZE |
| `request.contentType` | full | ALLOWED_MIME_TYPES |
| `request.schema.allowedMimeTypes` | partial | merged into service-level allowlist |
| `timeout.{connect,read,write}` | full | |
| `authentication.type=basic` | full | USE_AUTH_BASIC handles credentials |
| `authentication.type=none` | full | |
| `authentication.type=mtls` | partial | cert pinning unsupported |
| `authentication.type=bearer-jwt` | **full** | W23: BW 1.6+ `USE_AUTH_JWT` + `JWT_JWKS_URI` + `JWT_ALGORITHMS` (nginx_jwt_module). Header-presence SecRule chain stays as defense-in-depth. |
| `authentication.jwksUri` | **full** | W23: emitted as `JWT_JWKS_URI`. |
| `authentication.allowedAlgorithms` | **full** | W23: emitted as `JWT_ALGORITHMS` (comma-list). Defaults to `RS256,ES256` when unset — `none`/HS\* never appear in defaults. |
| `authentication.type=oauth2` | **full** | W23: same JWT path as bearer-jwt. Scope enforcement still requires upstream identity layer. |
| `authentication.type=api-key` | partial | Header-presence SecRule; value verification still requires upstream layer. |
| `authorization.type=rbac` (multi-role) | **full** | W23: SecRule chain (id:970600+) on `X-Forwarded-Groups` with alternation rx across declared roles. Tag `writ-rule-rbac-multi-role`. |
| `cacheable` | override-only | |
| `response.errorScrubbing.stripStackTraces` | **full** | W23: phase:4 SecRule (id:268xxx) denies on stack-frame patterns in RESPONSE_BODY. Tag `writ-output-sanitization`. |
| `response.errorScrubbing.stripServerHeaders` | **full** | W23: emitted as BW `REMOVE_HEADERS=Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version`. |
| `response.errorScrubbing.genericMessages` | **full** | W23: phase:4 SecRule (id:268xxx) denies on raw DB/runtime error keywords. |
| `request.schema.pii` (and response.schema sensitive-named fields) | **full** | W23: phase:4 SecRule (id:428xxx) per field. Tag `writ-data-exposure`. |
| `rateLimit.identifier=user-id` | **full** | W23: CUSTOM_CONF_HTTP_LIMIT_REQ_USER_\* snippet emits `limit_req_zone $http_x_forwarded_user`. Native `LIMIT_REQ_URL` stays as IP-keyed defense-in-depth. |
| `mtls.pinnedCertificates` | unsupported | |
| `deprecated` | **full** | W23: phase:1 SecRule (id:970500+) returns 410 with tag `writ-deprecated-endpoint-block` (attribution.py:35). `sunsetDate` surfaced in msg. |
| `sunsetDate` | partial | Carried in deprecated rule msg; not emitted as a `Sunset:` response header (use BW `CUSTOM_HEADER_*` for that). |
| mixed-issuer / mixed-audience in one service | unsupported | rejected at generate time (Bug #5). |

## Generate-time warnings

The generator surfaces structured warnings via `bunkerwebGenerator.lastWarnings`
AND prints them to stderr at `generate()` time. Each warning is also embedded
in `DEPLOYMENT.md` under the "Warnings" section.

Currently emitted:

- `[bunkerweb] WARNING: bearer-jwt declared on <endpoint> but BunkerWeb's
  libmodsec3 lacks Lua support; emitting header-presence check only. For real
  JWT signature validation, place an OIDC sidecar (or Kong with --kong-edition
  enterprise + OIDC plugin) in front of BunkerWeb.`
  (one per `bearer-jwt`/`oauth2` endpoint)
- `LIMIT_REQ_URL collision collapsed: <url> (idx N -> M, kept stricter rate ...)`
  (one per collapsed shared-URL rate limit)

## Service merge rules (unchanged from wave-5)

- `CUSTOM_CONF_MODSEC_*`: dedupe by `# Writ-generated authentication rules (<type>)`
  marker, then rebase rule IDs across distinct blocks (blockIndex * 100 offset).
- `LIMIT_REQ_URL_<n>` collisions across endpoints: collapse to one entry
  (stricter rate kept). Warning surfaced via `lastWarnings`.
- `ALLOWED_METHODS`, `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS`,
  `CORS_EXPOSE_HEADERS`: space- or comma-separated union.
- `CORS_ALLOW_ORIGIN`, `ALLOWED_MIME_TYPES`, `WHITELIST_IP`, `BLACKLIST_IP`:
  space-separated union.
- `MAX_CLIENT_SIZE`: largest wins.
- `USE_*`: any `yes` wins.
- `WRIT_AUTH_ISSUER` / `WRIT_AUTH_AUDIENCE`: mixed values across
  endpoints in one service throw at generate time.

## Verification

### Static
```
pnpm --filter @x-security/cli build   # exit 0
pnpm --filter @x-security/cli test    # all bunkerweb tests pass (24/24 in v6)
```

### Generator output on `e2e/fixtures/chain-vapi/openapi.yaml`
```
JWKS_URI=... JWT_ISSUER=... TURNSTILE_SECRET=... UPSTREAM_HMAC_SECRET=... \
  lazy generate --target bunkerweb --out /tmp/out e2e/fixtures/chain-vapi/openapi.yaml

# Output tree:
#   /tmp/out/configs/modsec/writ.conf
#   /tmp/out/DEPLOYMENT.md

grep -c "id:990000" /tmp/out/configs/modsec/writ.conf   # → 1 (dedupe holds)
grep -oE "id:99[0-9]{4}" /tmp/out/configs/modsec/writ.conf | sort -u | wc -l
ls /tmp/out/bunkerweb.yml      # → not present (deprecated)
ls /tmp/out/variables.env      # → not present (deprecated)
find /tmp/out -name "*.lua"    # → empty (deprecated)
```

### Dry-parse (modsec rules load cleanly)
```
docker run --rm --user root \
  -v /tmp/out/configs/modsec/writ.conf:/writ.conf:ro \
  owasp/modsecurity-crs:nginx sh -c '
    mkdir -p /tmp/m && cp /writ.conf /tmp/m/
    echo "SecRuleEngine On" > /tmp/m/main.conf
    echo "Include /tmp/m/writ.conf" >> /tmp/m/main.conf
    sed -i "s|modsecurity_rules_file .*|modsecurity_rules_file /tmp/m/main.conf;|" /etc/nginx/conf.d/default.conf
    nginx -t
  '
# → nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Stderr warnings on chain-vapi spec
The chain-vapi spec declares bearer-jwt on ~18 endpoints. Running the generator
emits the structured `[bunkerweb] WARNING:` line to stderr for each one, and
each warning is mirrored into DEPLOYMENT.md's "Warnings" section.

## Notes for Downstream Agents
- `bunkerwebGenerator.lastWarnings` surfaces JWT-not-validated warnings and
  `LIMIT_REQ_URL` collision-collapse events. The CLI `generate` command prints
  these.
- Service grouping uses only `servers[0]`. Multi-server specs collapse to a
  single service.
- For deployments needing real JWT enforcement, prefer `--target coraza-spoa`
  (Lua-enabled libmodsecurity) or `--target kong` (OIDC plugin) — see
  capabilities table above.
