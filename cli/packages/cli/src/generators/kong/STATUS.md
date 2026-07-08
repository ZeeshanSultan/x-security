# Kong Generator — Status

## CLI flags

| Flag | Values | Default | Effect |
|---|---|---|---|
| `--with-consumers` | bool | `true` | Emit top-level consumers/jwt_secrets/keyauth/acl/hmac credentials so OSS plugins actually authenticate. |
| `--kong-deployment` | `standalone`\|`behind-proxy`\|`with-coraza`\|`with-istio` | `standalone` | Controls per-service `url:`. See deployment matrix below. |
| `--kong-edition` | `oss`\|`enterprise` | `oss` | `enterprise` swaps OSS `jwt` for `openid-connect` (real JWKS+RS256) and skips the HS256 `jwt_secrets` downgrade. |

## Deployment-mode matrix

| Mode | service.url | Trusted IPs | Eliminates manual fix |
|---|---|---|---|
| `standalone` | `spec.servers[0].url` | n/a | — |
| `with-coraza` | `http://coraza:8080` (every service) | n/a | The v3 chain-demo `sed` patch is gone. Kong → Coraza → upstream. |
| `with-istio` | `http://localhost:15001` (every service) | n/a | Envoy sidecar inbound port. |
| `behind-proxy` | `spec.servers[0].url` | **operator must set `KONG_TRUSTED_IPS`** | The generator emits a `_x_security_warnings` entry reminding operators to set it; declarative-config alone cannot configure kong.conf-level server settings. |

## limit_by auto-switch (REPORT-v3 Open-4 fix)

Kong's `rate-limiting` plugin defaults `limit_by` to `consumer`. On
unauthenticated endpoints there is no consumer, so failed-login bursts
NEVER accumulate, which is why API2 credential-stuffing was UNBLOCKED in
the v3 attack matrix.

The generator now forces `limit_by: ip` (and records a structured warning
in `_x_security_warnings`) whenever **any** of these hold:

- `rateLimit.when === "unauthenticated"`
- `authentication.type === "none"` or `authentication` is absent
- endpoint matches the login/signup heuristic (`operationId` contains
  `login`/`signup`/`register`/`signin`, OR path matches
  `/login`/`/signup`/`/register`)

Authenticated endpoints with `identifier: user-id` still get
`limit_by: consumer` (unchanged).

## _x_security_warnings block

Every spec→runtime divergence appears in the generated `kong.yml` under a
top-level `_x_security_warnings:` array, AND in a `# WARNING: ...` comment
header at the top of the file. Format:

```yaml
_x_security_warnings:
  - field: authentication.allowedAlgorithms
    endpoint: getProfile
    declared: RS256
    emitted: HS256
    reason: "Kong OSS cannot fetch JWKS at runtime; ..."
```

What gets recorded:

- HS256 downgrade (every spec with `bearer-jwt + allowedAlgorithms: RS256/ES256` on OSS).
- `request.signature.algorithm: ed25519` → dropped (no Kong OSS support).
- `request.signature.headerName: <non-Authorization>` → ignored by hmac-auth.
- `request.signature.body: canonical` → falls back to raw.
- `targetOverrides.kong.edition: enterprise` on an OSS run → enterprise-only plugins suppressed.
- `deployment: behind-proxy` → `KONG_TRUSTED_IPS` not auto-configured.

Operators audit with `grep _x_security_warnings kong.yml` or
`grep '^# WARNING' kong.yml`.

## OSS limits (honest)

Kong OSS does NOT do, regardless of flags:

- **JWKS fetch / RS256 validation** — `--kong-edition=oss` emits HS256
  `jwt_secrets` with deterministic shared secrets; use `--kong-edition=enterprise`
  (openid-connect plugin) for real asymmetric-key validation.
- **Response-body filtering** (`response.schema`, `response.stripUnknownFields`) —
  OSS has no in-flight response inspection plugin.
- **Rule engine for authorization** (`authorization.rule-based`, `authorization.abac`) —
  requires a custom Lua plugin.
- **mtls-auth** — Enterprise only; OSS users must wire mTLS at the
  upstream/sidecar layer.
- **request-validator body_schema** — Enterprise only; OSS gets
  `request-size-limiting` + content-type allowlist only.
- **OAuth2 JWKS-based introspection** — Enterprise/openid-connect only.

---

# Kong OSS 3.x Generator — Status

## Capability matrix

### Full coverage
- `authentication.api-key` → `key-auth` plugin
- `authentication.none` → no plugin emitted
- `authorization.rbac` → `acl` plugin (`allow` list from `roles`)
- `rateLimit` (single or array) → `rate-limiting` plugin, window mapped to nearest
  Kong bucket (`second|minute|hour|day`), identifier mapped to `limit_by`
- `timeout.connect|read|write` → service-level `connect_timeout|read_timeout|write_timeout`
- `cacheable` → `proxy-cache` when true, `response-transformer` with `Cache-Control: no-store` when false
- `cors` → `cors` plugin
- `ipPolicy.allow|deny` → `ip-restriction` plugin
- `request.contentType` → `request-validator` `allowed_content_types`
- `request.maxBodySize` → `request-size-limiting` plugin
- `targetOverrides.kong` → passthrough plugins tagged with `# [OVERRIDE]`

### Partial coverage
- `authentication.bearer-jwt` — emits the `jwt` plugin. With `--with-consumers`
  (default ON, see "Consumer emission" below) the generator also emits
  `jwt_secrets:` entries per RBAC role using **HS256** and a deterministic
  per-role shared secret. This is a deliberate **STATUS-documented downgrade**:
  OSS Kong cannot fetch JWKS, so the RS256/ES256 algorithms the spec declares
  via `allowedAlgorithms` are not enforceable without Kong Enterprise + the
  OIDC plugin. The generator emits a `warning: ...HS256...` to stderr every
  run that touches a bearer-jwt route, so the downgrade is never silent.
  `jwksUri`, `issuer`, `audience` are still recorded as plugin tags.
  Use `--no-with-consumers` to skip credential emission entirely.
- `authentication.oauth2` — `oauth2` plugin scaffolded, but OSS lacks JWKS-based
  token introspection. Scope list is forwarded.
- `request.schema` — `request-validator` is **Kong Enterprise only**. The
  generator defaults to `kongEdition: "oss"` and suppresses this plugin
  entirely on OSS targets (emitting it caused `plugin 'request-validator'
  not enabled` at boot). Set `targetOverrides.kong.edition = "enterprise"`
  to opt in. Semantic types are mapped to JSON-schema primitives + formats.
- `response.contentType` — recorded but Kong cannot enforce response content
  type without a custom plugin.
- `request.signature` — `hmac-auth` plugin (Kong OSS bundled). Mapping:
  | XSecurityPolicy field            | Kong `hmac-auth` config                                                    |
  | -------------------------------- | -------------------------------------------------------------------------- |
  | `algorithm: hmac-sha{1,256,...}` | `algorithms: ["hmac-sha256"]` (Kong supports sha1/256/384/512)             |
  | `algorithm: ed25519`             | **unsupported** — no plugin emitted, stderr warning surfaced                |
  | `headerName: "Authorization"`    | native — Kong uses `Authorization: hmac ...` scheme                         |
  | `headerName: <other>`            | **partial** — Kong OSS has no custom-header mode. Plugin still attached so route is gated, stderr warning + plugin tag record the override |
  | `body: "raw"`                    | `validate_request_body: true`                                               |
  | `body: "canonical"`              | `validate_request_body: true` + stderr warning (Kong has no canonicalization) |
  | `timestampHeader`                | appended to `enforce_headers` alongside `date`                              |
  | `timestampToleranceSeconds`      | `clock_skew: <seconds>` (Kong default 300 when unset)                       |
  | `secretRef`                      | resolved by the kong-consumer pipeline into `hmacauth_credentials:` blocks  |

### Full coverage (continued)
- `authorization.rule-based` (K-1, W10-4, W10-11) — compiled into a Kong
  `pre-function` Lua snippet attached to the route. Runs in the `access`
  phase **before** the upstream is contacted; on rule violation it
  `kong.response.exit(403)`s with a x-security tag
  (`x-security-rule-bola-403`) and a `kong.log.warn(...)` line so the block
  is attributable in access logs.
  - **W10-4 attribution (pcall everywhere)**: every external call
    (`require("resty.http")`, `httpc:request_uri`, `cjson.decode`) is wrapped
    in `pcall`. Any failure returns a structured **403 with a x-security tag
    and a `reason` code** (`lookup_failed`, `decode_failed`,
    `resty_http_missing`) — never an opaque 500. `kong.log.warn` lines
    include the `[x-security-bola]` prefix so `docker logs <kong> | grep
    x-security-bola` is the audit grep. Before W10-4 a hostname blip or
    non-JSON response leaked a 500 that the scorer could not attribute as
    `x-security-attributable`.
  - **W10-11 shared_dict cache**: a synchronous HTTP call per request does
    not scale. The Lua now consults `ngx.shared.x_security_bola_cache`
    keyed on `<principal>:<resource_id>` first; cache hits skip the HTTP
    roundtrip entirely (`cache_hit` log line). Cache misses do the lookup
    and populate the dict with the resolved `ownerId` for
    `SS_BOLA_CACHE_TTL_SECONDS` (default 60s).
    - **Operator action required**: declarative kong.yml cannot configure
      nginx-level directives. Set `KONG_NGINX_HTTP_LUA_SHARED_DICT="x_security_bola_cache 10m"`
      on the Kong container env so the dict exists. The Lua is nil-safe —
      when the dict is missing it falls through to the per-request HTTP
      path so the rule still enforces (correctness preserved, perf
      regresses). A structured warning records this requirement in the
      `_x_security_warnings` block whenever a `pre-function` is emitted.
    - **TTL tradeoff (honest)**: cache TTL means owner changes
      (transfers, deletes) take up to TTL seconds to propagate. 60s is
      conservative — operators can tune via
      `targetOverrides.kong.bolaCacheTtl` (currently informational; the
      Lua constant lives in `plugins.ts`).
    - **Cache key**: `<principal>:<resource_id>` — both components
      required. Using `resource_id` alone would let user A's cached owner
      gate user B's request for the same resource (cross-user cache leak).
  - **Resource lookup**: when a rule references `resource.*` and
    `resourceLookup` is declared, the Lua does a synchronous
    `resty.http` GET against the resolved URL (path params substituted from
    `identifierFrom`) before evaluating rules. **Cost-of-doing-business**:
    one extra upstream call per request to the protected endpoint. Recommend
    only attaching to high-value endpoints (BOLA / IDOR routes).
  - **resty.http availability**: bundled in `kong/kong-gateway` and
    `kong:latest` (the OSS image), so no operator action is required for the
    standard distributions. For minimal images (`kong:alpine`, custom
    builds) operators must ensure `lua-resty-http` is on the runtime
    `lua_package_path` — the Lua fails closed (500 with the x-security tag)
    if `require("resty.http")` errors.
  - **v0.5 namespace handling**: `principal.id` is a synonym for `jwt.sub`
    (Kong's consumer model is JWT-shaped); `header.X-...` reads via
    `kong.request.get_header`; `session.<attr>` reads through
    `kong.ctx.shared.authenticated_session` (requires the OSS `session`
    plugin to populate it; nil-fails closed otherwise). Same code path
    compiles cleanly against v0.4 (`jwt.*`/`request.*`/`resource.*` only).
  - **Operators**: `equals`, `not-equals`, `in`, `not-in`, `matches`
    (Lua `string.match`), `contains` (Lua `string.find` non-pattern).
    Multiple rules are ANDed.

### Override-only
- `authentication.mtls` — `mtls-auth` is Kong Enterprise only; OSS users must
  supply a custom plugin via `targetOverrides.kong`. We still emit the plugin
  stub so the spec round-trips.
- `mtls` (top-level upstream mTLS) — same story.

### Unsupported (honest)
- `authentication.basic` — intentionally not mapped (basic-auth is discouraged).
- `authorization.abac` — Kong OSS has no attribute/rule engine outside
  rule-based; would require a custom plugin.

### W26: response-side + bot + fingerprint (closed implementation gaps)
The drift matrix previously flagged six fields as `unsupported`/`partial`
implementation-gaps on Kong OSS. W26 closes them via Kong's bundled
`post-function` / `pre-function` plugins (no Enterprise dependency):

| DSL field | Builder | Marker | Mechanism |
|---|---|---|---|
| `response.stripUnknownFields` | `buildResponseStripUnknownPlugins` | `x-security-response-strip-unknown` | post-function body_filter: `cjson.decode` → drop keys outside `response.schema` → re-encode |
| `response.errorScrubbing.stripStackTraces` | `buildResponseStripTracesPlugins` | `x-security-response-strip-traces` | post-function: `gsub` Lua patterns covering Java/JS/Python/Ruby/C++ stack frames on 4xx/5xx |
| `response.errorScrubbing.genericMessages` | `buildResponseGenericErrorPlugins` | `x-security-response-generic-error` | post-function: replaces 5xx body with `{"message":"Internal server error",...}` envelope |
| `response.schema.<f>.maxLength` | `buildResponseMaxLengthPlugins` | `x-security-response-maxlength` | post-function: truncates string response fields exceeding declared `maxLength` |
| `rateLimit.identifier=fingerprint` | `buildRateLimitFingerprintPlugins` | `x-security-rate-limit-fingerprint` | pre-function: composite key = client_ip + sha1(user-agent)\[0..16\]; written to `kong.ctx.shared.x_security_fp` and `X-x-security-Fingerprint` header |
| `botProtection` | `buildBotProtectionPlugins` | `x-security-bot-detected` | pre-function: curated UA blocklist (curl/wget/headless-chrome/sqlmap/...) + JS-challenge cookie gate when `mode: enforce` |

All six emit `kong.log.warn("[<marker>] ...")` lines so `docker logs <kong> | grep x-security-` is the audit grep, and tag the plugin so `kong.yml` self-documents.
Honest caveats:
- response-body plugins require Kong OSS to buffer the response (default for non-streaming upstreams); large bodies see a memory hit.
- `botProtection` provider= field is recorded but the CAPTCHA verification API call is provider-side (Turnstile/reCAPTCHA/hCaptcha clients); the heuristic gate runs in-Kong without that round-trip.
- `rateLimit.identifier=fingerprint` populates the composite key — pair it with `limit_by: header` + `header_name: X-x-security-Fingerprint` (or a `targetOverrides.kong` lua-resty-limit-req block) for the bucketing.

Still unsupported:
- `response.schema` type/min/pattern enforcement (only maxLength is covered).
- `deprecated`, `sunsetDate`, `replacementEndpoint` — K-5 emits 410 but `Sunset:` / `Link: rel=successor-version` headers are body-only.

## Output
- Single artifact: `kong.yml` (declarative DBless, `_format_version: 3.0`)
- One Kong service + one route per `EndpointIR`
- Path templates (`/api/users/{id}`) become Kong regex paths (`~/api/users/[^/]+`)
- Every plugin carries an explicit `id: <uuidv5>` derived from
  `route_name|plugin_name|index`. This is **required** by Kong 3.x — two
  plugins with identical config on different routes otherwise compute the
  same primary key and Kong rejects the second with "uniqueness violation".
  The UUID is deterministic so `lazy diff` stays stable across runs.
- Tag values are sanitized (`:` `/` `,` → `_`). Kong 3.4 rejects raw
  `jwks=https://...` tags as "invalid tag ... expected printable ascii".

## Open questions
1. **Path stripping.** We default `strip_path: false`. If upstream services
   expect prefixes stripped, callers will need `targetOverrides.kong`.
2. **Service URL.** Currently uses `spec.servers[0].url` as the single upstream
   for every endpoint. Per-endpoint upstream overrides (`x-upstream`) aren't in
   `XSecurityPolicy`; punted to override channel.
3. **JWT consumer wiring.** ~~OSS Kong has no JWKS fetch — we record JWKS as
   tags. A follow-up could emit `consumers:` + `jwt_secrets:` stubs the
   operator fills in, but that crosses the "declarative-only" bar.~~
   **ANSWERED (C-4):** we crossed the bar. `--with-consumers` (default ON)
   emits one `Consumer` per unique `authorization.rbac.roles[]` value plus
   matching `jwt_secrets`, `keyauth_credentials`, `hmacauth_credentials`,
   and `acls` entries. Secrets are deterministic (sha1 of role + spec title)
   so `lazy diff` stays stable. **Downgrade:** `jwt_secrets.algorithm`
   is hardcoded to `HS256` because OSS Kong cannot validate RS256 without
   JWKS — see the bearer-jwt entry above for the rationale and warning.
   `authentication.custom-token` has no Kong plugin and emits a warning only.
4. **Rate-limit bucket loss.** A 5-second window currently maps to `minute` bucket
   if seconds > 1. Reconsider rounding policy if sub-minute windows become common.
5. **Override merge semantics.** `targetOverrides.kong` is appended as plugins
   today. If overrides need to mutate existing plugin configs (e.g. swap
   `policy: local` for `redis`), a deep-merge mode is needed.

## Verification
- `pnpm --filter @x-security/cli test -- --test-name-pattern='kong generator'` → 7 / 7 pass
- Snapshot test: `fixtures/configs/kong/example.expected.yml` matches generator output (parsed YAML deep-equal)
- Isolated typecheck of `src/generators/kong/**` under strict + `exactOptionalPropertyTypes` passes clean
- **Note:** workspace-level `pnpm --filter @x-security/cli build` currently fails
  due to a pre-existing missing `Timeout` re-export in `@x-security/schema`
  referenced by `src/generators/bunkerweb/settings.ts`. Out of scope for this
  task; fix is one line in `packages/schema/src/index.ts`.
