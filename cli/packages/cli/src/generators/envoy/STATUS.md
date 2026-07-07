# Envoy Generator — STATUS (wave-9)

## Scope
Envoy v3 config emitter under `packages/cli/src/generators/envoy/`. Wave-9
refactor: native filters for JWT (`jwt_authn`), RBAC (`rbac`), rate-limit
(`local_ratelimit` per-route), and CORS (`cors`). Lua kept as a fallback for
fields with no native equivalent.

## Deliverables
- `index.ts` — `envoyGenerator: Generator`.
- `templates/envoy-yaml.ts` — full Envoy v3 bootstrap builder (admin +
  listener + route_config + filter chain + clusters).
- `templates/lua.ts` — residual Lua module (method-allowlist + per-endpoint
  Content-Type/maxBodySize/headerInjectionGuard/duplicateParamPolicy
  enforcement). Only emitted when at least one endpoint declares a
  Lua-requiring field.
- `../../test/generators/envoy.test.ts` — 34 unit tests + golden fixture.
- `../../test/verify/envoy.test.ts` — verify reader unit + integration tests.

## Filter chain order (contract, enforced by tests)
1. `envoy.filters.http.jwt_authn`        — JWKS-backed RS256/ES256/EdDSA validation
2. `envoy.filters.http.rbac`             — principal from jwt_authn metadata
3. `envoy.filters.http.local_ratelimit`  — per-route via typed_per_filter_config
4. `envoy.filters.http.cors`             — per-route CorsPolicy override
5. `envoy.filters.http.lua`              — residual fields only (omitted if unused)
6. `envoy.filters.http.router`           — terminal

## Feature Support

| XSecurityPolicy field             | Status        | Path     | Notes |
| --------------------------------- | ------------- | -------- | ----- |
| `authentication.type=bearer-jwt`  | `full`        | native   | `jwt_authn` with remote JWKS via `jwks_cluster` (TLS-aware) |
| `authentication.jwksUri`          | `full`        | native   | `remote_jwks.http_uri` |
| `authentication.issuer`           | `full`        | native   | provider.issuer |
| `authentication.audience`         | `full`        | native   | provider.audiences |
| `authentication.allowedAlgorithms`| `full`        | native   | jwt_authn validates signature; allowedAlgorithms acts as the allowlist |
| `authentication.bannedAlgorithms` | `partial`     | —        | jwt_authn has no explicit deny — relies on allowedAlgorithms. HS256/none ban requires a Lua sidecar (wave-10). |
| `authentication.scopes`           | `partial`     | —        | Needs custom claim matcher (wave-10) |
| `authorization.type=rbac`         | `full`        | native   | `rbac` filter; principal sourced from jwt_authn `payload_in_metadata.role` |
| `authorization.type=rule-based`   | `full`        | native+OPA | `ext_authz` filter (cluster `opa_grpc:9191`). Generator also emits `opa/policy.rego` — one `allow` block per (endpoint, rule). **Runtime dependency:** OPA gRPC ext_authz sidecar must be deployed alongside Envoy (see `e2e/fixtures/chain-envoy-vapi/docker-compose.yml`). Live BOLA evidence: `/tmp/vapi-test/fixes/v10-envoy-extauthz.md`. |
| `rateLimit`                       | `full`        | native   | `local_ratelimit` per-route via `typed_per_filter_config`. `stat_prefix` is the verify-able evidence (admin `/stats`). |
| `cors`                            | `full`        | native   | `cors` filter chain-level + per-route `CorsPolicy` override |
| `request.contentType[]`           | `full`        | lua      | 415 on mismatch |
| `request.maxBodySize`             | `full`        | lua      | 413 on exceed; also emits `request_body_buffer_limit` global cap |
| `request.headerInjectionGuard`    | `full`        | lua      | 400 on CR/LF/NUL |
| `request.duplicateParamPolicy`    | `partial`     | lua      | Query-string HPP only; body-form HPP needs body filter (wave-10) |
| `request.signature`               | `unsupported` | —        | Requires body-filter callback (wave-10) |
| `method` (from spec)              | `full`        | lua      | 405 if method not in spec for matched path |
| `request.schema.*`                | `unsupported` | —        | Out of scope for L7 Envoy |
| `ipPolicy.allow`                  | `full`        | native   | W22-A: second RBAC instance `envoy.filters.http.rbac.ip`; per-route ALLOW with `source_ip` principals |
| `ipPolicy.deny`                   | `full`        | native   | W22-A: per-route DENY policy on the same `envoy.filters.http.rbac.ip` filter |
| `timeout`                         | `unsupported` | —        | Cluster-level |
| `cacheable`                       | `full`        | native   | W22-A: `envoy.filters.http.cache` (SimpleHttpCache); per-route `disabled: true` for opt-out |
| `mtls`                            | `unsupported` | —        | TLS context concern |
| `csrf` (origin-check)             | `partial`     | native   | W22-A: `envoy.filters.http.csrf` + per-route `additional_origins`. `double-submit` / `custom-header` still need Lua. |
| `response.headers.csp`            | `full`        | native   | W22-A: per-route `response_headers_to_add` with `OVERWRITE_IF_EXISTS_OR_ADD` |
| `response.headers.hsts`           | `full`        | native   | W22-A: same; rendered as `max-age=...; includeSubDomains; preload` |
| `response.headers.frameOptions`   | `full`        | native   | W22-A |
| `response.headers.contentTypeOptions` | `full`    | native   | W22-A |
| `response.headers.referrerPolicy` | `full`        | native   | W22-A |
| `response.headers.permissionsPolicy` | `full`     | native   | W22-A |

## Generator output

| Artefact          | When emitted | Purpose |
| ----------------- | ------------ | ------- |
| `envoy.yaml`      | always       | Full Envoy v3 bootstrap. Runnable as-is (defaults: listener :8080, admin :9901, upstream cluster `upstream:80`). |
| `writ.lua`  | when at least one endpoint uses a Lua-only field | Residual Lua module. Loaded inline via `inline_code` in the bootstrap; the standalone file is identical for operators who prefer ConfigMap mounts. |

## Drift contract
File-mode. The drift detector regenerates the bootstrap from the SpecIR and
compares against the deployed `envoy.yaml`. Block identity for Lua-handled
fields is keyed by the `-- writ:<METHOD>:<path>` sentinel; native-filter
identity is keyed by:
- filter `name:` (e.g. `envoy.filters.http.jwt_authn`)
- jwt_authn rule path regex
- rbac policy name
- per-route rate-limit `stat_prefix`
- per-route CORS presence (route by method+path)

## Verification
```
pnpm --filter @x-security/cli build
pnpm --filter @x-security/cli test -- --test-name-pattern envoy
```

## E2E status (wave-9)

Run via `e2e/fixtures/chain-envoy-vapi/`. The harness wrapper is now a 5-line
script (sed retargets the upstream cluster at `vapi`, then execs envoy) — the
generator emits the full bootstrap.

| Concern | Result |
| ------- | ------ |
| Generator output shape | Full runnable bootstrap (admin + listeners + filter chain + clusters) |
| `jwt_authn` blocks unauthenticated requests | Access log shows `RESPONSE_CODE_DETAILS=jwt_authn_failed` (was `lua_response` in wave-7) |
| `rbac` blocks wrong-role JWTs | Access log shows `RESPONSE_CODE_DETAILS=rbac_access_denied_matched_policy[...]` |
| `local_ratelimit` per-route enforcement | `/stats` exposes `http.writ_hcm.http_local_rate_limit.<stat_prefix>.rate_limited` counters |
| `cors` preflight | OPTIONS request returns 200 with `Access-Control-Allow-Origin` |
| Residual Lua | Only loaded when needed; sentinel markers preserved for drift detection |
| `lazy verify --target envoy` | Reconciles each native filter independently (jwt rules, rbac policies, ratelimit prefixes, cors routes, lua sentinels) |
