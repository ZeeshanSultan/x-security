# x-security schema migration: v0.4 → v0.5

This release is **purely additive**. No existing v0.4 policy needs to change. The schema `$id` bumps from `v0.4.json` to `v0.5.json` and `SCHEMA_VERSION` from `0.4.0` to `0.5.0`.

## New fields (the 9 additions)

| ID | Field | One-liner |
|----|-------|-----------|
| S-10 | `RuleRef.ref` (pattern) | Widened namespaces from `{jwt,request,resource}` to `{jwt,principal,session,header,request,resource}`. |
| S-11 | `outboundCalls[]` (top-level) | Declared outbound calls — signature, response schema, TLS floor. |
| S-12 | `authentication.{mfaRequired, tokenSources, accountLockout, passwordPolicy}` | Step-up MFA, token-location pinning, brute-force lockout, password strength. |
| S-13 | `response.errorScrubbing` | Strip stack traces / server headers / verbose messages; remap status bodies. |
| S-14 | `rateLimit.identifier` (object form) | Composite-ID combinator: `concat` (default), `distinct`, `min-of`. |
| S-15 | `ParamSchema.redirectAllowedDomains` | Open-redirect defense on `type:'url'` params. |
| S-16 | `authentication.sessionRotateOnAuth` | Rotate session ID on successful auth (anti session-fixation). |
| S-17 | `request.signature.{nonceHeader, nonceCacheTtl}` | Per-request nonce + replay TTL. |
| S-18 | `tls` (top-level) | TLS floor: `minVersion`, `allowedCipherSuites`. |

## Breaking changes

**None.** Every addition is optional. The two areas to re-verify:

1. **`RuleRef` pattern (S-10)** — the *allowed* namespace set grew. If you had a test asserting that a previously-rejected ref (e.g. `session.userId`) is still invalid, it now passes. Update the negative test to use a namespace that's still out of set (e.g. `env.HOME`).
2. **`rateLimit.identifier` bare-array form (S-14)** — semantics are now *explicitly* `combinator: 'concat'`. This matches the v0.4 behavior — generators don't need to change. If you want a different combinator, switch from the array shorthand to the object form.

## Migration steps

There is **no auto-migration**. Recommended steps:

1. `pnpm --filter @x-security/schema build` — picks up the new `$id`.
2. Re-run `x-security validate --strict` on your existing spec to (a) confirm it still validates and (b) surface any newly-available stricter constraints you'd want to opt into.
3. If you author specs by hand, browse the new fields above and opt in where they apply.

## Per-target field-support matrix

Each **native** generator emits a `STATUS.md` documenting which fields are supported, partial, or unsupported. The six native generators are `kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`, and `envoy`:

- `packages/cli/src/generators/kong/STATUS.md`
- `packages/cli/src/generators/coraza/STATUS.md`
- `packages/cli/src/generators/bunkerweb/STATUS.md`
- `packages/cli/src/generators/openappsec/STATUS.md`
- `packages/cli/src/generators/firewall/STATUS.md`
- `packages/cli/src/generators/envoy/STATUS.md`

`cloudflare` and `aws-apigw` are **managed-cloud capability/feasibility targets**, not native config generators — they ship no `STATUS.md` under `generators/`. Their support surface is the capability matrix in `packages/cloudflare-compiler/src/capabilities.ts` and `packages/aws-apigw-compiler/src/capabilities.ts`, consumed by the feasibility reporter (`packages/cli/src/reporters/feasibility.ts`). (Earlier drafts of this doc pointed at `generators/cloudflare/STATUS.md` and `generators/aws-apigw/STATUS.md`; those paths never existed.)

If a target can't natively express a v0.5 field (common: TLS floor on a layer-7 WAF, MFA on a stateless proxy), the STATUS will say `unsupported` with a deployment-recipe pointer.

## Beyond v0.5: changes through v0.8

The schema has advanced to **v0.8.0** (`SCHEMA_VERSION` in `packages/schema/src/index.ts`). Each release since v0.5 is purely additive. Highlights:

- **v0.6** — `request.schema.<field>.injectionGuard` injection primitive (sinks `sql`/`nosql`/`os-command`/`xpath`/`ldap`/`code-eval`, then `xss`) with the x-security-native `SSEC-INJECTION` attribution.
- **v0.7** — `injectionGuard` gains `deserialization` and `ai-prompt` (the latter → `SSEC-PROMPT`); `authentication.passwordPolicy`/`accountLockout` enforcement; `response.forbidArrayRoot` (JSON-hijacking); `request.idempotencyKey`; `logging` (`SSEC-AUDIT`).
- **v0.8** — `graphql.operations[]` (per-operation authz/cost, override-only); `request.serializeBy` + `request.concurrencyLimit` (edge serialization, partial); `request.dataAtRest` (advisory-only, `SSEC-STORAGE`).

Full release notes: see [`CHANGELOG.md`](../CHANGELOG.md). Field-by-field reference: [`packages/schema/docs/v0.8-reference.md`](../packages/schema/docs/v0.8-reference.md).

## New Spectral rules

Cross-field constraints that JSON Schema struggles with (or that benefit from a more legible message) ship as Spectral rules:

- `xsec-outbound-call-secret-set-when-signed` (error)
- `xsec-redirect-allowed-domains-with-url-type` (warn)
- `xsec-account-lockout-identifier-shape` (warn)
- `xsec-nonce-cache-requires-header` (error)
