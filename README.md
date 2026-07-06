# x-security — security policy as an OpenAPI extension

Apache-2.0. Write policy next to the route it protects; compile it to any gateway with a deterministic CLI.

**Most teams run their API gateway and WAF on defaults.** The security is
already in the box — authentication, rate limits, request validation,
ownership/BOLA checks — but turning it on means learning each vendor's config
DSL, and the rules you write lock you into that vendor and drift out of sync
with your code.

**`x-security` is one security policy per route, written as an extension of the
OpenAPI spec you already have.** It versions in git, diffs like code, and a
deterministic CLI compiles it to whichever gateway you run.

- **No new DSL** — it's your OpenAPI file.
- **No vendor lock-in** — one spec compiles to Kong, Coraza, BunkerWeb, OpenAppSec, Envoy, or a firewall bundle. Switch gateways without rewriting policy.
- **No config drift** — the spec is the source of truth; drift fails CI.

This repo is the open spec: the JSON Schema, the OWASP mapping, a Spectral
ruleset, examples, and the reference CLI that compiles it —
[`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security).
Watch releases; schema changes are versioned and tagged.

## What it looks like

```yaml
paths:
  /auth/login:
    post:
      x-security:
        authentication: { type: none }
        rateLimit: { requests: 5, window: 1m, identifier: ip, burst: 2 }
        request:
          contentType: [application/json]
          maxBodySize: 10KB
          schema:
            email: { type: email, maxLength: 254, mitigates: ["API2:2023"] }
            password: { type: free-text, minLength: 8, maxLength: 128 }
        cacheable: false
        timeout: { read: 5000 }
```

One `x-security` block per route. It lives in the OpenAPI file you already
have, versions in git, and diffs like code.

## How it works

1. **Annotate** — attach an `x-security` block to each route: by hand, with the
   [visual builder](https://usewaf.com/policy-builder.html), or with the free AI
   plugin that reads your code and drafts the policy for you.
2. **Validate** — lint the annotated spec against the JSON Schema + Spectral
   ruleset in CI, so a malformed policy never merges.
3. **Compile** — `xsecurity generate` turns the spec into native config for your
   gateway. One spec, any supported target.
4. **Enforce & catch drift** — deploy the config, then run `xsecurity validate`
   so CI fails the moment the gateway and the spec disagree.

## Quickstart

```bash
# Validate any annotated spec against the schema + ruleset
npx @stoplight/spectral-cli lint --ruleset spectral-ruleset.yaml your-openapi.yaml

# Compile it to the gateway you run
npm i -g @chain305/x-security
xsecurity generate your-openapi.yaml --target kong > kong.yaml
xsecurity report   your-openapi.yaml            # OWASP API Top 10 coverage
xsecurity validate your-openapi.yaml --target kong --gateway http://localhost:8001
```

Full CLI walkthrough — install, `init`, `test`, `verify`, drift gating — in
[`cli/README.md`](cli/README.md). Or validate a single block against
`schema/x-security.schema.json` with any JSON Schema validator (draft 2020-12).

## Support matrix

### Compile & deploy targets

`xsecurity generate --target <name>` compiles one annotated spec to any of these. Two are hosted deploys; the rest are self-hosted bundles you drop into your gateway.

| Target (`--target`) | What it is | Delivery | Status |
| --- | --- | --- | --- |
| `cloudflare` | Cloudflare Ruleset Engine + WAF | hosted deploy | GA |
| `aws-apigw` | AWS API Gateway + WAFv2 | hosted deploy | beta |
| `kong` | Kong Gateway (decK plugin config) | self-hosted bundle | beta |
| `coraza` | Coraza / ModSecurity WAF (SecLang) | self-hosted bundle | beta |
| `coraza` *(nginx preset)* | NGINX + libcoraza | self-hosted bundle | beta |
| `bunkerweb` | BunkerWeb (OpenResty WAF) | self-hosted bundle | beta |
| `openappsec` | Check Point Open AppSec WAF | self-hosted bundle | beta |
| `envoy` | Envoy (ext_proc / Lua filter) | self-hosted bundle | alpha |
| `firewall` | Host firewall (iptables) | self-hosted bundle | SSRF egress only¹ |

¹ `firewall` is L3/L4 — it enforces only API7 SSRF egress via `domainAllowlist`; it can't introspect HTTP, so it's not on the coverage matrix below.

### OWASP API Top 10 coverage per target

How much of each class a target can **enforce natively**. 🟢 full · 🟡 partial · 🔴 gap · ⚪ not yet measured. Authorization cells show **stateless → with a JWT identity wired**.

| OWASP API class | Cloudflare | AWS API GW | BunkerWeb |
| --- | :--: | :--: | :--: |
| API1 · Broken Object Level Auth (BOLA) | 🔴→🟡 | 🔴→🟢 | 🔴 |
| API2 · Broken Authentication | 🟡 | 🟡 | 🟡 |
| API3 · Broken Object Property Auth (BOPLA) | 🟡 | 🟡 | 🟡 |
| API4 · Unrestricted Resource Consumption | 🟢 | 🟡 | 🟡 |
| API5 · Broken Function Level Auth (BFLA) | 🟡 | 🟡→🟢 | 🟡 |
| API6 · Unrestricted Access to Business Flows | 🟡 | 🟡 | 🟡 |
| API7 · Server-Side Request Forgery (SSRF) | 🔴 | 🔴 | 🟢 |
| API8 · Security Misconfiguration | 🟡 | 🟡 | 🟡 |
| API9 · Improper Inventory Management | 🔴 | 🔴 | 🟡 |
| API10 · Unsafe Consumption of APIs | 🟡 | 🟡 | 🟡 |

Only these three targets are independently **measured** today; Kong, Coraza, NGINX, Envoy and OpenAppSec compile the same policy but aren't yet published with a per-class measurement (⚪). Cells like **🔴→🟢** are the same control stateless vs. with a JWT identity wired — ownership checks (BOLA/BFLA) need to know who the caller is, so a stateless WAF can't enforce them. A **🟡** means the target enforces most of the class natively, not all. Full per-field matrix (incl. the Writ-native injection / prompt-injection / audit classes): **[usewaf.com/coverage](https://usewaf.com/coverage)**.

## Contents

| Path | What it is |
|---|---|
| [`schema/x-security.schema.json`](schema/x-security.schema.json) | JSON Schema for the `x-security` object — validate any policy block against it |
| [`schema/owasp-mapping.json`](schema/owasp-mapping.json) | Canonical mapping from policy fields to OWASP API Top 10 (2023) categories |
| [`spectral-ruleset.yaml`](spectral-ruleset.yaml) | Spectral ruleset — lint annotated OpenAPI specs in CI |
| [`docs/v0.8-reference.md`](docs/v0.8-reference.md) | Field-level reference for the current schema version |
| [`examples/`](examples/) | Annotated OpenAPI specs that validate against the schema |
| [`policy-builder.html`](policy-builder.html) | Visual builder — build `x-security` policies from an OpenAPI spec (or by hand) and export an annotated spec. Also hosted at [usewaf.com/policy-builder.html](https://usewaf.com/policy-builder.html) |
| [`cli/`](cli/) | Reference CLI (`xsecurity`) — compiles annotated specs into gateway config. Published as [`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security) |

## Versioning

The schema is versioned independently of any tooling. Current version:
**0.8.0**. Releases are tagged; breaking changes bump the minor version until
1.0.

## License

[Apache-2.0](LICENSE). The spec is the product: use it, implement it, fork it.
