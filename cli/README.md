# x-security CLI

**Most teams run their API gateway and WAF on defaults.** The security is
already in the box — authentication, rate limits, request validation,
ownership/BOLA checks — but turning it on means learning each vendor's config
DSL, and the rules you write lock you into that vendor and drift out of sync
with your code.

**`x-security` is one security policy per route, written as an extension of the
OpenAPI spec you already have.** It versions in git, diffs like code, and a
deterministic CLI compiles it to whichever gateway you run.

- **No new DSL** — policy lives in your OpenAPI file, next to the route it protects.
- **No vendor lock-in** — one spec compiles to Kong, Coraza, BunkerWeb, OpenAppSec, Envoy, or a firewall bundle. Switch gateways without rewriting a line of policy.
- **No config drift** — the spec is the source of truth; `validate` fails CI when the running gateway drifts from it.
- **Deterministic** — no LLM calls, no API keys. It compiles exactly what your spec says, and nothing it can't verify.

## Install

```
npm i -g @chain305/x-security     # installs the `x-security` command
x-security --help
```

Or run it without installing:

```
npx @chain305/x-security --help
```

Requires Node 20+. Docker is needed only for `x-security test`.

## How it works

```
   your OpenAPI spec                          your gateway
  ┌──────────────────┐   x-security generate  ┌──────────────┐
  │  paths:          │  ───────────────────► │ Kong / Coraza│
  │    /users/{id}:  │                       │ Envoy / WAF  │
  │      x-security: │  ◄─────────────────── │  …enforced   │
  │        …         │   x-security validate  └──────────────┘
  └──────────────────┘     (drift gate)
```

1. **Annotate** — attach an `x-security` block to each route. Write it by hand,
   with the [visual builder](https://usewaf.com/policy-builder.html), or with
   the free AI plugin that reads your code and drafts the policy for you.
2. **Compile** — `x-security generate` turns the annotated spec into native
   config for your gateway. One spec, any supported target.
3. **Test** — `x-security test` spins the gateway up in Docker, sends real
   traffic, and asserts the policy actually blocks what it should.
4. **Enforce & catch drift** — deploy the config, then run `x-security validate`
   in CI so the pipeline fails the moment the gateway and the spec disagree.

## Quickstart

```bash
npm i -g @chain305/x-security

# 1. scaffold empty x-security blocks on every route that lacks one
x-security init api.yaml

# 2. fill them in — by hand, the visual builder, or the plugin —
#    then check your OWASP API Top 10 coverage
x-security report api.yaml

# 3. compile to the gateway you run
x-security generate api.yaml --target kong > kong.yaml

# 4. prove it blocks the exploit and allows legit traffic (needs Docker)
x-security test api.yaml --target kong

# 5. gate CI on drift between the spec and the deployed gateway
x-security validate api.yaml --target kong --gateway http://localhost:8001
```

## Commands

| Command | What it does |
| --- | --- |
| `x-security init <spec>` | Add empty `x-security` blocks to operations missing them |
| `x-security report <spec>` | OWASP API Top 10 coverage and annotation reports |
| `x-security generate <spec> --target <t>` | Compile an annotated OpenAPI spec into gateway config (`kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`, `envoy`) |
| `x-security test <spec> --target <t>` | Closed-loop test: generate config, spin up Docker, send traffic, assert |
| `x-security validate <spec> --target kong --gateway <url\|file>` | Detect drift between the spec and a running/exported gateway config |
| `x-security verify <spec> --target <t> --gateway <addr>` | Read-only post-deploy check that the gateway loaded the emitted artifacts |
| `x-security diff <old> <new> --target <t>` | Diff the generated config for two spec versions |
| `x-security migrate <spec> --from 0.4 --to 0.5` | Rewrite a spec between schema versions |

Run `x-security <command> --help` for full flags.

## Support matrix

### Compile & deploy targets

`x-security generate --target <name>` compiles one annotated spec to any of these. Two are hosted deploys; the rest are self-hosted bundles you drop into your gateway.

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

Only these three targets are independently **measured** today; Kong, Coraza, NGINX, Envoy and OpenAppSec compile the same policy but aren't yet published with a per-class measurement (⚪). Cells like **🔴→🟢** are the same control stateless vs. with a JWT identity wired — ownership checks (BOLA/BFLA) need to know who the caller is, so a stateless WAF can't enforce them. A **🟡** means the target enforces most of the class natively, not all. Full per-field matrix (incl. the x-security-native injection / prompt-injection / audit classes): **[usewaf.com/coverage](https://usewaf.com/coverage)**.

## License

Apache-2.0
