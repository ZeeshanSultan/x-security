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
npm i -g @chain305/x-security     # installs the `xsecurity` command
xsecurity --help
```

Or run it without installing:

```
npx @chain305/x-security --help
```

Requires Node 20+. Docker is needed only for `xsecurity test`.

## How it works

```
   your OpenAPI spec                          your gateway
  ┌──────────────────┐   xsecurity generate  ┌──────────────┐
  │  paths:          │  ───────────────────► │ Kong / Coraza│
  │    /users/{id}:  │                       │ Envoy / WAF  │
  │      x-security: │  ◄─────────────────── │  …enforced   │
  │        …         │   xsecurity validate  └──────────────┘
  └──────────────────┘     (drift gate)
```

1. **Annotate** — attach an `x-security` block to each route. Write it by hand,
   with the [visual builder](https://usewaf.com/policy-builder.html), or with
   the free AI plugin that reads your code and drafts the policy for you.
2. **Compile** — `xsecurity generate` turns the annotated spec into native
   config for your gateway. One spec, any supported target.
3. **Test** — `xsecurity test` spins the gateway up in Docker, sends real
   traffic, and asserts the policy actually blocks what it should.
4. **Enforce & catch drift** — deploy the config, then run `xsecurity validate`
   in CI so the pipeline fails the moment the gateway and the spec disagree.

## Quickstart

```bash
npm i -g @chain305/x-security

# 1. scaffold empty x-security blocks on every route that lacks one
xsecurity init api.yaml

# 2. fill them in — by hand, the visual builder, or the plugin —
#    then check your OWASP API Top 10 coverage
xsecurity report api.yaml

# 3. compile to the gateway you run
xsecurity generate api.yaml --target kong > kong.yaml

# 4. prove it blocks the exploit and allows legit traffic (needs Docker)
xsecurity test api.yaml --target kong

# 5. gate CI on drift between the spec and the deployed gateway
xsecurity validate api.yaml --target kong --gateway http://localhost:8001
```

## Commands

| Command | What it does |
| --- | --- |
| `xsecurity init <spec>` | Add empty `x-security` blocks to operations missing them |
| `xsecurity report <spec>` | OWASP API Top 10 coverage and annotation reports |
| `xsecurity generate <spec> --target <t>` | Compile an annotated OpenAPI spec into gateway config (`kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`, `envoy`) |
| `xsecurity test <spec> --target <t>` | Closed-loop test: generate config, spin up Docker, send traffic, assert |
| `xsecurity validate <spec> --target kong --gateway <url\|file>` | Detect drift between the spec and a running/exported gateway config |
| `xsecurity verify <spec> --target <t> --gateway <addr>` | Read-only post-deploy check that the gateway loaded the emitted artifacts |
| `xsecurity diff <old> <new> --target <t>` | Diff the generated config for two spec versions |
| `xsecurity migrate <spec> --from 0.4 --to 0.5` | Rewrite a spec between schema versions |

Run `xsecurity <command> --help` for full flags.

## License

Apache-2.0
