# x-security CLI

Your API gateway and WAF already ship most of the security you need — auth, rate
limits, request validation, ownership/BOLA rules. Most teams run them on
defaults. `x-security` lets you write that policy **once**, as an extension of
the OpenAPI spec you already have, and compile it to whichever gateway you run.

- **No new DSL** — policy lives in your OpenAPI file, next to the route it protects.
- **No vendor lock-in** — one spec compiles to Kong, Coraza, BunkerWeb, OpenAppSec, Envoy, or a firewall bundle. Switch gateways without rewriting a line of policy.
- **No config drift** — the spec is the source of truth; it versions and diffs like code, and `validate` catches drift against a running gateway.

Deterministic. No LLM calls, no API keys.

## Install

```
npm i -g @chain305/x-security     # installs the `xsecurity` command
xsecurity --help
```

Or run it without installing:

```
npx @chain305/x-security --help
```

## Commands

| Command | What it does |
| --- | --- |
| `xsecurity generate <spec> --target <t>` | Compile an annotated OpenAPI spec into gateway config (`kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`, `envoy`) |
| `xsecurity validate <spec> --target kong --gateway <url\|file>` | Detect drift between the spec and a running/exported gateway config |
| `xsecurity test <spec> --target <t>` | Closed-loop test: generate config, spin up Docker, send traffic, assert |
| `xsecurity verify <spec> --target <t> --gateway <addr>` | Read-only post-deploy check that the gateway loaded the emitted artifacts |
| `xsecurity report <spec>` | OWASP API Top 10 coverage and annotation reports |
| `xsecurity diff <old> <new> --target <t>` | Diff the generated config for two spec versions |
| `xsecurity init <spec>` | Add empty `x-security` blocks to operations missing them |
| `xsecurity migrate <spec> --from 0.4 --to 0.5` | Rewrite a spec between schema versions |

Run `xsecurity <command> --help` for full flags.

## Requirements

- Node 20+
- Docker (only for `xsecurity test`)

## License

Apache-2.0
