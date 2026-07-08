# x-security CLI

Compile, validate, test, and report on `x-security` policies in OpenAPI specs — deterministic, no LLM calls, no API keys.

```
npx @chain305/x-security --help
```

## Commands

| Command | What it does |
| --- | --- |
| `x-security generate <spec> --target <t>` | Compile an annotated OpenAPI spec into gateway config (`kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`, `envoy`) |
| `x-security validate <spec> --target kong --gateway <url\|file>` | Detect drift between the spec and a running/exported gateway config |
| `x-security test <spec> --target <t>` | Closed-loop test: generate config, spin up Docker, send traffic, assert |
| `x-security verify <spec> --target <t> --gateway <addr>` | Read-only post-deploy check that the gateway loaded the emitted artifacts |
| `x-security report <spec>` | OWASP API Top 10 coverage and annotation reports |
| `x-security diff <old> <new> --target <t>` | Diff the generated config for two spec versions |
| `x-security init <spec>` | Add empty `x-security` blocks to operations missing them |
| `x-security migrate <spec> --from 0.4 --to 0.5` | Rewrite a spec between schema versions |

Run `x-security <command> --help` for full flags.

## Requirements

- Node 20+
- Docker (only for `x-security test`)

## License

Apache-2.0
