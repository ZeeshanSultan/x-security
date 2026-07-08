# x-security CLI

Compile, validate, test, and report on `x-security` policies in OpenAPI specs — deterministic, no LLM calls, no API keys.

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
- Docker (only for `lazy test`)

## License

Apache-2.0
