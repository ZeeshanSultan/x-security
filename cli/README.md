# x-security CLI

The reference implementation for the [`x-security`](../README.md) OpenAPI
extension: a deterministic, **LLM-free** CLI that compiles annotated OpenAPI
specs into gateway configuration and validates, tests, and reports on them. No
API keys, no network calls to a model — the same input always produces the same
output.

Published to npm as **[`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security)**.
The installed command is `xsecurity`.

## Install

```bash
npx @chain305/x-security --help        # run without installing
npm i -g @chain305/x-security          # global install → `xsecurity`
```

Requires Node 20+. Docker is only needed for `xsecurity test`.

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

Run `xsecurity <command> --help` for full flags. See
[`packages/cli/README.md`](packages/cli/README.md) for the package-level readme.

## Build from source

This folder is a self-contained pnpm workspace: the CLI package plus exactly the
`@writ/*` packages it depends on (all Apache-2.0, identical to the code inlined
into the published npm bundle). Nothing else from the upstream monorepo is
required.

```bash
cd cli
pnpm install
pnpm build             # tsc build → packages/cli/dist
node packages/cli/dist/bin/lazy.js --help
```

Reproduce the exact published npm artifact:

```bash
pnpm bundle            # → packages/cli/npm-dist  (package @chain305/x-security, command xsecurity)
```

## Layout

```
cli/
  packages/
    cli/                 the CLI itself (generators, reporters, verifiers)
    schema/              x-security schema types + validation
    core/                spec parsing + policy model
    detect-core/         detection primitives
    crypto/              release-bundle signing/verification
    shared/              shared utilities
    cursor-mcp/          Cursor MCP server surface
    aws-apigw-compiler/  AWS API Gateway target compiler
    cloudflare-compiler/ Cloudflare target compiler
  docs/                  CLI-specific guides
```

## Docs

- [`docs/byo-agent-plugin.md`](docs/byo-agent-plugin.md) — the BYO-agent runtime (`writ` verbs: routes, verify-finding, compile, audit, emit)
- [`docs/schema-migration-0.4-to-0.5.md`](docs/schema-migration-0.4-to-0.5.md) — migrating specs between schema versions

## License

[Apache-2.0](../LICENSE).
