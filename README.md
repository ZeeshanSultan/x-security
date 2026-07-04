# x-security: security policy as an OpenAPI extension. Apache-2.0.

Write policy next to the route it protects. Compile it with a deterministic CLI.

- The spec, JSON Schema for validation, and examples — all in this repo
- The reference CLI that compiles it — source in [`cli/`](cli/), published as [`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security)
- Watch releases: schema changes are versioned and tagged

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

## Contents

| Path | What it is |
|---|---|
| [`schema/x-security.schema.json`](schema/x-security.schema.json) | JSON Schema for the `x-security` object — validate any policy block against it |
| [`schema/owasp-mapping.json`](schema/owasp-mapping.json) | Canonical mapping from policy fields to OWASP API Top 10 (2023) categories |
| [`spectral-ruleset.yaml`](spectral-ruleset.yaml) | Spectral ruleset — lint annotated OpenAPI specs in CI |
| [`docs/v0.8-reference.md`](docs/v0.8-reference.md) | Field-level reference for the current schema version |
| [`examples/`](examples/) | Annotated OpenAPI specs that validate against the schema |
| [`cli/`](cli/) | Reference CLI (`xsecurity`) — compiles annotated specs into gateway config. Published as [`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security) |

## Validate a spec

```bash
npx @stoplight/spectral-cli lint --ruleset spectral-ruleset.yaml your-openapi.yaml
```

Or validate a single block against `schema/x-security.schema.json` with any
JSON Schema validator (draft 2020-12).

## Compile it: the CLI

The reference implementation lives in [`cli/`](cli/) — a deterministic,
**LLM-free** CLI that turns annotated OpenAPI specs into gateway configuration
(Kong, Coraza, BunkerWeb, OpenAppSec, Envoy, firewall) and validates, tests, and
reports on them. Published to npm as
[`@chain305/x-security`](https://www.npmjs.com/package/@chain305/x-security);
the installed command is `xsecurity`.

```bash
npx @chain305/x-security --help        # run without installing
npm i -g @chain305/x-security          # global install → `xsecurity`
```

```bash
xsecurity generate your-openapi.yaml --target kong
xsecurity report   your-openapi.yaml --owasp
```

Build it from source or reproduce the published artifact — see
[`cli/README.md`](cli/README.md).

## Versioning

The schema is versioned independently of any tooling. Current version:
**0.8.0**. Releases are tagged; breaking changes bump the minor version until
1.0.

## License

[Apache-2.0](LICENSE). The spec is the product: use it, implement it, fork it.
