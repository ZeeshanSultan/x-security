# @writ/cli — STATUS

CLI binary, command dispatch, drift detector, Docker test harness, reporters.
Generators (`src/generators/*`) are owned by other agents and only consumed here.

## Commands implemented

| Command | Status | R-ID | Notes |
|---|---|---|---|
| `generate --target <t> [--out <dir>] [--dry-run] [--no-strict] <spec>` | full | R2.1 | Dispatches to the registered generator; `--dry-run` prints artifacts without writing |
| `validate --target <t> --gateway <url|path> [--format <fmt>] <spec>` | full | R2.6 | Targets: `kong`, `coraza`, `bunkerweb`, `openappsec`, `firewall`. For `kong`, HTTP is autodetected (starts with `http://`/`https://`), else parses an exported `kong.yml`. Coraza/BunkerWeb/OpenAppSec/firewall are file-mode only — pass a path to the deployed config (firewall accepts a directory containing `iptables.rules`+`ip6tables.rules`, or a single rules file). Exit code 2 when CRITICAL/HIGH drift is found. Formats: `table`, `json`, `sarif`, `csv` |
| `test --target <t> [--upstream-port N] [--gateway-port N] [--dry-run] [--keep] [--format <fmt>] <spec>` | partial | R2.7 | Generates config + plans the docker-compose stack. `--dry-run` prints the plan. Kong target has a real container lifecycle via dockerode (pull, network, run, readiness probe, traffic, teardown). Other targets currently throw from `bringUp` — use `--dry-run` to print their plan. `--keep` leaves containers running on success for debugging |
| `report --owasp [--format <fmt>] <spec>` | full | R2.11 | Formats: `table`, `json`, `sarif`, `csv`, `html` |
| `report --coverage [--format <fmt>] <spec>` | full | R2.11 | Same formats (SARIF restricted to `--owasp`) |
| `diff --target <t> [--format <fmt>] <old> <new>` | full | R2.12 | Uses `jsondiffpatch` on each generated artifact; output `human` or `json` |
| `init <spec> [--defaults] [--target <t>] [--dry-run]` | full | R2.15 | Adds empty `x-security: {}` blocks (or a baseline policy with `--defaults`) to every operation that lacks one |
| `verify-bundle <tarball> [--public-key <pem-path>]` | full | R2.17 | Verifies a signed release bundle: extracts the tarball, recomputes sha256 of each file in `manifest.json` (exit 2 on mismatch), then checks the Ed25519 detached signature in `writ.sig` against the manifest bytes using `@writ/crypto` (exit 3 on mismatch). Defaults to an embedded release pubkey (placeholder until production substitution). Prints the public-key fingerprint (first 16 hex of sha256(PEM)) on success. |

Variable resolution (R2.10) is plumbed through a chain assembled by
`buildResolverChain` in `@writ/core/resolvers`. The chain always
includes `EnvResolver` and opts into remote backends via CLI flags:

- `--vault` — enables `VaultResolver` (HashiCorp Vault, KV v1 + v2). Credentials
  come from `VAULT_ADDR` plus either `VAULT_TOKEN` or AppRole
  (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`). `VAULT_NAMESPACE` is honored on
  Enterprise. KV version defaults to 2; override with `--vault-kv-version=1`
  or `VAULT_KV_VERSION=1`. Reads are cached in-process for the secret's
  `lease_duration`, falling back to 5 minutes. Reference syntax:
  `$vault.<engine>/<path>#<key>` (e.g. `$vault.kv/writ#jwks`). Without
  `#key` the entire secret is returned as JSON. Network failures surface as
  `Vault unreachable at <addr>: ...`.
- `--aws-secrets` — enables `AwsSecretsResolver` (AWS Secrets Manager). Uses
  the default AWS credential chain and `AWS_REGION`. The SDK
  (`@aws-sdk/client-secrets-manager`) is an optional peer dep and dynamically
  imported, so users who don't enable AWS don't pay the install cost.
  Reference syntax: `$aws.<secret-id>[#<json-key>]`. Without `#key` the raw
  `SecretString` is returned; with `#key`, the secret is JSON-parsed and the
  value at that key is extracted.

All resolvers are async-aware (`resolve(): Promise<string | undefined>`),
deduped, and resolved concurrently per spec load.

`--strict` is the default for `generate`; `report` / `validate` / `diff` run
in lenient mode so partially-annotated specs still work. The legacy
in-memory `StubVaultResolver` is preserved in `@writ/core` for tests.

## Files

- `src/bin/lazy.ts` — commander entrypoint, exit codes, stdout/stderr
- `src/registry.ts` — lazy `import()` of each generator; degrades gracefully when missing
- `src/commands/{generate,validate,test,report,diff,init}.ts` — thin command wrappers
- `src/drift/{kong-shared,kong-admin,kong-file,coraza,bunkerweb,openappsec,firewall}.ts` — drift detection (per-target)
- `src/test-harness/{docker-compose,traffic,assertions}.ts` — closed-loop testing
- `src/reporters/{human,json,sarif,junit,csv,html,owasp-analyze,types}.ts` — output formats
- `src/index.ts` — programmatic API re-exports

## Drift detection

Drift coverage now spans all five targets — `kong`, `coraza`, `bunkerweb`,
`openappsec`, and `firewall`. Every detector re-uses the matching generator
to build the *expected* config from the SpecIR, then diffs it against the
deployed artifact (or, for Kong only, the live admin API). This guarantees
detector and generator agree on the canonical shape — they share builders.

Per-target file-mode contracts:

| Target | Expected input | Matching strategy |
|---|---|---|
| `kong` | `kong.yml` declarative export, or live Admin URL | Endpoint→plugin map, plugin config shallow diff |
| `coraza` | Generator's `coraza.yml` (top-level `directives:` block) | Tokenize directives; locate per-endpoint rule blocks via the deterministic `ruleBase + SLOT` id scheme in `generators/coraza/rules.ts`; diff per slot |
| `bunkerweb` | Generator's `bunkerweb.yml` (`services: { <host>: { <KEY>: <value> } }`) | Per-host key-by-key compare with nginx-rate / size-aware semantics |
| `openappsec` | Generator's `openappsec/policy.yaml` | Match `schemaValidation[]` by `binding.method`+`binding.path`; match `practices[].rate-limit.rules[]` by URI |
| `firewall` | Single `iptables-save` / `.rules` file OR a directory containing `iptables.rules`+`ip6tables.rules` | Extract `# writ:`-tagged (comment, rule) pairs; pair by tag + destination CIDR/FQDN |
| `envoy` | Single `envoy.yaml` (Lua inlined under `inline_code: \|`) OR a directory containing `envoy.yaml` + `writ.lua` | Extract `-- writ:<METHOD>:<path>:START` / `-- writ:END` blocks from the Lua source; diff per-endpoint signals (auth/413/415/rate-limit-breadcrumb); compare deployed `rate_limit_descriptors` keys against expected |

Severity rules apply uniformly across targets:

| Drift | Severity |
|---|---|
| Missing endpoint / missing service / missing SSRF block | CRITICAL |
| Missing `jwt` / `acl` plugin (kong) / missing auth setting / missing schemaValidation (openappsec) | CRITICAL |
| Rate-limit *weakening* (actual > expected) | CRITICAL |
| Authentication / authorization config diff | CRITICAL |
| CORS / IP allowlist diff | HIGH |
| `maxBodySize` widened beyond spec | HIGH |
| Other plugin / setting presence diff | HIGH |
| Content-type / cacheable / timeout diff | MEDIUM |
| Unknown target-specific override (extra plugin/setting/rule) | LOW |

## Closed-loop testing

`docker-compose.ts::buildComposePlan` produces a valid compose YAML for
`kong | coraza | bunkerweb | openappsec`. The plan uses `node:20-alpine` with
an inline echo server as the mock upstream — no custom image to build.

Assertions in `assertions.ts` cover: authentication (401/403), CORS preflight,
content-type rejection (415/400), max body size (413), schema validation
(400/422), and rate limiting (expect 429 after N+1 requests). Each assertion is
endpoint-scoped and produces a `TestCaseResult{verdict, rule, durationMs, message}`,
which renders to JUnit XML for CI consumption.

## Running tests

```bash
pnpm --filter @writ/cli test
```

Runs all unit tests. **Does not require Docker.** As of writing: 75/75 pass.

### Docker integration tests

Live container tests are gated behind `WRIT_DOCKER_TESTS=1` and use the
`--test-only-names docker` node test runner flag:

```bash
WRIT_DOCKER_TESTS=1 node --test --import tsx \
  --test-only-names docker 'test/**/*.test.ts'
```

`test/test-harness/lifecycle.test.ts` is the live Kong lifecycle test. It is
skipped (with a clear "skip: WRIT_DOCKER_TESTS=1 not set" message) when
the flag is absent. When set with a reachable Docker daemon, it generates the
config, brings up `kong:3.4` + `mendhak/http-https-echo:36` on a private
bridge network, waits for Kong to answer HTTP, exercises the rate-limit
assertion on `/api/auth/login`, and tears the stack down in `finally{}`.

`test/test-harness/dry-run.test.ts` runs unconditionally and verifies the
compose plan YAML without touching Docker.

### Target lifecycle matrix

| Target | Image | Lifecycle |
|---|---|---|
| kong | `kong:3.4` | Real (dockerode-driven; pull, network, run, readiness probe, teardown) |
| coraza | `owasp/coraza-spoa:latest` | Stub — `bringUp` throws; use `--dry-run` |
| bunkerweb | `bunkerity/bunkerweb:latest` | Stub — `bringUp` throws; use `--dry-run` |
| openappsec | `ghcr.io/openappsec/agent:latest` | Stub — `bringUp` throws; use `--dry-run` |
| firewall | — | Out of scope (OS-host concern, no container) |
| envoy | `envoyproxy/envoy:v1.31-latest` | Stub — `bringUp` not wired; use `--dry-run`. File-mode drift detection is fully supported. |

Container names embed `pid + random suffix` so re-running after a failed
teardown does not collide. Stale containers with the same name are
force-removed before re-creation as a belt-and-braces guard.

## Smoke check

```bash
pnpm --filter @writ/cli build
node packages/cli/dist/bin/lazy.js report --owasp fixtures/specs/example.yaml
```

Prints a 10-column OWASP coverage table for the 3 endpoints in the fixture.

## Gaps and future work

- **`test` live execution — non-Kong targets**: `bringUp` for Coraza,
  BunkerWeb, and OpenAppSec throws "stubbed" with a pointer to `--dry-run`.
  Adding them requires per-target env/volume wiring and a per-target
  readiness probe. The Kong path in `docker-compose.ts::bringUp` is the
  template to follow.
- **Drift detection** now covers all five targets (`kong`, `coraza`,
  `bunkerweb`, `openappsec`, `firewall`). Non-Kong detectors are file-mode
  only — there is no live admin equivalent for those products in scope.
- **R2.13 fleet mode** (multi-spec validate / report) is not implemented.
- **R2.10 vault**: a real HashiCorp Vault resolver (uses `VAULT_ADDR` /
  `VAULT_TOKEN`) replaces `StubVaultResolver` — currently a stub.
- **`diff` color output** uses plain text; a chalk-tinted variant is a
  trivial follow-up.
- **CORS test assertion** doesn't yet verify `allowedMethods` /
  `Access-Control-Allow-Credentials` — only `Access-Control-Allow-Origin`.
