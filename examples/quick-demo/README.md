# quick-demo — secure a vulnerable API without touching its code

A Dockerized stack: a vulnerable API (vAPI) behind a Kong gateway and a
Coraza/ModSecurity WAF. An exploit script runs the same 8 attacks in two modes
and prints a before/after table:

- **Direct** — client hits the raw vulnerable API (`:8000`). Exploits land.
- **Indirect** — client hits Kong → Coraza → vAPI (`:18000`). The policy,
  compiled from an annotated OpenAPI spec, blocks the exploits.

The vAPI source code is never modified. The only thing between the two modes is
the policy in front of it.

## Prerequisites

- Docker + Docker Compose v2
- On the host: `jq`, `curl`, `openssl`, `basenc` (GNU coreutils).
  - macOS: `basenc` is not installed by default — `brew install coreutils`.

## Run

```bash
cd examples/quick-demo
./scripts/demo.sh        # boot + run both modes + print the before/after table
./scripts/teardown.sh    # optional: remove the stack + volumes
```

First run builds the vAPI image from upstream `roottusk/vapi@67152695` and
imports the DB dump, so it is slow (~3-5 min). Subsequent runs reuse the image.

## What you'll see

A before/after table (see `EXPECTED.md` for the captured ground truth on a
clean run):

```
ATTACK                             OWASP  DIRECT     INDIRECT     VERDICT
API1-BOLA-enum-61-ratelimit        API1   LANDED     BLOCKED      secured
JWT-HS256-banned-algorithm         API2   LANDED     BLOCKED      secured
API5-BFLA-admin-listing            API5   LANDED     BLOCKED      secured
API6-mass-assign-create            API6   LANDED     BLOCKED      secured
CORS-preflight-reflect             API7   blocked    BLOCKED      n/a-direct
SSRF-internal-deterministic        API8   LANDED     BLOCKED      secured
API9-deprecated-endpoint           API9   LANDED     BLOCKED      secured
API10-unauth-flag                  API10  LANDED     BLOCKED      secured
```

Covers 8 of the OWASP API Security Top 10 — all except API3 (excessive data
exposure) and API4 (unrestricted resource consumption).

- `LANDED` = the exploit succeeded against that target.
- `BLOCKED` = the policy stopped it.
- `secured` = landed in direct, blocked in indirect — the API was protected
  without modifying its source.
- `n/a-direct` = did not land in direct (a gateway-only vuln class that needs
  the gateway to manifest). Neither "secured" nor "broken"; doesn't count
  toward the exit contract.

`demo.sh` exits 0 when every attack that landed in direct was blocked in
indirect (no regressions).

## The policy is the source of truth

Both the Kong config (`policy/kong.yml`) and the Coraza rules
(`policy/coraza/`) are compiled from `openapi.yaml` — an OpenAPI spec annotated
with `x-security` policies — via the `lazy` CLI. To regenerate after editing
the spec:

```bash
./scripts/regen-policy.sh
```

## Stack

| Service | Role |
|---|---|
| vapi-db | MySQL 8.0 (vAPI's database, seeded from `database/vapi.sql` on first boot) |
| vapi | The vulnerable Laravel API (built from `roottusk/vapi@67152695`) |
| internal-only | In-network nginx SSRF target (no host port) |
| coraza | Coraza/ModSecurity-CRS WAF (`:8080`, diagnostic) |
| kong | Kong 3.4 gateway, DB-less, declarative config (`:18000` proxy, `:18001` admin) |

## Troubleshooting

- **`vAPI not healthy after 120s`** — first build is slow; re-run `./scripts/up.sh`.
  If it still fails: `docker compose logs vapi coraza kong`.
- **Port in use (8000/8080/18000/18001)** — stop whatever holds them, or edit the
  host-port mappings in `docker-compose.yml`.
- **`basenc: command not found`** — install GNU coreutils (`brew install coreutils`
  on macOS). It's used for JWT base64url encoding in `exploit.sh`.
- **Stale DB after a code change** — the DB dump imports only on first init. To
  re-seed: `./scripts/teardown.sh` (removes the volume) then `./scripts/up.sh`.
