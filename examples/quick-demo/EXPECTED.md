# EXPECTED — quick-demo ground truth

Captured from a clean `./scripts/demo.sh` run on a fresh `docker compose up`
(2026-07-07). This is regression reference, not aspiration. The demo's exit
contract: exit 0 iff every attack that LANDED in direct was BLOCKED in
indirect, with no regressions. The `n/a-direct` row (CORS) is a gateway-only
vuln class that doesn't manifest against the raw target — it's neither
"secured" nor "broken" and does not count toward the contract.

## before / after

```
=== before / after ===
ATTACK                             OWASP  DIRECT     INDIRECT     VERDICT
------------------------------------------------------------------------
API1-BOLA-enum-61-ratelimit        API1   LANDED     BLOCKED      secured
JWT-HS256-banned-algorithm         API2   LANDED     BLOCKED      secured
API5-BFLA-admin-listing            API5   LANDED     BLOCKED      secured
API6-mass-assign-create            API6   LANDED     BLOCKED      secured
CORS-preflight-reflect             API7   blocked    BLOCKED      n/a-direct
SSRF-internal-deterministic        API8   LANDED     BLOCKED      secured
API9-deprecated-endpoint           API9   LANDED     BLOCKED      secured
API10-unauth-flag                  API10  LANDED     BLOCKED      secured

[demo] contract met: every attack that landed in direct was blocked in indirect.
```

Coverage: 8 of the OWASP API Security Top 10 (API1, API2, API5, API6, API7,
API8, API9, API10). API3 (excessive data exposure) and API4 (unrestricted
resource consumption / rate limiting) are annotated in `openapi.yaml` and
generate policy, but are not yet exercised by `scripts/exploit.sh`.

demo.sh exit code: 0. Reproducibility: a second teardown + fresh `demo.sh` run
produced a byte-identical table section (`REPRODUCIBLE`).

## What each column means

- **DIRECT** — client hits the raw vAPI (`:8000`), no policy. `LANDED` = exploit succeeded.
- **INDIRECT** — client hits Kong → Coraza → vAPI (`:18000`), policy enforced. `BLOCKED` = policy stopped the exploit.
- **VERDICT**:
  - `secured` — landed in direct, blocked in indirect. The API was protected without modifying its source.
  - `UNBLOCKED` — landed in both. Policy failed to enforce (would be a regression).
  - `REGRESSION` — blocked in direct, landed in indirect (would be a regression).
  - `n/a-direct` — did not land in direct (gateway-only vuln class); no enforcement claim, doesn't count toward the contract.

## Notes

These come from `scripts/exploit.sh` honesty comments and the live signal
strings, not aspiration:

- **CORS-preflight-reflect (`n/a-direct`)** — the direct vAPI target has no
  CORS plugin, so an `OPTIONS /api7/user/key` with `Origin: https://evil.example`
  does not reflect `Access-Control-Allow-Origin`. The exploit therefore reports
  `exploit_succeeded=false` in direct mode — not because vAPI is safe, but
  because the vuln class requires a gateway/CORS plugin to manifest at all.
  Indirect mode also reports `BLOCKED` (no ACAO reflection through Kong).
  Per the demo contract this is informational: it is neither a "secured" claim
  nor a reproducibility failure. Calling it `secured` would overclaim; calling
  it "not reproducible" would mislabel an honest non-exploitable state as a
  test failure. `n/a-direct` is the honest verdict.

- **JWT-HS256-banned-algorithm (`secured`)** — landed in direct (raw vAPI has
  no auth, returns 2xx to the forged HS256 token), blocked in indirect. The
  honesty nuance: the indirect block is **hmac-auth**, not the JWT
  `bannedAlgorithms` rule. Kong OSS does not honor `bannedAlgorithms` on the
  JWT plugin; api10's route has both `hmac-auth` and `jwt`, and `hmac-auth`
  intercepts first, returning 401 regardless of which header carries the JWT
  or what algorithm it was signed with. So the row is honestly `secured`
  (the forged-token attack did not reach vAPI through the gateway) but the
  *mechanism* is HMAC credential enforcement, not algorithm-ban enforcement.
  A future run that strips hmac-auth from the api10 route would expose whether
  the banned-algorithm rule actually fires.

- **API1-BOLA-enum-61-ratelimit (`secured`)** — direct enumerates >60 user
  records with no 429; indirect is blocked at the JWT plugin on the api1
  route (401 before rate-limiting or BOLA pre-function evaluate), so the
  signal honestly reports `successes=0; saw_429=false`. The exploit did not
  freely enumerate, whatever the reason.

- **API5-BFLA-admin-listing (`secured`)** — vAPI's `GET /api5/users`
  (`showall()`) returns EVERY user to any valid `Authorization-Token`, with no
  function-level check; direct mode leaks the full listing including the admin
  row's `flag{api5_...}` (the `leaked_admin_flag=yes` signal). Indirect is
  blocked at the api5/users **ACL** (`allow: admin`) with a *valid* role_user
  JWT — the block is authorization (403 "cannot consume this service"), not
  missing auth. A control request with no Kong JWT returns 401 instead,
  confirming the 403 is the ACL path and not merely rejected credentials.

- **API9-deprecated-endpoint (`secured`)** — the raw app still answers the
  sunset `POST /api9/v1/user/login` (200). Indirect returns **410 Gone** from
  the compiled K-5 deprecated-endpoint-block pre-function, which fires in
  Kong's access phase before the request proxies (body carries
  `tag: x-security-deprecated-endpoint-block`, `sunset: 2024-01-01`). This is a
  distinct API9 primitive, not a rate-limit side effect.

- **API6-mass-assign-create / SSRF-internal-deterministic / API10-unauth-flag
  (`secured`)** — landed in direct (2xx), blocked in indirect (401/403 from
  Kong jwt + hmac-auth). No enforcement gaps observed for these three rows.
