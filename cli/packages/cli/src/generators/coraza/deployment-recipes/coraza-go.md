# Deploying x-security rules on Coraza WAF v3 (Go binary)

For Go services embedding `github.com/corazawaf/coraza/v3` directly.

## Generate

```bash
x-security generate \
  --target coraza \
  --coraza-engine coraza-go \
  --out ./out/coraza \
  spec.yaml
```

Produces `out/coraza/coraza.yml` — YAML wrapper with a `directives: |`
block plus metadata (generator version, source spec title/version).

## Load

```go
package main

import (
    "os"
    "gopkg.in/yaml.v3"
    "github.com/corazawaf/coraza/v3"
)

type config struct {
    Directives string `yaml:"directives"`
}

func loadWAF(path string) (coraza.WAF, error) {
    b, err := os.ReadFile(path)
    if err != nil { return nil, err }
    var c config
    if err := yaml.Unmarshal(b, &c); err != nil { return nil, err }
    return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(c.Directives))
}
```

## Verify

Coraza-Go logs parse errors to stderr at `NewWAF()` time. A successful
load returns a non-nil `WAF` and zero error lines containing `parse error`.

For runtime hit observation, configure Coraza's audit logger to a file
and grep for `ruleId:` (same convention as libmodsecurity3).

## Capability surface

Full feature parity with the x-security schema:
- All `rateLimit.identifier` modes (`ip`, `user-id`, `api-key`, `header:X`,
  `fingerprint`) emit a `user` collection where appropriate — no downgrades.
- Engine globals (`SecRuleEngine On`, `SecDefaultAction`, body-size limits)
  emitted; Coraza-Go starts from a blank slate.
- Body-field allowlist relies on Coraza's automatic JSON content-type
  routing — no explicit `ctl:requestBodyProcessor=JSON` needed.

No `WARNINGS.md` is emitted under this profile (no downgrades occur).
