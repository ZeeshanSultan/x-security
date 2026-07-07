# Writ BYO-Agent Plugin

One command turns your codebase into **verified** API-security policies, WAF
rules, a human report, and a CI gate — using **your own** top-tier coding agent
(Claude Code, Codex, or Cursor) as the detection brain.

Writ ships a **free, complete** plugin: schema + prompts/skills + a
deterministic CLI + an agent-neutral MCP server. There is **no Writ-hosted
inference and no detection API key** — detection runs on the host agent's model
(your own subscription). The hosted SaaS (monitoring, team dashboards) is an
optional, separate upsell; the plugin is fully complete on its own.

## How it works

```
host agent (your Opus / GPT / Cursor model)  ──drives──►  detection loop (shared skills)
        │                                                        │
        │ calls for every deterministic step                     ▼
        └────────────────────────────────────────────►  @x-security/cli  (free, no LLM)
                                                          validate · verify V1–V7 ·
                                                          cite byte-match · compile ·
                                                          WAF · report · CI
                                                                │
                                                       writes ► .writ/
```

The model may **propose** anything; only CLI-verified, code-cited controls reach
disk. Accuracy is enforced by the gate, not by trusting the model.

### One source of truth

The detection logic lives in exactly one place per concern:

- **Skills** (`packages/claude-plugin/skills/`) — inventory / detect /
  compile-emit prompts, in the open Agent Skills `SKILL.md` standard. Claude Code
  and Codex both read this format directly; the Cursor rule references them.
- **CLI** (`@x-security/cli`) — every deterministic step (schema, V1–V7 verify,
  cite byte-match, compile, WAF/report/CI emit, audit).
- **MCP** (`@x-security/mcp`) — one agent-neutral server wrapping the CLI as
  tools; all three host adapters consume this single server.

The per-agent adapters are **thin orchestrators** that point each host at that
shared core. No detection logic is forked.

## The one-shot UX

From your repo, you trigger one flow (the trigger differs per host, below). It
runs **autonomously** through six stages and then shows the report:

1. **Inventory** — the model walks your repo (grounded by the CLI's deterministic
   route extractor) and confirms every route.
2. **Profile** — each route is classified (`auth-endpoint`, `standard-crud`,
   `admin-panel`, …).
3. **Detect** — per route, the model reads handler → sink and emits cited findings
   with structured `controlHint`s.
4. **Verify** — the CLI runs V1–V7 (schema, cite byte-match, tightness,
   cross-route consistency). Failures return reasons; the model re-reads / fixes /
   drops within a few bounded rounds. **No rule that failed verify is ever
   written.**
5. **Emit** — verified findings compile into policies + WAF rules + a report + a
   CI gate.
6. **Self-check** — the CLI re-audits everything on disk and prints the
   cite-coverage proof.

Re-runs are **incremental**: only changed routes (`git diff`) are re-detected;
already-verified policies are reused, which keeps the CI gate cheap.

## What it emits

Everything lands under `.writ/` in the scanned repo:

| Path                          | What it is                                                                          |
| ----------------------------- | ----------------------------------------------------------------------------------- |
| `.writ/policies/*.yaml` | Per-route x-security policies (`<method>__<path>.yaml`)                              |
| `.writ/waf/`            | Deployable WAF / edge rules compiled from the verified policies                     |
| `.writ/report.md`       | Human report — every control with its `file:line` cite, plus `reviewRequired` items |
| `.writ/ci/`             | CI gate config that re-audits on future commits (incremental)                       |

## Install & run per agent

### Claude Code

```bash
claude plugin install writ   # (once published to a marketplace)
# today, from a checkout:
claude --plugin-dir /path/to/packages/claude-plugin
```

Run from your project root:

```
/lazy-scan            # scans the project root
/lazy-scan ./services/api   # or a specific directory
```

The CLI is invoked through `npx @x-security/cli`, so there is no build step.

### Codex

Adapter: `packages/codex-adapter/` (see its `INSTALL.md`).

```bash
# 1. register the MCP server
codex mcp add writ -- npx -y @x-security/mcp

# 2. install the shared skills (symlink the canonical SKILL.md files)
#    SKILLS_DIR = packages/claude-plugin/skills in your checkout
SKILLS_DIR=/path/to/writ/packages/claude-plugin/skills
mkdir -p .agents/skills
for s in writ-inventory writ-detect writ-compile-emit; do
  ln -s "$SKILLS_DIR/$s" ".agents/skills/$s"
done

# 3. copy AGENTS.md (the orchestrator) to your project root
cp packages/codex-adapter/AGENTS.md ./AGENTS.md
```

Then in Codex: "run a Writ scan on this repo." Codex Skills use the same
`SKILL.md` standard as Claude Code, so the skills are shared, not forked.

### Cursor

Adapter: `packages/cursor-adapter/` (see its `README.md`).

```bash
# copy the .cursor/ directory into your project root
cp -r packages/cursor-adapter/.cursor ./.cursor
```

This gives you `.cursor/rules/lazy-scan.mdc` (the orchestrator rule) and
`.cursor/mcp.json` (registers `@x-security/mcp`). Reload Cursor, then ask it to
"run a Writ scan on this repo."

> Cursor's adapter points at the **agent-neutral `@x-security/mcp`** server — not
> the older `packages/cursor-mcp`, which is a separate code-gen-time annotation
> helper that talks to the SaaS API. See `packages/cursor-adapter/README.md` for
> the full rationale.

## Accuracy: zero hallucinated rules

**Every rule Writ emits byte-matches a real `file:line` in your code.** The
model may propose anything, but only findings that pass the deterministic
`verify` gate — schema-valid, tightness-checked, and with a citation that
substring-matches the file — compile into a rule. Anything the gate cannot verify
is flagged `reviewRequired` in the report; it is **never** written as a rule. The
final `audit` step re-reads every rule on disk and proves the cite-coverage.

The guarantee is precise and bounded:

- **"100% of emitted rules cite your code."** — true by construction, proven by
  `audit`.
- **Recall scales with your model tier.** Stronger models detect more. We publish
  a recall-by-model-tier benchmark; we do **not** claim a fixed recall number.
- **Not a clean bill of health.** The report is a cited *starting point*. We never
  say "100% secure" or "100% recall."

This discipline is the product: it operationalizes Writ's detection rules
(every finding cites `file:line`; no placeholder scores; no shortcuts that mask a
quality gap) as an enforced gate rather than a hope.

## Positioning: free and complete, SaaS optional

- **Bring your own subscription.** Detection runs on your Claude Code / Codex /
  Cursor model. Writ never calls a paid LLM on your behalf and holds no
  detection API key.
- **Free and complete locally.** The plugin produces the final verified policies +
  WAF + report + CI gate on your machine, fully offline. Nothing is held back
  behind a paywall.
- **SaaS is optional.** The hosted product (monitoring, team dashboards, history,
  SSO) is a separate upsell for teams that want it. The plugin does not depend on
  it.
