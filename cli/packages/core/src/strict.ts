// Honest --strict contract. See errors.ts > StrictnessViolation for the
// four-gate model (S1 resolution, S2 emission, S3 fidelity, S4 loading).
//
// Each gate is a pure function over SpecIR / artifacts / capability matrices
// so callers (CLI generate, CLI report, future verify) can compose them
// independently without dragging in generator code.

import { StrictnessViolation } from './errors.js';
import type { SpecIR, EndpointIR, ConfigArtifact, CapabilityMatrix } from './ir.js';

// ─── S1: Placeholder detection ────────────────────────────────────────────────
//
// Rationale: the wave-2 loader already throws on UNresolved variables. What
// it cannot catch is a variable that's set but to obvious junk — the canonical
// failure mode is `JWKS_URI=x` in a `.env` skeleton. A resolved value passes
// the substitution step and silently produces an unenforceable rule.
//
// Heuristic — any of:
//   1. Length ≤ 2 (real secrets / URLs are ≥ 3 chars after trim).
//   2. Case-insensitive exact match against a dummy allow-list (changeme,
//      placeholder, todo, fixme, dummy, example, foo, bar, xxx, none, null).
//
// We deliberately keep this narrow. False positives on real values (e.g. a
// legitimate 2-char API key) are far rarer than the placeholder bug we're
// catching, and the user can `--no-strict` out of it.

const PLACEHOLDER_TOKENS = new Set([
  'x', 'xx', 'xxx', 'changeme', 'change-me', 'change_me',
  'placeholder', 'todo', 'fixme', 'dummy', 'example',
  'foo', 'bar', 'baz', 'none', 'null', 'undefined',
  'secret', 'password', 'mysecret', 'test'
]);

export function isPlaceholderShaped(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length <= 2) return true;
  return PLACEHOLDER_TOKENS.has(trimmed.toLowerCase());
}

export interface PlaceholderHit {
  variable: string;
  resolvedValue: string;
  endpoints: string[];
}

export function detectPlaceholderResolutions(spec: SpecIR): PlaceholderHit[] {
  // variable → { value, endpoints[] }
  const agg = new Map<string, { value: string; endpoints: Set<string> }>();
  for (const e of spec.endpoints) {
    for (const [ref, val] of e.resolvedVars.entries()) {
      if (!isPlaceholderShaped(val)) continue;
      const key = `${ref}=${val}`;
      const slot = agg.get(key) ?? { value: val, endpoints: new Set() };
      slot.endpoints.add(`${e.method} ${e.path}`);
      agg.set(key, slot);
    }
  }
  const out: PlaceholderHit[] = [];
  for (const [key, slot] of agg.entries()) {
    const eqIdx = key.indexOf('=');
    out.push({
      variable: key.slice(0, eqIdx),
      resolvedValue: slot.value,
      endpoints: Array.from(slot.endpoints).sort()
    });
  }
  return out.sort((a, b) => a.variable.localeCompare(b.variable));
}

export function assertNoPlaceholders(spec: SpecIR): void {
  const hits = detectPlaceholderResolutions(spec);
  if (hits.length === 0) return;
  const lines = [
    `${hits.length} variable${hits.length === 1 ? '' : 's'} resolved to placeholder-shaped value${hits.length === 1 ? '' : 's'}:`
  ];
  for (const h of hits) {
    const where = h.endpoints.slice(0, 3).join(', ') + (h.endpoints.length > 3 ? `, +${h.endpoints.length - 3} more` : '');
    lines.push(`  - ${h.variable}=${JSON.stringify(h.resolvedValue)}  (referenced at: ${where})`);
  }
  lines.push('Hint: set real values for these variables, or re-run with --no-strict to allow placeholders.');
  throw new StrictnessViolation('S1', lines.join('\n'), { hits });
}

// ─── S2: Emission coverage ────────────────────────────────────────────────────
//
// The zero-services bug (REPORT-v3 finding 3): the generator runs, writes a
// kong.yml with `services: []`, and the CLI prints the path without complaint.
// Strict-mode should refuse to ship that.
//
// "Enforceable artifact" is target-agnostic: we look for any mention of the
// endpoint's path OR operationId in any artifact's content. This is intentionally
// loose — generators emit endpoint paths in wildly different shapes (Kong
// services, Coraza SecRule chains, IAM Resource ARNs). Path-substring matching
// catches all of them without us baking generator semantics into core.
//
// Edge case: paths like `/` or `/api` collide trivially. We require the match
// to be of the *normalized* path (path templating stripped, leading slash kept)
// so `/users/{id}` matches the literal `/users/` in any artifact.

export interface EmissionGap {
  endpoint: string;
  reason: string;
}

function normalizePathForMatch(path: string): string {
  // Strip `{var}` placeholders so artifact-side paths like `/users/:id` or
  // `/users/[id]` still match. Leave the trailing slash so we anchor.
  return path.replace(/\{[^}]+\}/g, '').replace(/\/+$/, '/');
}

export function detectEmissionGaps(spec: SpecIR, artifacts: readonly ConfigArtifact[]): EmissionGap[] {
  if (artifacts.length === 0) {
    // No artifacts at all → every endpoint is a gap. Caller probably wants
    // a single top-level error rather than N per-endpoint ones.
    return spec.endpoints.map((e) => ({
      endpoint: `${e.method} ${e.path}`,
      reason: 'generator produced zero artifacts'
    }));
  }
  const joined = artifacts.map((a) => a.content).join('\n');
  const gaps: EmissionGap[] = [];
  for (const e of spec.endpoints) {
    const norm = normalizePathForMatch(e.path);
    const found = joined.includes(norm) || joined.includes(e.operationId);
    if (!found) {
      gaps.push({
        endpoint: `${e.method} ${e.path}`,
        reason: `no enforceable artifact references this endpoint (looked for path "${norm}" and operationId "${e.operationId}")`
      });
    }
  }
  return gaps;
}

export function assertEmission(spec: SpecIR, artifacts: readonly ConfigArtifact[]): void {
  const gaps = detectEmissionGaps(spec, artifacts);
  if (gaps.length === 0) return;
  const lines = [
    `${gaps.length} endpoint${gaps.length === 1 ? '' : 's'} compiled to ZERO enforceable artifacts:`
  ];
  for (const g of gaps) lines.push(`  - ${g.endpoint}: ${g.reason}`);
  lines.push('Hint: this is usually a spec→generator binding bug. Re-run without --strict to inspect the (empty) output anyway.');
  throw new StrictnessViolation('S2', lines.join('\n'), { gaps });
}

// ─── S3: Fidelity ─────────────────────────────────────────────────────────────
//
// A spec field declared by the user that the target+engine cannot enforce.
// We read the capability matrix (`gen.capabilities()`) — single source of
// truth, shared with --feasible — and walk each endpoint's policy looking for
// fields with status 'unsupported' or 'override-only'. 'partial' is reported
// but does NOT fail (the generator emitted *something*; we leave it to the
// operator).

// Capability keys come in two shapes:
//
//   1. Type-tagged: `authentication.bearer-jwt` → present iff
//      policy.authentication?.type === 'bearer-jwt'. The tail segment
//      (`bearer-jwt`, `rule-based`, `rbac` …) is the discriminator, NOT a
//      nested object key.
//   2. Path-only: `request.schema`, `timeout.read`, `targetOverrides.kong`,
//      or single-segment `rateLimit`/`cors`/`mtls` → standard nested lookup
//      with non-empty / non-false meaning "present".
//
// Tagged keys live under `authentication.*` and `authorization.*` today; we
// hardcode that prefix list rather than guessing by hyphens (`request.contentType`
// is not hyphenated but `authentication.api-key` is).
const TAGGED_PREFIXES = new Set(['authentication', 'authorization']);

function policyValueAt(policy: unknown, capKey: string): { present: boolean } {
  if (policy === null || policy === undefined || typeof policy !== 'object') {
    return { present: false };
  }
  const parts = capKey.split('.');
  const head = parts[0]!;

  if (TAGGED_PREFIXES.has(head) && parts.length === 2) {
    const obj = (policy as Record<string, unknown>)[head] as { type?: string } | undefined;
    if (!obj || typeof obj !== 'object') return { present: false };
    return { present: obj.type === parts[1] };
  }

  let cur: unknown = policy;
  for (const seg of parts) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return { present: false };
    cur = (cur as Record<string, unknown>)[seg];
  }
  if (cur === undefined || cur === null) return { present: false };
  if (typeof cur === 'boolean') return { present: cur };
  if (typeof cur === 'string') return { present: cur.length > 0 };
  if (Array.isArray(cur)) return { present: cur.length > 0 };
  if (typeof cur === 'object') return { present: Object.keys(cur as object).length > 0 };
  return { present: true };
}

export interface FidelityGap {
  endpoint: string;
  field: string;
  status: 'unsupported' | 'override-only' | 'partial';
}

export function detectFidelityGaps(
  spec: SpecIR,
  capabilities: CapabilityMatrix,
  opts: { includePartial?: boolean } = {}
): FidelityGap[] {
  const includePartial = opts.includePartial ?? false;
  const gaps: FidelityGap[] = [];
  for (const e of spec.endpoints) {
    for (const [capKey, status] of Object.entries(capabilities.fields)) {
      if (status === 'full' || (status === 'partial' && !includePartial)) continue;
      const probe = policyValueAt(e.policy, capKey);
      if (!probe.present) continue;
      gaps.push({
        endpoint: `${e.method} ${e.path}`,
        field: capKey,
        status: status as FidelityGap['status']
      });
    }
  }
  return gaps;
}

export function assertFidelity(
  spec: SpecIR,
  capabilities: CapabilityMatrix,
  opts: { includePartial?: boolean; targetName?: string } = {}
): void {
  const gaps = detectFidelityGaps(spec, capabilities, opts);
  // Only `unsupported` and `override-only` fail. `partial` is informational.
  const hard = gaps.filter((g) => g.status === 'unsupported' || g.status === 'override-only');
  if (hard.length === 0) return;
  const target = opts.targetName ?? 'target';
  const lines = [
    `${hard.length} spec field${hard.length === 1 ? '' : 's'} cannot be enforced by ${target}:`
  ];
  for (const g of hard) {
    lines.push(`  - ${g.endpoint}: ${g.field} = ${g.status}`);
  }
  lines.push('Hint: pick a target/engine that supports these fields, or drop --strict-fidelity.');
  throw new StrictnessViolation('S3', lines.join('\n'), { gaps: hard });
}
