// Canonicalization for the agentic policy-generation output.
//
// Determinism contract (plan §Determinism):
//   - canonicalize(run_1) byte-equals canonicalize(run_2) for two runs on the
//     same commit with the same model + caps.
//   - Semantic equivalence (same regex written `\d` vs `[0-9]`, same
//     allowedMethods in different order, same key order) collapses to a
//     single representation.

import type { XSecurityPolicy } from '@writ/schema';
import type {
  AgentOutput,
  PolicyEmission,
  RouteInventoryEntry,
  Assumption,
} from './schema.js';

/** Regex shorthand normalization. */
const REGEX_REPLACEMENTS: Array<[RegExp, string]> = [
  [/\\d/g, '[0-9]'],
  [/\\D/g, '[^0-9]'],
  [/\\s/g, '[ \\t\\n\\r]'],
  [/\\S/g, '[^ \\t\\n\\r]'],
  [/\\w/g, '[A-Za-z0-9_]'],
  [/\\W/g, '[^A-Za-z0-9_]'],
];

export function normalizeRegex(pattern: string): string {
  if (typeof pattern !== 'string') return pattern;
  let out = pattern;
  for (const [from, to] of REGEX_REPLACEMENTS) out = out.replace(from, to);
  return out;
}

/** Recursive key-sorted clone of a plain JSON value. */
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const src = value as Record<string, unknown>;
    const keys = Object.keys(src).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) out[k] = sortKeys(src[k]);
    return out;
  }
  return value;
}

/** Lexicographic stringify-compare; used for sorting authorization.rules. */
function jsonCompare(a: unknown, b: unknown): number {
  const sa = JSON.stringify(a);
  const sb = JSON.stringify(b);
  if (sa < sb) return -1;
  if (sa > sb) return 1;
  return 0;
}

function canonicalizeAuthorizationRules(p: XSecurityPolicy): void {
  const rules = p.authorization?.rules;
  if (!rules || rules.length === 0) return;
  rules.sort((a, b) => {
    const byField = a.field.localeCompare(b.field);
    if (byField !== 0) return byField;
    const byOp = a.operator.localeCompare(b.operator);
    if (byOp !== 0) return byOp;
    return jsonCompare(a.value, b.value);
  });
}

function sortStringArray(arr: string[] | undefined): void {
  if (!arr) return;
  arr.sort();
}

/** Normalize every regex string inside a ParamSchema record. */
function canonicalizeParamSchemas(
  schemas: Record<string, { pattern?: string }> | undefined,
): void {
  if (!schemas) return;
  for (const key of Object.keys(schemas)) {
    const s = schemas[key];
    if (s && typeof s.pattern === 'string') {
      s.pattern = normalizeRegex(s.pattern);
    }
  }
}

/**
 * Canonicalize a single policy in place AND return it. Mutates the input —
 * call with a defensive clone if the caller wants to keep the original.
 */
export function canonicalizePolicy(policy: XSecurityPolicy): XSecurityPolicy {
  // 1. Regex normalization on request/response schemas.
  canonicalizeParamSchemas(
    policy.request?.schema as Record<string, { pattern?: string }> | undefined,
  );
  canonicalizeParamSchemas(
    policy.response?.schema as Record<string, { pattern?: string }> | undefined,
  );

  // 2. Sort semantically-unordered arrays.
  sortStringArray(policy.mitigates);
  sortStringArray(policy.authentication?.scopes);
  sortStringArray(policy.authentication?.allowedAlgorithms as string[] | undefined);
  sortStringArray(policy.authorization?.roles);
  sortStringArray(policy.cors?.allowedOrigins);
  sortStringArray(
    policy.cors?.allowedMethods as unknown as string[] | undefined,
  );
  sortStringArray(policy.cors?.allowedHeaders);
  sortStringArray(policy.cors?.exposeHeaders);
  sortStringArray(policy.request?.contentType);
  sortStringArray(policy.request?.allowedHosts);
  sortStringArray(policy.response?.contentType);
  if (
    typeof policy.cacheable === 'object' &&
    policy.cacheable !== null &&
    'unkeyedHeadersStrip' in policy.cacheable
  ) {
    sortStringArray(policy.cacheable.unkeyedHeadersStrip);
  }
  if (policy.websocket) sortStringArray(policy.websocket.allowedOrigins);
  if (policy.csrf) sortStringArray(policy.csrf.allowedOrigins);
  if (Array.isArray(policy.ipPolicy?.allow)) {
    (policy.ipPolicy.allow as string[]).sort();
  }
  if (Array.isArray(policy.ipPolicy?.deny)) {
    (policy.ipPolicy.deny as string[]).sort();
  }

  // 3. Authorization rules: order-independent.
  canonicalizeAuthorizationRules(policy);

  // 4. Key sort (recursive).
  return sortKeys(policy) as XSecurityPolicy;
}

function canonicalizeAssumption(a: Assumption): Assumption {
  return {
    field: a.field,
    assumption: a.assumption,
    confidence: a.confidence,
    cite: {
      ...a.cite,
      // Trim — only outer whitespace, never inner. V6 still byte-matches the
      // inner content against the file.
      quote: a.cite.quote.replace(/^\s+|\s+$/g, ''),
    },
  };
}

function canonicalizeEmission(e: PolicyEmission): PolicyEmission {
  const policy = e.policy ? canonicalizePolicy(structuredClone(e.policy)) : null;
  const assumptions = e.assumptions
    .map(canonicalizeAssumption)
    .sort((a, b) => {
      const byField = a.field.localeCompare(b.field);
      if (byField !== 0) return byField;
      return a.assumption.localeCompare(b.assumption);
    });

  const out: PolicyEmission = {
    endpointId: e.endpointId,
    policy,
    reviewRequired: e.reviewRequired,
    assumptions,
  };
  if (e.reviewReasons && e.reviewReasons.length > 0) {
    out.reviewReasons = [...e.reviewReasons].sort();
  }
  return out;
}

function canonicalizeRouteEntry(r: RouteInventoryEntry): RouteInventoryEntry {
  // Don't sort middleware / dto refs — declared order is semantic for those.
  // Everything else is plain data.
  return { ...r };
}

/**
 * Canonicalize an entire AgentOutput. Returns a new object; the input is not
 * mutated.
 */
export function canonicalizeAgentOutput(out: AgentOutput): AgentOutput {
  const cloned: AgentOutput = structuredClone(out);

  cloned.routeInventory = cloned.routeInventory
    .map(canonicalizeRouteEntry)
    .sort((a, b) => {
      const byMethod = a.method.localeCompare(b.method);
      if (byMethod !== 0) return byMethod;
      return a.path.localeCompare(b.path);
    });

  cloned.emissions = cloned.emissions
    .map(canonicalizeEmission)
    .sort((a, b) => a.endpointId.localeCompare(b.endpointId));

  // Profiles map: key-sort happens in serializeStable. Nothing to do inline.

  cloned.coverage = {
    filesRead: [...new Set(cloned.coverage.filesRead)].sort(),
    grepQueriesIssued: [...new Set(cloned.coverage.grepQueriesIssued)].sort(),
    ...(cloned.coverage.notes !== undefined ? { notes: cloned.coverage.notes } : {}),
  };

  return cloned;
}

/**
 * Stable JSON stringification — recursively key-sorted, no trailing space,
 * newline-terminated. Used by the corpus gate to compare two runs.
 */
export function serializeStable(obj: unknown): string {
  return JSON.stringify(sortKeys(obj)) + '\n';
}
