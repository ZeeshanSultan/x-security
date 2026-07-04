/**
 * OPP-3: ABAC (attribute-based access control) defense class for the Envoy
 * ext_authz + OPA path. Reuses the same already-wired OPA sidecar that
 * rule-based / bfla / input-validation use (W17-A, W18-A).
 *
 * Caps OWASP API5:2023 (BFLA). Distinct from `authorization.rbac` (native rbac
 * filter / opa-bfla-403 admin-only) and `authorization.rule-based` (per-resource
 * ownership / opa-bola-403): ABAC evaluates a conjunction of attribute
 * predicates that compare *subject* attributes (JWT claims) against either a
 * literal *action/environment* value or a *resource* attribute drawn from the
 * request (a path segment).
 *
 * Attribute convention (authorization.attributes.rules[]) — each rule is one
 * predicate; ALL predicates must hold for the request to be permitted:
 *
 *   authorization:
 *     type: abac
 *     attributes:
 *       rules:
 *         - claim: department        # subject attribute: JWT payload[department]
 *           operator: equals         # equals (default) | in
 *           value: engineering       # literal action/environment value
 *         - claim: sub               # subject attribute
 *           operator: equals
 *           pathParam: id            # resource attribute: path segment for {id}
 *
 * A predicate is `claim <op> (value | path-segment)`. `value` and `pathParam`
 * are mutually exclusive; a predicate with neither (or with an unknown
 * operator) is non-enforceable and forces the endpoint to fail closed (only a
 * deny branch is emitted, no permit) so we never silently widen access (D-1).
 *
 * Emits, per ABAC endpoint:
 *   - permit (allow)   when every predicate holds against the decoded JWT
 *   - opa-abac-403     (fail closed) for any same-path/method request that does
 *                      not satisfy every predicate.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { ALLOW_LITERAL, paramSplitIndex, type BranchEmitDeps } from './extauthz-rego-util.js';

interface AbacPredicate {
  claim: string;
  operator: 'equals' | 'in';
  /** Literal value (action/environment attribute). Mutually exclusive with pathParam. */
  value?: string | number | boolean | Array<string | number | boolean>;
  /** Path-parameter name (resource attribute). Mutually exclusive with value. */
  pathParam?: string;
}

export interface AbacEndpoint {
  endpoint: EndpointIR;
  predicates: AbacPredicate[];
  /** True when every predicate is enforceable; false → emit deny-only (fail closed). */
  enforceable: boolean;
}

function coercePredicate(raw: unknown): AbacPredicate | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.claim !== 'string' || r.claim.length === 0) return null;
  const op = r.operator === 'in' ? 'in' : r.operator === 'equals' || r.operator === undefined ? 'equals' : null;
  if (op === null) return null;
  const hasValue = r.value !== undefined;
  const hasPathParam = typeof r.pathParam === 'string' && r.pathParam.length > 0;
  if (hasValue === hasPathParam) return null; // need exactly one
  if (hasPathParam) {
    return { claim: r.claim, operator: op, pathParam: r.pathParam as string };
  }
  const v = r.value;
  const okScalar = typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
  const okArray = Array.isArray(v) && v.every((x) => typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean');
  if (okScalar) return { claim: r.claim, operator: op, value: v };
  if (okArray) return { claim: r.claim, operator: op, value: v as Array<string | number | boolean> };
  return null;
}

/**
 * OPP-3: collect ABAC endpoints. An endpoint is ABAC iff
 * authorization.type === 'abac'. Its `attributes.rules` array (when present and
 * well-formed) defines the predicate conjunction. An ABAC endpoint with no
 * usable predicate is collected as non-enforceable so it emits a fail-closed
 * deny branch rather than being dropped (D-1: never silently widen access).
 */
export function collectAbac(spec: SpecIR): AbacEndpoint[] {
  const out: AbacEndpoint[] = [];
  for (const ep of spec.endpoints) {
    const authz = ep.policy.authorization;
    if (!authz || authz.type !== 'abac') continue;
    const rawRules = (authz.attributes as { rules?: unknown } | undefined)?.rules;
    const predicates: AbacPredicate[] = [];
    let allOk = Array.isArray(rawRules) && rawRules.length > 0;
    if (Array.isArray(rawRules)) {
      for (const raw of rawRules) {
        const p = coercePredicate(raw);
        if (p === null) { allOk = false; continue; }
        predicates.push(p);
      }
    }
    const enforceable = allOk && predicates.length > 0;
    out.push({ endpoint: ep, predicates: enforceable ? predicates : [], enforceable });
  }
  return out;
}

function jwtClaimRef(claim: string, regoString: (s: string) => string): string {
  return `payload[${regoString(claim)}]`;
}

function predicateClauses(
  p: AbacPredicate,
  endpoint: EndpointIR,
  regoString: (s: string) => string
): string[] {
  const lhs = jwtClaimRef(p.claim, regoString);
  if (p.pathParam !== undefined) {
    let idx = paramSplitIndex(endpoint.path, p.pathParam);
    if (idx === null) idx = endpoint.path.split('/').length - 1;
    const rhs = `parts[${idx}]`;
    if (p.operator === 'in') {
      // claim is a set/array of allowed resource ids; membership check.
      return [`    ${rhs} == ${lhs}[_]`];
    }
    return [`    ${lhs} == ${rhs}`];
  }
  // Literal value predicate.
  if (Array.isArray(p.value)) {
    const set = '{' + p.value.map((v) => regoString(String(v))).join(', ') + '}';
    const setName = `allowed_${p.claim}`;
    return [`    ${setName} := ${set}`, `    ${setName}[${lhs}]`];
  }
  return [`    ${lhs} == ${regoString(String(p.value))}`];
}

function needsPathSplit(item: AbacEndpoint): boolean {
  return item.predicates.some((p) => p.pathParam !== undefined);
}

/** Emit ABAC branches into the shared lines[] (OPP-3). */
export function emitAbacBranches(items: AbacEndpoint[], d: BranchEmitDeps): void {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) return a.endpoint.method.localeCompare(b.endpoint.method);
    return a.endpoint.path.localeCompare(b.endpoint.path);
  });

  for (const item of sorted) {
    const method = item.endpoint.method.toUpperCase();
    const pathRegex = d.pathToRegoRegex(item.endpoint.path);
    const matchClauses = [
      `    input.attributes.request.http.method == ${d.regoString(method)}`,
      `    regex.match(${d.regoString(pathRegex)}, input.attributes.request.http.path)`
    ];

    const predSummary = item.enforceable
      ? item.predicates.map((p) => `${p.claim}${p.operator === 'in' ? ' in' : '='}${p.pathParam !== undefined ? `{${p.pathParam}}` : JSON.stringify(p.value)}`).join(' & ')
      : 'non-enforceable (fail-closed)';
    d.lines.push(`# ${item.endpoint.method} ${item.endpoint.path} — abac ${predSummary} (OPP-3 ABAC)`);

    if (item.enforceable) {
      const permit: string[] = [
        ...matchClauses,
        '    token := bearer_token',
        '    [_, payload, _] := io.jwt.decode(token)'
      ];
      if (needsPathSplit(item)) {
        permit.push('    parts := split(input.attributes.request.http.path, "/")');
      }
      for (const p of item.predicates) {
        for (const clause of predicateClauses(p, item.endpoint, d.regoString)) permit.push(clause);
      }
      d.pushBranch(permit, ALLOW_LITERAL);
    }
    // Deny: same path/method that did not satisfy the permit branch (or, for a
    // non-enforceable endpoint, every request) → fail closed with opa-abac-403.
    d.pushBranch(matchClauses, d.denyLiteral('abac'));
    d.lines.push('');
  }
}
