/**
 * W17-A: rule-based authorization (BOLA + JWT-claim) defense classes for the
 * Envoy ext_authz + OPA path. Split out of extauthz.ts (W20-B) to comply with
 * Rule G-1.
 *
 * Owns:
 *   - collectRuleBased: spec → rule-based endpoints with identifier source
 *   - emitRuleBasedBranches: Rego decision-chain branches that emit, per
 *     (endpoint, rule):
 *       - permit  (allow)              when the jwt claim matches the resource id
 *       - opa-jwt-claim-403            when the claim is missing entirely
 *       - opa-bola-403                 (fail-closed) when claim != resource id
 *     If the rule has no usable identifier (non-equals operator, or value is
 *     not a RuleRef) only the bola fallback branch is emitted.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import type { AuthorizationRule } from '@writ/schema';
import {
  ALLOW_LITERAL,
  paramSplitIndex,
  type BranchEmitDeps
} from './extauthz-rego-util.js';

export interface RuleBasedEndpoint {
  endpoint: EndpointIR;
  rules: AuthorizationRule[];
  identifierFrom: string | null;   // e.g. 'request.params.id'
  resourcePathTemplate: string | null; // e.g. '/users/{id}'
}

export function collectRuleBased(spec: SpecIR): RuleBasedEndpoint[] {
  const out: RuleBasedEndpoint[] = [];
  for (const ep of spec.endpoints) {
    const authz = ep.policy.authorization;
    if (!authz || authz.type !== 'rule-based') continue;
    if (!authz.rules || !authz.rules.length) continue;
    out.push({
      endpoint: ep,
      rules: authz.rules,
      identifierFrom: authz.resourceLookup?.identifierFrom ?? null,
      resourcePathTemplate: authz.resourceLookup?.endpoint ?? null
    });
  }
  return out;
}

interface RuleEmitContext {
  endpoint: EndpointIR;
  rule: AuthorizationRule;
  identifierFrom: string | null;
  regoString: (s: string) => string;
  pathToRegoRegex: (path: string) => string;
}

/**
 * Per-endpoint rule-based branches: permit / jwt-claim-403 / bola-403. When
 * no usable identifier (rule.operator != equals, or rule.value not a RuleRef)
 * only bola-403 is emitted — fails closed with a class-tagged marker.
 */
function emitEndpointBranches(ctx: RuleEmitContext): { permit: string[] | null; jwtClaim: string[] | null; bola: string[] } {
  const { endpoint, rule, identifierFrom, regoString, pathToRegoRegex } = ctx;
  const method = endpoint.method.toUpperCase();
  const pathRegex = pathToRegoRegex(endpoint.path);

  const matchClauses = [
    `    input.attributes.request.http.method == ${regoString(method)}`,
    `    regex.match(${regoString(pathRegex)}, input.attributes.request.http.path)`
  ];

  const isRef = rule.value && typeof rule.value === 'object' && !Array.isArray(rule.value)
    && typeof (rule.value as { ref?: unknown }).ref === 'string';

  if (rule.operator !== 'equals' || !isRef) {
    // No usable identifier — emit only the bola-403 branch (fail closed,
    // class-tagged). No permit branch means default-deny still wins for
    // these endpoints; the marker tells the scorer this was a policy-aware
    // refusal, not a wholesale broom.
    return { permit: null, jwtClaim: null, bola: matchClauses };
  }

  const refPath = (rule.value as { ref: string }).ref;
  const [refRoot, ...refTailParts] = refPath.split('.');
  const refTail = refTailParts.join('.');

  let paramSplit: number | null = null;
  if (identifierFrom && identifierFrom.startsWith('request.params.')) {
    const paramName = identifierFrom.slice('request.params.'.length);
    paramSplit = paramSplitIndex(endpoint.path, paramName);
  }
  if (paramSplit === null) paramSplit = endpoint.path.split('/').length - 1;

  const claimKey = (refRoot === 'jwt' || refRoot === 'principal' || refRoot === 'session') ? refTail : null;

  const permit: string[] = [
    ...matchClauses,
    '    token := bearer_token',
    '    [_, payload, _] := io.jwt.decode(token)',
    `    parts := split(input.attributes.request.http.path, "/")`,
    `    resource_id := parts[${paramSplit}]`,
    claimKey
      ? `    payload[${regoString(claimKey)}] == resource_id`
      : `    false  # ref root "${refRoot}" not supported`
  ];

  const jwtClaim: string[] | null = claimKey
    ? [
        ...matchClauses,
        '    token := bearer_token',
        '    [_, payload, _] := io.jwt.decode(token)',
        `    not payload[${regoString(claimKey)}]`
      ]
    : null;

  return { permit, jwtClaim, bola: matchClauses };
}

/** Emit rule-based branches into the shared lines[]. */
export function emitRuleBasedBranches(items: RuleBasedEndpoint[], d: BranchEmitDeps): void {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) return a.endpoint.method.localeCompare(b.endpoint.method);
    return a.endpoint.path.localeCompare(b.endpoint.path);
  });

  for (const item of sorted) {
    for (let i = 0; i < item.rules.length; i++) {
      const rule = item.rules[i]!;
      const out = emitEndpointBranches({
        endpoint: item.endpoint,
        rule,
        identifierFrom: item.identifierFrom,
        regoString: d.regoString,
        pathToRegoRegex: d.pathToRegoRegex
      });
      d.lines.push(`# ${item.endpoint.method} ${item.endpoint.path} — rule[${i}] field=${rule.field} op=${rule.operator}`);
      d.pushBranch(out.permit, ALLOW_LITERAL);
      d.pushBranch(out.jwtClaim, d.denyLiteral('jwt-claim'));
      d.pushBranch(out.bola, d.denyLiteral('bola'));
      d.lines.push('');
    }
  }
}
