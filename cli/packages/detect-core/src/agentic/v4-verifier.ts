// V4 — Round-trip verifier.
//
// For each emission with a non-null policy:
//   1. Construct a synthetic POSITIVE request from the policy's allowed space.
//   2. Construct a synthetic NEGATIVE request that violates one constraint.
//   3. Evaluate both via the in-process policy evaluator.
//   4. positive blocked → demote (policy too tight).
//      negative allowed → demote (policy too loose).
//      both correct → pass.
//
// V4's job is to catch encoder bugs, impossible regexes, and silent
// over-constraint at policy-emission time without requiring a real gateway
// compile. The evaluator implements the input-side semantics of
// XSecurityPolicy directly; this is sufficient for V4's intent.

import type { RouteInventoryEntry, VerifierResult } from './schema.js';
import type { Verifier, VerifierContext } from './verify.js';
import { evaluatePolicy } from './policy-eval.js';
import {
  generateNegative,
  generatePositive,
  generatePositiveOwnershipAbsent,
  generatePositiveBodyOwnershipAbsent,
  generateAuthzNegative,
  hasAuthzRequestRule,
  hasViolableConstraint,
  isSelfMutationBodyOwnership,
} from './synthetic-requests.js';
import { discoverHandlerParams } from './verify-helpers.js';
import type { XSecurityPolicy } from '@x-security/schema';

/** url params whose `domainAllowlist` is present-but-EMPTY. An empty allowlist
 *  is a silent no-op in the evaluator (D1): it reads as "no constraint," so the
 *  SSRF is not blocked and no negative can be constructed for it — the control is
 *  theatre. V4 demotes so the model must provide ≥1 host or use blockPrivateRanges. */
function emptyDomainAllowlistParams(policy: XSecurityPolicy): string[] {
  const schema = policy.request?.schema;
  if (!schema) return [];
  const out: string[] = [];
  for (const [name, ps] of Object.entries(schema)) {
    if (ps?.type === 'url' && Array.isArray(ps.domainAllowlist) && ps.domainAllowlist.length === 0) {
      out.push(name);
    }
  }
  return out;
}

/** Authz request-rule BODY fields NOT independently required by request.schema.
 *  An ownership rule on such a body field over-blocks the legit omit-case (the
 *  dvrestaurant `PUT /profile` miss E: a clean update omits `username`).
 *
 *  Scope is deliberately BODY-only: a path/params field is part of the route
 *  address (always carried), and a query field on a read is how the resource is
 *  addressed (omitting it is a malformed request, not a legit omit-case — e.g.
 *  dvapi `GET /api/getNote?username=` whose ideal policy pins query.username
 *  with NO schema and must NOT demote). Only a write-method body field can be
 *  legitimately absent, so only it risks the silent over-block. */
function authzBodyFieldsNotInSchema(policy: XSecurityPolicy, method: string): string[] {
  const authz = policy.authorization;
  if (!authz || authz.type === 'rbac' || !authz.rules) return [];
  if (!['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) return [];
  const schemaKeys = new Set(Object.keys(policy.request?.schema ?? {}));
  const out: string[] = [];
  for (const rule of authz.rules) {
    const parts = rule.field.split('.');
    if (parts[0] !== 'request') continue;
    const loc = parts[1];
    const name = parts.slice(2).join('.');
    if (!loc || !name) continue;
    if (loc !== 'body') continue;
    if (!schemaKeys.has(name)) out.push(`request.${loc}.${name}`);
  }
  return out;
}

/** Authz request-rule BODY fields (regardless of whether request.schema also
 *  requires them). Used by the self-mutation demote, which must fire even when
 *  the field is required-in-schema (requiring the body owner id IS the
 *  over-block on a self-mutation route — FIX 1). */
function authzBodyFields(policy: XSecurityPolicy): string[] {
  const authz = policy.authorization;
  if (!authz || authz.type === 'rbac' || !authz.rules) return [];
  const out: string[] = [];
  for (const rule of authz.rules) {
    const parts = rule.field.split('.');
    if (parts[0] !== 'request') continue;
    const loc = parts[1];
    const name = parts.slice(2).join('.');
    if (!loc || !name) continue;
    if (loc !== 'body') continue;
    out.push(`request.${loc}.${name}`);
  }
  return out;
}

function endpointToRoute(endpointId: string): RouteInventoryEntry | null {
  // "METHOD path" — GraphQL/Lambda ids are out of scope for V4 because they
  // have no HTTP request shape. We pass for those.
  const m = /^([A-Z]+)\s+(.+)$/.exec(endpointId);
  if (!m) return null;
  return {
    method: m[1]!,
    path: m[2]!,
    sourceFile: '<synthetic>',
    sourceLine: 0,
  };
}

export const v4RoundTrip: Verifier = {
  id: 'V4',
  async run(ctx: VerifierContext): Promise<VerifierResult[]> {
    const results: VerifierResult[] = [];
    const byEndpoint = new Map<string, RouteInventoryEntry>();
    for (const r of ctx.output.routeInventory) {
      byEndpoint.set(`${r.method.toUpperCase()} ${r.path}`, r);
    }

    for (const e of ctx.output.emissions) {
      if (e.policy === null) {
        results.push({
          verifier: 'V4',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: ['policy is null — already review-required'],
        });
        continue;
      }
      const route = byEndpoint.get(e.endpointId) ?? endpointToRoute(e.endpointId);
      if (!route) {
        results.push({
          verifier: 'V4',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: ['V4: non-HTTP endpointId — round-trip skipped'],
        });
        continue;
      }

      // Handler-derived legit inputs (fix D): scope param discovery to THIS
      // route's handler so the positive sample carries the fields the handler
      // actually reads. An under-enumerated denyUnknownFields policy then
      // false-blocks its own handler-derived request → V4 demotes. Only feed
      // params when discovery was handler-scoped (scoped=true) — a whole-file
      // fallback could leak a sibling handler's field and over-demote a correct
      // policy, which we must never do.
      let handlerReadParams: Set<string> | undefined;
      if (route.sourceFile && route.sourceFile !== '<synthetic>') {
        const d = await discoverHandlerParams(ctx.repoDir, route.sourceFile, {
          handlerSymbol: route.handlerSymbol,
          sourceLine: route.sourceLine,
        });
        if (d.scoped && d.params.size > 0) handlerReadParams = d.params;
      }

      let positive;
      let negative;
      try {
        positive = generatePositive(route, e.policy, handlerReadParams);
        negative = generateNegative(route, e.policy);
      } catch (err) {
        const reason = `V4: synthetic request generation failed: ${(err as Error).message}`;
        results.push({
          verifier: 'V4',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons: [reason],
          modifications: {
            reviewRequired: true,
            reviewReasons: [...(e.reviewReasons ?? []), reason],
          },
        });
        continue;
      }

      const posResult = evaluatePolicy(positive, e.policy);
      const negResult = evaluatePolicy(negative, e.policy);

      const reasons: string[] = [];
      if (posResult.decision === 'block') {
        reasons.push(
          `V4: positive sample rejected by policy (policy too tight): ${posResult.blockedBy ?? 'unknown'}`,
        );
      }
      // Only a policy that DECLARES a violable request-shape constraint can be
      // "too loose": if there's nothing to violate (e.g. a rate-limited login
      // with no input schema), `generateNegative` returns the positive unchanged
      // and an "allow" here is correct, not a looseness. Gating on
      // hasViolableConstraint prevents that false demote (dvna POST /app/login).
      if (negResult.decision === 'allow' && hasViolableConstraint(e.policy)) {
        reasons.push(
          `V4: negative sample accepted (policy too loose): no constraint triggered`,
        );
      }

      // --- authz round-trip (E2) --------------------------------------------
      // For an ownership rule (request.<loc>.<field> == jwt.<claim>, or a
      // resourceLookup resource.<owner> == jwt.sub):
      //   (a) the wrong-owner negative MUST block (else the rule is too loose);
      //   (b) the omit-the-field positive MUST pass when the field is NOT
      //       independently required by request.schema (else the rule
      //       over-blocks the legit omit-case — the dvrestaurant PUT /profile
      //       miss). A field that IS in request.schema is independently a block
      //       on absence, so omission is coherent and not exercised here.
      const authzNeg = generateAuthzNegative(route, e.policy);
      if (authzNeg) {
        const authzNegResult = evaluatePolicy(authzNeg, e.policy);
        if (authzNegResult.decision === 'allow') {
          reasons.push(
            `V4: wrong-owner request accepted (authorization rule too loose): the ownership rule does not block a different principal's id`,
          );
        }
      }
      if (hasAuthzRequestRule(e.policy)) {
        // FIX 1 (keystone) — self-mutation routes. A PUT/PATCH whose ownership
        // rule names a BODY field that is the principal's own id (e.g. the
        // dvrestaurant `PUT /profile` `authz body.username == jwt.sub`) over-
        // blocks a legit clean update that omits that field. This fires EVEN
        // when the field is required-in-schema — making the principal a required
        // body field IS the over-block, so the schema's required-on-absence check
        // must NOT suppress it. A query/path id ownership rule where the legit
        // carries the id (getNote query.username, vampi params.username) is not
        // self-mutation and does not demote (isSelfMutationBodyOwnership=false).
        if (isSelfMutationBodyOwnership(route, e.policy)) {
          const absentPositive = generatePositiveBodyOwnershipAbsent(
            route,
            e.policy,
            handlerReadParams,
          );
          const absentResult = evaluatePolicy(absentPositive, e.policy);
          if (absentResult.decision === 'block') {
            for (const f of authzBodyFields(e.policy)) {
              const tail = f.split('.').slice(2).join('.');
              reasons.push(
                `V4: ownership rule on body.${tail} blocks a legit request that omits it — self-mutation routes must pin the principal server-side, not require a body owner id; drop to reviewRequired`,
              );
            }
          }
        } else {
          const omitFields = authzBodyFieldsNotInSchema(e.policy, route.method);
          if (omitFields.length > 0) {
            const absentPositive = generatePositiveOwnershipAbsent(
              route,
              e.policy,
              handlerReadParams,
            );
            const absentResult = evaluatePolicy(absentPositive, e.policy);
            if (absentResult.decision === 'block') {
              for (const f of omitFields) {
                const tail = f.split('.').slice(2).join('.');
                reasons.push(
                  `V4: authz rule on ${f} blocks a legit request that omits ${tail} — field not request-required (add ${tail} to request.schema or drop the ownership rule)`,
                );
              }
            }
          }
        }
      }

      // --- empty domainAllowlist is a silent no-op (D1) ---------------------
      for (const name of emptyDomainAllowlistParams(e.policy)) {
        reasons.push(
          `V4: request.schema.${name} has an empty domainAllowlist — a silent no-op (provide ≥1 host or use blockPrivateRanges:true)`,
        );
      }

      if (reasons.length === 0) {
        results.push({
          verifier: 'V4',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [],
        });
      } else {
        results.push({
          verifier: 'V4',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons,
          modifications: {
            reviewRequired: true,
            reviewReasons: [...(e.reviewReasons ?? []), ...reasons],
          },
        });
      }
    }
    return results;
  },
};
