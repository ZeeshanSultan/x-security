// Deterministic verifiers (V1–V7) for the agentic policy-generation pipeline.
//
// Contract: see interfaces.md §5. Each verifier exposes `id` + `run(ctx)` →
// `VerifierResult[]`. The runtime composes verdicts per emission (strictest
// wins) and applies `modifications` itself.
//
// V4 (round-trip) lives in v4-verifier.ts; it uses an in-process policy
// evaluator (policy-eval.ts) and synthetic request generators
// (synthetic-requests.ts) to catch encoder bugs, impossible regexes, and
// silent over-constraint without a real gateway compile.
//
// Pure helpers + IO live in verify-helpers.ts to keep this file focused on
// the verifier shapes and the orchestrator.

import path from 'node:path';

import { validateXSecurity } from '@writ/schema';

import type {
  AgentOutput,
  PolicyEmission,
  RouteInventoryEntry,
  VerifierResult,
} from './schema.js';
import {
  applyModifications,
  checkTightness,
  collectAuthRuleFields,
  computeV5Demotions,
  detectFilesystemHandlerCandidates,
  deterministicGrep,
  discoverHandlerParams,
  evaluateV6ForEmission,
  extractPathParams,
  paramSchemaEntries,
  tailOf,
  verdictStrictness,
} from './verify-helpers.js';
import { v4RoundTrip } from './v4-verifier.js';
import { normPath, routeKey, type ExtractedRoute } from '../frameworks/index.js';
import { isEducationalSourceViewPath } from './verify-fs-routing.js';

export { checkTightness } from './verify-helpers.js';
export { v4RoundTrip } from './v4-verifier.js';

export interface VerifierContext {
  output: AgentOutput;
  repoDir: string;
  /**
   * Deterministic route-extractor output, computed ONCE upstream (in
   * runPolicyGeneration) and threaded in — V7 merges these into its
   * denominator so a route the extractor found but the LLM inventory missed is
   * flagged. The extractor sees resolved-prefix / spec / GraphQL / protocol
   * surfaces that the grep + fs-candidate denominators structurally can't.
   * Optional so callers that don't compute it (or seedInventory=false) fall
   * back to the grep-only denominator unchanged.
   */
  extracted?: ExtractedRoute[];
}

export interface Verifier {
  id: 'V1' | 'V2' | 'V3' | 'V4' | 'V5' | 'V6' | 'V7';
  run(ctx: VerifierContext): Promise<VerifierResult[]>;
}

// --------------------------------------------------------------------------
// V1 — Schema validity
// --------------------------------------------------------------------------

export const v1SchemaValidity: Verifier = {
  id: 'V1',
  async run(ctx) {
    const results: VerifierResult[] = [];
    for (const e of ctx.output.emissions) {
      if (e.policy === null) {
        results.push({
          verifier: 'V1',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: ['policy is null — already review-required'],
        });
        continue;
      }
      const res = validateXSecurity(e.policy);
      if (res.valid) {
        results.push({
          verifier: 'V1',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [],
        });
      } else {
        const reasons = res.errors.map(
          (err) => `${err.instancePath || '/'} ${err.message ?? 'invalid'}`,
        );
        results.push({
          verifier: 'V1',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons: ['schema validation failed', ...reasons],
          modifications: {
            reviewRequired: true,
            reviewReasons: [
              ...(e.reviewReasons ?? []),
              'V1: schema validation failed',
              ...reasons,
            ],
          },
        });
      }
    }
    return results;
  },
};

// --------------------------------------------------------------------------
// V2 — Completeness
// --------------------------------------------------------------------------

export const v2Completeness: Verifier = {
  id: 'V2',
  async run(ctx) {
    const results: VerifierResult[] = [];
    const byEndpoint = new Map<string, RouteInventoryEntry>();
    for (const r of ctx.output.routeInventory) {
      byEndpoint.set(`${r.method.toUpperCase()} ${r.path}`, r);
    }

    for (const e of ctx.output.emissions) {
      if (e.policy === null) {
        results.push({
          verifier: 'V2',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: ['policy is null — already review-required'],
        });
        continue;
      }
      const route = byEndpoint.get(e.endpointId);
      const pathParams = route ? extractPathParams(route.path) : [];

      let handlerParams = new Set<string>();
      let unsupportedLang = false;
      if (route?.sourceFile) {
        const d = await discoverHandlerParams(ctx.repoDir, route.sourceFile, {
          handlerSymbol: route.handlerSymbol,
          sourceLine: route.sourceLine,
        });
        handlerParams = d.params;
        unsupportedLang = d.unsupported;
      }

      const reqKeys = new Set(
        Object.keys(e.policy.request?.schema ?? {}).map((k) => k.toLowerCase()),
      );
      const respKeys = new Set(
        Object.keys(e.policy.response?.schema ?? {}).map((k) => k.toLowerCase()),
      );
      const ruleFields = collectAuthRuleFields(e.policy.authorization?.rules);
      const ruleTails = new Set(ruleFields.map((f) => tailOf(f).toLowerCase()));
      const ruleRefs = ruleFields.map((f) => f.toLowerCase());

      const isCovered = (p: string): boolean => {
        const lower = p.toLowerCase();
        return (
          reqKeys.has(lower) ||
          respKeys.has(lower) ||
          ruleTails.has(lower) ||
          ruleRefs.some((r) => r.endsWith('.' + lower))
        );
      };

      // Path params and handler-read body/query params are different completeness
      // classes. A PATH param is structurally part of the URL — the gateway can
      // neither reject it (it's the route) nor is leaving it unconstrained a
      // looseness V2 should demote: that's a tightness (V3) / authorization
      // choice (an opaque resource id whose BOLA risk is an authorization-rule
      // matter, not a schema-coverage one). So an uncovered path param is
      // ADVISORY only. A handler-read BODY/QUERY field NOT in the schema is the
      // real completeness signal: under denyUnknownFields=true the gateway
      // rejects it (safe — advisory), otherwise it passes through unvalidated
      // (looseness — demote).
      const pathSet = new Set(pathParams.map((p) => p.toLowerCase()));
      const pathUncovered: string[] = [];
      for (const p of pathParams) if (!isCovered(p)) pathUncovered.push(p);
      const bodyUncovered: string[] = [];
      for (const p of handlerParams) {
        if (pathSet.has(p.toLowerCase())) continue; // counted as a path param
        if (!isCovered(p)) bodyUncovered.push(p);
      }

      const reasons: string[] = [];
      if (unsupportedLang && route) {
        reasons.push(
          `warning: handler language not recognized for ${route.sourceFile}; handler-body param discovery skipped`,
        );
      }
      if (pathUncovered.length > 0) {
        reasons.push(
          `note: unconstrained path param(s): ${pathUncovered.join(', ')} (structural — not a completeness demote; constrain via schema/authorization if needed)`,
        );
      }

      const denyUnknown = e.policy.request?.denyUnknownFields === true;
      if (bodyUncovered.length > 0 && !denyUnknown) {
        const reason = `uncovered params: ${bodyUncovered.join(', ')}`;
        reasons.unshift(reason);
        results.push({
          verifier: 'V2',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons,
          modifications: {
            reviewRequired: true,
            reviewReasons: [...(e.reviewReasons ?? []), `V2: ${reason}`],
          },
        });
      } else {
        if (bodyUncovered.length > 0) {
          // denyUnknownFields=true: the gateway rejects these unknown fields, so
          // omitting them from the schema is the SAFE action, not looseness.
          // Surface as a soft warning (D-1: explain it), don't demote.
          reasons.unshift(
            `uncovered params: ${bodyUncovered.join(', ')} (gated by request.denyUnknownFields=true; gateway rejects these)`,
          );
        }
        results.push({
          verifier: 'V2',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons,
        });
      }
    }
    return results;
  },
};

// --------------------------------------------------------------------------
// V3 — Tightness rubric
// --------------------------------------------------------------------------

export const v3Tightness: Verifier = {
  id: 'V3',
  async run(ctx) {
    const results: VerifierResult[] = [];
    for (const e of ctx.output.emissions) {
      if (e.policy === null) {
        results.push({
          verifier: 'V3',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: ['policy is null — already review-required'],
        });
        continue;
      }

      // STRIPPING MODE (extends partial-policy semantics from V2).
      // For each schema entry that fails the tightness rubric, REMOVE it from
      // the policy rather than demote the whole route. This converts V3 from
      // a binary demote-or-pass gate into a continuous filter: theater rules
      // are dropped, tight rules survive, and the policy ships with whatever
      // tight content remains. Routes that end up with NO useful policy
      // content after stripping still demote (no point shipping an empty
      // policy that's indistinguishable from the bare profile default).
      //
      // The model is now instructed (prompt rule 1) to OMIT weak fields, so
      // theater rules should be rare. This verifier is the safety net for
      // when the model emits a type-only "presence check" anyway.

      const strippedReq = new Map<string, string>();
      const strippedResp = new Map<string, string>();

      const reqEntries = paramSchemaEntries(e.policy.request?.schema);
      const respEntries = paramSchemaEntries(e.policy.response?.schema);

      for (const [name, ps] of reqEntries) {
        const why = checkTightness(ps);
        if (why) strippedReq.set(name, why);
      }
      for (const [name, ps] of respEntries) {
        const why = checkTightness(ps);
        if (why) strippedResp.set(name, why);
      }

      if (strippedReq.size === 0 && strippedResp.size === 0) {
        results.push({
          verifier: 'V3',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [],
        });
        continue;
      }

      // Build the stripped policy (immutable; emit as modifications.policy).
      const newPolicy: typeof e.policy = JSON.parse(JSON.stringify(e.policy));
      if (newPolicy.request?.schema) {
        for (const name of strippedReq.keys()) {
          delete newPolicy.request.schema[name];
        }
        // If request.schema is now empty, remove the key (canonicalization
        // would otherwise preserve {}). We deliberately keep request.* if
        // other request-level fields survive (denyUnknownFields, etc).
        if (Object.keys(newPolicy.request.schema).length === 0) {
          delete newPolicy.request.schema;
        }
      }
      if (newPolicy.response?.schema) {
        for (const name of strippedResp.keys()) {
          delete newPolicy.response.schema[name];
        }
        if (Object.keys(newPolicy.response.schema).length === 0) {
          delete newPolicy.response.schema;
        }
      }

      // Determine whether the stripped policy still has useful content.
      // "Useful" = at least one of: a surviving schema entry, an auth rule,
      // an authentication block (other than bare type:'none'), a non-default
      // rate-limit, or auth-equivalent gateway protection (csrf, signature).
      const reqSchemaSurvivors = Object.keys(newPolicy.request?.schema ?? {}).length;
      const respSchemaSurvivors = Object.keys(newPolicy.response?.schema ?? {}).length;
      const authRules = newPolicy.authorization?.rules?.length ?? 0;
      const hasAuthBlock =
        !!newPolicy.authentication &&
        newPolicy.authentication.type !== 'none' &&
        Object.keys(newPolicy.authentication).length > 1;
      const hasRateLimit = newPolicy.rateLimit !== undefined;
      const hasCsrf = newPolicy.csrf !== undefined;
      const hasSignature = newPolicy.request?.signature !== undefined;
      const useful =
        reqSchemaSurvivors > 0 ||
        respSchemaSurvivors > 0 ||
        authRules > 0 ||
        hasAuthBlock ||
        hasRateLimit ||
        hasCsrf ||
        hasSignature;

      const strippedSummary = [
        ...[...strippedReq.entries()].map(([n, w]) => `request.schema.${n}: ${w}`),
        ...[...strippedResp.entries()].map(([n, w]) => `response.schema.${n}: ${w}`),
      ];

      if (useful) {
        results.push({
          verifier: 'V3',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [
            `stripped ${strippedReq.size + strippedResp.size} theater rule(s); ${reqSchemaSurvivors + respSchemaSurvivors} schema entries + ${authRules} auth rules + ${hasRateLimit ? 'rateLimit' : 'no-rateLimit'} survive`,
            ...strippedSummary,
          ],
          modifications: {
            policy: newPolicy,
          },
        });
      } else {
        // Nothing useful left → demote. Don't keep an empty policy that's
        // indistinguishable from the bare profile default.
        results.push({
          verifier: 'V3',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons: [
            'tightness rubric failed; nothing tight survived stripping',
            ...strippedSummary,
          ],
          modifications: {
            reviewRequired: true,
            reviewReasons: [
              ...(e.reviewReasons ?? []),
              `V3: stripped all rules, nothing useful left`,
            ],
          },
        });
      }
    }
    return results;
  },
};

// --------------------------------------------------------------------------
// V4 — Round-trip (see v4-verifier.ts)
// --------------------------------------------------------------------------
// V5 — Cross-route consistency
// --------------------------------------------------------------------------

export const v5CrossRouteConsistency: Verifier = {
  id: 'V5',
  async run(ctx) {
    const demoted = computeV5Demotions(ctx.output.emissions);
    const results: VerifierResult[] = [];
    for (const e of ctx.output.emissions) {
      const reasons = demoted.get(e.endpointId);
      if (reasons && reasons.length > 0) {
        results.push({
          verifier: 'V5',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons,
          modifications: {
            reviewRequired: true,
            reviewReasons: [
              ...(e.reviewReasons ?? []),
              ...reasons.map((r) => `V5: ${r}`),
            ],
          },
        });
      } else {
        results.push({
          verifier: 'V5',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [],
        });
      }
    }
    return results;
  },
};

// --------------------------------------------------------------------------
// V6 — Citation justification
// --------------------------------------------------------------------------

export const v6CitationJustification: Verifier = {
  id: 'V6',
  async run(ctx) {
    const results: VerifierResult[] = [];
    for (const e of ctx.output.emissions) {
      const { kept, droppedReasons, cascadeReasons } =
        await evaluateV6ForEmission(e, ctx.repoDir);
      if (droppedReasons.length === 0) {
        results.push({
          verifier: 'V6',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: [],
        });
        continue;
      }
      const baseMods: Partial<PolicyEmission> = { assumptions: kept };
      if (cascadeReasons.length > 0) {
        results.push({
          verifier: 'V6',
          endpointId: e.endpointId,
          verdict: 'demote-to-review',
          reasons: [...droppedReasons, ...cascadeReasons],
          modifications: {
            ...baseMods,
            reviewRequired: true,
            reviewReasons: [
              ...(e.reviewReasons ?? []),
              ...cascadeReasons.map((r) => `V6: ${r}`),
            ],
          },
        });
      } else {
        results.push({
          verifier: 'V6',
          endpointId: e.endpointId,
          verdict: 'pass',
          reasons: droppedReasons.map((d) => `dropped assumption: ${d}`),
          modifications: baseMods,
        });
      }
    }
    return results;
  },
};

// --------------------------------------------------------------------------
// V7 — Inventory diff (deterministic grep)
// --------------------------------------------------------------------------

export const v7InventoryDiff: Verifier = {
  id: 'V7',
  async run(ctx) {
    const hits = await deterministicGrep(ctx.repoDir);
    const fsCandidates = await detectFilesystemHandlerCandidates(ctx.repoDir);

    const claimed = new Set<string>();
    const claimedFiles = new Map<string, number[]>();
    const claimedFileSet = new Set<string>();
    // Canonical (method, normPath) keys the LLM inventory claimed. The
    // extractor denominator matches against THIS so a resolved-prefix /
    // spec / GraphQL route the extractor canonicalized (`/api/x`) lines up
    // with the LLM's `/api/x` line even when neither cites the same file.
    const claimedRouteKeys = new Set<string>();
    for (const r of ctx.output.routeInventory) {
      const file = r.sourceFile.split(path.sep).join('/');
      claimed.add(`${file}:${r.sourceLine}`);
      const arr = claimedFiles.get(file) ?? [];
      arr.push(r.sourceLine);
      claimedFiles.set(file, arr);
      claimedFileSet.add(file);
      claimedRouteKeys.add(routeKey(r.method.toUpperCase(), r.path));
    }

    const missed: string[] = [];
    for (const h of hits) {
      const file = h.file.split(path.sep).join('/');
      if (claimed.has(`${file}:${h.line}`)) continue;
      const near = claimedFiles.get(file);
      if (near && near.some((ln) => Math.abs(ln - h.line) <= 2)) continue;
      missed.push(`${file}:${h.line}${h.path ? ` (${h.path})` : ''}`);
    }

    // Filesystem-routed misses — handler files the inventory does not
    // reference at all. These are the DVWA-style failure mode where the agent
    // saw one index.php and stopped.
    const missedHandlers: string[] = [];
    const fsCandidateFiles = new Set<string>();
    for (const cand of fsCandidates) {
      fsCandidateFiles.add(cand.file);
      if (claimedFileSet.has(cand.file)) continue;
      missedHandlers.push(`missed candidate handler: ${cand.file} (${cand.framework})`);
    }

    // Extractor denominator. The deterministic extractor sees surfaces the grep
    // + fs-candidate denominators structurally can't (resolved-prefix mounts,
    // OpenAPI spec routes, GraphQL ops, SOAP/XML-RPC). A route the extractor
    // found that the LLM inventory did NOT claim (by canonical route key, and
    // not already surfaced as a grep/fs miss) is flagged. Reconciled against the
    // other two denominators by canonical key + file so we don't double-count.
    const missedExtracted: string[] = [];
    const seenExtractedKeys = new Set<string>();
    for (const er of ctx.extracted ?? []) {
      const file = (er.sourceFile ?? '').split(path.sep).join('/');
      // Educational source-view decoys are filtered from the inventory
      // (filterEducationalSourceViewRoutes) — never flag them as missed.
      if (file && isEducationalSourceViewPath(file)) continue;
      const key = routeKey(er.method.toUpperCase(), er.path);
      if (claimedRouteKeys.has(key)) continue; // LLM claimed it — not a miss
      if (seenExtractedKeys.has(key)) continue; // de-dupe within extractor set
      // If the LLM claimed the SAME source file, treat as covered (it found the
      // file; line/path-shape drift is V6/V3's concern, not V7's denominator).
      if (file && claimedFileSet.has(file)) continue;
      // Already surfaced by the fs-candidate denominator for the same file —
      // don't emit a second miss line for the same gap.
      if (file && fsCandidateFiles.has(file)) continue;
      seenExtractedKeys.add(key);
      const loc = file
        ? ` @ ${file}${typeof er.sourceLine === 'number' ? `:${er.sourceLine}` : ''}`
        : '';
      const src = er.protocol ?? er.framework ?? er.source;
      missedExtracted.push(
        `missed extracted route: ${er.method.toUpperCase()} ${normPath(er.path)}${loc} (${src})`,
      );
    }

    const allMissed = [
      ...missed.map((m) => `missed routes: ${m}`),
      ...missedHandlers,
      ...missedExtracted,
    ];

    if (allMissed.length === 0) {
      return [{
        verifier: 'V7',
        verdict: 'pass',
        reasons: [
          `scanned ${hits.length} decl-router hits + ${fsCandidates.length} fs-routing candidates + ${(ctx.extracted ?? []).length} extractor routes; all matched inventory`,
        ],
      }];
    }
    return [{
      verifier: 'V7',
      verdict: 'demote-to-review',
      reasons: allMissed,
    }];
  },
};

export { extractV7MissedCandidateFiles } from './verify-fs-routing.js';

// --------------------------------------------------------------------------
// Orchestrator
// --------------------------------------------------------------------------

export const defaultVerifiers: Verifier[] = [
  v1SchemaValidity,
  v2Completeness,
  v3Tightness,
  v4RoundTrip,
  v5CrossRouteConsistency,
  v6CitationJustification,
  v7InventoryDiff,
];

export interface RunVerifiersResult {
  results: VerifierResult[];
  emissions: PolicyEmission[];
  globalReasons: string[];
  composedByEndpoint: Map<
    string,
    { verdict: 'pass' | 'fail' | 'demote-to-review'; reasons: string[] }
  >;
}

/**
 * Order-preserving dedupe. Multiple verifiers emit identical informational
 * reasons when policy is null (V1-V4 all pass with "policy is null — already
 * review-required"). Accumulating produces 4 copies in the composed rationale
 * that downstream surfaces as one duplicated sentence. Dedupe at the composer
 * so audit + rationale carry each reason once. Per D-1 we don't drop the
 * reason — we surface it once truthfully — but we don't multiplex it either.
 */
function dedupeReasons(reasons: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const r of reasons) {
    if (seen.has(r)) continue;
    seen.add(r);
    out.push(r);
  }
  return out;
}

/**
 * Run all verifiers and compose per-emission verdicts (strictest wins). The
 * returned `emissions` array is a clone with each verifier's `modifications`
 * applied in verifier order.
 */
export async function runVerifiers(
  ctx: VerifierContext,
  verifiers: Verifier[] = defaultVerifiers,
): Promise<RunVerifiersResult> {
  const results: VerifierResult[] = [];
  for (const v of verifiers) {
    const r = await v.run(ctx);
    for (const item of r) results.push(item);
  }

  const cloned: PolicyEmission[] = structuredClone(ctx.output.emissions);
  const byEndpoint = new Map<string, PolicyEmission>();
  for (const e of cloned) byEndpoint.set(e.endpointId, e);

  const composedByEndpoint = new Map<
    string,
    { verdict: 'pass' | 'fail' | 'demote-to-review'; reasons: string[] }
  >();
  const globalReasons: string[] = [];

  for (const r of results) {
    if (!r.endpointId) {
      if (r.verdict !== 'pass') {
        for (const reason of r.reasons) {
          globalReasons.push(`${r.verifier}: ${reason}`);
        }
      }
      continue;
    }
    const prior = composedByEndpoint.get(r.endpointId);
    if (!prior) {
      composedByEndpoint.set(r.endpointId, {
        verdict: r.verdict,
        reasons: dedupeReasons(r.reasons),
      });
    } else {
      const newVerdict =
        verdictStrictness(r.verdict) > verdictStrictness(prior.verdict)
          ? r.verdict
          : prior.verdict;
      composedByEndpoint.set(r.endpointId, {
        verdict: newVerdict,
        reasons: dedupeReasons([...prior.reasons, ...r.reasons]),
      });
    }
  }

  for (const r of results) {
    if (!r.endpointId) continue;
    const target = byEndpoint.get(r.endpointId);
    if (!target) continue;
    applyModifications(target, r);
  }

  return { results, emissions: cloned, globalReasons, composedByEndpoint };
}
