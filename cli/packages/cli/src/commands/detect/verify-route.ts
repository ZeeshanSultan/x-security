// `lazy verify-route`  (stdin JSON → stdout JSON)
//
// The whole-route PRECISION gate. Per-finding `verify-finding` proves each
// finding is real (cite byte-match + tightness + schema), but it CANNOT see
// that the route's findings, COMPOSED into one policy, over-block: a route whose
// findings omit a body field the handler actually reads compiles to a policy
// that rejects a legitimate request. That's the over-block class (dvna 0/5
// legit). This verb composes ALL findings into the route policy (the same
// compile path the scan will persist) and runs:
//
//   V2 — completeness: every declared handler/path param is covered (or gated
//        by denyUnknownFields). Catches the omitted-field shape directly.
//   V4 — round-trip: a synthetic POSITIVE (legit) request MUST be allowed and a
//        synthetic NEGATIVE (attack) request MUST be blocked by the composed
//        policy. A blocked positive = the route would false-block real traffic.
//   V5 — cross-route precondition consistency over the composed emission.
//
// verdict:"demote" when any of the three demotes (the route is too tight / too
// loose / inconsistent and must drop to reviewRequired rather than enforce).
// On a V4 positive-sample failure we surface the CONCRETE synthetic request that
// would be false-blocked, so the host agent can see exactly which legit shape the
// policy rejects (D-2: give the reviewer the evidence, not a placeholder verdict).
//
// Contract:
//   in  {"repoDir","route":{"method","path"},"findings":[{controlHint,cite,param?},...]}
//   out {"verdict":"pass"|"demote","positiveSample?":<SyntheticRequest>,"reasons":[...]}

import {
  extractRoutes,
  normPath,
  v2Completeness,
  v4RoundTrip,
  v5CrossRouteConsistency,
  runVerifiers,
  generatePositive,
  discoverHandlerParams,
  evaluatePolicy,
  buildEvidencePacks,
  buildAuthContext,
  assessRouteDepth,
  type AgentOutput,
  type DepthAssessment,
  type ExtractedRoute,
  type PolicyEmission,
  type RouteAuthChain,
  type RouteInventoryEntry,
  type SyntheticRequest,
  type VerifierContext,
} from '@x-security/detect-core';
import { runCompile, type CompileFinding } from './compile.js';
import { createTools } from './fs-tools.js';

export interface VerifyRouteInput {
  repoDir: string;
  route: { method: string; path: string };
  findings: CompileFinding[];
}

export interface VerifyRouteResult {
  verdict: 'pass' | 'demote';
  reasons: string[];
  /** The synthetic legit request a too-tight composed policy would false-block.
   * Present only on a V4 positive-sample failure. */
  positiveSample?: SyntheticRequest;
  /** Depth-completeness assessment of the composed policy vs the route's
   * EvidencePack. `gaps` are hard (the route is under-detected — re-detect, do
   * not persist a stub); `advisories` are soft surfaces the host must confirm or
   * cite-dismiss. Independent of `verdict`: a route can pass the over-block gate
   * (verdict:"pass") yet be an under-detected stub (depth.gaps non-empty). */
  depth?: DepthAssessment;
}

/** Ground the route against the machine extractor so V2 reads the REAL handler
 * file for param discovery — without the true sourceFile, V2 cannot see that the
 * composed policy omits a body field the handler reads (the over-block class).
 * Falls back to a synthetic entry (method+path only) when the extractor didn't
 * surface the route; V4 still round-trips on method+path, only V2's handler-body
 * discovery is skipped. */
function groundInventory(
  extracted: ExtractedRoute[],
  route: { method: string; path: string },
): RouteInventoryEntry {
  const wantMethod = route.method.toUpperCase();
  const wantPath = normPath(route.path);
  for (const r of extracted) {
    if (!r.sourceFile) continue;
    if (r.method.toUpperCase() !== wantMethod) continue;
    if (normPath(r.path) !== wantPath) continue;
    const entry: RouteInventoryEntry = {
      method: wantMethod,
      path: route.path,
      sourceFile: r.sourceFile,
      sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
    };
    if (r.handler) entry.handlerSymbol = r.handler;
    return entry;
  }
  // Transport-route fallback (GraphQL/gRPC/JSON-RPC): ground a fragment-less route
  // against its resolver keys (path#resolver) — same machine source (D-1).
  if (!wantPath.includes('#')) {
    const prefix = `${wantPath}#`;
    for (const r of extracted) {
      if (!r.sourceFile) continue;
      if (r.method.toUpperCase() !== wantMethod) continue;
      if (!normPath(r.path).startsWith(prefix)) continue;
      const entry: RouteInventoryEntry = {
        method: wantMethod,
        path: route.path,
        sourceFile: r.sourceFile,
        sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
      };
      if (r.handler) entry.handlerSymbol = r.handler;
      return entry;
    }
  }
  return { method: wantMethod, path: route.path, sourceFile: '<verify-route>', sourceLine: 0 };
}

// Auth-ish middleware name tokens — a declaration-router arg matching these is an
// authentication gate on the route (Express/Koa/Connect style).
const AUTH_MW_RE =
  /verify|isauthenticated|requireauth|require_login|requirelogin|ensureloggedin|passport|jwt|bearer|authenticate|\bauth\b|protect|guard|login_required|requires_auth|check_?auth|token/i;

/** Parse the auth-ish middleware off a declaration-router decl line:
 *  `router.get('/x', auth.verifyToken, ctrl.handler)` → ['auth.verifyToken'].
 *  Window-matched to tolerate the extractor's off-by-one sourceLine; matches the
 *  registration whose method + path are THIS route's. Returns [] for inline /
 *  decorator handlers or when nothing auth-ish is present. */
async function parseDeclAuthMiddleware(tools: AgentToolsLite, inv: RouteInventoryEntry): Promise<string[]> {
  if (!inv.sourceFile || inv.sourceFile === '<verify-route>') return [];
  const line = Math.max(1, inv.sourceLine || 1);
  let text = '';
  try {
    text = (await tools.read_file(inv.sourceFile, Math.max(1, line - 1), line + 2))?.content ?? '';
  } catch {
    return [];
  }
  const np = (p: string) => (p.replace(/[?#].*$/, '').replace(/\/+/g, '/').replace(/\/$/, '') || '/').toLowerCase().replace(/[:{<][^/}>]+[}>]?/g, '');
  const want = np(inv.path);
  const reg = new RegExp(`\\.(?:${inv.method.toLowerCase()}|all|use)\\s*\\(([^)]*)\\)`, 'gi');
  for (const ln of text.split('\n')) {
    reg.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = reg.exec(ln)) !== null) {
      const args = m[1]!.split(',').map((s) => s.trim()).filter(Boolean);
      if (args.length < 2) continue;
      const first = args[0]!.replace(/^['"`]|['"`]$/g, '');
      if (np(first) !== want) continue; // not this route's registration
      // middleware = every arg except the path (first) and handler (last)
      const mws = args.slice(1, -1);
      return mws.filter((a) => !/^['"`]/.test(a) && AUTH_MW_RE.test(a));
    }
  }
  return [];
}

/** Minimal tools shape parseDeclAuthMiddleware needs (read_file). */
interface AgentToolsLite {
  read_file(p: string, ls?: number, le?: number): Promise<{ content?: string } | undefined>;
}

/** Build the single-route AgentOutput the V2/V4/V5 verifiers consume. */
function buildOutput(
  inv: RouteInventoryEntry,
  policy: NonNullable<PolicyEmission['policy']>,
): AgentOutput {
  const emission: PolicyEmission = {
    endpointId: `${inv.method} ${inv.path}`,
    policy,
    reviewRequired: false,
    assumptions: [],
  };
  return {
    routeInventory: [inv],
    profiles: {},
    emissions: [emission],
    coverage: { filesRead: [], grepQueriesIssued: [] },
  };
}

export async function runVerifyRoute(input: VerifyRouteInput): Promise<VerifyRouteResult> {
  const { repoDir, route, findings } = input;

  // --- compose all findings into ONE route policy (the persist path) --------
  const compiled = await runCompile({ repoDir, route, findings });
  const reasons: string[] = [];
  for (const d of compiled.dropped) reasons.push(`compile: ${d}`);

  if (compiled.policy === null) {
    // No enforceable policy composed from these findings — there is nothing to
    // over-block, but there's also nothing to enforce. Demote: the route stays
    // review-required rather than shipping an empty/enforcing policy.
    reasons.unshift('compile: findings produced no enforceable route policy');
    return { verdict: 'demote', reasons };
  }

  const extracted = await extractRoutes(repoDir);
  const inv = groundInventory(extracted.routes, route);
  const endpointId = `${inv.method} ${inv.path}`;
  const output = buildOutput(inv, compiled.policy);

  // V2 reads the real handler file for param discovery; point it at the repo.
  const ctx: VerifierContext = { output, repoDir };
  const run = await runVerifiers(ctx, [v2Completeness, v4RoundTrip, v5CrossRouteConsistency]);

  const composed = run.composedByEndpoint.get(endpointId);
  const demote = composed !== undefined && composed.verdict !== 'pass';
  if (composed) reasons.push(...composed.reasons);

  // On a V4 positive-sample failure, recompute the concrete legit request the
  // composed policy false-blocks so the reviewer sees the exact shape (D-2).
  let positiveSample: SyntheticRequest | undefined;
  const v4Blocked =
    composed?.reasons.some((r) => r.includes('positive sample rejected')) ?? false;
  if (v4Blocked) {
    const inv = output.routeInventory[0]!;
    try {
      // Recompute the sample with the SAME handler-derived inputs V4 used, so
      // the surfaced sample reproduces the block V4 saw (fix D).
      let handlerReadParams: Set<string> | undefined;
      if (inv.sourceFile && inv.sourceFile !== '<synthetic>' && inv.sourceFile !== '<verify-route>') {
        const d = await discoverHandlerParams(repoDir, inv.sourceFile, {
          handlerSymbol: inv.handlerSymbol,
          sourceLine: inv.sourceLine,
        });
        if (d.scoped && d.params.size > 0) handlerReadParams = d.params;
      }
      const sample = generatePositive(inv, compiled.policy, handlerReadParams);
      const ev = evaluatePolicy(sample, compiled.policy);
      if (ev.decision === 'block') positiveSample = sample;
    } catch {
      // generation itself failed — V4 already recorded that reason; no sample
      // to surface. Don't synthesize a placeholder (D-1).
    }
  }

  // --- depth-completeness: is the composed policy DEEP enough for the surface
  // the handler actually exposes? Catches the empty-stub-claims-coverage shortcut
  // that V2/V4/V5 (over-block gates) pass trivially. Evidence-grounded; the pack
  // is the same deterministic extraction `context` hands the detector.
  let depth: DepthAssessment | undefined;
  if (inv.sourceFile && inv.sourceFile !== '<verify-route>') {
    try {
      const tools = await createTools(repoDir);
      const packs = await buildEvidencePacks({ inventory: [inv], tools });
      const pack = packs.get(endpointId);
      if (pack) {
        // Resolve the route's auth chain so the depth gate can fire the
        // sensitive-route-no-auth gap (C) and apply the public-read carve-out (A).
        let auth: RouteAuthChain | undefined;
        try {
          const authCtx = await buildAuthContext({ inventory: [inv], tools, repoDir });
          const inlineSymbols = authCtx.routeSymbols.get(endpointId) ?? [];
          const chain = inv.authnMiddlewareChain ?? [];
          // The extractor doesn't populate authnMiddlewareChain for declaration
          // routers (Express), so an authed `router.get('/x', auth.verifyToken, h)`
          // resolves to an EMPTY chain — which made the depth gate treat it as a
          // public read. Parse the auth-ish middleware args off the decl line.
          const declAuth = await parseDeclAuthMiddleware(tools, inv);
          auth = { chain: [...new Set([...chain, ...declAuth])], inlineSymbols: [...inlineSymbols] };
        } catch {
          // auth-context build failed — leave `auth` undefined (chain unknown);
          // the gate treats unknown-chain as empty, which is the safe default
          // for the public-read carve-out (won't force ownership on a GET).
        }
        const depthArgs: Parameters<typeof assessRouteDepth>[0] = {
          policy: compiled.policy,
          pack,
          method: inv.method,
          path: inv.path,
          // The V6-verified cites backing the composed policy double as the
          // cited-dismissal exit for the surface gaps (D-3 byte-matched).
          dismissalCites: compiled.cites,
        };
        if (auth) depthArgs.auth = auth;
        depth = assessRouteDepth(depthArgs);
      }
    } catch {
      // EvidencePack build failed (unreadable handler) — no depth signal to add.
      // Don't synthesize one (D-1); the over-block verdict still stands.
    }
  }

  const result: VerifyRouteResult = {
    verdict: demote ? 'demote' : 'pass',
    reasons,
  };
  if (positiveSample !== undefined) result.positiveSample = positiveSample;
  if (depth && (depth.gaps.length > 0 || depth.advisories.length > 0)) result.depth = depth;
  return result;
}
