// `lazy context <repoDir> --route "<METHOD> <path>"`  (stdout JSON)
//
// The D-2 context-resolution layer, per route. Runs detect-core's deterministic
// pre-pass — the same evidence-pack + auth-context stages the hosted pipeline
// runs between Pass-2 and Pass-3 — over a SINGLE route resolved from the machine
// extractor. The host detect skill consumes this instead of re-deriving the
// handler body / inputs / validators / auth chain with its own tool budget.
//
// Everything here is deterministic and LLM-free:
//   - the route is grounded against the extractor (sourceFile:line, handler),
//     never against agent text (D-1);
//   - the evidence pack is the static handler-body slice + observed
//     inputs/validators/outputs;
//   - the auth context is the resolved inline-auth chain for that handler.
//
// Contract:
//   in  --route "<METHOD> <path>"  (positional repoDir)
//   out {"evidencePack": <EvidencePack>, "authContext": {byChain, bySymbol, routeSymbols}}
//
// If the extractor cannot ground the requested route, this FAILS (no synthesized
// inventory entry, no placeholder pack — D-1/D-3).

import {
  extractRoutes,
  normPath,
  buildEvidencePacks,
  buildAuthContext,
  deriveCandidateFindings,
  deriveMassAssignmentCandidates,
  routeAnalysisIncomplete,
  type AuthContext,
  type AuthContextSnippet,
  type CandidateFinding,
  type MassAssignmentCandidate,
  type EvidencePack,
  type ExtractedRoute,
  type RouteInventoryEntry,
} from '@writ/detect-core';
import { createTools } from './fs-tools.js';

export interface ContextInput {
  repoDir: string;
  route: { method: string; path: string };
}

/** Serializable projection of AuthContext (Maps → plain objects). */
export interface SerializedAuthContext {
  byChain: Record<string, AuthContextSnippet>;
  bySymbol: Record<string, AuthContextSnippet>;
  routeSymbols: Record<string, string[]>;
}

export interface ContextResult {
  evidencePack: EvidencePack;
  authContext: SerializedAuthContext;
  /** Deterministic candidate injection findings (#1) the model confirms/rejects. */
  candidateFindings: CandidateFinding[];
  /** Deterministic mass-assignment candidates (API6): wholesale `req.body` →
   *  persist. The model confirms and emits request.denyFields. */
  massAssignmentCandidates: MassAssignmentCandidate[];
  /** Fail-loud: true when the handler body could not be resolved on a risk
   *  surface — the route is UNANALYZED and must be marked reviewRequired, not
   *  reported clean. Mirrors evidencePack.coverage. */
  analysisIncomplete: boolean;
}

/** Parse a `"<METHOD> <path>"` route string. Strict — the method and a
 * leading-slash path are both required. */
export function parseRouteArg(raw: string): { method: string; path: string } {
  const m = /^\s*([A-Za-z]+)\s+(\S.*)$/.exec(raw);
  if (!m) {
    throw new Error(`--route must be "<METHOD> <path>", got: ${JSON.stringify(raw)}`);
  }
  return { method: m[1]!.toUpperCase(), path: m[2]!.trim() };
}

/** Ground the requested route against the machine extractor (D-1). A route the
 * extractor did not surface — or surfaced without a source citation — cannot be
 * resolved; we never invent an inventory entry. Matches on (method, normPath). */
function groundRoute(
  extracted: ExtractedRoute[],
  want: { method: string; path: string },
): RouteInventoryEntry | null {
  const wantMethod = want.method.toUpperCase();
  const wantPath = normPath(want.path);
  for (const r of extracted) {
    if (!r.sourceFile) continue;
    if (r.method.toUpperCase() !== wantMethod) continue;
    if (normPath(r.path) !== wantPath) continue;
    const entry: RouteInventoryEntry = {
      method: r.method.toUpperCase(),
      path: r.path,
      sourceFile: r.sourceFile,
      sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
    };
    if (r.handler) entry.handlerSymbol = r.handler;
    return entry;
  }
  // Transport-route fallback: a fragment-less route (POST /graphql) that the
  // GraphQL-one-route rule asks for has no exact extractor key, but the resolver
  // keys (POST /graphql#mutation.x) ARE the evidence it exists. Ground against
  // the first such resolver — same machine-derived source (D-1), the inverse of
  // the one-route collapse. The resolver line anchors the handler body so the
  // EvidencePack reads real resolver code (where the sinks live).
  if (!wantPath.includes('#')) {
    const prefix = `${wantPath}#`;
    for (const r of extracted) {
      if (!r.sourceFile) continue;
      if (r.method.toUpperCase() !== wantMethod) continue;
      if (!normPath(r.path).startsWith(prefix)) continue;
      const entry: RouteInventoryEntry = {
        method: wantMethod,
        path: want.path,
        sourceFile: r.sourceFile,
        sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
      };
      if (r.handler) entry.handlerSymbol = r.handler;
      return entry;
    }
  }
  return null;
}

function serializeAuthContext(ctx: AuthContext): SerializedAuthContext {
  return {
    byChain: Object.fromEntries(ctx.byChain),
    bySymbol: Object.fromEntries(ctx.bySymbol),
    routeSymbols: Object.fromEntries(ctx.routeSymbols),
  };
}

export async function runContext(input: ContextInput): Promise<ContextResult> {
  const { repoDir, route } = input;
  const extracted = await extractRoutes(repoDir);

  const entry = groundRoute(extracted.routes, route);
  if (!entry) {
    throw new Error(
      `route not grounded: the deterministic extractor did not surface a cited ` +
        `"${route.method.toUpperCase()} ${route.path}" in ${repoDir}. ` +
        `Run \`routes\` to see the grounded inventory (D-1: no synthesized context).`,
    );
  }

  const id = `${entry.method} ${entry.path}`;
  const tools = await createTools(repoDir);
  const inventory: RouteInventoryEntry[] = [entry];

  const packs = await buildEvidencePacks({ inventory, tools });
  const evidencePack = packs.get(id) ?? {
    endpointId: id,
    observedInputs: [],
    observedValidators: [],
    observedOutputs: [],
    objectIdParams: [],
    bodyParsed: null,
    bytes: 0,
  };

  const authContext = await buildAuthContext({ inventory, tools, repoDir });

  // Candidate injection findings (#1): cited sink lines + the tainted input, derived
  // deterministically from the resolved handler body. The model CONFIRMS each (reads
  // the cite, accepts) or rejects with a cited reason — and adds the long tail.
  const candidateFindings = deriveCandidateFindings(evidencePack);
  const massAssignmentCandidates = deriveMassAssignmentCandidates(evidencePack);
  const analysisIncomplete = routeAnalysisIncomplete(evidencePack);

  return { evidencePack, authContext: serializeAuthContext(authContext), candidateFindings, massAssignmentCandidates, analysisIncomplete };
}
