// `x-security compile`  (stdin JSON → stdout JSON)
//
// Compile a route's VERIFIED findings into a single x-security policy. Each
// finding's controlHint becomes an enforced control via the deterministic
// assumption→control compiler (the LLM detected; code emits). The policy is
// then canonicalized so two runs on the same input byte-match.
//
// Rule D-3 / D-1: a control is only compiled from a finding whose cite
// byte-matches the file. This command re-runs the cite byte-match (V6) on every
// finding defensively and DROPS any whose cite no longer matches — never emits
// a control backed by an unverifiable citation, even if the caller marked it
// "verified". The dropped findings are reported in `dropped`.
//
// Contract:
//   in  {"route":{"method","path"},"findings":[{controlHint,cite,...}]}
//   out {"policy":<x-security policy object>,"dropped":[...]}

import {
  evaluateV6ForEmission,
  compileAssumptionsToPolicy,
  canonicalizePolicy,
  applyPerimeterTightnessDefaults,
  type Assumption,
  type Citation,
  type ControlHint,
  type PolicyEmission,
  type XSecurityPolicy,
} from '@x-security/detect-core';

export interface CompileFinding {
  /** Full control descriptor — the compiler reads the per-kind structured
   * fields (param, principalRef, operator, sink, identifier, …). The CLI
   * forwards it VERBATIM; it must not strip fields or the new control kinds
   * (authorization, denyUnknownFields, rateLimit, …) can never emit. */
  controlHint: ControlHint;
  cite: Citation;
  /** Optional assumption dot-path; derived from the controlHint when absent. */
  field?: string;
  /** Legacy/explicit param the control protects (also accepted as
   * controlHint.param, which takes precedence). */
  param?: string;
}

// Best-effort dot-path for the assumption. The compiler keys off the
// controlHint's structured fields, not this string — but V6's tightness cascade
// only inspects request/response.schema.* paths, so non-schema controls
// (authorization, rateLimit, …) deliberately get a non-schema field.
function deriveField(hint: ControlHint, param: string | undefined): string {
  if (param !== undefined) return `request.schema.${param}`;
  switch (hint.kind) {
    case 'injectionGuard': return 'request.schema.input.injectionGuard';
    case 'authentication': return 'authentication';
    case 'authorization': return 'authorization';
    case 'denyUnknownFields': return 'request.denyUnknownFields';
    case 'rateLimit': return 'rateLimit';
    case 'contentType': return 'request.contentType';
    case 'responseShape': return 'response.stripUnknownFields';
    default: return 'request.schema';
  }
}

export interface CompileInput {
  repoDir: string;
  route: { method: string; path: string };
  findings: CompileFinding[];
}

export interface CompileResult {
  policy: XSecurityPolicy | null;
  /** Verified (cite-snapped) citations backing the emitted controls. The bin
   * persists these as the audit sidecar when `--write` is passed. */
  cites: Citation[];
  dropped: string[];
  applied: string[];
}

function findingToAssumption(f: CompileFinding): Assumption {
  // controlHint.param wins; a legacy top-level f.param is merged in only when
  // the descriptor itself didn't carry one. The full descriptor is forwarded
  // verbatim so the compiler sees every structured field.
  const param = f.controlHint.param ?? f.param;
  const controlHint: ControlHint =
    param !== undefined && f.controlHint.param === undefined
      ? { ...f.controlHint, param }
      : f.controlHint;
  return {
    field: f.field ?? deriveField(controlHint, param),
    assumption: controlHint.kind,
    confidence: 'high',
    cite: f.cite,
    controlHint,
  };
}

export async function runCompile(input: CompileInput): Promise<CompileResult> {
  const { repoDir, route, findings } = input;
  const dropped: string[] = [];
  const keptAssumptions: Assumption[] = [];

  // Re-verify every cite (D-3). Drop any finding whose quote no longer
  // byte-matches its file; never compile a control backed by an unverifiable
  // citation. evaluateV6ForEmission snaps real-but-drifted cites in place.
  for (const f of findings) {
    const probe: PolicyEmission = {
      endpointId: `${route.method.toUpperCase()} ${route.path}`,
      policy: null,
      reviewRequired: true,
      assumptions: [findingToAssumption(f)],
    };
    const v6 = await evaluateV6ForEmission(probe, repoDir);
    if (v6.kept.length === 1) {
      keptAssumptions.push(v6.kept[0]!);
    } else {
      dropped.push(...v6.droppedReasons);
    }
  }

  // The cites that survived V6 (snapped to their true lines) back the controls.
  const cites: Citation[] = keptAssumptions.map((a) => a.cite);

  const emission: PolicyEmission = {
    endpointId: `${route.method.toUpperCase()} ${route.path}`,
    policy: null,
    reviewRequired: true,
    assumptions: keptAssumptions,
  };

  const prevFlag = process.env['COMPILE_ASSUMPTIONS'];
  process.env['COMPILE_ASSUMPTIONS'] = '1';
  let compiled;
  try {
    compiled = compileAssumptionsToPolicy(emission);
  } finally {
    if (prevFlag === undefined) delete process.env['COMPILE_ASSUMPTIONS'];
    else process.env['COMPILE_ASSUMPTIONS'] = prevFlag;
  }

  if (compiled.emission.policy === null || compiled.applied.length === 0) {
    return { policy: null, cites, dropped, applied: [] };
  }

  // Tighten then canonicalize. applyPerimeterTightnessDefaults is flag-gated
  // (default identity); canonicalize so the emitted policy is reproducible.
  const tightened = applyPerimeterTightnessDefaults(compiled.emission.policy);
  const policy = canonicalizePolicy(structuredClone(tightened.policy));

  return { policy, cites, dropped, applied: [...compiled.applied, ...tightened.applied] };
}
