// `lazy verify`  (stdin JSON → stdout JSON)
//
// The zero-hallucination gate, per single finding. The host agent proposes a
// finding {route, controlHint, cite}; this runs the deterministic checks that
// decide whether the finding is real enough to become an enforced control:
//
//   V6 — cite byte-match: the quote MUST byte-match the cited file. If the
//        quote is real but the line drifted, snap it to its true location and
//        return the corrected cite. Absent from the file entirely → FAIL
//        (D-3: never invent a citation).
//   V3 — tightness: the control the finding implies must be a real bound, not
//        type-only theatre.
//   V1 — schema: the compiled control must be a schema-valid x-security policy.
//
// PASS only when all three hold. Any failure returns verdict:"fail" with the
// reasons the agent uses to re-read / fix / drop (bounded retry loop upstream).
//
// Contract:
//   in  {"repoDir","finding":{"route":{"method","path"},
//        "controlHint":{"kind","sink?"},"cite":{"file","lineStart","lineEnd","quote"}}}
//   out {"verdict":"pass"|"fail","reasons":[...],"snappedCite?":{...}}

import {
  evaluateV6ForEmission,
  compileAssumptionsToPolicy,
  validateXSecurity,
  checkTightness,
  type Assumption,
  type ControlHint,
  type PolicyEmission,
  type Citation,
} from '@writ/detect-core';
import type { ParamSchema } from '@writ/schema';

export interface VerifyFinding {
  route: { method: string; path: string };
  /** Full control descriptor — forwarded verbatim so verify exercises the same
   * compile path the full scan will, across all 9 control kinds. */
  controlHint: ControlHint;
  cite: Citation;
  field?: string;
  param?: string;
}

export interface VerifyInput {
  repoDir: string;
  finding: VerifyFinding;
}

export interface VerifyResult {
  verdict: 'pass' | 'fail';
  reasons: string[];
  snappedCite?: Citation;
}

/** Best-effort dot-path for the assumption. The compiler keys off the
 * controlHint's structured fields; V6's tightness cascade only inspects
 * request/response.schema.* paths, so non-schema controls get a non-schema
 * field. */
function deriveField(hint: ControlHint, param: string | undefined): string {
  if (param !== undefined) return `request.schema.${param}`;
  switch (hint.kind) {
    // injectionGuard with no bound param: a synthetic placeholder so the control
    // can form (the real param name is the model's job in the full compile pass).
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

export async function runVerify(input: VerifyInput): Promise<VerifyResult> {
  const { repoDir, finding } = input;
  const reasons: string[] = [];

  const param = finding.controlHint.param ?? finding.param;
  const controlHint: ControlHint =
    param !== undefined && finding.controlHint.param === undefined
      ? { ...finding.controlHint, param }
      : finding.controlHint;

  const assumption: Assumption = {
    field: finding.field ?? deriveField(controlHint, param),
    assumption: `${controlHint.kind} on ${finding.route.method} ${finding.route.path}`,
    confidence: 'high',
    cite: finding.cite,
    controlHint,
  };

  const emission: PolicyEmission = {
    endpointId: `${finding.route.method.toUpperCase()} ${finding.route.path}`,
    policy: null,
    reviewRequired: true,
    assumptions: [assumption],
  };

  // --- V6: cite byte-match (+ snap on line drift) --------------------------
  const v6 = await evaluateV6ForEmission(emission, repoDir);
  if (v6.kept.length === 0) {
    reasons.push(...v6.droppedReasons.map((r) => `V6: ${r}`));
    return { verdict: 'fail', reasons };
  }
  const keptCite = v6.kept[0]!.cite;
  let snappedCite: Citation | undefined;
  if (
    keptCite.lineStart !== finding.cite.lineStart ||
    keptCite.lineEnd !== finding.cite.lineEnd
  ) {
    snappedCite = keptCite;
    reasons.push(
      `V6: cite snapped from ${finding.cite.file}:${finding.cite.lineStart}-${finding.cite.lineEnd} to ${keptCite.file}:${keptCite.lineStart}-${keptCite.lineEnd}`,
    );
  }

  // --- compile the (cite-verified) finding into a control ------------------
  const verifiedEmission: PolicyEmission = { ...emission, assumptions: v6.kept };
  const prevFlag = process.env['COMPILE_ASSUMPTIONS'];
  process.env['COMPILE_ASSUMPTIONS'] = '1';
  let compiled;
  try {
    compiled = compileAssumptionsToPolicy(verifiedEmission);
  } finally {
    if (prevFlag === undefined) delete process.env['COMPILE_ASSUMPTIONS'];
    else process.env['COMPILE_ASSUMPTIONS'] = prevFlag;
  }

  if (compiled.applied.length === 0 || compiled.emission.policy === null) {
    reasons.push('compile: finding produced no enforceable control (sink not resolvable)');
    return { verdict: 'fail', reasons };
  }
  const policy = compiled.emission.policy;

  // --- V3: tightness on every compiled request/response param --------------
  const sections: Array<Record<string, ParamSchema> | undefined> = [
    policy.request?.schema as Record<string, ParamSchema> | undefined,
    policy.response?.schema as Record<string, ParamSchema> | undefined,
  ];
  for (const schema of sections) {
    if (!schema) continue;
    for (const [name, ps] of Object.entries(schema)) {
      const why = checkTightness(ps);
      if (why) reasons.push(`V3: ${name}: ${why}`);
    }
  }
  if (reasons.some((r) => r.startsWith('V3:'))) {
    return buildFail(reasons, snappedCite);
  }

  // --- V1: schema validity -------------------------------------------------
  const v1 = validateXSecurity(policy);
  if (!v1.valid) {
    for (const e of v1.errors) {
      reasons.push(`V1: ${e.instancePath || '/'} ${e.message ?? 'invalid'}`);
    }
    return buildFail(reasons, snappedCite);
  }

  return buildPass(reasons, snappedCite);
}

function buildPass(reasons: string[], snappedCite?: Citation): VerifyResult {
  const out: VerifyResult = { verdict: 'pass', reasons };
  if (snappedCite !== undefined) out.snappedCite = snappedCite;
  return out;
}

function buildFail(reasons: string[], snappedCite?: Citation): VerifyResult {
  const out: VerifyResult = { verdict: 'fail', reasons };
  if (snappedCite !== undefined) out.snappedCite = snappedCite;
  return out;
}
