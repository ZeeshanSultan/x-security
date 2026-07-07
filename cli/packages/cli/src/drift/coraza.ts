/**
 * Coraza WAF drift detector (file-mode only).
 *
 * Strategy:
 *  1. Load the deployed Coraza YAML — it has a top-level `directives:` string
 *     (multi-line ModSecurity directives).
 *  2. Re-generate the expected directives block from the SpecIR by invoking
 *     the existing coraza generator.
 *  3. For each endpoint, locate its rule block in the actual config by the
 *     deterministic rule-ID slot scheme defined in `generators/coraza/rules.ts`
 *     (BASE_ID=100000 + (endpointHash % 9000) * 10, with SLOT offsets per
 *     category). This makes block identification robust to whitespace and
 *     comment drift.
 *  4. Diff the two directive blocks line-by-line per endpoint, classifying
 *     each delta by x-security's standard severity rules.
 */
import { readFile } from 'node:fs/promises';
import yaml from 'js-yaml';
import type { SpecIR, EndpointIR } from '@x-security/core';
import type { DriftIssue, DriftReport, DriftSeverity } from '../reporters/types.js';
import { corazaGenerator } from '../generators/coraza/index.js';
import { ruleBase, SLOT, parseByteSize } from '../generators/coraza/rules.js';
import { endpointLabel } from './kong-shared.js';

export interface CorazaDriftOptions {
  filePath: string;
  /** Raw YAML override (for tests). */
  yamlContent?: string;
}

interface CorazaDoc {
  directives?: string;
  [k: string]: unknown;
}

const RULE_ID_RE = /\bid:(\d+)\b/;

/** Group raw directive lines into "rule blocks": one block = run of consecutive
 * non-blank lines sharing the same rule id (or, for `# comment` lines,
 * attaching to the following rule). */
interface RuleBlock {
  ruleId: number | null;
  lines: string[]; // full block including leading comments
}

function tokenizeDirectives(text: string): RuleBlock[] {
  const lines = text.split(/\r?\n/);
  const blocks: RuleBlock[] = [];
  let buf: string[] = [];

  const flush = () => {
    if (buf.length === 0) return;
    let id: number | null = null;
    for (const l of buf) {
      const m = RULE_ID_RE.exec(l);
      if (m && m[1]) {
        id = Number(m[1]);
        break;
      }
    }
    blocks.push({ ruleId: id, lines: buf });
    buf = [];
  };

  for (const l of lines) {
    if (l.trim() === '') {
      flush();
      continue;
    }
    buf.push(l);
  }
  flush();
  return blocks;
}

/** Build a map of ruleId → block for fast lookup. */
function indexById(blocks: RuleBlock[]): Map<number, RuleBlock> {
  const out = new Map<number, RuleBlock>();
  for (const b of blocks) {
    if (b.ruleId !== null) out.set(b.ruleId, b);
  }
  return out;
}

/**
 * Categorize a rule slot to a policy field for severity classification.
 *
 * Rate-limit emission consumes a multi-rule block (initcol / counter / check
 * — plus optional burst), so any slot in the range `[SLOT.rate, SLOT.schema)`
 * belongs to `rateLimit`.
 */
function fieldForSlot(slot: number): { field: string; severity: DriftSeverity } {
  if (slot >= SLOT.rate && slot < SLOT.schema) {
    return { field: 'rateLimit', severity: 'CRITICAL' };
  }
  switch (slot) {
    case SLOT.scope:    return { field: 'scope',            severity: 'LOW' };
    case SLOT.ctype:    return { field: 'request.contentType', severity: 'MEDIUM' };
    case SLOT.bodySize: return { field: 'request.maxBodySize', severity: 'HIGH' };
    case SLOT.auth:     return { field: 'authentication',   severity: 'CRITICAL' };
    case SLOT.ipAllow:  return { field: 'ipPolicy.allow',   severity: 'HIGH' };
    case SLOT.ipDeny:   return { field: 'ipPolicy.deny',    severity: 'HIGH' };
    default:            return { field: 'request.schema',   severity: 'MEDIUM' };
  }
}


/**
 * Extract the numeric rate-limit threshold from the `@gt N` check rule.
 *
 * Matches legacy (`IP:RATE_<op>`), wave-5 (`IP:rl_<op>` / `USER:rl_<op>` /
 * `TX:rl_<op>`), and W10-7 (`IP:x_security_rl_<op>`) emissions. Burst counters
 * use a `_burst` suffix and are intentionally ignored here — drift detection
 * compares against the primary window threshold (`rl.requests`), not the burst cap.
 */
function extractRateLimitThreshold(block: RuleBlock): number | null {
  for (const l of block.lines) {
    // W10-7: identifier=ip on coraza-go/spoa now uses the IP persistent
    // collection with a `x_security_rl_` variable prefix.
    const m =
      /SecRule\s+(?:IP|USER|GLOBAL|TX):(?:RATE_|x_security_rl_|rl_)([A-Za-z0-9_]+?)(?:_burst)?\s+"@gt\s+(\d+)"/.exec(l);
    if (m && m[2] && !l.includes('_burst')) return Number(m[2]);
  }
  return null;
}

/** Extract body-size threshold (`Content-Length "@gt N"`). */
function extractBodySize(block: RuleBlock): number | null {
  for (const l of block.lines) {
    const m = /Content-Length\s+"@gt\s+(\d+)"/.exec(l);
    if (m && m[1]) return Number(m[1]);
  }
  return null;
}

function endpointFromActual(blocks: RuleBlock[], ep: EndpointIR): Map<number, RuleBlock> {
  const base = ruleBase(ep);
  // Endpoint owns 30 contiguous IDs (see SLOT_STRIDE in generators/coraza/rules.ts).
  const stride = 30;
  const map = new Map<number, RuleBlock>();
  for (const b of blocks) {
    if (b.ruleId === null) continue;
    if (b.ruleId >= base && b.ruleId < base + stride) {
      const slot = b.ruleId - base;
      map.set(slot, b);
    }
  }
  return map;
}

function diffEndpoint(
  ep: EndpointIR,
  expectedBlocks: Map<number, RuleBlock>,
  actualBlocks: Map<number, RuleBlock>
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  const label = endpointLabel(ep);

  for (const [slot, expBlock] of expectedBlocks.entries()) {
    const actBlock = actualBlocks.get(slot);
    const { field, severity } = fieldForSlot(slot);

    if (!actBlock) {
      // Missing rule slot.
      // Auth missing for an endpoint that requires it → already CRITICAL.
      issues.push({
        endpoint: label,
        field,
        severity,
        expected: 'present',
        actual: 'missing',
        message: `Coraza rule slot ${slot} (${field}) missing on deployed config`
      });
      continue;
    }

    // Specialized comparisons:
    // The rate-limit emission spans multiple SecRules (initcol / counter /
    // check + optional burst) that the tokenizer groups under the first
    // rule ID it sees (the `initcol` at offset 0). The numeric `@gt N`
    // threshold lives on the check rule inside that same block — so we look
    // for it on the `SLOT.rate` block. Trailing rate slots that the
    // tokenizer happens to emit as separate blocks (when blank lines split
    // them) are presence-only.
    if (slot > SLOT.rate && slot < SLOT.schema) {
      continue;
    }
    if (slot === SLOT.rate) {
      const expN = extractRateLimitThreshold(expBlock);
      const actN = extractRateLimitThreshold(actBlock);
      if (expN !== null && actN !== null && expN !== actN) {
        const weakened = actN > expN;
        issues.push({
          endpoint: label,
          field: 'rateLimit.requests',
          severity: weakened ? 'CRITICAL' : 'MEDIUM',
          expected: expN,
          actual: actN,
          message: weakened
            ? `rateLimit weakened: spec=${expN} actual=${actN}`
            : `rateLimit tighter than spec: spec=${expN} actual=${actN}`
        });
      }
      continue;
    }

    if (slot === SLOT.bodySize) {
      const expN = extractBodySize(expBlock);
      const actN = extractBodySize(actBlock);
      if (expN !== null && actN !== null && expN !== actN) {
        const wider = actN > expN;
        issues.push({
          endpoint: label,
          field: 'request.maxBodySize',
          severity: wider ? 'HIGH' : 'MEDIUM',
          expected: expN,
          actual: actN,
          message: wider
            ? `maxBodySize widened: spec=${expN} actual=${actN}`
            : `maxBodySize tightened: spec=${expN} actual=${actN}`
        });
      }
      continue;
    }

    // Default: byte-equal compare of the rule body (strip trailing whitespace).
    const expBody = expBlock.lines.map((l) => l.trimEnd()).join('\n').trim();
    const actBody = actBlock.lines.map((l) => l.trimEnd()).join('\n').trim();
    if (expBody !== actBody) {
      issues.push({
        endpoint: label,
        field,
        severity,
        expected: expBody,
        actual: actBody,
        message: `${field}: directive body drift in rule slot ${slot}`
      });
    }
  }

  // Detect unknown x-security-tagged rules that aren't in our expected set —
  // LOW severity.
  for (const [slot, actBlock] of actualBlocks.entries()) {
    if (expectedBlocks.has(slot)) continue;
    issues.push({
      endpoint: label,
      field: 'unknown-rule',
      severity: 'LOW',
      expected: 'absent',
      actual: actBlock.ruleId,
      message: `Unknown x-security rule slot ${slot} (id=${actBlock.ruleId}) on deployed config`
    });
  }

  return issues;
}

/** Compare global directive — currently just the global body limit. */
function diffGlobals(spec: SpecIR, expected: string, actual: string): DriftIssue[] {
  const issues: DriftIssue[] = [];
  const expBodyCap = /SecRequestBodyLimit\s+(\d+)/.exec(expected)?.[1];
  const actBodyCap = /SecRequestBodyLimit\s+(\d+)/.exec(actual)?.[1];
  if (expBodyCap && actBodyCap && expBodyCap !== actBodyCap) {
    const e = Number(expBodyCap);
    const a = Number(actBodyCap);
    const wider = a > e;
    issues.push({
      endpoint: '*',
      field: 'global.SecRequestBodyLimit',
      severity: wider ? 'HIGH' : 'MEDIUM',
      expected: e,
      actual: a,
      message: wider
        ? `Global SecRequestBodyLimit widened: spec=${e} actual=${a}`
        : `Global SecRequestBodyLimit tightened: spec=${e} actual=${a}`
    });
  }
  // Touch parseByteSize so unused-import lints stay clean while keeping it
  // available for future per-endpoint comparisons.
  void parseByteSize;
  void spec;
  return issues;
}

export async function detectCorazaDrift(
  spec: SpecIR,
  opts: CorazaDriftOptions
): Promise<DriftReport> {
  const raw = opts.yamlContent ?? (await readFile(opts.filePath, 'utf8'));
  const doc = (yaml.load(raw) as CorazaDoc | undefined) ?? {};
  const actualDirectives = typeof doc.directives === 'string' ? doc.directives : '';

  const expectedArtifacts = await Promise.resolve(corazaGenerator.generate(spec));
  const expectedYaml = expectedArtifacts[0]?.content ?? '';
  const expectedDoc = (yaml.load(expectedYaml) as CorazaDoc | undefined) ?? {};
  const expectedDirectives = typeof expectedDoc.directives === 'string' ? expectedDoc.directives : '';

  const expectedBlocks = tokenizeDirectives(expectedDirectives);
  const actualBlocks = tokenizeDirectives(actualDirectives);

  const issues: DriftIssue[] = [];
  issues.push(...diffGlobals(spec, expectedDirectives, actualDirectives));

  const actualByEndpoint = (() => {
    // Pre-bucket all actual blocks by their endpoint slot base.
    return actualBlocks;
  })();
  void indexById; // reserved for future per-id direct compare

  for (const ep of spec.endpoints) {
    const exp = endpointFromActual(expectedBlocks, ep);
    const act = endpointFromActual(actualByEndpoint, ep);
    if (exp.size === 0) continue; // generator emitted no slots for this endpoint
    if (act.size === 0) {
      // Whole endpoint missing — severity follows the most critical expected slot.
      let topSev: DriftSeverity = 'LOW';
      const order: DriftSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      for (const slot of exp.keys()) {
        const sev = fieldForSlot(slot).severity;
        if (order.indexOf(sev) < order.indexOf(topSev)) topSev = sev;
      }
      issues.push({
        endpoint: endpointLabel(ep),
        field: 'endpoint',
        severity: topSev,
        expected: 'present',
        actual: 'missing',
        message: `Endpoint not configured in Coraza directives (no rules in slot range ${ruleBase(ep)}..${ruleBase(ep) + 29})`
      });
      continue;
    }
    issues.push(...diffEndpoint(ep, exp, act));
  }

  return {
    kind: 'drift',
    target: 'coraza',
    gatewaySource: opts.filePath,
    issues
  };
}
