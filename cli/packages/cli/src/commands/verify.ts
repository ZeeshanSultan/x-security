// `lazy verify --target <kong|coraza> --gateway <addr> [--engine <e>] [--format <f>] <spec>`
//
// Thin wrapper around src/verify/index.ts. The bin layer parses args,
// this layer validates them and dispatches.

import { runVerify, type VerifyTarget, type VerifyEngine, type VerifyFormat, type VerifyRunResult } from '../verify/index.js';

export interface VerifyCliOptions {
  target: string;
  gateway: string;
  engine?: string;
  format?: string;
  threshold?: number;
}

export interface VerifyCliResult {
  rendered: string;
  exitCode: 0 | 2 | 3;
  passed: boolean;
}

const VALID_TARGETS: VerifyTarget[] = ['kong', 'coraza', 'envoy', 'bunkerweb', 'openappsec'];
const VALID_ENGINES: VerifyEngine[] = ['modsec-nginx', 'coraza-go', 'coraza-spoa'];
const VALID_FORMATS: VerifyFormat[] = ['table', 'json', 'sarif'];

export async function runVerifyCli(specPath: string, opts: VerifyCliOptions): Promise<VerifyCliResult> {
  if (!VALID_TARGETS.includes(opts.target as VerifyTarget)) {
    throw new Error(`verify: --target must be one of ${VALID_TARGETS.join('|')} (got "${opts.target}")`);
  }
  const target = opts.target as VerifyTarget;

  let engine: VerifyEngine | undefined;
  if (target === 'coraza') {
    engine = (opts.engine as VerifyEngine | undefined) ?? 'modsec-nginx';
    if (!VALID_ENGINES.includes(engine)) {
      throw new Error(`verify: --engine must be one of ${VALID_ENGINES.join('|')} (got "${engine}")`);
    }
  } else if (opts.engine) {
    throw new Error(`verify: --engine is only valid for --target coraza`);
  }

  // Envoy doesn't take an --engine (admin API is universal across deployments).
  // The gateway URL points at the Envoy admin port (default 9901).

  const format = (opts.format as VerifyFormat | undefined) ?? 'table';
  if (!VALID_FORMATS.includes(format)) {
    throw new Error(`verify: --format must be one of ${VALID_FORMATS.join('|')} (got "${format}")`);
  }

  if (!opts.gateway) {
    throw new Error('verify: --gateway is required');
  }

  const runOpts: Parameters<typeof runVerify>[1] = {
    target,
    gateway: opts.gateway,
    format
  };
  if (engine) runOpts.engine = engine;
  if (opts.threshold !== undefined) runOpts.thresholdPct = opts.threshold;

  const r: VerifyRunResult = await runVerify(specPath, runOpts);
  return { rendered: r.rendered, exitCode: r.exitCode, passed: r.report.passed };
}
