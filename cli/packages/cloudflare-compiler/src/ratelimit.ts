// Rate-limit lowering. Cloudflare's allowed periods are a fixed set and the
// identifier → characteristics mapping is non-trivial; keep this logic in its
// own file so the main compile.ts stays under the 500-line policy.

import type { RateLimit } from '@x-security/schema';
import { and, hasHeader, missingHeader } from './expressions.js';
import { parseDurationSeconds } from './expressions.js';
import type { CompiledRule, Confidence, RuleAction } from './types.js';
import { isObserveMode } from './v3-shared.js';

const CF_PERIODS = [10, 60, 120, 300, 600, 3600];

export interface RateLimitContext {
  eid: string;
  warn(field: string, message: string, severity: 'info' | 'warn'): void;
  emit(rule: { kind: string; description: string; expression: string; action: RuleAction; ratelimit: NonNullable<CompiledRule['ratelimit']>; sourceField: string; confidence: Confidence; }): void;
}

export function compileRateLimit(
  ctx: RateLimitContext,
  rl: RateLimit | RateLimit[] | undefined,
  baseMatch: string
): void {
  if (!rl) return;
  const list = Array.isArray(rl) ? rl : [rl];
  list.forEach((r, idx) => emitRateLimit(ctx, r, baseMatch, idx));
}

/**
 * Bridge into the V3 builder: emit any rate-limit rules from policy and,
 * in observe mode, attach a partial-support note (counters still run).
 * Kept in this file so compile.ts stays under 500 lines.
 */
export function compileEndpointRateLimit(
  b: import('./v3-shared.js').V3Builder,
  buildRule: (args: { kind: string; description: string; expression: string; action: RuleAction; actionParameters?: Record<string, unknown>; ratelimit?: CompiledRule['ratelimit']; sourceField: string; confidence: Confidence }) => CompiledRule,
  baseMatch: string
): void {
  const rl = b.endpoint.policy?.rateLimit;
  compileRateLimit(
    {
      eid: b.eid,
      warn: (field, message, severity) =>
        b.warnings.push({ endpoint_id: b.eid, field, message, severity }),
      emit: (args) => b.rateLimit.push(buildRule(args))
    },
    rl,
    baseMatch
  );
  if (rl && isObserveMode(b.mode)) {
    b.observeModeNotes.push({
      endpoint_id: b.eid,
      field: 'rateLimit',
      support: 'partial',
      message:
        'observe-mode: trigger action demoted to `log`; counters and mitigation_timeout still run. ' +
        'Plans without a native `mode: "simulate"` knob see counter state accumulate (no client impact).'
    });
  }
}

function emitRateLimit(ctx: RateLimitContext, r: RateLimit, baseMatch: string, idx: number): void {
  let period: number;
  try {
    period = parseDurationSeconds(r.window);
  } catch {
    ctx.warn('rateLimit.window', `Invalid window: ${r.window}`, 'warn');
    return;
  }
  const cfPeriod = CF_PERIODS.includes(period) ? period : nearest(CF_PERIODS, period);
  if (cfPeriod !== period) {
    ctx.warn(
      'rateLimit.window',
      `Window ${r.window} rounded to ${cfPeriod}s (CF only allows ${CF_PERIODS.join('/')}).`,
      'info'
    );
  }
  // v0.4 / v0.5: identifier widened to string | string[] | {components, combinator}.
  // CF rate-limit characteristics is itself a list, so we can map each component
  // independently and union them.
  let idValues: (string | undefined)[];
  let descId: string;
  if (typeof r.identifier === 'string') {
    idValues = [r.identifier];
    descId = r.identifier;
  } else if (Array.isArray(r.identifier)) {
    idValues = r.identifier;
    descId = r.identifier.join('+');
  } else if (r.identifier && typeof r.identifier === 'object' && 'components' in r.identifier) {
    idValues = (r.identifier as { components: string[] }).components;
    descId = idValues.join('+');
  } else {
    idValues = [undefined];
    descId = 'ip';
  }
  const characteristics = Array.from(
    new Set(idValues.flatMap((id) => identifierToCharacteristics(id)))
  );
  let expr = baseMatch;
  if (r.when === 'authenticated') expr = and(expr, hasHeader('authorization'));
  if (r.when === 'unauthenticated') expr = and(expr, missingHeader('authorization'));
  ctx.emit({
    kind: `ratelimit-${idx}`,
    description: `Rate limit ${r.requests} req / ${r.window} per ${descId}`,
    expression: expr,
    action: 'block',
    ratelimit: {
      characteristics,
      period: cfPeriod,
      requests_per_period: r.requests,
      mitigation_timeout: cfPeriod,
      requests_to_origin: true
    },
    sourceField: `rateLimit[${idx}]`,
    confidence: 'HIGH'
  });
}

function nearest(allowed: number[], target: number): number {
  return allowed.reduce((best, cur) => Math.abs(cur - target) < Math.abs(best - target) ? cur : best);
}

function identifierToCharacteristics(identifier: string | undefined): string[] {
  switch (identifier) {
    case undefined:
    case 'ip':
      return ['ip.src'];
    case 'fingerprint':
      return ['cf.unique_visitor_id'];
    case 'api-key':
      return ['http.request.headers["x-api-key"]'];
    case 'user-id':
      // No native JWT claim accessor in CF expressions — fall back to auth header.
      return ['http.request.headers["authorization"]'];
    default:
      if (identifier.startsWith('header:')) {
        const name = identifier.slice('header:'.length).toLowerCase();
        return [`http.request.headers["${name}"]`];
      }
      return ['ip.src'];
  }
}
