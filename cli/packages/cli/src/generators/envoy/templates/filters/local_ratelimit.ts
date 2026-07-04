/**
 * envoy.filters.http.local_ratelimit — per-route token bucket.
 *
 * Each route owns its own bucket via typed_per_filter_config (see routes.ts);
 * the chain-level filter emitted here is the default-allow shell.
 *
 * Wave-15 W15-B: when the spec does not specify `burst`, we synthesize a
 * burst capacity so the bucket has headroom for auth-evaluating filters
 * (jwt_authn / rbac / ext_authz) to actually reach and reject the bulk of
 * an attack stream before local_ratelimit short-circuits it with 429.
 *
 * Without burst headroom a tight bucket (e.g. `requests: 10, window: 1m`)
 * gets drained inside the first ~10 requests of a credential-stuffing run,
 * and every subsequent attack request is masked as a 429 RateLimit hit
 * instead of an AuthN/AuthZ rejection. The scorer's intent-attribution
 * downgrade then weighs the whole burst as ×0.3 (rate-limit) instead of
 * ×1.0 (auth-blocked).
 *
 * The multiplier is intentionally chosen so:
 *   - small requests/window values (e.g. 5/min on /login) still allow a
 *     visible auth-rejection band before throttling kicks in;
 *   - large requests/window values (e.g. 60/min on /user/{id}) gain
 *     proportional headroom for BOLA enumeration traffic to reach
 *     ext_authz / OPA;
 *   - steady-state rate is unchanged (tokens_per_fill = primary.requests).
 *
 * Explicit `burst` in the spec always wins; the synthesized value is only
 * applied when `burst` is unset.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { parseDurationSec } from '../../../coraza/rules.js';
import { safeStatId } from '../yaml-util.js';

export interface RouteRateLimit {
  endpoint: EndpointIR;
  maxTokens: number;
  tokensPerFill: number;
  fillIntervalSec: number;
  statPrefix: string;
}

const DEFAULT_BURST_MULTIPLIER = 3;
const DEFAULT_BURST_MINIMUM_HEADROOM = 20;

function defaultBurst(requests: number): number {
  return Math.max(requests * DEFAULT_BURST_MULTIPLIER, requests + DEFAULT_BURST_MINIMUM_HEADROOM);
}

export function collectRateLimits(spec: SpecIR): RouteRateLimit[] {
  const out: RouteRateLimit[] = [];
  for (const ep of spec.endpoints) {
    const rl = ep.policy.rateLimit;
    const primary = Array.isArray(rl) ? rl[0] : rl;
    if (!primary) continue;
    const sec = parseDurationSec(primary.window) || 60;
    const burst = (primary as { burst?: number }).burst;
    const maxTokens =
      burst && burst > primary.requests ? burst : defaultBurst(primary.requests);
    out.push({
      endpoint: ep,
      maxTokens,
      tokensPerFill: primary.requests,
      fillIntervalSec: sec,
      statPrefix: `writ_${safeStatId(ep)}_ratelimit`
    });
  }
  return out;
}

export function emitLocalRateLimitChain(lines: string[]): void {
  // Chain-level shell filter; per-route token buckets live in
  // typed_per_filter_config overrides on the route entries.
  lines.push('  - name: envoy.filters.http.local_ratelimit');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit');
  lines.push('      stat_prefix: writ_chain_ratelimit');
  // W16-A: Envoy treats a missing token_bucket on an *enforced* chain filter
  // as a 0-token bucket → every request 429s before per-route configs run.
  // We keep filter_enabled at 100% so the filter still tracks stats, but
  // pin filter_enforced numerator to 0 so chain-level enforcement is a no-op.
  // Per-route typed_per_filter_config carries the real token buckets.
  lines.push('      filter_enabled:');
  lines.push('        runtime_key: writ.local_ratelimit_enabled');
  lines.push('        default_value: { numerator: 100, denominator: HUNDRED }');
  lines.push('      filter_enforced:');
  lines.push('        runtime_key: writ.local_ratelimit_enforced');
  lines.push('        default_value: { numerator: 0, denominator: HUNDRED }');
}
