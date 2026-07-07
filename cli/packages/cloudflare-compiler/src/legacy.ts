// Legacy v0.2 lowering paths kept for backward compatibility. v0.3 adds
// richer per-field declarative knobs (response.headers, botProtection
// typed object) — when those are present, the v0.3 compilers take over and
// the legacy emit is suppressed (see compileEndpoint in compile.ts).

import type { XSecurityPolicy } from '@x-security/schema';
import { and } from './expressions.js';
import { decorate, isObserveMode, noteObserveMode, type V3Builder } from './v3-shared.js';

/**
 * Default response-header injection (HSTS / nosniff / X-Frame-Options /
 * Referrer-Policy + strip Server/X-Powered-By). Used only when the policy
 * does NOT declare `response.headers` — v0.3 design doc states "absence
 * means do not emit" for `response.headers`, but we keep these defaults
 * for v0.2-shape policies to avoid a backward-compat regression.
 */
export function compileLegacyResponseHeaders(b: V3Builder, _policy: XSecurityPolicy, baseMatch: string): void {
  b.respTransform.push(decorate(b, {
    kind: 'security-headers',
    description: 'Inject HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy',
    expression: baseMatch,
    action: 'rewrite',
    action_parameters: {
      headers: {
        'Strict-Transport-Security': { operation: 'set', value: 'max-age=31536000; includeSubDomains' },
        'X-Content-Type-Options': { operation: 'set', value: 'nosniff' },
        'X-Frame-Options': { operation: 'set', value: 'DENY' },
        'Referrer-Policy': { operation: 'set', value: 'strict-origin-when-cross-origin' }
      }
    },
    sourceField: 'response.securityHeaders',
    confidence: 'HIGH'
  }));
  b.respTransform.push(decorate(b, {
    kind: 'strip-server-headers',
    description: 'Strip Server / X-Powered-By response headers',
    expression: baseMatch,
    action: 'rewrite',
    action_parameters: {
      headers: {
        'Server': { operation: 'remove' },
        'X-Powered-By': { operation: 'remove' }
      }
    },
    sourceField: 'response.stripHeaders',
    confidence: 'MEDIUM'
  }));
  if (isObserveMode(b.mode)) {
    noteObserveMode(
      b,
      'response.securityHeaders',
      'always-applied',
      'Default security headers (HSTS / nosniff / X-Frame-Options / Referrer-Policy) and ' +
      'Server/X-Powered-By strip are Transform Rules — always applied; observe-mode does not suppress them.'
    );
  }
}

/**
 * Legacy v0.2 `botProtection: true` toggle. v0.3's typed `BotProtection`
 * object is handled in v3-protocol.ts; this path runs only when the policy
 * uses the legacy boolean shape.
 */
export function compileLegacyBotProtection(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const raw = policy as Record<string, unknown>;
  if (raw.botProtection !== true) return;
  if (b.planTier !== 'business' && b.planTier !== 'enterprise') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'botProtection',
      message: `Bot Fight Mode requires Cloudflare Business or Enterprise plan; skipped on '${b.planTier}' tier.`,
      severity: 'warn'
    });
    return;
  }
  b.custom.push(decorate(b, {
    kind: 'bot-protection',
    description: 'Enable Bot Fight Mode (managed_challenge for likely bots)',
    expression: and(baseMatch, 'cf.client.bot'),
    action: 'managed_challenge',
    sourceField: 'botProtection',
    confidence: 'MEDIUM'
  }));
}
