// v0.3 response-side lowering: response.headers (all sub-fields),
// response.cookies.defaults, cacheable.unkeyedHeadersStrip.

import type { CookieDefaults, Hsts, ResponseHeaders, XSecurityPolicy } from '@x-security/schema';
import type { RewriteParameters } from './types.js';
import { decorate, getOverride, isObserveMode, noteObserveMode, noteProvenance, type V3Builder } from './v3-shared.js';

export function compileV3Response(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  compileResponseHeadersV3(b, policy, baseMatch);
  compileResponseCookies(b, policy, baseMatch);
  compileUnkeyedHeadersStrip(b, policy, baseMatch);
}

function compileResponseHeadersV3(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const rh = policy.response?.headers;
  if (!rh) return;
  // Per the v0.3 design doc: "absence means do not emit." We only set the
  // sub-fields the policy declares; the legacy injection (HSTS / nosniff /
  // frameOptions defaults) is suppressed when policy.response.headers exists.
  const headers: NonNullable<RewriteParameters['headers']> = {};
  if (rh.csp) headers['Content-Security-Policy'] = { operation: 'set', value: rh.csp };
  if (rh.hsts) headers['Strict-Transport-Security'] = { operation: 'set', value: serializeHsts(rh.hsts) };
  if (rh.frameOptions) headers['X-Frame-Options'] = { operation: 'set', value: rh.frameOptions };
  if (rh.contentTypeOptions) headers['X-Content-Type-Options'] = { operation: 'set', value: rh.contentTypeOptions };
  if (rh.referrerPolicy) headers['Referrer-Policy'] = { operation: 'set', value: rh.referrerPolicy };
  if (rh.permissionsPolicy) headers['Permissions-Policy'] = { operation: 'set', value: rh.permissionsPolicy };
  if (rh.coop) headers['Cross-Origin-Opener-Policy'] = { operation: 'set', value: rh.coop };
  if (rh.coep) headers['Cross-Origin-Embedder-Policy'] = { operation: 'set', value: rh.coep };
  if (rh.corp) headers['Cross-Origin-Resource-Policy'] = { operation: 'set', value: rh.corp };
  if (rh.cacheControl) headers['Cache-Control'] = { operation: 'set', value: rh.cacheControl };
  if (Object.keys(headers).length === 0) return;
  b.respTransform.push(decorate(b, {
    kind: 'response-headers-v3',
    description: `Set ${Object.keys(headers).length} response hardening headers`,
    expression: baseMatch,
    action: 'rewrite',
    action_parameters: { headers } as RewriteParameters,
    sourceField: 'response.headers',
    confidence: 'HIGH'
  }));
  if (isObserveMode(b.mode)) {
    noteObserveMode(
      b,
      'response.headers',
      'always-applied',
      'Cloudflare Response Header Modification Transform Rules have no action to demote; ' +
      `the ${Object.keys(headers).length} configured response headers are injected even in observe-mode.`
    );
  }
}

function serializeHsts(h: Hsts): string {
  const parts = [`max-age=${h.maxAge}`];
  if (h.includeSubDomains) parts.push('includeSubDomains');
  if (h.preload) parts.push('preload');
  return parts.join('; ');
}

function compileResponseCookies(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const defaults = policy.response?.cookies?.defaults;
  if (!defaults) return;
  // Cloudflare Transform Rules can rewrite Set-Cookie via "set" or "add". For
  // attribute defaults we can either (a) replace the entire Set-Cookie value
  // (loses origin attributes) or (b) emit an "add" Set-Cookie with a
  // canonical attribute suffix. We take approach (b) — closer to "fill
  // missing attributes" semantics — and emit a provenance note that
  // documents the limitation.
  const suffix = serializeCookieDefaults(defaults);
  if (!suffix) return;
  const headers: NonNullable<RewriteParameters['headers']> = {
    'Set-Cookie': { operation: 'add', value: suffix }
  };
  b.respTransform.push(decorate(b, {
    kind: 'response-cookie-defaults',
    description: `Append default cookie attributes: ${suffix}`,
    expression: baseMatch,
    action: 'rewrite',
    action_parameters: { headers } as RewriteParameters,
    sourceField: 'response.cookies.defaults',
    confidence: 'MEDIUM'
  }));
  if (isObserveMode(b.mode)) {
    noteObserveMode(
      b,
      'response.cookies.defaults',
      'always-applied',
      'Set-Cookie attribute defaults are a Transform Rule rewrite — always applied; ' +
      'observe-mode does not suppress them.'
    );
  }
  if (defaults.path || defaults.domain) {
    noteProvenance(
      b,
      'response.cookies.defaults',
      'path/domain cookie defaults are best-effort: CF Transform Rules cannot inspect existing cookie attributes, so origin-set values are not overwritten. Native fill-missing semantics require a Worker.',
      'partial',
      getOverride(b, 'response.cookies.defaults')
    );
  }
}

function serializeCookieDefaults(d: CookieDefaults): string {
  const parts: string[] = [];
  if (d.httpOnly) parts.push('HttpOnly');
  if (d.secure) parts.push('Secure');
  if (d.sameSite) parts.push(`SameSite=${d.sameSite}`);
  if (d.path) parts.push(`Path=${d.path}`);
  if (d.domain) parts.push(`Domain=${d.domain}`);
  if (typeof d.maxAge === 'number') parts.push(`Max-Age=${d.maxAge}`);
  return parts.join('; ');
}

function compileUnkeyedHeadersStrip(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const cacheable = policy.cacheable;
  if (!cacheable || typeof cacheable === 'boolean') return;
  const strip = cacheable.unkeyedHeadersStrip;
  if (!strip || strip.length === 0) return;
  // Cloudflare Cache Rules custom cache key supports header inclusion/exclusion
  // via the dashboard's "custom_key.header" config. We surface the directive as
  // a provenance note containing the override payload so the deployer can
  // wire it into the Cache Rules ruleset (which lives in a different phase
  // — `http_request_cache_settings` — beyond this compiler's current scope).
  noteProvenance(
    b,
    'cacheable.unkeyedHeadersStrip',
    `Cache Rule directive: exclude headers [${strip.join(', ')}] from cache key. Apply via http_request_cache_settings phase.`,
    'partial',
    {
      cache_key: {
        custom_key: {
          header: {
            exclude_origin: false,
            include: [],
            check_presence: [],
            exclude: strip.map(h => h.toLowerCase())
          }
        }
      }
    }
  );
  // Strip the headers before they hit origin too — defense-in-depth.
  const headers: NonNullable<RewriteParameters['headers']> = {};
  for (const h of strip) headers[h] = { operation: 'remove' };
  b.reqTransform.push(decorate(b, {
    kind: 'cache-unkey-strip',
    description: `Strip [${strip.join(', ')}] from request before cache lookup to prevent cache poisoning`,
    expression: baseMatch,
    action: 'rewrite',
    action_parameters: { headers } as RewriteParameters,
    sourceField: 'cacheable.unkeyedHeadersStrip',
    confidence: 'MEDIUM'
  }));
  if (isObserveMode(b.mode)) {
    noteObserveMode(
      b,
      'cacheable.unkeyedHeadersStrip',
      'always-applied',
      'Cache-key strip + Transform Rule are always applied; observe-mode does not suppress them.'
    );
  }
}
