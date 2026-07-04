/**
 * envoy.filters.http.cache — per-route cacheability hint.
 *
 * Chain-level shell uses the SimpleHttpCache (in-memory) typed_config so the
 * filter is enabled globally; per-route typed_per_filter_config sets
 * `disabled: true` for endpoints that opt out (cacheable === false) and
 * leaves the cache active for endpoints that opt in (cacheable === true or
 * { enabled: true }). Wave-22 W22-A.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import type { Cacheable } from '@writ/schema';

export interface RouteCache {
  endpoint: EndpointIR;
  enabled: boolean;
}

function isEnabled(c: Cacheable | undefined): boolean | null {
  if (c === undefined) return null;
  if (typeof c === 'boolean') return c;
  return !!c.enabled;
}

export function collectCache(spec: SpecIR): RouteCache[] {
  const out: RouteCache[] = [];
  for (const ep of spec.endpoints) {
    const e = isEnabled(ep.policy.cacheable);
    if (e === null) continue;
    out.push({ endpoint: ep, enabled: e });
  }
  return out;
}

export function emitCacheFilterChain(lines: string[]): void {
  lines.push('  - name: envoy.filters.http.cache');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig');
  lines.push('      typed_config:');
  lines.push('        "@type": type.googleapis.com/envoy.extensions.http.cache.simple_http_cache.v3.SimpleHttpCacheConfig');
}

export function emitRouteCache(lines: string[], rc: RouteCache): void {
  lines.push('          envoy.filters.http.cache:');
  if (rc.enabled) {
    lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig');
    lines.push('            typed_config:');
    lines.push('              "@type": type.googleapis.com/envoy.extensions.http.cache.simple_http_cache.v3.SimpleHttpCacheConfig');
  } else {
    lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig');
    lines.push('            disabled: true');
  }
}
