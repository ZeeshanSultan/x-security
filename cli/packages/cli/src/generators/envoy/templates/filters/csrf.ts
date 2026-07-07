/**
 * envoy.filters.http.csrf — native CSRF protection.
 *
 * Chain-level filter is the disabled-by-default shell. Per-route
 * typed_per_filter_config enables enforcement for endpoints that declare
 * x-security.csrf with method === 'origin-check' (the only mode the native
 * filter supports — double-submit / custom-header CSRF still requires Lua).
 *
 * Wave-22 W22-A.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';
import type { Csrf } from '@x-security/schema';
import { yamlString } from '../yaml-util.js';

export interface RouteCsrf {
  endpoint: EndpointIR;
  allowedOrigins: string[];
}

export function collectCsrf(spec: SpecIR): RouteCsrf[] {
  const out: RouteCsrf[] = [];
  for (const ep of spec.endpoints) {
    const c = ep.policy.csrf as Csrf | undefined;
    if (!c) continue;
    if (c.method !== 'origin-check') continue;
    const origins = c.allowedOrigins ?? [];
    out.push({ endpoint: ep, allowedOrigins: origins });
  }
  return out;
}

/** Chain-level shell — filter loaded, default-disabled (per-route turns it on). */
export function emitCsrfFilterChain(lines: string[]): void {
  lines.push('  - name: envoy.filters.http.csrf');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy');
  lines.push('      filter_enabled:');
  lines.push('        default_value: { numerator: 0, denominator: HUNDRED }');
  lines.push('        runtime_key: csrf.enabled');
}

export function emitRouteCsrf(lines: string[], rc: RouteCsrf): void {
  lines.push('          envoy.filters.http.csrf:');
  lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.csrf.v3.CsrfPolicy');
  lines.push('            filter_enabled:');
  lines.push('              default_value: { numerator: 100, denominator: HUNDRED }');
  lines.push('              runtime_key: csrf.enabled');
  if (rc.allowedOrigins.length) {
    lines.push('            additional_origins:');
    for (const o of rc.allowedOrigins) {
      lines.push(`              - exact: ${yamlString(o)}`);
    }
  }
}
