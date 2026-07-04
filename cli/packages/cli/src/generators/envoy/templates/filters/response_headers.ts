/**
 * Per-route response header hardening — emitted via `response_headers_to_add`
 * on each route entry. No chain-level filter is required; the HCM applies
 * route-level `response_headers_to_add` automatically.
 *
 * Covered DSL fields (x-security.response.headers):
 *   - csp                  → Content-Security-Policy
 *   - hsts                 → Strict-Transport-Security (rendered from Hsts object)
 *   - frameOptions         → X-Frame-Options
 *   - contentTypeOptions   → X-Content-Type-Options
 *   - referrerPolicy       → Referrer-Policy
 *   - permissionsPolicy    → Permissions-Policy
 *
 * Each header is emitted with `append_action: OVERWRITE_IF_EXISTS_OR_ADD` so a
 * mis-configured upstream cannot override the hardened value. Wave-22 W22-A.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import type { Hsts, ResponseHeaders } from '@writ/schema';
import { yamlString } from '../yaml-util.js';

export interface RouteResponseHeader {
  key: string;
  value: string;
}

export interface RouteResponseHeaders {
  endpoint: EndpointIR;
  headers: RouteResponseHeader[];
}

function renderHsts(h: Hsts): string {
  const parts: string[] = [`max-age=${h.maxAge}`];
  if (h.includeSubDomains) parts.push('includeSubDomains');
  if (h.preload) parts.push('preload');
  return parts.join('; ');
}

export function collectResponseHeaders(spec: SpecIR): RouteResponseHeaders[] {
  const out: RouteResponseHeaders[] = [];
  for (const ep of spec.endpoints) {
    const rh = ep.policy.response?.headers as ResponseHeaders | undefined;
    if (!rh) continue;
    const headers: RouteResponseHeader[] = [];
    if (rh.csp) headers.push({ key: 'Content-Security-Policy', value: rh.csp });
    if (rh.hsts) headers.push({ key: 'Strict-Transport-Security', value: renderHsts(rh.hsts) });
    if (rh.frameOptions) headers.push({ key: 'X-Frame-Options', value: rh.frameOptions });
    if (rh.contentTypeOptions) headers.push({ key: 'X-Content-Type-Options', value: rh.contentTypeOptions });
    if (rh.referrerPolicy) headers.push({ key: 'Referrer-Policy', value: rh.referrerPolicy });
    if (rh.permissionsPolicy) headers.push({ key: 'Permissions-Policy', value: rh.permissionsPolicy });
    if (headers.length) out.push({ endpoint: ep, headers });
  }
  return out;
}

/**
 * Emit `response_headers_to_add` lines under a route entry. Caller is
 * responsible for the surrounding indentation; lines emitted at the
 * 8-space prefix expected by routes.ts (i.e. same as `typed_per_filter_config:`).
 */
export function emitRouteResponseHeaders(lines: string[], headers: RouteResponseHeader[]): void {
  if (!headers.length) return;
  lines.push('        response_headers_to_add:');
  for (const h of headers) {
    lines.push('          - header:');
    lines.push(`              key: ${yamlString(h.key)}`);
    lines.push(`              value: ${yamlString(h.value)}`);
    lines.push('            append_action: OVERWRITE_IF_EXISTS_OR_ADD');
  }
}
