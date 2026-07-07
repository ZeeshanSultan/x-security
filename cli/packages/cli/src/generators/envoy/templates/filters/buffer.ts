/**
 * envoy.filters.http.buffer — max_request_bytes guard.
 *
 * Sourced from the smallest declared `request.maxBodySize` across endpoints.
 * Placed first in the http_filters chain so the body cap enforces before
 * jwt_authn / rbac / ext_authz / rate-limit do work. Envoy returns 413 with
 * RESPONSE_CODE_DETAILS=request_payload_too_large when the body exceeds
 * max_request_bytes.
 */

import type { EndpointIR } from '@x-security/core';
import { parseByteSize } from '../../../coraza/rules.js';

/** Compute the smallest declared maxBodySize across endpoints (or null). */
export function smallestBodyLimit(endpoints: EndpointIR[]): number | null {
  let min: number | null = null;
  for (const ep of endpoints) {
    const v = parseByteSize(ep.policy.request?.maxBodySize);
    if (Number.isFinite(v) && v > 0) {
      if (min === null || v < min) min = v;
    }
  }
  return min;
}

export function emitBufferFilter(lines: string[], maxRequestBytes: number | null): void {
  if (maxRequestBytes === null) return;
  lines.push('  - name: envoy.filters.http.buffer');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer');
  lines.push(`      max_request_bytes: ${maxRequestBytes}`);
}
