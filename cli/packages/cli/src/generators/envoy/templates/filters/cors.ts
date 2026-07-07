/**
 * envoy.filters.http.cors — per-route CorsPolicy via typed_per_filter_config.
 *
 * The chain-level filter is just the plumbing; the actual policy lives on
 * each route entry (see routes.ts).
 */

import type { EndpointIR, SpecIR } from '@x-security/core';

export interface RouteCors {
  endpoint: EndpointIR;
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  exposeHeaders: string[];
  maxAge: number | null;
  credentials: boolean;
}

export function collectCors(spec: SpecIR): RouteCors[] {
  const out: RouteCors[] = [];
  for (const ep of spec.endpoints) {
    const cors = ep.policy.cors;
    if (!cors) continue;
    out.push({
      endpoint: ep,
      allowedOrigins: cors.allowedOrigins ?? [],
      allowedMethods: cors.allowedMethods ?? [],
      allowedHeaders: cors.allowedHeaders ?? [],
      exposeHeaders: cors.exposeHeaders ?? [],
      maxAge: cors.maxAge ?? null,
      credentials: !!cors.credentials
    });
  }
  return out;
}

export function emitCorsFilterChain(lines: string[]): void {
  lines.push('  - name: envoy.filters.http.cors');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors');
}
