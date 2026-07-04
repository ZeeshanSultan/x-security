/**
 * Per-route entry emission for the Envoy route_config.
 *
 * Builds one match block per endpoint with typed_per_filter_config overrides
 * for the per-route filters (local_ratelimit, cors). The chain-level filters
 * themselves are emitted by ./filters/*.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { collectCache, emitRouteCache, type RouteCache } from './filters/cache.js';
import { collectCors, type RouteCors } from './filters/cors.js';
import { collectCsrf, emitRouteCsrf, type RouteCsrf } from './filters/csrf.js';
import { collectIpPolicies, emitRouteIpPolicy, type RouteIpPolicy } from './filters/ip_policy.js';
import { collectRateLimits, type RouteRateLimit } from './filters/local_ratelimit.js';
import {
  collectResponseHeaders,
  emitRouteResponseHeaders,
  type RouteResponseHeaders
} from './filters/response_headers.js';
import { pathToSafeRegex, yamlString } from './yaml-util.js';

export interface RouteContext {
  rateLimits: Map<string, RouteRateLimit>;     // key = `${method} ${path}`
  cors: Map<string, RouteCors>;
  ipPolicies: Map<string, RouteIpPolicy>;
  cache: Map<string, RouteCache>;
  csrf: Map<string, RouteCsrf>;
  responseHeaders: Map<string, RouteResponseHeaders>;
}

export function buildRouteContext(spec: SpecIR): RouteContext {
  const rl = new Map<string, RouteRateLimit>();
  const co = new Map<string, RouteCors>();
  const ip = new Map<string, RouteIpPolicy>();
  const ca = new Map<string, RouteCache>();
  const cs = new Map<string, RouteCsrf>();
  const rh = new Map<string, RouteResponseHeaders>();
  for (const r of collectRateLimits(spec)) {
    rl.set(`${r.endpoint.method} ${r.endpoint.path}`, r);
  }
  for (const c of collectCors(spec)) {
    co.set(`${c.endpoint.method} ${c.endpoint.path}`, c);
  }
  for (const p of collectIpPolicies(spec)) {
    ip.set(`${p.endpoint.method} ${p.endpoint.path}`, p);
  }
  for (const c of collectCache(spec)) {
    ca.set(`${c.endpoint.method} ${c.endpoint.path}`, c);
  }
  for (const c of collectCsrf(spec)) {
    cs.set(`${c.endpoint.method} ${c.endpoint.path}`, c);
  }
  for (const h of collectResponseHeaders(spec)) {
    rh.set(`${h.endpoint.method} ${h.endpoint.path}`, h);
  }
  return { rateLimits: rl, cors: co, ipPolicies: ip, cache: ca, csrf: cs, responseHeaders: rh };
}

export function emitRouteEntry(lines: string[], ep: EndpointIR, ctx: RouteContext, upstreamCluster: string): void {
  const key = `${ep.method} ${ep.path}`;
  const rl = ctx.rateLimits.get(key);
  const cors = ctx.cors.get(key);
  const ip = ctx.ipPolicies.get(key);
  const cache = ctx.cache.get(key);
  const csrf = ctx.csrf.get(key);
  const respHeaders = ctx.responseHeaders.get(key);

  lines.push(`      - match:`);
  lines.push(`          safe_regex: { regex: ${yamlString(pathToSafeRegex(ep.path))} }`);
  lines.push(`          headers:`);
  lines.push(`            - name: ":method"`);
  lines.push(`              string_match: { exact: ${yamlString(ep.method)} }`);
  lines.push(`        route: { cluster: ${upstreamCluster} }`);
  if (respHeaders) emitRouteResponseHeaders(lines, respHeaders.headers);
  if (rl || cors || ip || cache || csrf) {
    lines.push('        typed_per_filter_config:');
    if (rl) {
      lines.push('          envoy.filters.http.local_ratelimit:');
      lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit');
      lines.push(`            stat_prefix: ${rl.statPrefix}`);
      lines.push('            token_bucket:');
      lines.push(`              max_tokens: ${rl.maxTokens}`);
      lines.push(`              tokens_per_fill: ${rl.tokensPerFill}`);
      lines.push(`              fill_interval: ${rl.fillIntervalSec}s`);
      lines.push('            filter_enabled:');
      lines.push('              runtime_key: local_rate_limit_enabled');
      lines.push('              default_value: { numerator: 100, denominator: HUNDRED }');
      lines.push('            filter_enforced:');
      lines.push('              runtime_key: local_rate_limit_enforced');
      lines.push('              default_value: { numerator: 100, denominator: HUNDRED }');
      lines.push('            response_headers_to_add:');
      lines.push('              - append: false');
      lines.push('                header: { key: x-writ-ratelimit, value: enforced }');
    }
    if (cors) {
      lines.push('          envoy.filters.http.cors:');
      lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy');
      if (cors.allowedOrigins.length) {
        lines.push('            allow_origin_string_match:');
        for (const o of cors.allowedOrigins) {
          lines.push(`              - exact: ${yamlString(o)}`);
        }
      }
      if (cors.allowedMethods.length) {
        lines.push(`            allow_methods: ${yamlString(cors.allowedMethods.join(','))}`);
      }
      if (cors.allowedHeaders.length) {
        lines.push(`            allow_headers: ${yamlString(cors.allowedHeaders.join(','))}`);
      }
      if (cors.exposeHeaders.length) {
        lines.push(`            expose_headers: ${yamlString(cors.exposeHeaders.join(','))}`);
      }
      if (cors.maxAge !== null) lines.push(`            max_age: ${yamlString(String(cors.maxAge))}`);
      lines.push(`            allow_credentials: ${cors.credentials}`);
    }
    if (ip) emitRouteIpPolicy(lines, ip);
    if (cache) emitRouteCache(lines, cache);
    if (csrf) emitRouteCsrf(lines, csrf);
  }
}
