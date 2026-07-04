/**
 * Envoy v3 bootstrap builder (wave-9 native-filter refactor).
 *
 * Wave-7 emitted a partial snippet (`http_filters:` + `rate_limit_descriptors:`)
 * that the chain harness had to splice into a bootstrap. Wave-9 emits a
 * **full runnable bootstrap** — admin block, listener, route_config with
 * typed_per_filter_config overrides, the native HTTP filter chain in the
 * correct order, and the upstream / JWKS clusters.
 *
 * The native filters generated, in order:
 *
 *   0. envoy.filters.http.buffer          — max_request_bytes guard sourced
 *                                            from the smallest declared
 *                                            request.maxBodySize across
 *                                            endpoints. Placed first so body
 *                                            limits enforce before auth /
 *                                            rate-limit work runs.
 *   1. envoy.filters.http.jwt_authn       — JWKS-backed RS256/ES256/EdDSA
 *                                            validation. Replaces the Lua
 *                                            "header presence" check; this is
 *                                            real signature validation.
 *   2. envoy.filters.http.rbac            — principal sourced from jwt_authn
 *                                            payload metadata (`role` claim).
 *   3. envoy.filters.http.local_ratelimit — per-route token bucket via
 *                                            typed_per_filter_config (each
 *                                            route owns its own bucket; the
 *                                            chain-level filter is the
 *                                            default-allow shell).
 *   4. envoy.filters.http.cors            — per-route CorsPolicy via
 *                                            typed_per_filter_config.
 *   5. envoy.filters.http.lua             — residual filter; only emitted when
 *                                            at least one endpoint declares a
 *                                            field with no native equivalent
 *                                            (duplicateParamPolicy,
 *                                            headerInjectionGuard,
 *                                            request.signature, etc.).
 *   6. envoy.filters.http.router          — terminal.
 *
 * The bootstrap is hand-built (not js-yaml dump) so it is byte-stable across
 * runs and snapshot-comparable.
 *
 * Wave-19 W19-B: per-filter emit helpers split into ./filters/*.ts and
 * ./clusters.ts / ./routes.ts / ./yaml-util.ts to keep every file under the
 * Rule G-1 500-line cap. This module is now pure orchestration.
 */

import type { SpecIR } from '@writ/core';
import { UPSTREAM_CLUSTER, emitJwksCluster, emitUpstreamCluster } from './clusters.js';
import {
  collectBflaAdmin,
  collectInputValidation,
  collectRuleBased,
  emitExtAuthzFilter,
  emitOpaCluster,
  needsOpa
} from './extauthz.js';
import { emitExtProcCluster, emitExtProcFilter, needsExtProc } from './ext_proc.js';
import { emitAccessLog, emitAlsCluster, needsAlsCluster } from './access_log.js';
import { emitBufferFilter, smallestBodyLimit } from './filters/buffer.js';
import { emitCacheFilterChain } from './filters/cache.js';
import { emitCsrfFilterChain } from './filters/csrf.js';
import { emitIpRbacFilterChain } from './filters/ip_policy.js';
import { collectJwtEndpoints, emitJwtAuthnFilter } from './filters/jwt_authn.js';
import { emitLuaFilter, emitRouterFilter } from './filters/lua_filter.js';
import { collectRbacEndpoints, emitRbacFilter } from './filters/rbac.js';
import { emitLocalRateLimitChain } from './filters/local_ratelimit.js';
import { emitCorsFilterChain } from './filters/cors.js';
import { buildRouteContext, emitRouteEntry } from './routes.js';

export const VERSION = '0.3.0';

// Re-exports so existing external imports (apps/generators index.ts, tests) keep working.
export { smallestBodyLimit };
export { pathToSafeRegex } from './yaml-util.js';

export interface BuildEnvoyYamlOptions {
  spec: SpecIR;
  /** Residual Lua source (or null when the spec has no Lua-requiring fields). */
  luaSource: string | null;
  /** Upstream cluster host. Default 'upstream'. */
  upstreamHost?: string;
  /** Upstream cluster port. Default 80. */
  upstreamPort?: number;
  /** Listener port. Default 8080. */
  listenerPort?: number;
  /** Admin port. Default 9901. */
  adminPort?: number;
}

export function buildEnvoyYaml(opts: BuildEnvoyYamlOptions): string {
  const {
    spec,
    luaSource,
    upstreamHost = 'upstream',
    upstreamPort = 80,
    listenerPort = 8080,
    adminPort = 9901
  } = opts;

  const lines: string[] = [];

  // ── Header ─────────────────────────────────────────────────────────────
  lines.push('# Writ → Envoy — auto-generated. DO NOT EDIT BY HAND.');
  lines.push(`# generator: writ-envoy v${VERSION}`);
  lines.push(`# source: ${spec.info.title} ${spec.info.version}`);
  lines.push('');

  // Wave-10 E-3: rule-based authorization is now enforced via ext_authz + OPA.
  // Wave-18 W18-A: BFLA admin-only routes + input-validation strict-body routes
  // are also routed through OPA so per-class markers (opa-bfla-403,
  // opa-input-validation-403) can fire on denial. We still emit a header
  // comment listing the routes so the bootstrap is operator-grep-friendly.
  const ruleBased = collectRuleBased(spec);
  const bflaAdmin = collectBflaAdmin(spec);
  const inputValidation = collectInputValidation(spec);
  const opaWired = needsOpa(spec);
  if (opaWired) {
    lines.push('# ext_authz: rule-based / BFLA / input-validation authorization enforced by the OPA sidecar (cluster opa_grpc).');
    lines.push('# Endpoints fronted by ext_authz (Rego policy emitted to opa/policy.rego):');
    for (const e of ruleBased) lines.push(`#   - rule-based ${e.endpoint.method} ${e.endpoint.path}`);
    for (const e of bflaAdmin) lines.push(`#   - bfla-admin  ${e.endpoint.method} ${e.endpoint.path}`);
    for (const e of inputValidation) lines.push(`#   - input-val  ${e.endpoint.method} ${e.endpoint.path}`);
    lines.push('');
  }

  // ── Admin ──────────────────────────────────────────────────────────────
  lines.push('admin:');
  lines.push('  address:');
  lines.push(`    socket_address: { address: 0.0.0.0, port_value: ${adminPort} }`);
  lines.push('');

  // ── Static resources ───────────────────────────────────────────────────
  const jwt = collectJwtEndpoints(spec);
  const rbac = collectRbacEndpoints(spec);
  const ctx = buildRouteContext(spec);
  const globalBodyCap = smallestBodyLimit(spec.endpoints);

  lines.push('static_resources:');
  lines.push('  listeners:');
  lines.push('    - name: writ_listener');
  lines.push('      address:');
  lines.push(`        socket_address: { address: 0.0.0.0, port_value: ${listenerPort} }`);
  lines.push('      filter_chains:');
  lines.push('        - filters:');
  lines.push('            - name: envoy.filters.network.http_connection_manager');
  lines.push('              typed_config:');
  lines.push('                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager');
  lines.push('                stat_prefix: writ_hcm');
  // NOTE: request body size cap is enforced by the buffer HTTP filter
  // (envoy.filters.http.buffer) emitted first in the http_filters chain.
  // It is NOT a valid HCM-scoped field on Envoy v1.28+.
  // access_log: native HCM logger built from the declared `logging` policy
  // (v0.7 SSEC-AUDIT, capability full). When no endpoint declares `logging`,
  // emitAccessLog reproduces the historical default text logger byte-for-byte
  // so the golden fixture does not drift.
  emitAccessLog(lines, spec);
  lines.push('                route_config:');
  lines.push('                  name: writ_routes');
  lines.push('                  virtual_hosts:');
  lines.push('                    - name: writ_vhost');
  lines.push('                      domains: ["*"]');
  lines.push('                      routes:');

  // One route entry per endpoint (sorted by method then path for stability).
  const sortedEps = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );
  // Subroute lines need a 4-space outdent to fit under `routes:` (10-space indent inside `emitRouteEntry`).
  // emitRouteEntry already emits with 6-space indent; we want 24-space final indent → wrap.
  const routeLines: string[] = [];
  for (const ep of sortedEps) emitRouteEntry(routeLines, ep, ctx, UPSTREAM_CLUSTER);
  // emitRouteEntry uses 6-space prefix on `- match:`. We need 24-space prefix → add 18 more spaces.
  for (const r of routeLines) lines.push(r.length === 0 ? '' : '                  ' + r);

  // ── http_filters chain ─────────────────────────────────────────────────
  lines.push('                http_filters:');
  // Each helper emits 2-space-indented filter blocks; we need 18-space prefix → +16 spaces.
  const filterLines: string[] = [];
  emitBufferFilter(filterLines, globalBodyCap);
  emitJwtAuthnFilter(filterLines, jwt);
  emitRbacFilter(filterLines, rbac, jwt?.providerName ?? null);
  if (opaWired) emitExtAuthzFilter(filterLines);
  if (ctx.ipPolicies.size) emitIpRbacFilterChain(filterLines);
  if (ctx.rateLimits.size) emitLocalRateLimitChain(filterLines);
  if (ctx.cors.size) emitCorsFilterChain(filterLines);
  if (ctx.csrf.size) emitCsrfFilterChain(filterLines);
  if (ctx.cache.size) emitCacheFilterChain(filterLines);
  emitLuaFilter(filterLines, luaSource);
  // ext_proc sits last before the router so its response phase runs first on
  // the way back (response filters execute in reverse chain order). Body
  // validation happens in the operator-supplied processor; see ext_proc.ts.
  if (needsExtProc(spec)) emitExtProcFilter(filterLines);
  emitRouterFilter(filterLines);
  for (const f of filterLines) lines.push(f.length === 0 ? '' : '                ' + f);

  // ── Clusters ───────────────────────────────────────────────────────────
  lines.push('  clusters:');
  const clusterLines: string[] = [];
  emitUpstreamCluster(clusterLines, upstreamHost, upstreamPort);
  if (jwt) emitJwksCluster(clusterLines, jwt);
  if (opaWired) emitOpaCluster(clusterLines);
  if (needsExtProc(spec)) emitExtProcCluster(clusterLines);
  if (needsAlsCluster(spec)) emitAlsCluster(clusterLines);
  for (const c of clusterLines) lines.push(c);
  lines.push('');

  // ── Rate-limit descriptor digest (operator-facing, byte-stable docs) ───
  if (ctx.rateLimits.size) {
    lines.push('# Per-route rate-limit stat prefixes (verify-able via /stats):');
    for (const [key, rl] of ctx.rateLimits.entries()) {
      lines.push(`#   ${key}  →  ${rl.statPrefix}  (max=${rl.maxTokens}, fill=${rl.tokensPerFill}/${rl.fillIntervalSec}s)`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
