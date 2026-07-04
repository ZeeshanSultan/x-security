/**
 * ext_authz + OPA emitter (wave-10 E-3; W17-A; W18-A; W19-A; W20-B).
 *
 * Emits opa/policy.rego with the OPA-Envoy structured-decision shape:
 *   { "allowed": true }
 *   { "allowed": false, "http_status": 403,
 *     "headers": {"x-writ-rule": "opa-<class>-403"}, "body": "..." }
 *
 * Defense classes (else-chain order, most-specific first):
 *   opa-bfla-403              W18-A — rbac admin-only routes
 *   opa-input-validation-403  W18-A — strict-body routes (denyUnknownFields)
 *   opa-ssrf-403              W19-A — url-allowlist / blockPrivateRanges
 *   opa-bola-403              W17-A — rule-based per-resource ownership
 *   opa-jwt-claim-403         W17-A — required jwt claim missing
 *   opa-default-403           W17-A — terminal catch-all (stays ×0.3)
 *
 * Input contract (Envoy → OPA): input.attributes.request.http.{method, path,
 * headers, query, body}. The body is forwarded via `with_request_body`; the
 * query string is the raw `?k=v&...` form (no parsing done by Envoy).
 *
 * W20-B: per-defense-class collectors + branch emitters live in sibling
 * modules (extauthz-bfla.ts, extauthz-input-validation.ts, extauthz-ssrf.ts,
 * extauthz-rule-based.ts). This file is the orchestration entry point.
 */

import type { SpecIR } from '@writ/core';
import {
  denyLiteral,
  OPA_CLUSTER,
  OPA_PORT,
  pathToRegoRegex,
  regoString,
  VERSION
} from './extauthz-rego-util.js';
import {
  collectBflaAdmin,
  emitBflaBranches,
  type BflaEndpoint
} from './extauthz-bfla.js';
import {
  collectInputValidation,
  emitInputValidationBranches,
  type InputValidationEndpoint
} from './extauthz-input-validation.js';
import {
  collectRuleBased,
  emitRuleBasedBranches,
  type RuleBasedEndpoint
} from './extauthz-rule-based.js';
import {
  collectAbac,
  emitAbacBranches,
  type AbacEndpoint
} from './extauthz-abac.js';
import {
  collectSsrfPolicy,
  emitSsrfBranches,
  type SsrfPolicyEndpoint
} from './extauthz-ssrf.js';

// Re-exports for back-compat with callers (envoy/index.ts, envoy-yaml.ts,
// filters/rbac.ts) that import from extauthz.js.
export {
  OPA_CLUSTER,
  OPA_DECISION_PATH,
  OPA_PORT,
  VERSION
} from './extauthz-rego-util.js';
export {
  collectBflaAdmin,
  isAdminOnlyRbac,
  type BflaEndpoint
} from './extauthz-bfla.js';
export {
  collectInputValidation,
  type InputValidationEndpoint
} from './extauthz-input-validation.js';
export {
  collectRuleBased,
  type RuleBasedEndpoint
} from './extauthz-rule-based.js';
export {
  collectAbac,
  type AbacEndpoint
} from './extauthz-abac.js';
export {
  collectSsrfPolicy,
  type SsrfPolicyEndpoint
} from './extauthz-ssrf.js';

/** Aggregated count: does this spec need ext_authz at all? */
export function needsOpa(spec: SpecIR): boolean {
  return (
    collectRuleBased(spec).length > 0 ||
    collectBflaAdmin(spec).length > 0 ||
    collectInputValidation(spec).length > 0 ||
    collectSsrfPolicy(spec).length > 0 ||
    collectAbac(spec).length > 0
  );
}

/**
 * Build the ext_authz HTTP filter block. Indented as a child of `http_filters:`
 * with the same 2-space leading style every other emitJWTAuthn etc. uses; the
 * outer emitter applies the route_config-wide indentation prefix.
 *
 * Wave-17 W17-A: no `headers_to_remove` is set; Envoy forwards every header
 * from OPA's DeniedHttpResponse to the client by default, which is how the
 * `x-writ-rule` marker reaches the scorer.
 */
export function emitExtAuthzFilter(lines: string[]): void {
  lines.push('  - name: envoy.filters.http.ext_authz');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz');
  lines.push('      transport_api_version: V3');
  lines.push('      grpc_service:');
  lines.push('        envoy_grpc:');
  lines.push(`          cluster_name: ${OPA_CLUSTER}`);
  lines.push('        timeout: 0.5s');
  lines.push('      failure_mode_allow: false');
  lines.push('      include_peer_certificate: false');
  // W17-A: explicitly carry OPA's denied_response headers (including the
  // x-writ-rule marker) through to the downstream client. This is
  // Envoy's default but we declare it so the contract is greppable.
  lines.push('      # W17-A: forward OPA-emitted x-writ-rule marker downstream.');
  lines.push('      with_request_body:');
  lines.push('        max_request_bytes: 8192');
  lines.push('        allow_partial_message: true');
}

export function emitOpaCluster(lines: string[], host = 'opa', port = OPA_PORT): void {
  lines.push(`  - name: ${OPA_CLUSTER}`);
  lines.push('    type: STRICT_DNS');
  lines.push('    connect_timeout: 1s');
  lines.push('    lb_policy: ROUND_ROBIN');
  lines.push('    typed_extension_protocol_options:');
  lines.push('      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:');
  lines.push('        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions');
  lines.push('        explicit_http_config:');
  lines.push('          http2_protocol_options: {}');
  lines.push('    load_assignment:');
  lines.push(`      cluster_name: ${OPA_CLUSTER}`);
  lines.push('      endpoints:');
  lines.push('        - lb_endpoints:');
  lines.push('            - endpoint:');
  lines.push('                address:');
  lines.push(`                  socket_address: { address: ${host}, port_value: ${port} }`);
}

export interface RegoBuildInput {
  ruleBased: RuleBasedEndpoint[];
  bflaAdmin?: BflaEndpoint[];
  inputValidation?: InputValidationEndpoint[];
  ssrfPolicy?: SsrfPolicyEndpoint[];
  abac?: AbacEndpoint[];
  specTitle: string;
  specVersion: string;
}

/**
 * Build the full `policy.rego` source. Always emits:
 *   - `default allow` returning the opa-default-403 object
 *   - `bearer_token` helper
 *   - `allow := decision` plus a chain of `decision := ...` / `else := ...`
 *     branches, ordered most-specific first:
 *       1. BFLA admin-only branches (opa-bfla-403)        — W18-A
 *       2. Input-validation strict-body branches          — W18-A
 *       3. SSRF url-allowlist branches                    — W19-A
 *       4. Rule-based permit / jwt-claim / bola branches  — W17-A
 *       5. Terminal default-403 else                      — W17-A
 *
 * Two call shapes are supported for back-compat: the legacy positional form
 * `(rb, title, version)` and the named-object form `(RegoBuildInput)`.
 */
export function buildRegoPolicy(input: RegoBuildInput): string;
export function buildRegoPolicy(rb: RuleBasedEndpoint[], specTitle: string, specVersion: string): string;
export function buildRegoPolicy(
  a: RuleBasedEndpoint[] | RegoBuildInput,
  b?: string,
  c?: string
): string {
  const cfg: RegoBuildInput = Array.isArray(a)
    ? { ruleBased: a, specTitle: b!, specVersion: c! }
    : a;
  return buildRegoPolicyInner(cfg);
}

function buildRegoPolicyInner(cfg: RegoBuildInput): string {
  const rb = cfg.ruleBased;
  const bfla = cfg.bflaAdmin ?? [];
  const iv = cfg.inputValidation ?? [];
  const ssrf = cfg.ssrfPolicy ?? [];
  const abac = cfg.abac ?? [];
  const lines: string[] = [];
  lines.push('# Writ → OPA — auto-generated. DO NOT EDIT BY HAND.');
  lines.push(`# generator: writ-envoy/extauthz v${VERSION}`);
  lines.push(`# source: ${cfg.specTitle} ${cfg.specVersion}`);
  lines.push('# Wave-10 E-3: rule-based authorization → ext_authz + OPA sidecar.');
  lines.push('# Wave-17 W17-A: structured decision object emits per-class x-writ-rule');
  lines.push('# headers (opa-bola-403, opa-jwt-claim-403, opa-default-403) so the scorer\'s');
  lines.push('# intent-attribution layer can map a denial back to the right defense-class.');
  lines.push('# Wave-18 W18-A: + opa-bfla-403 (rbac admin-only routes, principal-role check)');
  lines.push('# and opa-input-validation-403 (strict-body routes, body-key allowlist check).');
  lines.push('');
  lines.push('package envoy.authz');
  lines.push('');
  lines.push('import future.keywords.if');
  lines.push('');
  lines.push(`default allow := ${denyLiteral('default')}`);
  lines.push('');
  lines.push('# Extract bearer token from either the standard Authorization header (Bearer prefix)');
  lines.push('# or the vAPI-style Authorization-Token header (bare token). One of these MUST resolve');
  lines.push('# for any permit branch to fire.');
  lines.push('bearer_token := t if {');
  lines.push('  h := input.attributes.request.http.headers.authorization');
  lines.push('  startswith(h, "Bearer ")');
  lines.push('  t := substring(h, 7, -1)');
  lines.push('}');
  lines.push('');
  lines.push('bearer_token := t if {');
  lines.push('  t := input.attributes.request.http.headers["authorization-token"]');
  lines.push('  t != ""');
  lines.push('}');
  lines.push('');

  lines.push('# Routing head: every request runs through `decision`, whose ordered');
  lines.push('# else-chain picks the first matching branch.  The chain ends with a');
  lines.push('# terminal default-403 else so `decision` is total (always resolves).');
  lines.push('allow := decision');
  lines.push('');

  const hasAny = bfla.length > 0 || iv.length > 0 || ssrf.length > 0 || rb.length > 0 || abac.length > 0;
  if (!hasAny) {
    // No policy-aware endpoints — decision is a single default-deny.
    lines.push(`decision := ${denyLiteral('default')}`);
    return lines.join('\n');
  }

  // Else-chain: first branch `decision := ... if`, rest `else := ... if`,
  // terminal `else := default-403`. W18-A ordering invariant: BFLA, then
  // input-validation, then SSRF, then rule-based, then default.
  let isFirst = true;
  const pushBranch = (body: string[] | null, value: string) => {
    if (!body) return;
    const keyword = isFirst ? 'decision' : 'else';
    lines.push(`${keyword} := ${value} if {`);
    for (const b of body) lines.push(b);
    lines.push('}');
    isFirst = false;
  };

  const deps = { regoString, pathToRegoRegex, denyLiteral, pushBranch, lines };

  if (bfla.length > 0) emitBflaBranches(bfla, deps);
  if (iv.length > 0) emitInputValidationBranches(iv, deps);
  if (ssrf.length > 0) emitSsrfBranches(ssrf, deps);
  if (rb.length > 0) emitRuleBasedBranches(rb, deps);
  if (abac.length > 0) emitAbacBranches(abac, deps);

  // Terminal else — unconditional default-403. Required so `decision` is
  // total when no per-endpoint branch matches.
  lines.push(`else := ${denyLiteral('default')}`);

  return lines.join('\n');
}