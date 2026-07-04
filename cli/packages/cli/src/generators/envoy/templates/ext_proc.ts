/**
 * Response-schema validation via Envoy's External Processing filter
 * (`envoy.filters.http.ext_proc`).
 *
 * WHY ext_proc and not ext_authz/Lua:
 *   - ext_authz (the OPA sidecar already chained on opa_grpc) is a REQUEST-path
 *     filter. It never sees the response body, so it cannot validate
 *     `response.schema`.
 *   - Lua's in-engine sandbox has no JSON parser, and Rule D-1 bans regex over
 *     raw response bytes to recover structured fields.
 *   - `ext_proc` is the only NATIVE Envoy mechanism that streams the RESPONSE
 *     body to an external gRPC service, which can do real `JSON.parse` +
 *     typed-constraint evaluation on the parsed value.
 *
 * HONESTY (Rule D-1 — the crux for envoy):
 *   Writ does NOT ship an ext_proc ExternalProcessor binary, and the
 *   `openpolicyagent/opa:latest-envoy` sidecar this generator wires only speaks
 *   the ext_authz gRPC API (request path) — its ext_proc support is an
 *   unmerged upstream PR and would need a second port + a different image.
 *   Therefore this module emits SCAFFOLDING:
 *     - the ext_proc HTTP filter (response-body processing mode),
 *     - an `ext_proc` processing cluster pointing at an operator-run service,
 *     - a self-contained `ext_proc/response-schema.json` data file describing
 *       the per-route typed constraints the processor must enforce.
 *   Enforcement DEPENDS ON the operator supplying the processor that consumes
 *   that JSON. Until they do, nothing validates the response body. The honest
 *   matrix status is therefore `override-only`, NOT `full`. We do not fall back
 *   to regex to claim a higher status.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import type { ParamSchema } from '@writ/schema';
import { pathToRegoRegex } from './extauthz-rego-util.js';

export const EXT_PROC_CLUSTER = 'writ_ext_proc';
export const EXT_PROC_PORT = 9292;
/** Default host of the operator-supplied processor (override at deploy time). */
export const EXT_PROC_HOST = 'writ-respval';

export interface ResponseSchemaEndpoint {
  endpoint: EndpointIR;
  /** Typed per-field constraints from `response.schema` (may be empty). */
  schema: Record<string, ParamSchema>;
  /** `response.stripUnknownFields` — when true, keys outside `schema` are rejected. */
  stripUnknownFields: boolean;
  /**
   * `response.forbidArrayRoot` (API3 JSON-hijacking defense) — when true, the
   * processor must reject a bare top-level JSON array. This is a RESPONSE-BODY
   * SHAPE check: the same class as response.schema, requiring the same real
   * JSON.parse in the operator-supplied ext_proc processor. Envoy has no native
   * response-body shape inspector, so it rides this scaffolding as override-only
   * (NOT full — Rule D-1). A Lua regex over raw response bytes to spot a leading
   * '[' is exactly the masked-quality shortcut the rule bans.
   */
  forbidArrayRoot: boolean;
}

/**
 * Endpoints that declare `response.schema` OR `response.stripUnknownFields` OR
 * `response.forbidArrayRoot`. Any one alone is enough to require response-body
 * processing.
 */
export function collectResponseSchema(spec: SpecIR): ResponseSchemaEndpoint[] {
  const out: ResponseSchemaEndpoint[] = [];
  for (const ep of spec.endpoints) {
    const res = ep.policy.response;
    if (!res) continue;
    const schema = res.schema ?? {};
    const strip = res.stripUnknownFields === true;
    const forbidArrayRoot = res.forbidArrayRoot === true;
    const hasSchema = Object.keys(schema).length > 0;
    if (!hasSchema && !strip && !forbidArrayRoot) continue;
    out.push({ endpoint: ep, schema, stripUnknownFields: strip, forbidArrayRoot });
  }
  return out;
}

export function needsExtProc(spec: SpecIR): boolean {
  return collectResponseSchema(spec).length > 0;
}

/**
 * One field's typed constraints, normalized to exactly the keys a JSON-parsing
 * processor evaluates against the parsed value. Only constraints Writ can
 * express are emitted; absent keys mean "unconstrained".
 */
interface FieldRule {
  type?: string;
  minLength?: number;
  maxLength?: number;
  fixedLength?: number;
  min?: number;
  max?: number;
  pattern?: string;
}

function fieldRule(s: ParamSchema): FieldRule {
  const r: FieldRule = {};
  if (s.type !== undefined) r.type = s.type;
  if (s.minLength !== undefined) r.minLength = s.minLength;
  if (s.maxLength !== undefined) r.maxLength = s.maxLength;
  if (s.fixedLength !== undefined) r.fixedLength = s.fixedLength;
  if (s.min !== undefined) r.min = s.min;
  if (s.max !== undefined) r.max = s.max;
  if (s.pattern !== undefined) r.pattern = s.pattern;
  return r;
}

interface RouteRule {
  method: string;
  path: string;
  /** Anchored regex the processor matches `:path` against to select this rule. */
  pathRegex: string;
  /** Reject response-body keys outside `fields`. */
  stripUnknownFields: boolean;
  /** Reject a bare top-level JSON array body (API3 JSON-hijacking defense). */
  forbidArrayRoot: boolean;
  /** Per-top-level-key typed constraints, evaluated on the PARSED JSON value. */
  fields: Record<string, FieldRule>;
}

interface ResponseSchemaConfig {
  $comment: string;
  generator: string;
  source: string;
  /** What enforces this and what the operator must supply. Read by humans. */
  enforcement: {
    status: 'override-only';
    enforcedBy: string;
    operatorMustSupply: string;
    dataPath: string;
  };
  routes: RouteRule[];
}

/**
 * Build the `ext_proc/response-schema.json` data file. This is the contract
 * between Writ (which knows the schema) and the operator's processor
 * (which parses the body and enforces). Byte-stable: keys/routes sorted.
 */
export function buildResponseSchemaConfig(
  items: ResponseSchemaEndpoint[],
  specTitle: string,
  specVersion: string
): string {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) {
      return a.endpoint.method.localeCompare(b.endpoint.method);
    }
    return a.endpoint.path.localeCompare(b.endpoint.path);
  });

  const routes: RouteRule[] = sorted.map((item) => {
    const fields: Record<string, FieldRule> = {};
    for (const key of Object.keys(item.schema).sort()) {
      fields[key] = fieldRule(item.schema[key]!);
    }
    return {
      method: item.endpoint.method.toUpperCase(),
      path: item.endpoint.path,
      pathRegex: pathToRegoRegex(item.endpoint.path),
      stripUnknownFields: item.stripUnknownFields,
      forbidArrayRoot: item.forbidArrayRoot,
      fields
    };
  });

  const cfg: ResponseSchemaConfig = {
    $comment:
      'Writ → Envoy ext_proc response-schema contract. Auto-generated. ' +
      'DO NOT EDIT BY HAND. Consumed by an operator-supplied ext_proc gRPC ' +
      'ExternalProcessor that parses the response body as JSON and enforces ' +
      'these per-field typed constraints on the parsed value. Writ does ' +
      'NOT ship that processor; this file + the envoy.yaml ext_proc filter are ' +
      'scaffolding. No regex over raw bytes — the processor MUST JSON.parse.',
    generator: 'writ-envoy/ext_proc',
    source: `${specTitle} ${specVersion}`,
    enforcement: {
      status: 'override-only',
      enforcedBy:
        'operator-supplied ext_proc gRPC ExternalProcessor (cluster ' +
        `${EXT_PROC_CLUSTER}, host ${EXT_PROC_HOST}:${EXT_PROC_PORT})`,
      operatorMustSupply:
        'A gRPC service implementing envoy.service.ext_proc.v3.ExternalProcessor ' +
        'that JSON-parses the response body and evaluates the rules below. ' +
        'Writ does not bundle it; the OPA sidecar (opa_grpc) is ext_authz-only.',
      dataPath:
        'Envoy ext_proc filter streams the response body (processing_mode: ' +
        'response_body_mode=BUFFERED) to the processor, which returns an ' +
        'ImmediateResponse(502) to block a schema-violating body or continues otherwise.'
    },
    routes
  };

  return JSON.stringify(cfg, null, 2) + '\n';
}

/**
 * Emit the `envoy.filters.http.ext_proc` HTTP filter. Helpers emit 2-space
 * indentation under `http_filters:`; the orchestrator applies the outer prefix.
 *
 * processing_mode buffers the RESPONSE body and sends it to the processor.
 * Request path is skipped (SKIP) — request-body validation already lives on the
 * ext_authz/OPA path. `failure_mode_allow: false` means a processor outage
 * fails closed (the response is blocked), so a missing operator service does
 * NOT silently pass an unvalidated body.
 */
export function emitExtProcFilter(lines: string[]): void {
  lines.push('  # response.schema validation (override-only): real JSON parse happens in the');
  lines.push('  # operator-supplied ext_proc processor; this filter only delivers the body.');
  lines.push('  # Writ does NOT ship the processor — see ext_proc/response-schema.json.');
  lines.push('  - name: envoy.filters.http.ext_proc');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor');
  lines.push('      grpc_service:');
  lines.push('        envoy_grpc:');
  lines.push(`          cluster_name: ${EXT_PROC_CLUSTER}`);
  lines.push('        timeout: 1s');
  lines.push('      failure_mode_allow: false');
  lines.push('      processing_mode:');
  lines.push('        request_header_mode: SKIP');
  lines.push('        request_body_mode: NONE');
  lines.push('        response_header_mode: SEND');
  lines.push('        response_body_mode: BUFFERED');
  lines.push('      message_timeout: 1s');
}

/**
 * Emit the ext_proc processing cluster. STRICT_DNS + HTTP/2 (gRPC), same shape
 * as the opa_grpc cluster. The host defaults to a name the operator wires to
 * their processor; nothing in the Writ-shipped compose resolves it.
 */
export function emitExtProcCluster(lines: string[], host = EXT_PROC_HOST, port = EXT_PROC_PORT): void {
  lines.push(`  - name: ${EXT_PROC_CLUSTER}`);
  lines.push('    type: STRICT_DNS');
  lines.push('    connect_timeout: 1s');
  lines.push('    lb_policy: ROUND_ROBIN');
  lines.push('    typed_extension_protocol_options:');
  lines.push('      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:');
  lines.push('        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions');
  lines.push('        explicit_http_config:');
  lines.push('          http2_protocol_options: {}');
  lines.push('    load_assignment:');
  lines.push(`      cluster_name: ${EXT_PROC_CLUSTER}`);
  lines.push('      endpoints:');
  lines.push('        - lb_endpoints:');
  lines.push('            - endpoint:');
  lines.push('                address:');
  lines.push(`                  socket_address: { address: ${host}, port_value: ${port} }`);
}
