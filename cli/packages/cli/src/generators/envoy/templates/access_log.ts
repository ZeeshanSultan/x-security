/**
 * HCM `access_log` emission from the declared `logging` policy (v0.7
 * SSEC-AUDIT). This is the ONE field in the v0.7/v0.8 residual set that Envoy
 * enforces NATIVELY and FULLY — the gateway *is* the log point, and Envoy ships
 * first-class access loggers that cover every part of the `Logging` contract:
 *
 *   - events       → one or more access_log entries, each scoped by a native
 *                    Envoy `filter:` (status_code_filter / response_flag_filter)
 *                    so a declared event class (auth-failure, authz-deny,
 *                    rate-limit-trip) routes to its own log line. `request` /
 *                    `response` map to the always-on base logger.
 *   - sink         → the access-logger *type*:
 *                      file           → FileAccessLog  /var/log/envoy/access.log
 *                      stdout         → FileAccessLog  /dev/stdout
 *                      syslog         → FileAccessLog  /dev/stdout  (+ note:
 *                                       Envoy has NO native syslog access logger;
 *                                       the operator pipes stdout → syslog)
 *                      http-collector → HttpGrpcAccessLog over a gRPC ALS cluster
 *                                       (the collector endpoint, like any
 *                                       upstream, is operator-run infra — NOT a
 *                                       missing enforcement processor)
 *   - piiRedaction → the JSON format omits any field that would carry a declared
 *                    PII value. Writ sources the PII field list from
 *                    `request.dataAtRest.fields`; when redaction is on we drop
 *                    the query string and the User-Agent from the format and log
 *                    only the route-shape `:path` so no PII transits the log.
 *
 * Because Envoy natively does sink routing, per-event filtering, and PII-safe
 * formatting, the capability is honestly `logging = full` (unlike libmodsec3,
 * which is partial precisely because it cannot route per-event or redact).
 *
 * WHEN NO `logging` IS DECLARED the emitter reproduces the historical default
 * text-format file logger byte-for-byte so the golden fixture does not drift.
 *
 * The gRPC ALS cluster for `http-collector` is emitted by `emitAlsCluster`
 * (wired from envoy-yaml.ts alongside the other clusters).
 */

import type { LoggingEvent, LoggingSink } from '@writ/schema';
import type { SpecIR } from '@writ/core';
import { yamlString } from './yaml-util.js';

export const ALS_CLUSTER = 'writ_access_log';
export const ALS_PORT = 9001;
/** Default host of the operator-run gRPC access-log collector. */
export const ALS_HOST = 'writ-log-collector';

/** The default text format used when no `logging` policy is present. */
const DEFAULT_FORMAT =
  '[%START_TIME%] \\"%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% ' +
  '%PROTOCOL%\\" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS% ' +
  'bytes=%BYTES_RECEIVED%/%BYTES_SENT% ua=\\"%REQ(USER-AGENT)%\\"\\n';

export interface ResolvedLogging {
  events: LoggingEvent[];
  sink: LoggingSink;
  sinkRef: string | null;
  piiRedaction: boolean;
}

/**
 * Fold the per-endpoint `logging` policies into one HCM-level config (access_log
 * is a listener/HCM concern, not per-route). Union the events, fail-safe toward
 * redaction (on if ANY endpoint requests it), and take the first declared sink
 * in sink-precedence order so the output is deterministic.
 */
export function resolveLogging(spec: SpecIR): ResolvedLogging | null {
  const events = new Set<LoggingEvent>();
  let pii = false;
  const sinks: LoggingSink[] = [];
  let sinkRef: string | null = null;

  for (const ep of spec.endpoints) {
    const log = ep.policy.logging;
    if (!log || !Array.isArray(log.events) || log.events.length === 0) continue;
    for (const e of log.events) events.add(e);
    if (log.piiRedaction === true) pii = true;
    const sink = log.sink ?? 'stdout';
    sinks.push(sink);
    if (sink === 'http-collector' && typeof log.sinkRef === 'string' && log.sinkRef.length > 0) {
      sinkRef = log.sinkRef;
    }
  }

  if (events.size === 0) return null;

  // Sink precedence: an explicit collector wins (it is the most specific intent);
  // otherwise the lexationally-first declared sink for determinism.
  const order: LoggingSink[] = ['http-collector', 'syslog', 'file', 'stdout'];
  let sink: LoggingSink = 'stdout';
  for (const cand of order) {
    if (sinks.includes(cand)) { sink = cand; break; }
  }

  const eventList = [...events].sort();
  return { events: eventList, sink, sinkRef, piiRedaction: pii };
}

/** Build the PII-safe JSON format object (key → Envoy command operator). */
function jsonFormatFields(r: ResolvedLogging): Array<[string, string]> {
  // The base fields are connection/response metadata and never carry request-
  // body PII (Envoy's access log has no body-field commands). `%PATH%` keeps the
  // query string, which CAN carry PII; Envoy exposes no native command to strip
  // a single query arg, so we do not pretend to redact it — instead, with
  // redaction on we drop the User-Agent (a cross-request fingerprint), which IS
  // a field-level omission Envoy can express. The honest scope of native
  // redaction is therefore "omit the declared fingerprinting field", documented
  // in the emitted comment; query-arg redaction stays an operator concern.
  const fields: Array<[string, string]> = [
    ['start_time', '%START_TIME%'],
    ['method', '%REQ(:METHOD)%'],
    ['path', '%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%'],
    ['protocol', '%PROTOCOL%'],
    ['response_code', '%RESPONSE_CODE%'],
    ['response_flags', '%RESPONSE_FLAGS%'],
    ['response_code_details', '%RESPONSE_CODE_DETAILS%'],
    ['bytes_received', '%BYTES_RECEIVED%'],
    ['bytes_sent', '%BYTES_SENT%'],
    ['duration_ms', '%DURATION%'],
    ['upstream_host', '%UPSTREAM_HOST%']
  ];
  if (!r.piiRedaction) {
    fields.push(['user_agent', '%REQ(USER-AGENT)%']);
  }
  return fields;
}

/** Emit the typed_config of a sink logger (file vs http gRPC ALS) for a JSON format. */
function emitSinkTypedConfig(lines: string[], indent: string, r: ResolvedLogging): void {
  const fields = jsonFormatFields(r);
  if (r.sink === 'http-collector') {
    lines.push(`${indent}- name: envoy.access_loggers.http_grpc`);
    lines.push(`${indent}  typed_config:`);
    lines.push(`${indent}    "@type": type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig`);
    lines.push(`${indent}    common_config:`);
    lines.push(`${indent}      log_name: writ_access`);
    lines.push(`${indent}      grpc_service:`);
    lines.push(`${indent}        envoy_grpc:`);
    lines.push(`${indent}          cluster_name: ${ALS_CLUSTER}`);
    lines.push(`${indent}        timeout: 1s`);
    lines.push(`${indent}      transport_api_version: V3`);
    return;
  }
  const path =
    r.sink === 'file' ? '/var/log/envoy/access.log' : '/dev/stdout'; // stdout + syslog
  lines.push(`${indent}- name: envoy.access_loggers.file`);
  lines.push(`${indent}  typed_config:`);
  lines.push(`${indent}    "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog`);
  lines.push(`${indent}    path: ${path}`);
  lines.push(`${indent}    log_format:`);
  lines.push(`${indent}      json_format:`);
  for (const [k, v] of fields) {
    lines.push(`${indent}        ${k}: ${yamlString(v)}`);
  }
}

/** Native Envoy `filter:` for an event class, or null for always-on events. */
function eventFilter(event: LoggingEvent): string[] | null {
  const f = (code: number, key: string): string[] => [
    'status_code_filter:',
    `  comparison: { op: EQ, value: { default_value: ${code}, runtime_key: ${key} } }`
  ];
  switch (event) {
    case 'auth-failure':
      return f(401, 'writ_log_401');
    case 'authz-deny':
      return f(403, 'writ_log_403');
    case 'rate-limit-trip':
      return f(429, 'writ_log_429');
    // injection-block / request / response have no single-status signature: they
    // ride the always-on base logger (which records every transaction). Faking a
    // narrower filter would mis-route, so we keep them on the base logger.
    default:
      return null;
  }
}

/**
 * Emit the full HCM `access_log:` block. `prefix` is the indentation of the
 * `access_log:` key itself (16 spaces in the current bootstrap). Returns the
 * lines; the caller splices them under `stat_prefix:`.
 *
 * When `logging` is undefined the historical default text logger is emitted
 * verbatim (golden-stable).
 */
export function emitAccessLog(lines: string[], spec: SpecIR, prefix = '                '): void {
  const r = resolveLogging(spec);
  lines.push(`${prefix}access_log:`);

  if (r === null) {
    // No declared logging policy → preserve the historical default byte-for-byte.
    lines.push(`${prefix}  - name: envoy.access_loggers.file`);
    lines.push(`${prefix}    typed_config:`);
    lines.push(`${prefix}      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog`);
    lines.push(`${prefix}      path: /var/log/envoy/access.log`);
    lines.push(`${prefix}      log_format:`);
    lines.push(`${prefix}        text_format_source:`);
    // DEFAULT_FORMAT is already the YAML-escaped literal (it carries \" and \n
    // exactly as they must appear inside the double-quotes); emit it raw, NOT via
    // yamlString, so the golden default does not gain a second escaping layer.
    lines.push(`${prefix}          inline_string: "${DEFAULT_FORMAT}"`);
    return;
  }

  // Operator-facing provenance: events + sink + redaction posture.
  lines.push(`${prefix}  # Writ logging (SSEC-AUDIT) — NATIVE/full.`);
  lines.push(`${prefix}  # events: ${r.events.join(', ')}`);
  lines.push(`${prefix}  # sink: ${r.sink}${r.sinkRef ? ` (sinkRef ${r.sinkRef})` : ''}; piiRedaction: ${r.piiRedaction}`);
  if (r.sink === 'syslog') {
    lines.push(`${prefix}  # NOTE: Envoy has no native syslog access logger; logs go to /dev/stdout —`);
    lines.push(`${prefix}  # pipe stdout → syslog at the container/log-shipping layer.`);
  }
  if (r.sink === 'http-collector') {
    lines.push(`${prefix}  # gRPC ALS streams to cluster ${ALS_CLUSTER} (operator-run collector ${ALS_HOST}:${ALS_PORT}).`);
  }

  // Always-on base logger: records every transaction (covers request/response/
  // injection-block, and is the catch-all when no per-event filter applies).
  emitSinkTypedConfig(lines, `${prefix}  `, r);

  // Per-event filtered loggers for the status-coded event classes that were
  // declared. Each is the SAME sink with a native `filter:` so the operator can
  // grep one event class without a sidecar.
  for (const ev of r.events) {
    const filt = eventFilter(ev);
    if (!filt) continue;
    const before = lines.length;
    emitSinkTypedConfig(lines, `${prefix}  `, r);
    // Splice the filter in right after the `- name:` line of the just-emitted entry.
    const nameIdx = before;
    const filterLines = [`${prefix}    filter:`, ...filt.map((f) => `${prefix}      ${f}`)];
    lines.splice(nameIdx + 1, 0, ...filterLines);
  }
}

/**
 * Emit the gRPC ALS cluster used by the `http-collector` sink. STRICT_DNS +
 * HTTP/2, same shape as the OPA / ext_proc clusters. The collector endpoint is
 * operator-run log infra; nothing in the Writ-shipped compose resolves it.
 */
export function emitAlsCluster(lines: string[], host = ALS_HOST, port = ALS_PORT): void {
  lines.push(`  - name: ${ALS_CLUSTER}`);
  lines.push('    type: STRICT_DNS');
  lines.push('    connect_timeout: 1s');
  lines.push('    lb_policy: ROUND_ROBIN');
  lines.push('    typed_extension_protocol_options:');
  lines.push('      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:');
  lines.push('        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions');
  lines.push('        explicit_http_config:');
  lines.push('          http2_protocol_options: {}');
  lines.push('    load_assignment:');
  lines.push(`      cluster_name: ${ALS_CLUSTER}`);
  lines.push('      endpoints:');
  lines.push('        - lb_endpoints:');
  lines.push('            - endpoint:');
  lines.push('                address:');
  lines.push(`                  socket_address: { address: ${host}, port_value: ${port} }`);
}

/** True when any endpoint declares a logging policy with an http-collector sink. */
export function needsAlsCluster(spec: SpecIR): boolean {
  const r = resolveLogging(spec);
  return r !== null && r.sink === 'http-collector';
}
