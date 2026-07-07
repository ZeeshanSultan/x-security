/**
 * Shared YAML emission helpers for the Envoy bootstrap builder.
 *
 * These helpers are byte-stability-critical — every per-filter emitter calls
 * into them, and the golden snapshot at fixtures/configs/envoy/example.expected.yaml
 * pins their exact output.
 */

import type { EndpointIR } from '@x-security/core';

/** YAML double-quote a string. */
export function yamlString(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/**
 * Build an Envoy path-matcher (route match block) from an OpenAPI path
 * template. We use a safe_regex match so `{id}` segments become `[^/]+`. The
 * leading slash and segments are escaped where they contain regex-magic
 * characters (period, etc.).
 */
export function pathToSafeRegex(path: string): string {
  const parts: string[] = [];
  let i = 0;
  while (i < path.length) {
    const open = path.indexOf('{', i);
    if (open === -1) {
      parts.push(escapeRegex(path.slice(i)));
      break;
    }
    if (open > i) parts.push(escapeRegex(path.slice(i, open)));
    const close = path.indexOf('}', open + 1);
    if (close === -1) {
      parts.push(escapeRegex(path.slice(open)));
      break;
    }
    parts.push('[^/]+');
    i = close + 1;
  }
  return '^' + parts.join('') + '$';
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Coerce schema StringOrVarRef into a plain string (refs are pre-resolved by loadSpec). */
export function asString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  // Unresolved refs leak through as the literal `${VAR}` token when the spec
  // was loaded with strict=false. We treat that as "no value" so the caller
  // omits the field rather than emitting a placeholder Envoy will reject.
  if (/^\$\{[^}]+\}$/.test(value.trim())) return null;
  return value;
}

/** Stable identifier derived from an endpoint, used as a stat_prefix suffix. */
export function safeStatId(ep: EndpointIR): string {
  return (ep.operationId || `${ep.method}_${ep.path}`)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

/** Extract host + port from a URL string. Returns null on parse failure. */
export function urlHostPort(uri: string): { host: string; port: number; useTls: boolean } | null {
  try {
    const u = new URL(uri);
    const useTls = u.protocol === 'https:';
    const port = u.port ? parseInt(u.port, 10) : useTls ? 443 : 80;
    return { host: u.hostname, port, useTls };
  } catch {
    return null;
  }
}
