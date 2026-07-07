/**
 * Rego emission primitives shared across the per-class extauthz modules.
 *
 * Split out of extauthz.ts (W20-B) to comply with Rule G-1's 500-line cap.
 * Holds:
 *   - OPA wiring constants (cluster name, port, decision path, generator version)
 *   - Rego literal helpers (regoString, escapeRegex, pathToRegoRegex,
 *     paramSplitIndex)
 *   - Decision-object literals (denyLiteral, ALLOW_LITERAL)
 *
 * Pure functions / constants — no side effects, no I/O.
 */

export const VERSION = '0.4.0';
export const OPA_CLUSTER = 'opa_grpc';
export const OPA_PORT = 9191;

/**
 * OPA decision path (envoy_ext_authz_grpc plugin `path` setting).
 *
 * Wave-17 changes this from `envoy/authz/allow` (boolean) to
 * `envoy/authz/allow` returning an *object*. The plugin recognizes either
 * shape; we keep the path stable so the chain harness doesn't need a
 * docker-compose change.
 */
export const OPA_DECISION_PATH = 'envoy/authz/allow';

/** Escape a string for safe interpolation into a Rego double-quoted literal. */
export function regoString(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** OpenAPI path template → Rego regex for `regex.match`. */
export function pathToRegoRegex(path: string): string {
  const parts: string[] = [];
  let i = 0;
  while (i < path.length) {
    const open = path.indexOf('{', i);
    if (open === -1) { parts.push(escapeRegex(path.slice(i))); break; }
    if (open > i) parts.push(escapeRegex(path.slice(i, open)));
    const close = path.indexOf('}', open + 1);
    if (close === -1) { parts.push(escapeRegex(path.slice(open))); break; }
    parts.push('[^/]+');
    i = close + 1;
  }
  return '^' + parts.join('') + '$';
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Find the segment index of {paramName} via split("/")[k] (k is 1-based after leading /). */
export function paramSplitIndex(path: string, paramName: string): number | null {
  const parts = path.split('/'); // first element is "" because of leading /
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === `{${paramName}}`) return i;
  }
  return null;
}

/** Rego object literal for the OPA-Envoy DeniedHttpResponse. */
export function denyLiteral(ruleClass: string): string {
  const marker = `opa-${ruleClass}-403`;
  return [
    '{',
    `    "allowed": false,`,
    `    "http_status": 403,`,
    `    "headers": {"x-x-security-rule": ${regoString(marker)}},`,
    `    "body": ${regoString(marker)}`,
    '  }'
  ].join('\n  ');
}

export const ALLOW_LITERAL = '{"allowed": true}';

/** Shared shape used by per-class emitters to splice branches into the chain. */
export interface BranchEmitDeps {
  regoString: (s: string) => string;
  pathToRegoRegex: (path: string) => string;
  denyLiteral: (cls: string) => string;
  pushBranch: (body: string[] | null, value: string) => void;
  lines: string[];
}
