import { createHash } from 'node:crypto';

/**
 * Stable per-endpoint hash. Method + path template, normalized.
 * Used as the basis for rule IDs so the same endpoint always produces the
 * same rule IDs across compilations.
 */
export function endpointHash(method: string, path: string): string {
  const normalized = `${method.toUpperCase()} ${normalizePath(path)}`;
  return createHash('sha256').update(normalized).digest('hex').slice(0, 12);
}

export function endpointId(method: string, path: string): string {
  return `${method.toUpperCase()}_${normalizePath(path)}`;
}

function normalizePath(path: string): string {
  // Collapse repeated slashes, strip trailing slash (except root)
  let p = path.replace(/\/+/g, '/');
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  if (!p.startsWith('/')) p = '/' + p;
  return p;
}

/**
 * Build a Cloudflare Firewall Rule Language expression matching the request
 * path template. OpenAPI path templates use `{id}` parameters; CF doesn't
 * understand those, so we translate each `{param}` into a regex segment.
 *
 * Examples:
 *   /users           → http.request.uri.path eq "/users"
 *   /users/{id}      → http.request.uri.path matches "^/users/[^/]+$"
 *   /a/{x}/b/{y}     → http.request.uri.path matches "^/a/[^/]+/b/[^/]+$"
 */
export function pathMatchExpression(path: string): string {
  const p = normalizePath(path);
  if (!p.includes('{')) {
    return `http.request.uri.path eq "${escapeStr(p)}"`;
  }
  const regex = '^' + p.replace(/\{[^}]+\}/g, '[^/]+').replace(/\./g, '\\.') + '$';
  return `http.request.uri.path matches "${escapeStr(regex)}"`;
}

export function methodMatchExpression(method: string): string {
  return `http.request.method eq "${method.toUpperCase()}"`;
}

export function escapeStr(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
