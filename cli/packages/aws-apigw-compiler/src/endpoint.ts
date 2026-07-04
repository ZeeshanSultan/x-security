import { createHash } from 'node:crypto';

/**
 * Per-endpoint stable hash. Mirrors cloudflare-compiler/endpoint.ts so the
 * same endpoint produces matching IDs across compilers, easing cross-target
 * comparison in the UI.
 */
export function endpointHash(method: string, path: string): string {
  const normalized = `${method.toUpperCase()} ${normalizePath(path)}`;
  return createHash('sha256').update(normalized).digest('hex').slice(0, 12);
}

export function endpointId(method: string, path: string): string {
  return `${method.toUpperCase()}_${normalizePath(path)}`;
}

/** Sanitized name segment safe for AWS resource names (max 128 chars). */
export function endpointNameSegment(method: string, path: string): string {
  const raw = `${method.toUpperCase()}-${normalizePath(path)}`;
  return raw.replace(/[^A-Za-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}

export function normalizePath(path: string): string {
  let p = path.replace(/\/+/g, '/');
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  if (!p.startsWith('/')) p = '/' + p;
  return p;
}

/**
 * Build a regex that matches the path (with OpenAPI `{param}` templates expanded).
 * Used inside ByteMatchStatement / RegexPatternSetReferenceStatement.
 *
 * Examples:
 *   /users           → ^/users$
 *   /users/{id}      → ^/users/[^/]+$
 */
export function pathMatchRegex(path: string): string {
  const p = normalizePath(path);
  if (!p.includes('{')) {
    // Escape regex metachars for literal match
    return '^' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
  }
  return (
    '^' +
    p
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\\\{[^}]+\\\}/g, '[^/]+') +
    '$'
  );
}
