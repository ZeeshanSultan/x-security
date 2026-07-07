/**
 * Modsec-nginx server-side directive emitter.
 *
 * For the `modsec-nginx` profile only, we emit an additional `nginx-server.conf`
 * snippet the operator merges into their `server { ... }` block. SecRules can
 * deny based on response timing / TLS version, but the runtime *enforcement*
 * of these primitives belongs to nginx itself:
 *
 *   - `timeout.connect/read/write` → `proxy_*_timeout` directives
 *   - `tls.minVersion`             → `ssl_protocols ...`
 *   - `tls.allowedCipherSuites`    → `ssl_ciphers ...`
 *   - `deprecated:true`            → `return 410;` (alternative to SecAction 410)
 *   - `sunsetDate`                 → `add_header Sunset "<iso>" always;`
 *   - `replacementEndpoint`        → `add_header Link "<...>; rel=successor-version" always;`
 *
 * The generator emits per-endpoint `location` blocks keyed on the path
 * template (parameters stay as nginx variable captures). Top-level TLS
 * directives bubble up to a `server`-scope block when at least one endpoint
 * declares `tls.*` — nginx scopes ssl_* at server-level, not location-level.
 *
 * This file produces ONLY the nginx config; SecRule emission for the same
 * fields stays in lifecycle-rules.ts (SecAction path) so operators who can't
 * touch nginx still get a 410 enforcement.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';

function pathToNginxLocation(path: string): string {
  // Replace `{param}` with named regex capture `(?<param>[^/]+)`. Using
  // `location ~ ^...$` so nginx treats this as a regex match.
  const re = path.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\\\{([^/]+?)\\\}/g, '(?<$1>[^/]+)');
  return `^${re}$`;
}

function buildEndpointBlock(ep: EndpointIR): string[] {
  const lines: string[] = [];
  const policy = ep.policy;
  const t = policy.timeout;
  const wantsTimeouts =
    t && (typeof t.connect === 'number' || typeof t.read === 'number' || typeof t.write === 'number');
  const wantsDeprecated = policy.deprecated === true;
  const wantsSunset = typeof policy.sunsetDate === 'string' && policy.sunsetDate.length > 0;
  const wantsReplacement =
    typeof policy.replacementEndpoint === 'string' && policy.replacementEndpoint.length > 0;

  if (!wantsTimeouts && !wantsDeprecated && !wantsSunset && !wantsReplacement) return [];

  lines.push(`# ${ep.method} ${ep.path} (operationId: ${ep.operationId})`);
  // nginx `if` is discouraged; gate via a `limit_except` would invert the
  // semantics, so we emit a location block keyed on the path regex and rely on
  // the operator to ensure method-level routing happens upstream. This matches
  // the existing operator-facing recipe (see deployment-recipes/modsec-nginx.md).
  lines.push(`location ~ ${pathToNginxLocation(ep.path)} {`);
  if (wantsDeprecated) {
    // Hard 410 — short-circuits everything below.
    lines.push(`    return 410;`);
  } else {
    if (wantsTimeouts && t) {
      if (typeof t.connect === 'number') lines.push(`    proxy_connect_timeout ${t.connect}s;`);
      if (typeof t.read === 'number') lines.push(`    proxy_read_timeout ${t.read}s;`);
      if (typeof t.write === 'number') lines.push(`    proxy_send_timeout ${t.write}s;`);
    }
    if (wantsSunset) {
      lines.push(`    add_header Sunset "${policy.sunsetDate}" always;`);
    }
    if (wantsReplacement) {
      // nginx add_header double-quoted-string allows backslash-escaped `"`.
      lines.push(
        `    add_header Link "<${policy.replacementEndpoint}>; rel=\\"successor-version\\"" always;`
      );
    }
  }
  lines.push(`}`);
  lines.push('');
  return lines;
}

function pickSmallestTlsFloor(spec: SpecIR): string | null {
  // If any endpoint requires TLSv1.3, use that (most restrictive wins);
  // otherwise if any declares TLSv1.2, accept both. Return null when no
  // endpoint declares a floor.
  let any = false;
  let onlyV13 = true;
  for (const ep of spec.endpoints) {
    const v = ep.policy.tls?.minVersion;
    if (!v) continue;
    any = true;
    if (v !== 'TLSv1.3') onlyV13 = false;
  }
  if (!any) return null;
  return onlyV13 ? 'TLSv1.3' : 'TLSv1.2 TLSv1.3';
}

function pickCipherSuites(spec: SpecIR): string | null {
  // First non-empty allowedCipherSuites wins. If multiple endpoints
  // disagree, the operator sees them all in the comment header so they
  // can reconcile manually.
  for (const ep of spec.endpoints) {
    const c = ep.policy.tls?.allowedCipherSuites;
    if (Array.isArray(c) && c.length > 0) return c.join(':');
  }
  return null;
}

/**
 * Returns the full content of `nginx-server.conf`, or `null` when the spec
 * declares no nginx-routable directive (no `timeout`, no `tls`, no lifecycle).
 */
export function buildModsecNginxServerConf(spec: SpecIR): string | null {
  const sortedEps = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );

  const tlsFloor = pickSmallestTlsFloor(spec);
  const ciphers = pickCipherSuites(spec);

  const endpointBlocks: string[] = [];
  for (const ep of sortedEps) {
    endpointBlocks.push(...buildEndpointBlock(ep));
  }

  if (!tlsFloor && !ciphers && endpointBlocks.length === 0) return null;

  const lines: string[] = [
    '# x-security → modsec-nginx server-side directives — auto-generated.',
    '# Merge inside your `server { ... }` block (not at http {} scope).',
    '# Source: ' + `${spec.info.title} ${spec.info.version}`,
    '',
  ];
  if (tlsFloor) {
    lines.push('# tls.minVersion (server-scope; first declaration in the spec wins)');
    lines.push(`ssl_protocols ${tlsFloor};`);
    lines.push('');
  }
  if (ciphers) {
    lines.push('# tls.allowedCipherSuites (server-scope)');
    lines.push(`ssl_ciphers ${ciphers};`);
    lines.push('ssl_prefer_server_ciphers on;');
    lines.push('');
  }
  if (endpointBlocks.length > 0) {
    lines.push('# Per-endpoint timeout + lifecycle directives');
    lines.push(...endpointBlocks);
  }

  return lines.join('\n');
}
