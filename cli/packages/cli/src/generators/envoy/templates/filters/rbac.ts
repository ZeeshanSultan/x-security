/**
 * envoy.filters.http.rbac — native role-based authorization.
 *
 * Principal sourced from jwt_authn payload metadata (`role` claim). Admin-only
 * rbac routes are routed through OPA (ext_authz) instead of the native rbac
 * filter so the `opa-bfla-403` marker can fire on denial — see extauthz.ts.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { isAdminOnlyRbac } from '../extauthz.js';
import { pathToSafeRegex, safeStatId, yamlString } from '../yaml-util.js';

export interface RbacEntry {
  endpoint: EndpointIR;
  roles: string[];
}

export function collectRbacEndpoints(spec: SpecIR): RbacEntry[] {
  const out: RbacEntry[] = [];
  for (const ep of spec.endpoints) {
    const authz = ep.policy.authorization;
    if (!authz) continue;
    if (authz.type === 'rbac' && authz.roles && authz.roles.length) {
      // W18-A: admin-only rbac routes are routed through OPA (ext_authz)
      // instead of the native rbac filter so the `opa-bfla-403` marker can
      // fire on denial. Multi-role rbac routes stay on the native filter
      // because a non-admin principal can legitimately reach them.
      if (isAdminOnlyRbac(ep)) continue;
      out.push({ endpoint: ep, roles: authz.roles });
    }
  }
  return out;
}

export function emitRbacFilter(lines: string[], rbac: RbacEntry[], jwtName: string | null): void {
  if (!rbac.length || !jwtName) return;
  lines.push('  - name: envoy.filters.http.rbac');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC');
  lines.push('      rules:');
  lines.push('        action: ALLOW');
  lines.push('        policies:');
  // Aggregate unique role sets so we emit one policy per distinct (path, role).
  for (const entry of rbac) {
    for (const role of entry.roles) {
      const polName = `writ-rbac-${safeStatId(entry.endpoint)}-${role.replace(/[^a-z0-9]+/gi, '-')}`;
      lines.push(`          ${yamlString(polName)}:`);
      lines.push('            permissions:');
      lines.push('              - url_path:');
      lines.push('                  path:');
      lines.push(`                    safe_regex: { regex: ${yamlString(pathToSafeRegex(entry.endpoint.path))} }`);
      lines.push('            principals:');
      lines.push('              - metadata:');
      lines.push(`                  filter: envoy.filters.http.jwt_authn`);
      lines.push(`                  path: [{ key: ${yamlString(jwtName)} }, { key: "role" }]`);
      lines.push(`                  value: { string_match: { exact: ${yamlString(role)} } }`);
    }
  }
}
