/**
 * W18-A: BFLA (admin-only rbac) defense class for the Envoy ext_authz + OPA
 * path. Split out of extauthz.ts (W20-B) to comply with Rule G-1.
 *
 * Owns:
 *   - isAdminOnlyRbac: classifier (single role == "admin")
 *   - collectBflaAdmin: spec → admin-only endpoints
 *   - emitBflaBranches: Rego decision-chain branches that emit opa-bfla-403
 *     when the principal's `role` claim != "admin".
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { ALLOW_LITERAL, type BranchEmitDeps } from './extauthz-rego-util.js';

export interface BflaEndpoint {
  endpoint: EndpointIR;
}

/**
 * W18-A: admin-only iff rbac roles == ["admin"]. Multi-role rbac routes
 * stay on the native rbac filter; admin-only routes are routed via OPA so
 * the opa-bfla-403 marker can fire on denial.
 */
export function isAdminOnlyRbac(ep: EndpointIR): boolean {
  const authz = ep.policy.authorization;
  if (!authz || authz.type !== 'rbac') return false;
  const roles = authz.roles ?? [];
  return roles.length === 1 && roles[0] === 'admin';
}

export function collectBflaAdmin(spec: SpecIR): BflaEndpoint[] {
  const out: BflaEndpoint[] = [];
  for (const ep of spec.endpoints) {
    if (isAdminOnlyRbac(ep)) out.push({ endpoint: ep });
  }
  return out;
}

/** Emit BFLA admin-only branches into the shared lines[]. */
export function emitBflaBranches(items: BflaEndpoint[], d: BranchEmitDeps): void {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) return a.endpoint.method.localeCompare(b.endpoint.method);
    return a.endpoint.path.localeCompare(b.endpoint.path);
  });

  for (const item of sorted) {
    const method = item.endpoint.method.toUpperCase();
    const pathRegex = d.pathToRegoRegex(item.endpoint.path);
    const matchClauses = [
      `    input.attributes.request.http.method == ${d.regoString(method)}`,
      `    regex.match(${d.regoString(pathRegex)}, input.attributes.request.http.path)`
    ];
    d.lines.push(`# ${item.endpoint.method} ${item.endpoint.path} — rbac admin-only (W18-A BFLA)`);
    // Permit: principal role == "admin".
    d.pushBranch(
      [
        ...matchClauses,
        '    token := bearer_token',
        '    [_, payload, _] := io.jwt.decode(token)',
        '    payload["role"] == "admin"'
      ],
      ALLOW_LITERAL
    );
    // Deny: same path/method, role missing or != admin.
    d.pushBranch(matchClauses, d.denyLiteral('bfla'));
    d.lines.push('');
  }
}
