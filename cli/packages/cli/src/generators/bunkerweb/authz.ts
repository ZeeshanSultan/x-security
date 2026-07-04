/**
 * RBAC multi-role SecRules — closes drift on `authorization.type=rbac` with
 * 2+ roles (`id-aware` capability).
 *
 * Trust contract: an upstream identity layer (OIDC sidecar, oauth2-proxy,
 * Kong+OIDC) sets `X-Forwarded-Groups: role1,role2` on verified requests.
 * If the header is absent OR none of the spec-declared roles appears in it,
 * we deny 403.
 *
 * Single-role RBAC is already handled by Coraza-style identity rules emitted
 * elsewhere; this module specifically lifts the multi-role case that the
 * stricter `@streq` single-value pattern cannot express.
 *
 * Rule ID range: 970600-970699 (sibling of the lifecycle 970500-block; both
 * sit inside the identity 970000-979999 space but in slots the standard
 * identity emitter never touches).
 */

import type { EndpointIR } from '@writ/core';

const RBAC_BASE_ID = 970600;
const TRUSTED_GROUPS_HEADER = 'X-Forwarded-Groups';

function escMsec(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}

function pathRegex(p: string): string {
  const parts = p.split('/').filter((s) => s.length > 0);
  const rebuilt = parts
    .map((seg) => {
      if (/^\{[^}]+\}$/.test(seg)) return '[^/]+';
      return seg.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return `^/${rebuilt}$`;
}

function slotIdFor(method: string, path: string): number {
  let h = 0;
  const s = `${method} ${path}`;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  // Spread across 50 slots; pair-of-rules per endpoint (missing + non-role) → 2*slot.
  return (Math.abs(h) % 50) * 2;
}

/** Validate role token shape — must be safe for inclusion in @rx args. */
function isLegalRoleToken(role: string): boolean {
  return /^[A-Za-z0-9_.\-:]+$/.test(role);
}

/**
 * Emit multi-role RBAC SecRules for one endpoint. Returns an empty array
 * unless authorization.type === 'rbac' AND roles.length >= 2 AND all roles
 * pass the token-shape check.
 */
export function buildAuthzMultiRoleRules(endpoint: EndpointIR): string[] {
  const authz = endpoint.policy.authorization;
  if (!authz || authz.type !== 'rbac') return [];
  const roles = authz.roles ?? [];
  if (roles.length < 2) return [];
  const safeRoles = roles.filter(isLegalRoleToken);
  if (safeRoles.length !== roles.length) return [];

  const pathRx = pathRegex(endpoint.path);
  const base = RBAC_BASE_ID + slotIdFor(endpoint.method, endpoint.path);
  const idMissing = base;
  const idNoMatch = base + 1;
  // Build an alternation rx that matches a CSV groups header with ANY allowed role.
  // Boundaries: start-of-string, end-of-string, or comma either side.
  // Example: "(?:^|,)(?:admin|operator)(?:,|$)"
  const altRx = `(?:^|,)(?:${safeRoles.map((r) => r.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?:,|$)`;
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rolesStr = safeRoles.join(',');

  const lines: string[] = [];

  // Case (a): X-Forwarded-Groups header absent → deny 403.
  lines.push(
    [
      `# Writ-generated authorization rules (rbac multi-role: ${rolesStr})`,
      `# Source: ${endpoint.method} ${endpoint.path}`,
      `# Chain on X-Forwarded-Groups (set by upstream OIDC sidecar / Kong+OIDC).`,
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${idMissing},phase:1,deny,status:403,log,auditlog,msg:'Writ rbac-multi-role denied (no ${TRUSTED_GROUPS_HEADER} header)',tag:'${escMsec(tag)}',tag:'writ-rule-rbac-multi-role',chain"`,
      `  SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "chain"`,
      `    SecRule &REQUEST_HEADERS:${TRUSTED_GROUPS_HEADER} "@eq 0" "t:none"`,
    ].join('\n')
  );

  // Case (b): header present but none of the allowed roles appears in the CSV.
  lines.push(
    [
      `# Writ-generated authorization rules (rbac multi-role: ${rolesStr})`,
      `# Source: ${endpoint.method} ${endpoint.path}`,
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${idNoMatch},phase:1,deny,status:403,log,auditlog,msg:'Writ rbac-multi-role denied (${TRUSTED_GROUPS_HEADER} lacks any of: ${escMsec(rolesStr)})',tag:'${escMsec(tag)}',tag:'writ-rule-rbac-multi-role',chain"`,
      `  SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "chain"`,
      `    SecRule REQUEST_HEADERS:${TRUSTED_GROUPS_HEADER} "!@rx ${escRx(altRx)}" "t:none"`,
    ].join('\n')
  );

  return lines;
}

export const __test = {
  RBAC_BASE_ID,
  TRUSTED_GROUPS_HEADER,
  pathRegex,
  slotIdFor,
  isLegalRoleToken,
};
