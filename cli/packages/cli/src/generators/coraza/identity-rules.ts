/**
 * B1: Identity-aware authorization SecRules (BOLA / BFLA).
 *
 * Lifts the W13-C hand-crafted rules at
 * `e2e/fixtures/chain-coraza-spoa-vapi/haproxy/x-security-identity.conf`
 * into generator emission, gated on `x-security.authorization` primitives.
 *
 * Trust contract (set upstream by HAProxy / API gateway):
 *
 *   X-Forwarded-User: <jwt.sub>    iff the bearer token verified
 *
 * If the header is absent, the upstream auth gate already returned 401
 * before Coraza saw the request. If it is PRESENT, Coraza trusts it
 * (the gateway is responsible for stripping client-supplied values).
 *
 * Rule-ID range 970000–979999 is reserved for identity rules so they
 * cannot collide with the generator's per-endpoint primary range
 * (100000–369999) or any other category. The W13-C identity-conf used
 * fixed IDs 970010/11/20/21 — slot 0 of this scheme reproduces those
 * exactly, so the chain fixture remains byte-comparable after dedup.
 *
 *   base   = 970000 + (endpointHash % 100) * 100
 *   +10    BOLA-read     (GET   path-id != principal)
 *   +11    BOLA-update   (PUT   path-id != principal)
 *   +20    BFLA-missing  (role route, no X-Forwarded-User)
 *   +21    BFLA-non-role (role route, X-Forwarded-User != allowed role)
 */

import type { EndpointIR } from '@x-security/core';
import type { Authorization, AuthorizationRule, RuleRef } from '@x-security/schema';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash } from './rules.js';

const IDENTITY_BASE_ID = 970000;
const IDENTITY_SLOT_STRIDE = 100;
const IDENTITY_SLOT_COUNT = 100;

const TRUSTED_PRINCIPAL_HEADER = 'X-Forwarded-User';

/** Refs the generator treats as "the authenticated principal id". */
const PRINCIPAL_REFS = new Set([
  'principal.id',
  'principal.sub',
  'jwt.sub',
]);

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** Escape a regex for inclusion as an `@rx` arg (no backslash doubling). */
function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment
    .split('\n')
    .map((l) => `# ${l}`)
    .join('\n');
}

/** Per-endpoint base ID inside the identity range. */
function identityBase(endpoint: EndpointIR): number {
  const slot = endpointHash(endpoint.method, endpoint.path) % IDENTITY_SLOT_COUNT;
  return IDENTITY_BASE_ID + slot * IDENTITY_SLOT_STRIDE;
}

function isRuleRef(v: AuthorizationRule['value']): v is RuleRef {
  return typeof v === 'object' && v !== null && 'ref' in (v as object);
}

/**
 * Pick the path-parameter name whose value must equal the principal id.
 * Returns the param name (e.g. "id") or null if no such rule is declared.
 *
 * Recognised rule shape:
 *   { field: "request.params.<name>", operator: "equals", value: { ref: "principal.id" } }
 */
function findOwnershipParam(authz: Authorization | undefined): string | null {
  if (!authz?.rules) return null;
  for (const r of authz.rules) {
    if (r.operator !== 'equals') continue;
    if (!isRuleRef(r.value)) continue;
    if (!PRINCIPAL_REFS.has(r.value.ref)) continue;
    const m = /^request\.params\.([A-Za-z0-9_-]+)$/.exec(r.field);
    if (m) return m[1]!;
    // W24 vAPI integration: spec form `field: resource.<name>` combined with
    // a resourceLookup whose identifierFrom is `request.params.<param>` is
    // semantically "path-id IS owner-id" — the same simplification W13-C
    // made by hand. Coraza can't perform the runtime resource fetch the
    // resourceLookup implies, but the deny condition (path-id != principal)
    // is the safe-by-default approximation.
    if (/^resource\.[A-Za-z0-9_]+$/.test(r.field) && authz.resourceLookup) {
      const idFrom = authz.resourceLookup.identifierFrom;
      if (typeof idFrom === 'string') {
        const pm = /^request\.params\.([A-Za-z0-9_-]+)$/.exec(idFrom);
        if (pm) return pm[1]!;
      }
    }
  }
  return null;
}

/**
 * Required role for BFLA enforcement. We emit only when `authorization.roles`
 * has exactly one entry — multi-role membership requires upstream resolution
 * (group claims, RBAC service) that a static SecRule cannot express. If
 * multiple roles are declared we leave a warning to the caller (handled by
 * returning null; caller may surface it).
 */
function findRequiredRole(authz: Authorization | undefined): string | null {
  if (!authz?.roles) return null;
  if (authz.roles.length !== 1) return null;
  const role = authz.roles[0];
  if (typeof role !== 'string' || role.length === 0) return null;
  // SecRule arg uses @streq which is byte-exact; reject anything that would
  // need quoting or break the rule arg.
  if (!/^[A-Za-z0-9_.\-]+$/.test(role)) return null;
  return role;
}

/**
 * BOLA pair: per-resource ownership. Path-param value must equal the
 * principal id carried in X-Forwarded-User. Emitted only for GET / PUT /
 * PATCH / DELETE / POST methods that touch a parameterised resource.
 *
 * Path regex accepts both `/{prefix}/...` and a bare-mount equivalent
 * (e.g. `/vapi/api1/user/{id}` and `/api1/user/{id}`) so a single rule
 * covers the gateway-prefixed and gateway-unprefixed shapes the chain
 * uses. The optional prefix is the first path segment (no slashes inside).
 *
 * Capture group 1 is the resource id segment; TX:1 is compared
 * case-sensitively against the principal header.
 */
function buildBolaRule(
  endpoint: EndpointIR,
  param: string,
  method: string,
  ruleId: number,
  kind: 'read' | 'update',
  profile: CorazaEngineProfile
): string | null {
  const paramToken = `{${param}}`;
  if (!endpoint.path.includes(paramToken)) return null;

  // Replace only the target param with a capture group; other path-params
  // (e.g. /api3/user/{id}/order/{oid}) become a non-capturing `[^/]+`.
  // The leading anchor accepts an optional gateway prefix segment so the
  // rule matches both `/vapi/api1/user/123` and `/api1/user/123`. Trailing
  // anchor is loose (allow `?…`) because REQUEST_URI carries the query
  // string on libmodsec3; we only need the path to match up to the param.
  const parts = endpoint.path.split('/').filter((p) => p.length > 0);
  const rebuilt = parts
    .map((seg) => {
      const m = /^\{([^}]+)\}$/.exec(seg);
      if (!m) return seg.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
      return m[1] === param ? '([^/?]+)' : '[^/]+';
    })
    .join('/');
  const captureRx = `^(?:/[^/]+)?/${rebuilt}(?:[/?]|$)`;

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const term = profile.legalCollections.has('user') ? '' : ' "t:none"';

  return [
    header(
      `B1: BOLA-${kind} — ${method} ${endpoint.path} requires path.${param} == ${TRUSTED_PRINCIPAL_HEADER}\n` +
        `lifted from W13-C identity-conf; emitted because authorization.rules\n` +
        `declares request.params.${param} equals principal.id (BOLA defense).`
    ),
    `SecRule REQUEST_METHOD "@streq ${method}" "id:${ruleId},phase:1,deny,status:403,log,auditlog,msg:'x-security B1: BOLA-${kind} denied (path-${param} != ${TRUSTED_PRINCIPAL_HEADER})',tag:'${esc(tag)}',tag:'x-security/b1/bola-${kind}',chain"`,
    `  SecRule REQUEST_URI "@rx ${escRx(captureRx)}" "capture,chain"`,
    `    SecRule TX:1 "!@streq %{REQUEST_HEADERS.${TRUSTED_PRINCIPAL_HEADER}}"${term}`,
  ].join('\n');
}

/**
 * BFLA pair: collection route restricted to a single role. Emits two
 * siblings because Coraza chained SecRules cannot express (header-absent
 * OR header-non-matching) in one rule — `!@streq` on a missing collection
 * variable silently fails.
 *
 * Path regex matches the endpoint path AND the same path with one extra
 * leading segment (gateway-mount tolerant; see buildBolaRule). We also
 * accept trailing `/`, `?`, or end-of-string so query strings don't
 * defeat the anchor.
 */
function buildBflaRules(
  endpoint: EndpointIR,
  role: string,
  baseId: number,
  profile: CorazaEngineProfile
): string[] {
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const term = profile.legalCollections.has('user') ? '' : ' "t:none"';

  const escapedPath = endpoint.path.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withParams = escapedPath.replace(/\\\{[^/]+?\\\}/g, '[^/]+');
  const pathRx = `^(?:/[^/]+)?${withParams}(?:[/?]|$)`;

  const idMissing = baseId + 20;
  const idNonRole = baseId + 21;

  return [
    [
      header(
        `B1: BFLA — ${endpoint.method} ${endpoint.path} requires ${TRUSTED_PRINCIPAL_HEADER} == '${role}'\n` +
          `case (a): no authenticated principal. Upstream gate should have\n` +
          `returned 401, but we deny defensively in case the gate is bypassed.`
      ),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${idMissing},phase:1,deny,status:403,log,auditlog,msg:'x-security B1: BFLA denied (${role}-only route, no authenticated principal)',tag:'${esc(tag)}',tag:'x-security/b1/bfla',chain"`,
      `  SecRule REQUEST_URI "@rx ${escRx(pathRx)}" "chain"`,
      `    SecRule &REQUEST_HEADERS:${TRUSTED_PRINCIPAL_HEADER} "@eq 0"${term}`,
    ].join('\n'),
    [
      header(
        `B1: BFLA — ${endpoint.method} ${endpoint.path}\n` +
          `case (b): authenticated but ${TRUSTED_PRINCIPAL_HEADER} != '${role}'.`
      ),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${idNonRole},phase:1,deny,status:403,log,auditlog,msg:'x-security B1: BFLA denied (${role}-only route, non-${role} principal)',tag:'${esc(tag)}',tag:'x-security/b1/bfla',chain"`,
      `  SecRule REQUEST_URI "@rx ${escRx(pathRx)}" "chain"`,
      `    SecRule REQUEST_HEADERS:${TRUSTED_PRINCIPAL_HEADER} "!@streq ${role}" "t:none"`,
    ].join('\n'),
  ];
}

/** Method → BOLA rule-id offset + kind. */
const BOLA_METHOD_MAP: Record<string, { offset: number; kind: 'read' | 'update' }> = {
  GET: { offset: 10, kind: 'read' },
  PUT: { offset: 11, kind: 'update' },
  PATCH: { offset: 11, kind: 'update' },
  DELETE: { offset: 11, kind: 'update' },
};

/**
 * Public entry: emit identity-aware authorization SecRules for one endpoint.
 *
 * - BOLA: requires authorization.rules with operator=equals,
 *   field=request.params.<name>, value={ref: "principal.id"|"jwt.sub"|"principal.sub"}.
 *   Emits one SecRule for the endpoint's method (GET → 970x10, PUT/PATCH/DELETE → 970x11).
 *
 * - BFLA: requires authorization.roles to have exactly one entry.
 *   Emits the missing-principal + non-role pair (970x20 + 970x21).
 *
 * The two are not mutually exclusive — an endpoint may declare both
 * (admin-only mutation on a resource), in which case all four rules emit.
 */
export function buildIdentityRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const authz = endpoint.policy.authorization;
  if (!authz) return [];
  const out: string[] = [];
  const base = identityBase(endpoint);

  const ownerParam = findOwnershipParam(authz);
  if (ownerParam) {
    const mapping = BOLA_METHOD_MAP[endpoint.method];
    if (mapping) {
      const r = buildBolaRule(
        endpoint,
        ownerParam,
        endpoint.method,
        base + mapping.offset,
        mapping.kind,
        profile
      );
      if (r) out.push(r);
    }
  }

  const role = findRequiredRole(authz);
  if (role) {
    out.push(...buildBflaRules(endpoint, role, base, profile));
  }

  return out;
}

export const __test = {
  identityBase,
  findOwnershipParam,
  findRequiredRole,
  IDENTITY_BASE_ID,
  IDENTITY_SLOT_STRIDE,
  TRUSTED_PRINCIPAL_HEADER,
};
