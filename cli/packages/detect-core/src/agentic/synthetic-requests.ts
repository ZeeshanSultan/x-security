// Synthetic positive + negative request generators for V4.
//
// Strategy:
//   * Positive — pick a value satisfying every constraint on every schema'd
//     param. Substitute path templates, fill query/headers/body, attach a
//     valid Authorization header when authentication.type !== 'none', and a
//     Host header from request.allowedHosts[0] when set.
//   * Negative — violate exactly one constraint, picked in this priority:
//     pattern mismatch > range out-of-bounds > maxSize exceeded > missing
//     required > unknown field added > host mismatch > CRLF in header >
//     content-type denied > duplicate-param (when reject).
//   For type:string with no constraint (V3 should have caught), we inject
//   a SQLi/XSS payload to expose any V3 bypass.

import type {
  ParamSchema,
  XSecurityPolicy,
  SemanticType,
  AuthorizationRule,
  AuthorizationRuleValue,
} from '@x-security/schema';

import type { SyntheticRequest } from './policy-eval.js';
import type { RouteInventoryEntry } from './schema.js';
import { parseByteSize } from './policy-eval.js';

// --- authz round-trip support (E2) ----------------------------------------
//
// The synthetic principal a positive request authenticates as. Ownership rules
// of the form `request.<loc>.<field> == jwt.<claim>` pass when the request field
// equals the principal's claim. The negative flips that field to a DIFFERENT
// principal's value (DIFFERENT_OWNER) so a correct ownership rule blocks it.
const SYNTHETIC_PRINCIPAL: Record<string, unknown> = {
  sub: 'principal-self-0001',
  user_id: 'principal-self-0001',
  userId: 'principal-self-0001',
  id: 'principal-self-0001',
  username: 'selfuser',
  email: 'self@example.com',
  account: 'acct-self-0001',
  account_id: 'acct-self-0001',
  tenant: 'tenant-self-0001',
  org: 'org-self-0001',
  role: 'user',
};
const DIFFERENT_OWNER = 'principal-other-9999';

function isRuleRef(v: AuthorizationRuleValue): v is { ref: string } {
  return typeof v === 'object' && v !== null && !Array.isArray(v) &&
    typeof (v as { ref?: unknown }).ref === 'string';
}

/** The value the synthetic principal exposes for a `{ref:'jwt.<claim>'}`, so a
 *  `== jwt.<claim>` ownership rule's request field can be set to pass. */
function principalValueFor(ref: string): unknown {
  const parts = ref.split('.');
  const claim = parts.slice(1).join('.');
  if (claim && Object.prototype.hasOwnProperty.call(SYNTHETIC_PRINCIPAL, claim)) {
    return SYNTHETIC_PRINCIPAL[claim];
  }
  return SYNTHETIC_PRINCIPAL.sub;
}

interface AuthzFieldRef {
  loc: 'params' | 'path' | 'query' | 'body' | 'header';
  name: string;
  rule: AuthorizationRule;
}

/** Parse `request.<loc>.<name>` authz rule fields (resource.* / rbac are not
 *  request-settable, so they're excluded). */
function authzRequestFields(policy: XSecurityPolicy): AuthzFieldRef[] {
  const authz = policy.authorization;
  if (!authz || authz.type === 'rbac' || !authz.rules) return [];
  const out: AuthzFieldRef[] = [];
  for (const rule of authz.rules) {
    const parts = rule.field.split('.');
    if (parts[0] !== 'request') continue;
    const loc = parts[1];
    const name = parts.slice(2).join('.');
    if (!loc || !name) continue;
    if (loc === 'params' || loc === 'path' || loc === 'query' || loc === 'body' || loc === 'header') {
      out.push({ loc, name, rule });
    }
  }
  return out;
}

/** The value a request field must carry to SATISFY its ownership rule. For
 *  `== jwt.sub` that's the principal's sub; for a literal `equals`, the literal. */
function passValueForRule(rule: AuthorizationRule): unknown {
  if (isRuleRef(rule.value)) return principalValueFor(rule.value.ref);
  if (Array.isArray(rule.value)) return rule.value[0];
  return rule.value;
}

// --- positive value generators --------------------------------------------

const PRINTABLE_ALPHANUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

function repeatChar(c: string, n: number): string {
  return c.repeat(Math.max(0, n));
}

/** Generate a string of `n` chars satisfying a regex if we can; null otherwise. */
function regexCandidate(pattern: string, hintLen: number): string | null {
  // Quick wins: simple character-class + length quantifier patterns.
  // We try a few canned values first, then fall back to the hint.
  const candidates: string[] = [
    'abcdef12',
    'abcdefghij1234567890',
    '00000000-0000-4000-8000-000000000000',
    'a'.repeat(Math.max(1, hintLen)),
    '1'.repeat(Math.max(1, hintLen)),
    'ABC123',
  ];
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    return null;
  }
  for (const c of candidates) {
    if (re.test(c)) return c;
  }
  return null;
}

function positiveString(ps: ParamSchema): string {
  const min = ps.fixedLength ?? ps.minLength ?? 1;
  const max = ps.fixedLength ?? ps.maxLength ?? Math.max(min, 12);
  const target = Math.min(Math.max(min, 8), max);
  if (ps.pattern) {
    const c = regexCandidate(ps.pattern, target);
    if (c !== null) return c;
    // Fall through — generator returns its best guess; caller may reject.
  }
  return PRINTABLE_ALPHANUM.slice(0, target).padEnd(target, 'a').slice(0, target);
}

function positiveForType(ps: ParamSchema): unknown {
  const t = ps.type as SemanticType | undefined;
  switch (t) {
    case 'uuid':
      return '00000000-0000-4000-8000-000000000000';
    case 'email':
      return 'user@example.com';
    case 'url': {
      const dom = ps.domainAllowlist?.[0] ?? 'example.com';
      return `https://${dom}/x`;
    }
    case 'ip-address':
      return '10.0.0.1';
    case 'date':
      return '2026-01-01';
    case 'datetime':
      return '2026-01-01T00:00:00Z';
    case 'integer': {
      const lo = ps.min ?? 0;
      const hi = ps.max ?? lo + 100;
      const mid = Math.floor((lo + hi) / 2);
      return mid;
    }
    case 'float': {
      const lo = ps.min ?? 0;
      const hi = ps.max ?? lo + 100;
      return (lo + hi) / 2;
    }
    case 'boolean':
      return true;
    case 'phone':
      return '+15555550100';
    case 'name':
      return 'Alice';
    case 'binary':
      // body is generated externally; param value is irrelevant.
      return '';
    case 'free-text':
    case 'string':
    case undefined:
    default:
      return positiveString(ps);
  }
}

// --- path / route helpers -------------------------------------------------

/** Replace {name} or :name in a path template with substitutions. */
function substitutePath(
  template: string,
  paramValues: Record<string, unknown>,
): string {
  return template
    .replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, n) => {
      const v = paramValues[n];
      return v === undefined ? '_' : String(v);
    })
    .replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, (_m, n) => {
      const v = paramValues[n];
      return v === undefined ? '_' : String(v);
    });
}

function pathParamNames(template: string): Set<string> {
  const out = new Set<string>();
  for (const m of template.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
    if (m[1]) out.add(m[1]);
  }
  for (const m of template.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

const VALID_JWT =
  'Bearer aaaaaaaaaaaaa.bbbbbbbbbbbbb.cccccccccccccc';

function buildHeaders(policy: XSecurityPolicy): Record<string, string> {
  const headers: Record<string, string> = {};
  if (policy.authentication && policy.authentication.type !== 'none') {
    const name = policy.authentication.headerName || 'Authorization';
    if (policy.authentication.type === 'bearer-jwt' || policy.authentication.type === 'oauth2') {
      headers[name] = VALID_JWT;
    } else if (policy.authentication.type === 'api-key') {
      headers[name] = 'k_synthetic_abc123';
    } else if (policy.authentication.type === 'basic') {
      headers[name] = 'Basic dXNlcjpwYXNz';
    } else {
      headers[name] = VALID_JWT;
    }
  }
  return headers;
}

// --- positive --------------------------------------------------------------

export function generatePositive(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
  /**
   * Param names the route's HANDLER actually reads (handler-scoped, V4 fix D).
   * A legit request carries these even when the policy's schema under-enumerates
   * them. Including them lets V4 catch an under-enumerated denyUnknownFields
   * policy that would false-block its OWN handler-derived legit input — while a
   * mass-assignment field (bulk-assigned, never named-read) won't appear, so a
   * complete policy isn't falsely demoted.
   */
  handlerReadParams?: ReadonlySet<string>,
  /**
   * `ownershipAbsent` (E2): build the legit "omit-the-authz-field" variant —
   * authz-referenced body/query fields that are NOT in request.schema are left
   * ABSENT, modelling a legit request that omits an over-tight ownership field
   * (the dvrestaurant `PUT /profile` over-block). If a correct policy lets this
   * pass, the rule is request-required-coherent; if it blocks, V4 demotes.
   *
   * `omitBodyOwnershipFields` (iteration 2, FIX 1): a SUPERSET of the absent
   * probe for self-mutation routes (PUT/PATCH on /profile,/me,/account, or with
   * no other request-visible id). On such a route a legit self-update should not
   * need to name its own principal in the body, so we omit EVERY authz-referenced
   * body field — EVEN one made required in request.schema. Making the principal a
   * required body field IS the over-block; the schema's required-on-absence check
   * must not suppress the demote here.
   */
  opts?: { ownershipAbsent?: boolean; omitBodyOwnershipFields?: boolean },
): SyntheticRequest {
  const method = route.method.toUpperCase();
  const pathParams = pathParamNames(route.path);
  const schemas = policy.request?.schema ?? {};
  const ownershipAbsent = opts?.ownershipAbsent === true;
  const omitBodyOwnershipFields = opts?.omitBodyOwnershipFields === true;

  const headers = buildHeaders(policy);
  if (policy.request?.allowedHosts && policy.request.allowedHosts.length > 0) {
    headers['Host'] = policy.request.allowedHosts[0]!;
  }

  const query: Record<string, string | string[]> = {};
  const body: Record<string, unknown> = {};
  const pathSubs: Record<string, unknown> = {};

  // Whether the route looks like it carries a body (POST/PUT/PATCH/DELETE).
  const hasBody = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

  for (const [name, ps] of Object.entries(schemas)) {
    const v = positiveForType(ps);
    if (pathParams.has(name)) {
      pathSubs[name] = v;
      // Also expose path-param values via query so the evaluator (which has
      // no knowledge of the path template) can find them by name.
      query[name] = String(v);
      continue;
    }
    if (ps.type === 'binary') {
      // Binary fields live in the body; size handled below.
      continue;
    }
    if (hasBody) {
      body[name] = v;
    } else {
      query[name] = String(v);
    }
  }

  // Handler-derived legit inputs (fix D): a real request carries every field the
  // handler reads. Add those NOT already covered by the schema or the path. If
  // the policy is complete they're already in `schemas` (no-op); if it
  // under-enumerates a field the handler reads, this field exposes the gap —
  // under denyUnknownFields the evaluator blocks it → V4 demotes (too tight).
  if (handlerReadParams) {
    for (const name of handlerReadParams) {
      if (pathParams.has(name)) continue;
      if (Object.prototype.hasOwnProperty.call(schemas, name)) continue;
      const placeholder = 'x';
      if (hasBody) {
        if (!Object.prototype.hasOwnProperty.call(body, name)) body[name] = placeholder;
      } else if (!Object.prototype.hasOwnProperty.call(query, name)) {
        query[name] = placeholder;
      }
    }
  }

  // Authz round-trip (E2): for every request field an authorization rule
  // references, set it to the value that SATISFIES the rule so the legit
  // positive passes the ownership check. A field already in the schema is left
  // as-is unless the rule demands a specific principal-pinned value. In the
  // `ownershipAbsent` variant, a field NOT independently required by the schema
  // is left ABSENT (models a legit request that omits the over-tight field).
  for (const af of authzRequestFields(policy)) {
    const inSchema = Object.prototype.hasOwnProperty.call(schemas, af.name);
    const passVal = passValueForRule(af.rule);
    if (af.loc === 'params' || af.loc === 'path') {
      // path param: always present (route can't be addressed without it).
      pathSubs[af.name] = passVal;
      query[af.name] = String(passVal);
      continue;
    }
    if (af.loc === 'header') {
      if (ownershipAbsent && !inSchema) continue;
      headers[af.name] = String(passVal);
      continue;
    }
    // body / query field
    // FIX 1: on a self-mutation route, omit an authz-referenced BODY field even
    // when it IS required in request.schema — a legit self-update need not name
    // its own principal, so requiring it is itself the over-block.
    if (omitBodyOwnershipFields && af.loc === 'body') {
      delete body[af.name];
      continue;
    }
    if (ownershipAbsent && !inSchema) {
      // omit it — model the legit request that doesn't carry the field.
      if (hasBody) delete body[af.name];
      else delete query[af.name];
      continue;
    }
    if (hasBody) body[af.name] = passVal;
    else query[af.name] = String(passVal);
  }

  // Content-Type: choose the first allowed if specified; else json by default.
  if (policy.request?.contentType && policy.request.contentType.length > 0) {
    headers['Content-Type'] = policy.request.contentType[0]!;
  } else if (hasBody) {
    headers['Content-Type'] = 'application/json';
  }

  // Binary param handling — pick the first binary schema and use it for the
  // body. Use a size at most 1KB.
  let bodyBytes: number | undefined;
  for (const [, ps] of Object.entries(schemas)) {
    if (ps.type === 'binary') {
      bodyBytes = 1024;
      if (ps.allowedMimeTypes && ps.allowedMimeTypes.length > 0) {
        headers['Content-Type'] = ps.allowedMimeTypes[0]!;
      }
      break;
    }
  }

  if (bodyBytes === undefined && hasBody) {
    bodyBytes = JSON.stringify(body).length;
  }

  const substitutedPath = substitutePath(route.path, pathSubs);

  const req: SyntheticRequest = {
    method,
    path: substitutedPath,
    headers,
    query,
    remoteAddress: '10.0.0.1',
  };
  if (hasBody || bodyBytes !== undefined) {
    req.body = hasBody ? body : undefined;
    if (bodyBytes !== undefined) req.bodyBytes = bodyBytes;
  }
  // Attach the synthetic principal/resource so the evaluator can resolve
  // `{ref:'jwt.<claim>'}` and `resourceLookup` rules. The positive's principal
  // OWNS the resource (resourceLookup `resource.<owner> == jwt.sub` passes).
  const authz = policy.authorization;
  if (authz && authz.type !== 'rbac') {
    req.principal = { ...SYNTHETIC_PRINCIPAL };
    if (authz.resourceLookup) {
      req.resource = buildOwnedResource(authz.resourceLookup.expose);
    }
  }
  return req;
}

/** A synthetic resource whose exposed owner-ish fields equal the principal's,
 *  so a `resource.<owner> == jwt.sub` lookup rule passes for the positive. */
function buildOwnedResource(expose: string[] | undefined): Record<string, unknown> {
  const res: Record<string, unknown> = {};
  for (const f of expose ?? []) {
    const lc = f.toLowerCase();
    if (/(owner|user_?id|account|tenant|org|sub)/.test(lc)) {
      res[f] = SYNTHETIC_PRINCIPAL.sub;
    } else {
      res[f] = `res-${f}`;
    }
  }
  return res;
}

// --- negative --------------------------------------------------------------

/** Mutate a schema-passing value so it fails the schema in one specific way. */
function negativeForParam(
  ps: ParamSchema,
  positive: unknown,
): { value: unknown; constraint: string } | null {
  const t = ps.type as SemanticType | undefined;
  // Priority 1: pattern mismatch
  if (ps.pattern) {
    return { value: '!@#$%^&*()_+', constraint: `pattern:${ps.pattern}` };
  }
  // Priority 2: range out-of-bounds
  if ((t === 'integer' || t === 'float')) {
    if (typeof ps.max === 'number') {
      return { value: ps.max + 1000, constraint: `max:${ps.max}` };
    }
    if (typeof ps.min === 'number') {
      return { value: ps.min - 1000, constraint: `min:${ps.min}` };
    }
  }
  // Priority 3: length out-of-bounds (string-like only)
  if (t !== 'integer' && t !== 'float' && t !== 'boolean' && t !== 'binary') {
    if (typeof ps.maxLength === 'number') {
      return { value: 'a'.repeat(ps.maxLength + 50), constraint: `maxLength:${ps.maxLength}` };
    }
    if (typeof ps.minLength === 'number' && ps.minLength > 0) {
      return { value: '', constraint: `minLength:${ps.minLength}` };
    }
  }
  // Type-specific negatives.
  switch (t) {
    case 'uuid':
      return { value: 'not-a-uuid', constraint: 'type:uuid' };
    case 'email':
      return { value: 'not-an-email', constraint: 'type:email' };
    case 'url': {
      // SSRF (D2): a blockPrivateRanges url param's negative is the metadata
      // endpoint — a literal link-local host the evaluator must reject. This
      // exercises the SSRF block directly (proves the control bites).
      if (ps.blockPrivateRanges) {
        return { value: 'http://169.254.169.254/latest/meta-data/', constraint: 'blockPrivateRanges' };
      }
      if (ps.domainAllowlist && ps.domainAllowlist.length > 0) {
        return { value: 'https://evil.example.org/x', constraint: 'domainAllowlist' };
      }
      return { value: 'not-a-url', constraint: 'type:url' };
    }
    case 'ip-address':
      return { value: 'not-an-ip', constraint: 'type:ip-address' };
    case 'date':
      return { value: 'not-a-date', constraint: 'type:date' };
    case 'datetime':
      return { value: 'not-a-datetime', constraint: 'type:datetime' };
    case 'integer':
      return { value: 'not-an-integer', constraint: 'type:integer' };
    case 'float':
      return { value: 'not-a-float', constraint: 'type:float' };
    case 'boolean':
      return { value: 'maybe', constraint: 'type:boolean' };
    case 'binary':
      // handled via maxSize / mime overrides at the policy level
      return null;
    case 'string':
    case 'free-text':
    case 'name':
    case 'phone':
    case undefined:
    default:
      // unconstrained string → V3 bypass; smuggle a SQLi payload to surface
      // the gap. evaluatePolicy will return allow for unconstrained string;
      // V4 catches this as `negative accepted`.
      return { value: "' OR 1=1 --", constraint: 'unconstrained-string' };
  }
}

/** Find the first param worth violating, given the policy's schema map. */
function pickNegativeTarget(
  schemas: Record<string, ParamSchema>,
): { name: string; ps: ParamSchema; mutation: { value: unknown; constraint: string } } | null {
  // Priority: pattern → range → length → type-specific → unconstrained-string.
  const ordered = Object.entries(schemas);
  // Pass 1: pattern
  for (const [n, p] of ordered) {
    if (p.pattern) {
      const m = negativeForParam(p, undefined);
      if (m) return { name: n, ps: p, mutation: m };
    }
  }
  // Pass 2: numeric range
  for (const [n, p] of ordered) {
    if ((p.type === 'integer' || p.type === 'float') &&
        (typeof p.max === 'number' || typeof p.min === 'number')) {
      const m = negativeForParam(p, undefined);
      if (m) return { name: n, ps: p, mutation: m };
    }
  }
  // Pass 3: length
  for (const [n, p] of ordered) {
    if (typeof p.maxLength === 'number' || (typeof p.minLength === 'number' && p.minLength > 0)) {
      const m = negativeForParam(p, undefined);
      if (m) return { name: n, ps: p, mutation: m };
    }
  }
  // Pass 4: type-specific
  for (const [n, p] of ordered) {
    if (p.type && p.type !== 'string' && p.type !== 'free-text' && p.type !== 'binary') {
      const m = negativeForParam(p, undefined);
      if (m) return { name: n, ps: p, mutation: m };
    }
  }
  // Pass 5: any string → unconstrained payload (V3-bypass canary)
  for (const [n, p] of ordered) {
    const m = negativeForParam(p, undefined);
    if (m) return { name: n, ps: p, mutation: m };
  }
  return null;
}

export function generateNegative(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
): SyntheticRequest {
  // Start from a positive; mutate one thing.
  const base = generatePositive(route, policy);
  const schemas = policy.request?.schema ?? {};

  // If the policy has any schemas, prefer per-param mutation (highest signal).
  const target = pickNegativeTarget(schemas);
  const pathParams = pathParamNames(route.path);
  if (target) {
    const { name, ps, mutation } = target;
    if (pathParams.has(name)) {
      // Rebuild path with the mutated value substituted in.
      const subs: Record<string, unknown> = {};
      for (const [pn] of Object.entries(schemas)) {
        if (pathParams.has(pn)) subs[pn] = pn === name ? mutation.value : positiveForType(ps);
      }
      base.path = substitutePath(route.path, subs);
      // Also surface the mutated value to the evaluator via query.
      base.query[name] = String(mutation.value);
    } else if (ps.type === 'binary' && ps.maxSize) {
      const cap = parseByteSize(ps.maxSize);
      if (cap !== null) base.bodyBytes = cap + 1;
    } else if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(base.method)) {
      const body = (base.body as Record<string, unknown> | undefined) ?? {};
      body[name] = mutation.value;
      base.body = body;
      base.bodyBytes = JSON.stringify(body).length;
    } else {
      base.query[name] = String(mutation.value);
    }
    return base;
  }

  // No schemas to violate — fall back to policy-level mutations.
  if (policy.request?.denyUnknownFields) {
    const body = (base.body as Record<string, unknown> | undefined) ?? {};
    body['__unexpected_field__'] = 'x';
    base.body = body;
    base.bodyBytes = JSON.stringify(body).length;
    return base;
  }
  if (policy.request?.allowedHosts && policy.request.allowedHosts.length > 0) {
    base.headers['Host'] = 'not-allowed.example';
    return base;
  }
  if (policy.request?.headerInjectionGuard) {
    base.headers['X-Test'] = 'a\r\nInjected: yes';
    return base;
  }
  if (policy.request?.contentType && policy.request.contentType.length > 0) {
    base.headers['Content-Type'] = 'application/x-not-allowed';
    return base;
  }
  if (policy.request?.duplicateParamPolicy === 'reject') {
    base.query['x'] = ['1', '2'];
    return base;
  }
  if (policy.authentication && policy.authentication.type !== 'none') {
    delete base.headers['Authorization'];
    return base;
  }
  return base;
}

// --- authz round-trip probes (E2) -----------------------------------------

/** Does the policy carry any request-settable ownership rule V4 can exercise? */
export function hasAuthzRequestRule(policy: XSecurityPolicy): boolean {
  return authzRequestFields(policy).length > 0;
}

/**
 * The "omit-the-ownership-field" positive (E2): a legit request where every
 * authz-referenced body/query field NOT independently required by request.schema
 * is ABSENT. A correct policy still ALLOWS this (the ownership field's absence is
 * only safe if the schema independently requires it). If the policy BLOCKS it,
 * the ownership rule over-blocks the legit omit-case → V4 demotes (the precise
 * dvrestaurant `PUT /profile` fix).
 */
export function generatePositiveOwnershipAbsent(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
  handlerReadParams?: ReadonlySet<string>,
): SyntheticRequest {
  return generatePositive(route, policy, handlerReadParams, { ownershipAbsent: true });
}

const SELF_MUTATION_PATH_TOKENS = ['/profile', '/me', '/account'];

/**
 * FIX 1 — a "self-mutation" route: a PUT/PATCH whose authz body-ownership field
 * is the principal's own id. Such a route should pin the principal server-side,
 * not require the caller to echo its own owner id in the body. True when the
 * method is PUT/PATCH AND either the path names a self-resource (/profile, /me,
 * /account) OR no authz rule pins a path/query id (there is no request-visible
 * id param the rule addresses the object by — the only thing the body field
 * could be is the principal's own id). A query/path id ownership rule (dvapi
 * getNote `query.username`, vampi `params.username`) is NOT self-mutation and
 * never demotes here.
 */
export function isSelfMutationBodyOwnership(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
): boolean {
  const method = route.method.toUpperCase();
  if (method !== 'PUT' && method !== 'PATCH') return false;
  const fields = authzRequestFields(policy);
  const hasBodyOwnership = fields.some((f) => f.loc === 'body');
  if (!hasBodyOwnership) return false;
  const path = route.path.toLowerCase();
  if (SELF_MUTATION_PATH_TOKENS.some((t) => path.includes(t))) return true;
  // No path/query id the rule pins ⇒ the principal can only be named in the body.
  const pinsRequestVisibleId = fields.some(
    (f) => f.loc === 'path' || f.loc === 'params' || f.loc === 'query',
  );
  return !pinsRequestVisibleId;
}

/**
 * FIX 1 — the self-mutation omit-the-body-owner positive: a legit self-update
 * that does NOT carry its own principal id in the body, EVEN if request.schema
 * marks that field required. A correct self-mutation policy pins the principal
 * server-side and still ALLOWS this; one that requires the body owner id BLOCKS
 * it → V4 demotes. (Superset of `generatePositiveOwnershipAbsent` for body
 * fields on self-mutation routes.)
 */
export function generatePositiveBodyOwnershipAbsent(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
  handlerReadParams?: ReadonlySet<string>,
): SyntheticRequest {
  return generatePositive(route, policy, handlerReadParams, {
    ownershipAbsent: true,
    omitBodyOwnershipFields: true,
  });
}

/**
 * The wrong-owner negative (E2): a legit-shaped request whose ownership fields
 * are flipped to a DIFFERENT principal's value. A correct ownership rule
 * (`request.<loc>.<field> == jwt.sub`, or a `resourceLookup` `resource.<owner>
 * == jwt.sub`) MUST block this. A rule that doesn't is too loose → V4 demotes.
 * Returns null when there is no authz rule to exercise.
 */
export function generateAuthzNegative(
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
): SyntheticRequest | null {
  const fields = authzRequestFields(policy);
  const authz = policy.authorization;
  const hasResourceLookup = Boolean(authz && authz.type !== 'rbac' && authz.resourceLookup);
  if (fields.length === 0 && !hasResourceLookup) return null;

  const base = generatePositive(route, policy);
  const pathParams = pathParamNames(route.path);

  // Flip every request-settable ownership field to the other principal's value.
  for (const af of fields) {
    if (af.loc === 'params' || af.loc === 'path') {
      if (pathParams.has(af.name)) {
        const subs: Record<string, unknown> = { [af.name]: DIFFERENT_OWNER };
        base.path = substitutePath(route.path, subs);
      }
      base.query[af.name] = DIFFERENT_OWNER;
    } else if (af.loc === 'header') {
      base.headers[af.name] = DIFFERENT_OWNER;
    } else if (af.loc === 'body' && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(base.method)) {
      const body = (base.body as Record<string, unknown> | undefined) ?? {};
      body[af.name] = DIFFERENT_OWNER;
      base.body = body;
      base.bodyBytes = JSON.stringify(body).length;
    } else {
      base.query[af.name] = DIFFERENT_OWNER;
    }
  }

  // Flip the resourceLookup-exposed owner fields too, so a server-side-join
  // ownership rule (resource.<owner> == jwt.sub) blocks the wrong-owner request.
  if (hasResourceLookup && authz?.resourceLookup) {
    const res = (base.resource as Record<string, unknown> | undefined) ?? {};
    for (const f of authz.resourceLookup.expose ?? []) {
      if (/(owner|user_?id|account|tenant|org|sub)/.test(f.toLowerCase())) {
        res[f] = DIFFERENT_OWNER;
      }
    }
    base.resource = res;
  }

  return base;
}

/**
 * Whether the policy declares ANY request-shape constraint a synthetic negative
 * can actually violate. When false, `generateNegative` can only return the
 * positive unchanged — so V4's "negative accepted → too loose" check would
 * FALSE-DEMOTE a policy whose protection is non-request-shape (e.g. a
 * rate-limited login with no input schema). V4 gates the too-loose verdict on
 * this: no violable constraint ⇒ there is no negative to construct ⇒ not loose.
 *
 * Mirrors the branch order of `generateNegative` exactly so the two never drift.
 */
export function hasViolableConstraint(policy: XSecurityPolicy): boolean {
  const schemas = policy.request?.schema ?? {};
  if (pickNegativeTarget(schemas) !== null) return true;
  const req = policy.request;
  if (req?.denyUnknownFields) return true;
  if (req?.allowedHosts && req.allowedHosts.length > 0) return true;
  if (req?.headerInjectionGuard) return true;
  if (req?.contentType && req.contentType.length > 0) return true;
  if (req?.duplicateParamPolicy === 'reject') return true;
  if (policy.authentication && policy.authentication.type !== 'none') return true;
  return false;
}
