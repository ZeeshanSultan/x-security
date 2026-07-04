// In-process XSecurityPolicy evaluator for the V4 round-trip verifier.
// Pure functions, no IO. Catches encoder bugs, impossible regexes, and silent
// over-constraint at policy-emission time.
//
// Skip list — fields not evaluated here because they require runtime state
// the verifier cannot reasonably synthesise:
//   * rateLimit              — needs a request history / counter store
//   * mtls                   — TLS handshake state
//   * botProtection          — third-party CAPTCHA verify roundtrip
//   * cacheable              — cache state
//   * response.*             — V4 only sees the request path
//   * authorization.rbac     — role membership needs role-state the verifier
//                              cannot synthesise offline (kept skip-listed)
//   * csrf double-submit     — needs cookie + header pair; origin-check is in
//                              scope via cors.allowedOrigins instead
//   * graphql.* / websocket.*— protocol-specific, separate verifier scope
//   * request.signature      — webhook HMAC needs secret material
//   * request.pathCanonicalization — assumed canonical input
//   * deprecated / sunsetDate — metadata only
//
// Fields actually enforced (with observable allow/block effect):
//   * authentication.type            (none vs require Authorization)
//   * authorization.rules            (request-field-vs-principal grammar:
//                                     request.<loc>.<name> vs jwt.<claim> /
//                                     literal; resource.<f> via resourceLookup)
//   * request.contentType            (allowlist)
//   * request.maxBodySize            (ByteSize parsed)
//   * request.allowedHosts           (Host header)
//   * request.duplicateParamPolicy   (when `reject`)
//   * request.headerInjectionGuard   (CR/LF/NUL in header values)
//   * request.denyUnknownFields      (body field allowlist via schema keys)
//   * request.schema[name]           (type/pattern/length/range/domain/mime/maxSize)
//   * cors.allowedOrigins            (Origin header)
//   * ipPolicy.allow / deny          (CIDR match on remote address)

import type {
  ParamSchema,
  XSecurityPolicy,
  Authentication,
  Authorization,
  AuthorizationRule,
  AuthorizationRuleValue,
} from '@writ/schema';

export interface SyntheticRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  /** Each entry is one or more raw values; multiple => duplicate param. */
  query: Record<string, string | string[]>;
  body?: unknown;
  bodyBytes?: number;
  host?: string;
  origin?: string;
  cookies?: Record<string, string>;
  remoteAddress?: string;
  /** Synthetic principal claims (jwt.<claim>) the authz evaluator resolves
   *  `{ref:'jwt.<claim>'}` against. Attached by generatePositive/Negative. */
  principal?: Record<string, unknown>;
  /** Synthetic resource fields (resource.<f>) the authz evaluator resolves
   *  `resourceLookup` rules against. Attached by generatePositive/Negative. */
  resource?: Record<string, unknown>;
}

export interface EvalResult {
  decision: 'allow' | 'block';
  blockedBy?: string;
  reasons: string[];
}

// --- ByteSize parsing -----------------------------------------------------

const BYTE_UNITS: Record<string, number> = {
  B: 1,
  KB: 1024,
  MB: 1024 * 1024,
  GB: 1024 * 1024 * 1024,
};

export function parseByteSize(s: string | undefined): number | null {
  if (!s) return null;
  const m = /^(\d+)(B|KB|MB|GB)$/.exec(s);
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2]!;
  return n * (BYTE_UNITS[unit] ?? 1);
}

// --- ParamSchema evaluation -----------------------------------------------

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IP_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$|^[0-9a-fA-F:]+$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DATETIME_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/;

/** Returns null if value passes the param schema, else a reason string. */
export function evaluateParam(
  value: unknown,
  ps: ParamSchema,
  paramName: string,
): string | null {
  const t = ps.type;
  if (t === 'integer' || t === 'float') {
    const n =
      typeof value === 'number'
        ? value
        : typeof value === 'string' && value.length > 0 && !Number.isNaN(Number(value))
        ? Number(value)
        : null;
    if (n === null) return `${paramName}: not a ${t}`;
    if (t === 'integer' && !Number.isInteger(n)) {
      return `${paramName}: not an integer`;
    }
    if (typeof ps.min === 'number' && n < ps.min) {
      return `${paramName}: below min ${ps.min}`;
    }
    if (typeof ps.max === 'number' && n > ps.max) {
      return `${paramName}: above max ${ps.max}`;
    }
    return null;
  }

  if (t === 'boolean') {
    if (typeof value === 'boolean') return null;
    if (value === 'true' || value === 'false') return null;
    return `${paramName}: not a boolean`;
  }

  if (t === 'binary') {
    return null; // body-level checks happen in evaluatePolicy
  }

  const s = typeof value === 'string' ? value : value == null ? '' : String(value);

  if (typeof ps.fixedLength === 'number' && s.length !== ps.fixedLength) {
    return `${paramName}: length ${s.length} != fixedLength ${ps.fixedLength}`;
  }
  if (typeof ps.minLength === 'number' && s.length < ps.minLength) {
    return `${paramName}: length ${s.length} < minLength ${ps.minLength}`;
  }
  if (typeof ps.maxLength === 'number' && s.length > ps.maxLength) {
    return `${paramName}: length ${s.length} > maxLength ${ps.maxLength}`;
  }

  if (ps.pattern) {
    let re: RegExp;
    try {
      re = new RegExp(ps.pattern);
    } catch {
      return `${paramName}: pattern is not a valid regex: ${ps.pattern}`;
    }
    if (!re.test(s)) {
      return `${paramName}: pattern mismatch (${ps.pattern})`;
    }
  }

  switch (t) {
    case 'uuid':
      if (!UUID_RE.test(s)) return `${paramName}: not a uuid`;
      break;
    case 'email':
      if (!EMAIL_RE.test(s)) return `${paramName}: not an email`;
      break;
    case 'url': {
      let u: URL;
      try {
        u = new URL(s);
      } catch {
        return `${paramName}: not a url`;
      }
      if (ps.domainAllowlist && ps.domainAllowlist.length > 0) {
        const host = u.hostname.toLowerCase();
        const ok = ps.domainAllowlist.some((d) => {
          const dom = d.toLowerCase();
          return host === dom || host.endsWith('.' + dom);
        });
        if (!ok) return `${paramName}: host ${host} not in domainAllowlist`;
      }
      // SSRF defense (D2): reject literal private-range / metadata hosts and
      // non-http(s) schemes. Offline: classify literal hosts only, no DNS.
      if (ps.blockPrivateRanges) {
        const scheme = u.protocol.replace(/:$/, '').toLowerCase();
        if (scheme !== 'http' && scheme !== 'https') {
          return `${paramName}: scheme ${scheme}: not allowed (blockPrivateRanges)`;
        }
        if (isPrivateOrLoopbackHost(u.hostname)) {
          return `${paramName}: host ${u.hostname} is a private/loopback/link-local address (blockPrivateRanges)`;
        }
      }
      break;
    }
    case 'ip-address':
      if (!IP_RE.test(s)) return `${paramName}: not an ip address`;
      break;
    case 'date':
      if (!DATE_RE.test(s)) return `${paramName}: not a date`;
      break;
    case 'datetime':
      if (!DATETIME_RE.test(s)) return `${paramName}: not a datetime`;
      break;
    case 'string':
    case 'free-text':
    case 'name':
    case 'phone':
    case undefined:
      // length/pattern already enforced above
      break;
  }
  return null;
}

// --- Header / IP helpers --------------------------------------------------

const HEADER_INJECTION_CHARS = ['\r', '\n', String.fromCharCode(0)];

function hasHeaderInjection(v: string): boolean {
  for (const c of HEADER_INJECTION_CHARS) {
    if (v.includes(c)) return true;
  }
  return false;
}

function isAuthorizationShapeOk(
  authHeader: string | undefined,
  auth: Authentication,
): { ok: boolean; reason?: string } {
  if (!authHeader || authHeader.length === 0) {
    return { ok: false, reason: 'Authorization header missing' };
  }
  if (auth.type === 'bearer-jwt') {
    if (!/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authHeader)) {
      return { ok: false, reason: 'Authorization header is not a syntactic bearer JWT' };
    }
    return { ok: true };
  }
  if (auth.type === 'api-key') {
    return { ok: true };
  }
  if (auth.type === 'basic') {
    if (!/^Basic [A-Za-z0-9+/=]+$/.test(authHeader)) {
      return { ok: false, reason: 'Authorization is not a Basic credential' };
    }
    return { ok: true };
  }
  if (auth.type === 'oauth2') {
    if (!/^Bearer \S+/.test(authHeader)) {
      return { ok: false, reason: 'Authorization is not an OAuth2 Bearer token' };
    }
    return { ok: true };
  }
  // mtls is transport-layer; no header check possible here.
  return { ok: true };
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/');
  if (!base) return false;
  if (!bitsRaw) return ip === base;
  const bits = Number(bitsRaw);
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return ip === base;
  const toN = (s: string): number | null => {
    const parts = s.split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      const x = Number(p);
      if (!Number.isInteger(x) || x < 0 || x > 255) return null;
      n = (n * 256) + x;
    }
    return n >>> 0;
  };
  const a = toN(ip);
  const b = toN(base);
  if (a === null || b === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

function ipInList(ip: string, list: string[]): boolean {
  for (const c of list) {
    if (ipInCidr(ip, c)) return true;
  }
  return false;
}

// --- Private-range / SSRF host classifier (literal hosts only, no DNS) ----

const PRIVATE_V4_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '0.0.0.0/8',
  '100.64.0.0/10',
];

const IPV4_LITERAL_RE =
  /^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;

/** True for a literal RFC1918 / loopback / link-local / ULA host or `localhost`.
 *  IPv4 via the existing CIDR machinery; IPv6 literals via prefix checks. No DNS
 *  — a non-literal hostname (example.com) returns false (allowed). */
function isPrivateOrLoopbackHost(hostnameRaw: string): boolean {
  let host = hostnameRaw.toLowerCase().trim();
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  // URL() strips IPv6 brackets from .hostname; guard both forms.
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.includes(':')) {
    // IPv6 literal
    const zoneless = host.split('%')[0]!;
    if (zoneless === '::1') return true; // loopback
    if (zoneless === '::') return true; // unspecified
    if (zoneless.startsWith('fe80')) return true; // link-local
    if (zoneless.startsWith('fc') || zoneless.startsWith('fd')) return true; // ULA fc00::/7
    // IPv4-mapped (::ffff:127.0.0.1)
    const mapped = /::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(zoneless);
    if (mapped && mapped[1]) return ipInList(mapped[1], PRIVATE_V4_CIDRS);
    return false;
  }
  if (IPV4_LITERAL_RE.test(host)) {
    return ipInList(host, PRIVATE_V4_CIDRS);
  }
  return false;
}

// --- Authorization (request-field-vs-principal grammar) -------------------
//
// V4 models only the request-time observable subset of authz the real gateway
// enforces: a rule whose `field` is `request.<loc>.<name>` (path/query/body/
// header) or `resource.<f>` (resolved via resourceLookup), compared against a
// principal claim (`{ref:'jwt.<claim>'}`) or a literal. `rbac` roles are out of
// scope (need role state) and remain skip-listed. A failing rule blocks.

function isRuleRef(v: AuthorizationRuleValue): v is { ref: string } {
  return typeof v === 'object' && v !== null && !Array.isArray(v) &&
    typeof (v as { ref?: unknown }).ref === 'string';
}

/** Resolve a `request.<loc>.<name>` / `resource.<f>` field path against a
 *  synthetic request. Returns `{ found, value }` — `found:false` means the
 *  field is absent (distinct from a present-but-undefined value). Only the
 *  request-observable namespaces are resolvable; anything else is unresolvable
 *  and the rule is skipped (not a block). */
function resolveAuthzField(
  req: SyntheticRequest,
  field: string,
): { resolvable: boolean; found: boolean; value: unknown } {
  const parts = field.split('.');
  const ns = parts[0];
  if (ns === 'request') {
    const loc = parts[1];
    const name = parts.slice(2).join('.');
    if (!loc || !name) return { resolvable: false, found: false, value: undefined };
    if (loc === 'params' || loc === 'path') {
      // path params are surfaced to the evaluator via query by name.
      const q = req.query[name];
      if (Object.prototype.hasOwnProperty.call(req.query, name)) {
        return { resolvable: true, found: true, value: Array.isArray(q) ? q[0] : q };
      }
      return { resolvable: true, found: false, value: undefined };
    }
    if (loc === 'query') {
      if (Object.prototype.hasOwnProperty.call(req.query, name)) {
        const q = req.query[name];
        return { resolvable: true, found: true, value: Array.isArray(q) ? q[0] : q };
      }
      return { resolvable: true, found: false, value: undefined };
    }
    if (loc === 'body') {
      if (req.body && typeof req.body === 'object' && !Array.isArray(req.body) &&
          Object.prototype.hasOwnProperty.call(req.body, name)) {
        return { resolvable: true, found: true, value: (req.body as Record<string, unknown>)[name] };
      }
      return { resolvable: true, found: false, value: undefined };
    }
    if (loc === 'header') {
      const lc = name.toLowerCase();
      for (const [k, v] of Object.entries(req.headers || {})) {
        if (k.toLowerCase() === lc) return { resolvable: true, found: true, value: v };
      }
      return { resolvable: true, found: false, value: undefined };
    }
    return { resolvable: false, found: false, value: undefined };
  }
  if (ns === 'resource') {
    const name = parts.slice(1).join('.');
    if (!name) return { resolvable: false, found: false, value: undefined };
    if (req.resource && Object.prototype.hasOwnProperty.call(req.resource, name)) {
      return { resolvable: true, found: true, value: req.resource[name] };
    }
    return { resolvable: true, found: false, value: undefined };
  }
  return { resolvable: false, found: false, value: undefined };
}

/** Resolve a rule's `value` to a concrete comparison operand. A `{ref:'jwt.x'}`
 *  resolves against the synthetic principal; a literal is itself. Returns
 *  `{ resolvable }` false when a ref points at no synthetic state — the rule is
 *  then skipped (can't be exercised offline). */
function resolveAuthzValue(
  req: SyntheticRequest,
  value: AuthorizationRuleValue,
): { resolvable: boolean; value: unknown } {
  if (isRuleRef(value)) {
    const parts = value.ref.split('.');
    const ns = parts[0];
    const claim = parts.slice(1).join('.');
    if ((ns === 'jwt' || ns === 'principal' || ns === 'session') && claim) {
      if (req.principal && Object.prototype.hasOwnProperty.call(req.principal, claim)) {
        return { resolvable: true, value: req.principal[claim] };
      }
      return { resolvable: false, value: undefined };
    }
    return { resolvable: false, value: undefined };
  }
  return { resolvable: true, value };
}

function authzOperatorHolds(
  op: AuthorizationRule['operator'],
  left: unknown,
  right: unknown,
): boolean {
  const L = left == null ? left : String(left);
  const R = right == null ? right : right;
  switch (op) {
    case 'equals':
      return L === (R == null ? R : String(R));
    case 'not-equals':
      return L !== (R == null ? R : String(R));
    case 'in':
      return Array.isArray(R) && R.map(String).includes(String(left));
    case 'not-in':
      return !(Array.isArray(R) && R.map(String).includes(String(left)));
    case 'contains':
      return typeof left === 'string' && typeof right === 'string' && left.includes(right);
    case 'matches':
      if (typeof right !== 'string') return false;
      try {
        return new RegExp(right).test(String(left));
      } catch {
        return false;
      }
    default:
      return false;
  }
}

/** Evaluate the request-observable authorization rules. Returns a block result
 *  for the first failing rule, else null (allow). rbac is not evaluated here. */
function evaluateAuthorization(
  req: SyntheticRequest,
  authz: Authorization,
): EvalResult | null {
  const rules = authz.rules;
  if (!rules || rules.length === 0) return null;
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]!;
    const lhs = resolveAuthzField(req, rule.field);
    if (!lhs.resolvable) continue; // not a request-observable field — skip
    const rhs = resolveAuthzValue(req, rule.value);
    if (!rhs.resolvable) continue; // ref points at no synthetic state — skip
    // An absent field cannot satisfy an ownership comparison: undefined != claim.
    const leftValue = lhs.found ? lhs.value : undefined;
    const holds = authzOperatorHolds(rule.operator, leftValue, rhs.value);
    if (!holds) {
      return {
        decision: 'block',
        blockedBy: `authorization.rules[${i}]: ${rule.field} ${rule.operator} ${
          isRuleRef(rule.value) ? rule.value.ref : JSON.stringify(rule.value)
        }`,
        reasons: [
          `authorization rule on ${rule.field} not satisfied (${
            lhs.found ? 'value mismatch' : 'field absent'
          })`,
        ],
      };
    }
  }
  return null;
}

// --- Main evaluator -------------------------------------------------------

export function evaluatePolicy(
  req: SyntheticRequest,
  policy: XSecurityPolicy,
): EvalResult {
  const reasons: string[] = [];
  const headersLc: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers || {})) {
    headersLc[k.toLowerCase()] = v;
  }

  // 1. headerInjectionGuard — runs across every header value
  if (policy.request?.headerInjectionGuard) {
    for (const [k, v] of Object.entries(req.headers || {})) {
      if (hasHeaderInjection(v)) {
        return {
          decision: 'block',
          blockedBy: `request.headerInjectionGuard: CRLF/NUL in header ${k}`,
          reasons: [`header ${k} contains CR/LF/NUL`],
        };
      }
    }
  }

  // 2. authentication
  if (policy.authentication && policy.authentication.type !== 'none') {
    const headerName = (policy.authentication.headerName || 'Authorization').toLowerCase();
    const authVal = headersLc[headerName];
    const r = isAuthorizationShapeOk(authVal, policy.authentication);
    if (!r.ok) {
      return {
        decision: 'block',
        blockedBy: `authentication.type: ${r.reason}`,
        reasons: [r.reason || 'auth failed'],
      };
    }
  }

  // 2b. authorization — request-field-vs-principal grammar (rbac skip-listed).
  //     Runs after authentication: an authz rule presumes an authenticated
  //     principal. rule-based / abac only; rbac roles need role-state V4 lacks.
  if (policy.authorization && policy.authorization.type !== 'rbac') {
    const blocked = evaluateAuthorization(req, policy.authorization);
    if (blocked) return blocked;
  }

  // 3. allowedHosts (Host header)
  if (policy.request?.allowedHosts && policy.request.allowedHosts.length > 0) {
    const host = req.host ?? headersLc['host'];
    if (!host || !policy.request.allowedHosts.includes(host)) {
      return {
        decision: 'block',
        blockedBy: `request.allowedHosts: host ${host ?? '(missing)'} not allowed`,
        reasons: ['host not in allowedHosts'],
      };
    }
  }

  // 4. cors.allowedOrigins (only when an Origin is present — CORS is
  //    cross-origin-only; same-origin requests don't carry Origin)
  if (policy.cors?.allowedOrigins && policy.cors.allowedOrigins.length > 0) {
    const origin = req.origin ?? headersLc['origin'];
    if (origin && !policy.cors.allowedOrigins.includes(origin)) {
      return {
        decision: 'block',
        blockedBy: `cors.allowedOrigins: origin ${origin} not allowed`,
        reasons: ['origin not in allowedOrigins'],
      };
    }
  }

  // 5. ipPolicy
  if (policy.ipPolicy) {
    const ip = req.remoteAddress;
    if (ip) {
      const allow = policy.ipPolicy.allow;
      const deny = policy.ipPolicy.deny;
      if (Array.isArray(deny) && ipInList(ip, deny)) {
        return {
          decision: 'block',
          blockedBy: `ipPolicy.deny: ${ip} matches deny list`,
          reasons: [`ip ${ip} denied`],
        };
      }
      if (Array.isArray(allow) && !ipInList(ip, allow)) {
        return {
          decision: 'block',
          blockedBy: `ipPolicy.allow: ${ip} not in allow list`,
          reasons: [`ip ${ip} not allowed`],
        };
      }
    }
  }

  // 6. contentType allowlist
  if (policy.request?.contentType && policy.request.contentType.length > 0) {
    const ct = headersLc['content-type'];
    if (ct) {
      const base = ct.split(';')[0]!.trim().toLowerCase();
      const ok = policy.request.contentType.some((x) => x.toLowerCase() === base);
      if (!ok) {
        return {
          decision: 'block',
          blockedBy: `request.contentType: ${base} not allowed`,
          reasons: [`content-type ${base} denied`],
        };
      }
    }
  }

  // 7. maxBodySize (top-level cap)
  if (policy.request?.maxBodySize) {
    const cap = parseByteSize(policy.request.maxBodySize);
    if (cap !== null && typeof req.bodyBytes === 'number' && req.bodyBytes > cap) {
      return {
        decision: 'block',
        blockedBy: `request.maxBodySize: ${req.bodyBytes} > ${cap}`,
        reasons: ['body exceeds maxBodySize'],
      };
    }
  }

  // 8. duplicateParamPolicy — only `reject` has request-time observable effect.
  //    Positive samples emit scalar query values; negative samples emit an
  //    array (length > 1) to represent `?x=1&x=2`.
  if (policy.request?.duplicateParamPolicy === 'reject') {
    for (const [k, v] of Object.entries(req.query)) {
      if (Array.isArray(v) && v.length > 1) {
        return {
          decision: 'block',
          blockedBy: `request.duplicateParamPolicy=reject: duplicate ${k}`,
          reasons: [`duplicate query param ${k}`],
        };
      }
    }
  }

  // 9. request.schema — per-param validation, denyUnknownFields enforcement
  const schemas = policy.request?.schema;
  if (schemas) {
    for (const [name, ps] of Object.entries(schemas)) {
      const lower = name.toLowerCase();
      let value: unknown;
      if (Object.prototype.hasOwnProperty.call(req.query, name)) {
        const q = req.query[name];
        value = Array.isArray(q) ? q[0] : q;
      } else if (Object.prototype.hasOwnProperty.call(headersLc, lower)) {
        value = headersLc[lower];
      } else if (
        req.body && typeof req.body === 'object' && !Array.isArray(req.body) &&
        Object.prototype.hasOwnProperty.call(req.body, name)
      ) {
        value = (req.body as Record<string, unknown>)[name];
      } else if (req.cookies && Object.prototype.hasOwnProperty.call(req.cookies, name)) {
        value = req.cookies[name];
      } else {
        value = undefined;
      }
      if (value === undefined) {
        // Missing required param. V4 treats every schema entry as required —
        // V3 already filters out theatre rules.
        return {
          decision: 'block',
          blockedBy: `request.schema.${name}: missing required value`,
          reasons: [`${name} not present`],
        };
      }

      if (ps.type === 'binary') {
        const mime = headersLc['content-type'];
        if (ps.allowedMimeTypes && ps.allowedMimeTypes.length > 0) {
          const base = mime ? mime.split(';')[0]!.trim().toLowerCase() : '';
          const ok = ps.allowedMimeTypes.some((m) => m.toLowerCase() === base);
          if (!ok) {
            return {
              decision: 'block',
              blockedBy: `request.schema.${name}: mime ${base} not in allowedMimeTypes`,
              reasons: [`${name} mime denied`],
            };
          }
        }
        if (ps.maxSize) {
          const cap = parseByteSize(ps.maxSize);
          if (cap !== null && typeof req.bodyBytes === 'number' && req.bodyBytes > cap) {
            return {
              decision: 'block',
              blockedBy: `request.schema.${name}: body ${req.bodyBytes} > maxSize ${cap}`,
              reasons: [`${name} exceeds maxSize`],
            };
          }
        }
        continue;
      }

      const why = evaluateParam(value, ps, `request.schema.${name}`);
      if (why) {
        return {
          decision: 'block',
          blockedBy: why,
          reasons: [why],
        };
      }
    }

    if (
      policy.request?.denyUnknownFields &&
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ) {
      const allowed = new Set(Object.keys(schemas));
      for (const k of Object.keys(req.body as Record<string, unknown>)) {
        if (!allowed.has(k)) {
          return {
            decision: 'block',
            blockedBy: `request.denyUnknownFields: unknown field "${k}"`,
            reasons: [`unknown body field ${k}`],
          };
        }
      }
    }
  }

  return { decision: 'allow', reasons };
}
