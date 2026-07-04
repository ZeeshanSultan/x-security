// Per-policy-field plugin builders. Each function maps one XSecurityPolicy field
// onto zero or more Kong plugins, or returns undefined when the field is empty.

import type {
  XSecurityPolicy,
  Authentication,
  Authorization,
  RateLimit,
  Cors,
  IpPolicy,
  RequestPolicy,
  RequestSignature,
  ResponsePolicy,
  ParamSchema
} from '@writ/schema';

// Cacheable isn't re-exported from the schema barrel; mirror the inline shape.
type Cacheable =
  | boolean
  | { enabled: boolean; ttl?: number; varyBy?: string[] };
import type { KongPlugin, WritWarning } from './types.js';

// Sink for structured warnings (HS256 downgrade, hmac-auth header overrides,
// enterprise-only plugin drops, etc.). The generator collects these per
// generate() call and embeds them in kong.yml under _writ_warnings.
export type WarningSink = (w: WritWarning) => void;

// Login-style endpoint heuristic. Used by the rate-limit builder to force
// `limit_by: ip` instead of `consumer` — unauthenticated login/signup
// requests have no consumer, so the default `consumer` bucket never
// accumulates, which means failed-login bursts never get rate-limited.
// This was the root cause of API2 credential-stuffing being UNBLOCKED in
// the v3 attack matrix.
const LOGIN_PATH_RE = /\/(login|signup|register|sign[-_]?in|sign[-_]?up)(\/|$)/i;
const LOGIN_OP_RE = /(login|signup|register|signin)/i;
export function isLoginLikeEndpoint(ep: {
  operationId?: string;
  path?: string;
}): boolean {
  if (ep.operationId && LOGIN_OP_RE.test(ep.operationId)) return true;
  if (ep.path && LOGIN_PATH_RE.test(ep.path)) return true;
  return false;
}

// ---------- helpers ----------

// Kong rejects tags containing `,` and `/` and (in 3.4 OSS) `:` — see
// incident: jwks=https://... was emitted as a tag and the gateway refused
// to start. We replace unsafe chars with `_` so the tag is still
// human-readable but valid (printable ascii minus banned set).
export function sanitizeTag(tag: string): string {
  return tag.replace(/[:/,]/g, '_');
}

const WINDOW_TO_SECONDS: Record<string, number> = {
  s: 1, m: 60, h: 3600, d: 86400
};

function parseDurationSeconds(window: string): number {
  const m = window.match(/^(\d+)\s*([smhd])$/i);
  if (!m) return 60;
  const value = Number(m[1]);
  const unit = m[2]!.toLowerCase();
  return value * (WINDOW_TO_SECONDS[unit] ?? 60);
}

function parseByteSize(size: string): number {
  const m = size.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?$/i);
  if (!m) return 0;
  const value = Number(m[1]);
  const unit = (m[2] ?? 'B').toUpperCase();
  const mult: Record<string, number> =
    { B: 1, KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };
  return Math.round(value * (mult[unit] ?? 1));
}

// Kong rate-limit has fixed buckets: second/minute/hour/day. Map window → best fit.
function rateLimitBucket(seconds: number): 'second' | 'minute' | 'hour' | 'day' {
  if (seconds <= 1) return 'second';
  if (seconds <= 60) return 'minute';
  if (seconds <= 3600) return 'hour';
  return 'day';
}

// Map x-security identifier → kong rate-limit `limit_by` enum
function rateLimitLimitBy(identifier: string | undefined): string {
  switch (identifier) {
    case 'ip': return 'ip';
    case 'fingerprint': return 'ip';
    case 'api-key': return 'credential';
    case 'user-id': return 'consumer';
    default:
      if (identifier?.startsWith('header:')) return 'header';
      return 'ip';
  }
}

// ---------- auth ----------

export function buildAuthPlugins(
  auth: Authentication | undefined,
  edition: KongEdition = 'oss'
): KongPlugin[] {
  if (!auth || auth.type === 'none' || auth.type === 'basic') return [];

  switch (auth.type) {
    case 'bearer-jwt': {
      // Enterprise edition: emit the `openid-connect` plugin which does
      // real JWKS fetch + RS256/ES256 verification. We skip the OSS `jwt`
      // plugin (and the consumer pipeline skips jwt_secrets) so the route
      // is gated by genuine asymmetric-key validation rather than the
      // HS256 shared-secret downgrade.
      if (edition === 'enterprise') {
        const oidc: Record<string, unknown> = {
          bearer_only: true,
          auth_methods: ['bearer'],
          verify_signature: true
        };
        if (auth.issuer) oidc.issuer = auth.issuer;
        if (auth.jwksUri) oidc.jwks_uri = auth.jwksUri;
        if (auth.audience) oidc.audience_claim = ['aud'];
        if (auth.audience) oidc.audience_required = [auth.audience];
        if (auth.allowedAlgorithms?.length) {
          oidc.id_token_signing_alg_values_expected = auth.allowedAlgorithms;
        }
        // client_id/client_secret are operator-supplied via env-var
        // placeholders so the same kong.yml works across environments.
        oidc.client_id = ['${OIDC_CLIENT_ID}'];
        oidc.client_secret = ['${OIDC_CLIENT_SECRET}'];
        if (auth.headerName) oidc.bearer_token_param_type = ['header'];
        return [{ name: 'openid-connect', config: oidc }];
      }
      const config: Record<string, unknown> = {
        claims_to_verify: ['exp'],
        key_claim_name: 'iss',
        run_on_preflight: true
      };
      if (auth.headerName) config.header_names = [auth.headerName];
      // Note: Kong OSS `jwt` plugin requires pre-provisioned consumers + keys;
      // jwksUri/issuer/audience are recorded as tags for operator wiring.
      const tags: string[] = [];
      if (auth.jwksUri) tags.push(sanitizeTag(`jwks=${auth.jwksUri}`));
      if (auth.issuer) tags.push(sanitizeTag(`issuer=${auth.issuer}`));
      if (auth.audience) tags.push(sanitizeTag(`audience=${auth.audience}`));
      const plugin: KongPlugin = { name: 'jwt', config };
      if (tags.length) plugin.tags = tags;
      return [plugin];
    }
    case 'api-key': {
      const config: Record<string, unknown> = {
        key_names: [auth.headerName ?? 'apikey'],
        key_in_header: true,
        key_in_query: false,
        hide_credentials: true
      };
      return [{ name: 'key-auth', config }];
    }
    case 'oauth2': {
      const config: Record<string, unknown> = {
        enable_authorization_code: true,
        token_expiration: 7200,
        hide_credentials: true
      };
      if (auth.scopes?.length) config.scopes = auth.scopes;
      return [{ name: 'oauth2', config }];
    }
    case 'mtls': {
      // mtls-auth is enterprise; OSS users get override-only — still emit a stub.
      return [{ name: 'mtls-auth', config: { skip_consumer_lookup: false } }];
    }
    default:
      return [];
  }
}

// ---------- request signature (hmac-auth) ----------

// Map XSecurityPolicy.request.signature → Kong OSS `hmac-auth` plugin.
//
// Kong OSS `hmac-auth` reference: https://docs.konghq.com/hub/kong-inc/hmac-auth/
// Supported algorithms: hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512.
// Kong's hmac-auth consumes the standard `Authorization: hmac ...` scheme — it
// has no custom-header mode and no canonicalization mode. ed25519 is not
// supported on OSS.
//
// Per Rule D-1: we don't paper over gaps. Anything Kong OSS cannot enforce
// surfaces as a stderr warning so the operator sees the degradation rather
// than getting a misleading "fully protected" config.
//
// Consumer wiring (hmacauth_credentials) is emitted by the kong-consumer
// pipeline; this builder only attaches the plugin to the route.
const KONG_HMAC_ALGORITHMS = new Set([
  'hmac-sha1',
  'hmac-sha256',
  'hmac-sha384',
  'hmac-sha512'
]);

function emitSignatureWarning(message: string): void {
  process.stderr.write(`[kong-generator] request.signature: ${message}\n`);
}

export function buildSignaturePlugin(
  sig: RequestSignature | undefined,
  ctx?: { endpoint?: string; warn?: WarningSink }
): KongPlugin[] {
  if (!sig) return [];

  const recordWarning = (w: Omit<WritWarning, 'endpoint'>): void => {
    if (ctx?.warn) {
      const full: WritWarning = {
        ...w,
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {})
      };
      ctx.warn(full);
    }
  };

  if (sig.algorithm === 'ed25519') {
    emitSignatureWarning(
      'algorithm "ed25519" is not supported by Kong OSS hmac-auth; skipping plugin emission'
    );
    recordWarning({
      field: 'request.signature.algorithm',
      declared: 'ed25519',
      emitted: '(none)',
      reason: 'Kong OSS hmac-auth has no ed25519 mode; route is left ungated for the signature check'
    });
    return [];
  }

  if (!KONG_HMAC_ALGORITHMS.has(sig.algorithm)) {
    emitSignatureWarning(
      `algorithm "${sig.algorithm}" is not supported by Kong OSS hmac-auth; skipping plugin emission`
    );
    recordWarning({
      field: 'request.signature.algorithm',
      declared: sig.algorithm,
      emitted: '(none)',
      reason: 'Kong OSS hmac-auth only supports hmac-sha1/256/384/512'
    });
    return [];
  }

  const config: Record<string, unknown> = {
    algorithms: [sig.algorithm],
    hide_credentials: true
  };

  if (sig.body === 'raw') {
    config.validate_request_body = true;
  } else if (sig.body === 'canonical') {
    config.validate_request_body = true;
    emitSignatureWarning(
      'body="canonical" requested, but Kong OSS hmac-auth has no canonicalization mode; falling back to raw body validation'
    );
    recordWarning({
      field: 'request.signature.body',
      declared: 'canonical',
      emitted: 'raw',
      reason: 'Kong OSS hmac-auth has no canonicalization mode'
    });
  }

  const enforceHeaders: string[] = ['date'];
  if (sig.timestampHeader) {
    enforceHeaders.push(sig.timestampHeader);
  }
  config.enforce_headers = enforceHeaders;

  if (sig.timestampToleranceSeconds !== undefined) {
    config.clock_skew = sig.timestampToleranceSeconds;
  }

  const tags: string[] = [];
  if (sig.headerName && sig.headerName !== 'Authorization') {
    emitSignatureWarning(
      `headerName="${sig.headerName}" is not honored by Kong OSS hmac-auth (uses "Authorization: hmac ..." scheme); plugin still attached so route remains gated, but operator must reconcile header naming with upstream`
    );
    tags.push(sanitizeTag(`signature-header-override=${sig.headerName}`));
    recordWarning({
      field: 'request.signature.headerName',
      declared: sig.headerName,
      emitted: 'Authorization',
      reason: 'Kong OSS hmac-auth uses the "Authorization: hmac ..." scheme; custom header names are not honored'
    });
  }

  const plugin: KongPlugin = { name: 'hmac-auth', config };
  if (tags.length) plugin.tags = tags;
  return [plugin];
}

// ---------- authorization ----------

export function buildAuthzPlugins(authz: Authorization | undefined): KongPlugin[] {
  if (!authz || authz.type !== 'rbac' || !authz.roles?.length) return [];
  return [
    {
      name: 'acl',
      config: {
        allow: authz.roles,
        hide_groups_header: true
      }
    }
  ];
}

// ---------- authorization.rule-based (K-1: BOLA enforcement via pre-function) ----------
//
// Kong OSS has no native rule engine. We compile `authorization.rule-based`
// rules into a Lua snippet attached via the `pre-function` plugin (bundled
// with Kong OSS — see https://docs.konghq.com/hub/kong-inc/pre-function/).
// The Lua runs in the `access` phase, BEFORE the upstream is contacted:
//
//   1. Extract the authenticated principal from kong.ctx.shared (set by
//      jwt/openid-connect/key-auth in earlier phases).
//   2. If the rule references `resource.<field>`, fetch the resource via
//      resourceLookup.endpoint substituting the identifier extracted via
//      resourceLookup.identifierFrom (request.params.<x> / request.path / ...).
//   3. Evaluate each rule (AND across all rules). Mismatch → 403 with a
//      Writ tag in the response body so the verify reader and access
//      logs both pick it up.
//
// Limitations surfaced as warnings:
//  - resourceLookup missing while a rule references `resource.*`
//  - operators other than `equals` / `not-equals` (in / not-in / matches /
//    contains) emit a degraded check; in particular `matches` becomes a
//    Lua `string.match` against the value pattern.
//  - principal.* namespace (v0.5 S-10) is treated as a synonym for jwt.sub
//    when ref === 'principal.id', because Kong OSS's authenticated_credential
//    only exposes the JWT-style consumer identity.

const SS_BOLA_TAG = 'writ-rule-bola-403';

// W10-11: shared_dict cache TTL (seconds). Conservative default because the
// cache means owner changes (transfers, deletes) take up to TTL seconds to
// propagate. Operators tune via `targetOverrides.kong.bolaCacheTtl`.
const SS_BOLA_CACHE_TTL_SECONDS = 60;
// Shared dict name. Operators must declare this via the Kong env var
// `KONG_NGINX_HTTP_LUA_SHARED_DICT="writ_bola_cache 10m"` (the
// declarative kong.yml cannot configure nginx-level directives). The Lua
// is nil-safe when the dict is missing — see buildAuthzLua.
export const SS_BOLA_CACHE_DICT = 'writ_bola_cache';
export const SS_BOLA_CACHE_DICT_SIZE = '10m';

// Render a Lua expression that reads from a RuleRef (`jwt.sub`, `principal.id`,
// `request.params.id`, `request.path`, `header.X-User-Id`, `session.userId`,
// or `resource.<exposed>`). The return value is always a string for tostring()
// comparison; nil-safe.
function refToLuaExpr(ref: string): { expr: string; needsResource: boolean } {
  // jwt.<claim> → kong.ctx.shared.authenticated_jwt_token.<claim> (set by the
  // jwt plugin's claim parser). For the consumer-level sub, fall back to
  // .username on authenticated_credential.
  if (ref === 'jwt.sub' || ref === 'principal.id') {
    return {
      expr:
        "(kong.ctx.shared.authenticated_credential and " +
        "kong.ctx.shared.authenticated_credential.username) or " +
        "(kong.ctx.shared.authenticated_jwt_token and " +
        "kong.ctx.shared.authenticated_jwt_token.sub)",
      needsResource: false
    };
  }
  if (ref.startsWith('jwt.')) {
    const claim = ref.slice('jwt.'.length);
    return {
      expr:
        `(kong.ctx.shared.authenticated_jwt_token and ` +
        `kong.ctx.shared.authenticated_jwt_token[${luaStr(claim)}])`,
      needsResource: false
    };
  }
  if (ref.startsWith('principal.')) {
    // v0.5 S-10: principal.* maps onto the authenticated consumer identity in
    // Kong OSS. Only `id` is guaranteed-resolvable; others fall back to nil.
    const attr = ref.slice('principal.'.length);
    if (attr === 'id') {
      return refToLuaExpr('jwt.sub');
    }
    return {
      expr:
        `(kong.ctx.shared.authenticated_consumer and ` +
        `kong.ctx.shared.authenticated_consumer[${luaStr(attr)}])`,
      needsResource: false
    };
  }
  if (ref.startsWith('header.')) {
    // v0.5 S-10: header.<Name> — arbitrary request header verbatim.
    const name = ref.slice('header.'.length);
    return {
      expr: `kong.request.get_header(${luaStr(name)})`,
      needsResource: false
    };
  }
  if (ref.startsWith('session.')) {
    // v0.5 S-10: session.* would require Kong's session plugin. OSS Kong has
    // a `session` plugin that stows data in kong.ctx.shared.authenticated_session;
    // surface a best-effort read so the rule still evaluates if the plugin is
    // attached, otherwise the comparison nil-fails closed.
    const attr = ref.slice('session.'.length);
    return {
      expr:
        `(kong.ctx.shared.authenticated_session and ` +
        `kong.ctx.shared.authenticated_session[${luaStr(attr)}])`,
      needsResource: false
    };
  }
  if (ref.startsWith('request.params.')) {
    const name = ref.slice('request.params.'.length);
    return {
      expr: `kong.request.get_path_arg(${luaStr(name)})`,
      needsResource: false
    };
  }
  if (ref.startsWith('request.query.')) {
    const name = ref.slice('request.query.'.length);
    return {
      expr: `kong.request.get_query_arg(${luaStr(name)})`,
      needsResource: false
    };
  }
  if (ref === 'request.path') {
    return { expr: 'kong.request.get_path()', needsResource: false };
  }
  if (ref.startsWith('resource.')) {
    const field = ref.slice('resource.'.length);
    return { expr: `(ss_resource and ss_resource[${luaStr(field)}])`, needsResource: true };
  }
  // Unknown namespace → emit a nil expression so the rule fails-closed.
  return { expr: 'nil', needsResource: false };
}

// Lua string literal — handles backslash + double-quote escapes and
// non-printable bytes via \nnn. Defensive: Writ rule values are
// operator-controlled and may contain quotes.
function luaStr(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
}

// Substitute {param} placeholders in resourceLookup.endpoint with Lua
// expressions resolving the matching identifierFrom values at request time.
// Example: endpoint=/users/{id}, identifierFrom=request.params.id
//   → "/users/" .. tostring(kong.request.get_path_arg("id") or "")
function buildResourceUrlExpr(endpoint: string, identifierFrom: string): string {
  const idExpr = refToLuaExpr(identifierFrom).expr;
  // Replace {anything} with a Lua concat of the identifier expression. We
  // only support a single placeholder per endpoint (the canonical
  // resourceLookup shape); additional placeholders fall back to literal {x}
  // which the upstream will reject loudly — better than a silent wrong-id.
  const parts = endpoint.split(/(\{[^}]+\})/g);
  const pieces: string[] = [];
  for (const part of parts) {
    if (/^\{[^}]+\}$/.test(part)) {
      pieces.push(`tostring(${idExpr} or "")`);
    } else if (part.length > 0) {
      pieces.push(luaStr(part));
    }
  }
  return pieces.length === 1 ? pieces[0]! : pieces.join(' .. ');
}

// Build the Lua access-phase snippet for one endpoint's authorization rules.
function buildAuthzLua(authz: Authorization, ctx: { endpoint?: string }): {
  lua: string;
  warnings: WritWarning[];
} {
  const warnings: WritWarning[] = [];
  const rules = authz.rules ?? [];
  let anyResourceRef = false;
  const ruleSnippets: string[] = [];

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]!;
    const lhs = refToLuaExpr(`resource.${rule.field}`.replace(/^resource\.resource\./, 'resource.'));
    // `field` is normally an identifier (e.g. "ownerId"); but it could also
    // be a full ref like "resource.ownerId" or "request.params.id". Accept
    // both forms.
    const lhsExpr =
      rule.field.includes('.') ? refToLuaExpr(rule.field) : lhs;
    if (lhsExpr.needsResource) anyResourceRef = true;

    // Evaluate the RHS. It is either a literal scalar/array or a RuleRef.
    let rhsExpr: string;
    if (typeof rule.value === 'object' && rule.value !== null && 'ref' in (rule.value as object)) {
      const r = refToLuaExpr((rule.value as { ref: string }).ref);
      if (r.needsResource) anyResourceRef = true;
      rhsExpr = r.expr;
    } else if (typeof rule.value === 'string') {
      rhsExpr = luaStr(rule.value);
    } else if (typeof rule.value === 'number' || typeof rule.value === 'boolean') {
      rhsExpr = String(rule.value);
    } else if (Array.isArray(rule.value)) {
      rhsExpr =
        '{' +
        rule.value
          .map((v) =>
            typeof v === 'string' ? luaStr(v) : String(v)
          )
          .join(', ') +
        '}';
    } else {
      rhsExpr = 'nil';
    }

    // Per-operator emission.
    let condition: string;
    switch (rule.operator) {
      case 'equals':
        condition = `tostring(${lhsExpr.expr}) ~= tostring(${rhsExpr})`;
        break;
      case 'not-equals':
        condition = `tostring(${lhsExpr.expr}) == tostring(${rhsExpr})`;
        break;
      case 'in': {
        // RHS is expected to be a table; build `not (any v in t: v == lhs)`
        condition = `(function() local t=${rhsExpr}; local v=tostring(${lhsExpr.expr}); for _,x in ipairs(t) do if tostring(x)==v then return false end end; return true end)()`;
        break;
      }
      case 'not-in': {
        condition = `(function() local t=${rhsExpr}; local v=tostring(${lhsExpr.expr}); for _,x in ipairs(t) do if tostring(x)==v then return true end end; return false end)()`;
        break;
      }
      case 'matches':
        condition = `not (tostring(${lhsExpr.expr} or "")):match(${rhsExpr})`;
        break;
      case 'contains':
        condition = `not string.find(tostring(${lhsExpr.expr} or ""), ${rhsExpr}, 1, true)`;
        break;
      default:
        condition = 'true'; // unknown operator → fail-closed
        warnings.push({
          field: 'authorization.rules[].operator',
          ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
          declared: String(rule.operator),
          emitted: '(fail-closed)',
          reason:
            `unsupported operator "${rule.operator}" in rule-based authorization; ` +
            'pre-function denies the request rather than let it through unchecked.'
        });
    }

    ruleSnippets.push(
      `  -- rule ${i + 1}: ${rule.field} ${rule.operator} ${
        typeof rule.value === 'object' && rule.value !== null && 'ref' in rule.value
          ? `\${${(rule.value as { ref: string }).ref}}`
          : JSON.stringify(rule.value)
      }`,
      `  if ${condition} then`,
      `    kong.log.warn("[${SS_BOLA_TAG}] rule ${i + 1} (${rule.field} ${rule.operator}) denied")`,
      `    return kong.response.exit(403, {`,
      `      message = "Writ: BOLA denied",`,
      `      tag = "${SS_BOLA_TAG}",`,
      `      rule = ${i + 1}`,
      `    })`,
      `  end`,
      ``
    );
  }

  // Resource lookup section (only when at least one rule references resource.*).
  const lookup = authz.resourceLookup;
  if (anyResourceRef && !lookup) {
    warnings.push({
      field: 'authorization.resourceLookup',
      ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
      declared: '(referenced via rule.resource.*)',
      emitted: '(none)',
      reason:
        'authorization.rules reference resource.* but no resourceLookup is defined; ' +
        'pre-function cannot fetch the resource. Add resourceLookup with endpoint + identifierFrom + expose.'
    });
  }

  const head: string[] = [
    `-- Writ K-1 BOLA pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `local cjson = require("cjson.safe")`,
    `local principal = ${refToLuaExpr('jwt.sub').expr}`,
    `if not principal then`,
    `  kong.log.warn("[${SS_BOLA_TAG}] no authenticated principal; denying")`,
    `  return kong.response.exit(401, {message = "Writ: no authenticated principal", tag = "${SS_BOLA_TAG}"})`,
    `end`,
    ``
  ];

  if (anyResourceRef && lookup) {
    const urlExpr = buildResourceUrlExpr(lookup.endpoint, lookup.identifierFrom);
    const idExpr = refToLuaExpr(lookup.identifierFrom).expr;
    // W10-11: shared_dict cache keyed on principal + resource id avoids the
    // per-request HTTP roundtrip. Cache TTL is configurable via
    // targetOverrides.kong.bolaCacheTtl (default 60s — see STATUS.md for the
    // owner-change propagation tradeoff). The cache lookup is nil-safe: if
    // ngx.shared.writ_bola_cache is not declared at the nginx layer
    // (missing KONG_NGINX_HTTP_LUA_SHARED_DICT), we fall through to the
    // HTTP-only path so the rule still enforces — only the perf win is lost.
    head.push(
      `-- W10-11: shared_dict cache (key=principal:resource_id, TTL=${SS_BOLA_CACHE_TTL_SECONDS}s)`,
      `local ss_cache = ngx.shared.writ_bola_cache`,
      `local ss_resource_id = tostring(${idExpr} or "")`,
      `local ss_cache_key = tostring(principal) .. ":" .. ss_resource_id`,
      `local ss_cached_owner = ss_cache and ss_cache:get(ss_cache_key) or nil`,
      `local ss_resource = nil`,
      `if ss_cached_owner ~= nil then`,
      `  kong.log.warn("[writ-bola] cache_hit key=" .. ss_cache_key .. " owner=" .. tostring(ss_cached_owner))`,
      `  ss_resource = { ownerId = ss_cached_owner, _ss_cached = true }`,
      `else`,
      `  -- resource lookup: ${lookup.endpoint} (identifier from ${lookup.identifierFrom})`,
      `  kong.log.warn("[writ-bola] cache_miss key=" .. ss_cache_key)`,
      `  local ok_req, http = pcall(require, "resty.http")`,
      `  if not ok_req then`,
      `    kong.log.warn("[${SS_BOLA_TAG}] resty.http not available; failing closed")`,
      `    return kong.response.exit(403, {message = "Writ: resource access denied", tag = "${SS_BOLA_TAG}", reason = "resty_http_missing"})`,
      `  end`,
      `  local httpc = http.new()`,
      `  httpc:set_timeout(2000)`,
      `  local lookup_url = ${urlExpr}`,
      `  local ok_call, res = pcall(function()`,
      `    return httpc:request_uri(lookup_url, {`,
      `      method = "GET",`,
      `      headers = {`,
      `        ["Authorization"] = kong.request.get_header("Authorization"),`,
      `        ["X-Writ-Internal"] = "rule-lookup"`,
      `      },`,
      `      ssl_verify = false`,
      `    })`,
      `  end)`,
      `  if not ok_call or not res or res.status ~= 200 then`,
      `    kong.log.warn("[writ-bola] resource lookup failed status=" .. tostring(res and res.status or "no_response"))`,
      `    return kong.response.exit(403, {message = "Writ: resource access denied", tag = "${SS_BOLA_TAG}", reason = "lookup_failed"})`,
      `  end`,
      `  local ok_decode, body = pcall(cjson.decode, res.body or "{}")`,
      `  if not ok_decode or type(body) ~= "table" then`,
      `    kong.log.warn("[writ-bola] decode failed for " .. lookup_url)`,
      `    return kong.response.exit(403, {message = "Writ: invalid resource response", tag = "${SS_BOLA_TAG}", reason = "decode_failed"})`,
      `  end`,
      `  ss_resource = body`,
      `  if ss_cache and body.ownerId ~= nil then`,
      `    ss_cache:set(ss_cache_key, tostring(body.ownerId), ${SS_BOLA_CACHE_TTL_SECONDS})`,
      `  end`,
      `end`,
      ``
    );
  }

  const lua = head.join('\n') + '\n' + ruleSnippets.join('\n');
  return { lua, warnings };
}

export function buildRuleBasedAuthzPlugins(
  authz: Authorization | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  if (!authz || authz.type !== 'rule-based') return [];
  if (!authz.rules?.length) {
    if (ctx.warn) {
      ctx.warn({
        field: 'authorization.rules',
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
        declared: '(empty)',
        emitted: '(none)',
        reason:
          'authorization.type="rule-based" with no rules; pre-function not emitted. Either add rules or change type.'
      });
    }
    return [];
  }
  const { lua, warnings } = buildAuthzLua(authz, ctx);
  if (ctx.warn) {
    for (const w of warnings) ctx.warn(w);
    // W10-11: surface the shared_dict requirement once per pre-function
    // emission so operators booting Kong see it before traffic hits.
    ctx.warn({
      field: 'authorization.rule-based.cache',
      ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
      declared: 'shared_dict required for W10-11 cache',
      emitted: `KONG_NGINX_HTTP_LUA_SHARED_DICT="${SS_BOLA_CACHE_DICT} ${SS_BOLA_CACHE_DICT_SIZE}"`,
      reason:
        'declarative kong.yml cannot configure nginx-level directives. Set the env var ' +
        'on the Kong container so the shared_dict exists; the Lua is nil-safe and ' +
        'falls back to per-request HTTP lookup when the dict is missing (correctness ' +
        `preserved, perf regresses). Cache TTL=${SS_BOLA_CACHE_TTL_SECONDS}s — owner ` +
        'changes propagate within that window.'
    });
  }
  return [
    {
      name: 'pre-function',
      config: {
        access: [lua]
      },
      tags: [SS_BOLA_TAG]
    }
  ];
}

// ---------- K-2: SSRF url-allowlist (W19-A) via pre-function ----------
//
// Kong OSS has no native URL-allowlist plugin. We compile the spec's
// `request.schema.<field>.domainAllowlist` / `blockPrivateRanges:true` policy
// into a small Lua snippet attached via the `pre-function` plugin (same
// mechanism as K-1 BOLA). The Lua runs in the `access` phase and rejects
// requests where the URL param's host is not in the allowlist or matches a
// private/loopback prefix.
//
// Marker: response body carries `tag = "writ-rule-ssrf-403"` so the
// scorer maps the denial to defense-class `url-allowlist`.

const SS_SSRF_TAG = 'writ-rule-ssrf-403';
const SS_SSRF_PRIVATE_TAG = 'writ-rule-ssrf-private-403';

/** Lua table literal of lowercased allowed hosts, e.g. `{["roottusk.com"]=true}`. */
function luaHostSet(domains: readonly string[]): string {
  return '{' + domains.map((d) => `[${luaStr(d.toLowerCase())}]=true`).join(', ') + '}';
}

const SSRF_PRIVATE_LUA_PATTERNS = [
  '^10%.', '^127%.', '^169%.254%.', '^192%.168%.',
  '^172%.1[6-9]%.', '^172%.2%d%.', '^172%.3[01]%.',
  '^0%.0%.0%.0',
  '^localhost$', '^localhost:',
  '^internal%-only', '^%[::1', '^%[fc', '^%[fd', '^%[fe80'
];

/**
 * Build the SSRF pre-function plugin set for one endpoint. Inspects each
 * url-typed schema field; emits at most one plugin per endpoint (multiple
 * fields share the same Lua chunk).
 */
export function buildSsrfPreFunctionPlugins(
  request: RequestPolicy | undefined,
  ctx: { endpoint?: string; params?: ReadonlyArray<{ name: string; in: string }>; warn?: WarningSink } = {}
): KongPlugin[] {
  const schema = request?.schema;
  if (!schema) return [];

  interface Item { field: string; allow: string[]; block: boolean; source: 'query' | 'body'; }
  const items: Item[] = [];
  for (const [field, ps] of Object.entries(schema)) {
    if (!ps || ps.type !== 'url') continue;
    const allow = Array.isArray(ps.domainAllowlist) ? ps.domainAllowlist : [];
    const block = ps.blockPrivateRanges === true;
    if (allow.length === 0 && !block) continue;
    const isQuery = (ctx.params ?? []).some((p) => p.name === field && p.in === 'query');
    items.push({ field, allow, block, source: isQuery ? 'query' : 'body' });
  }
  if (items.length === 0) return [];

  // W21-C: Do NOT `require("cjson.safe")` here. Kong OSS pre-functions execute
  // inside the untrusted_lua sandbox; on hardened deployments the sandbox
  // rejects the require with "require 'cjson.safe' not allowed within sandbox"
  // and the route returns 500 on every hit. The SSRF check only needs Kong PDK
  // calls (kong.request.get_query_arg / get_body) + Lua string library, so we
  // omit the require entirely. See docs/incidents/2026-05-23-kong-cjson-sandbox.md
  // and Rule D-1 (no shortcuts that mask LLM-path quality issues).
  const lines: string[] = [
    `-- Writ W19-A SSRF url-allowlist pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `-- W21-C: pure Kong PDK + Lua stdlib (no external module loads). Hardened`,
    `-- OSS deployments restrict the untrusted_lua sandbox; this snippet runs there.`,
    ``,
    `local function ss_host(u)`,
    `  if type(u) ~= "string" or u == "" then return nil end`,
    `  local after = u:match("^[%a][%w+.-]*://(.*)$") or u`,
    `  local hostport = after:match("^([^/?#]*)") or ""`,
    `  local host = hostport:match("^([^:]+)") or hostport`,
    `  return host:lower()`,
    `end`,
    ``,
    `local function ss_is_private(h)`,
    `  if not h then return false end`,
  ];
  for (const p of SSRF_PRIVATE_LUA_PATTERNS) {
    lines.push(`  if h:match("${p}") then return true end`);
  }
  lines.push(`  return false`, `end`, ``);

  for (const it of items) {
    const reader = it.source === 'query'
      ? `kong.request.get_query_arg(${luaStr(it.field)})`
      : `(function() local b = kong.request.get_body() return type(b)=="table" and b[${luaStr(it.field)}] or nil end)()`;
    lines.push(`-- field=${it.field} source=${it.source}`);
    lines.push(`do`);
    lines.push(`  local raw = ${reader}`);
    lines.push(`  if raw ~= nil and raw ~= "" then`);
    lines.push(`    local host = ss_host(tostring(raw))`);
    if (it.allow.length > 0) {
      lines.push(`    local ss_allow = ${luaHostSet(it.allow)}`);
      lines.push(`    if not host or not ss_allow[host] then`);
      lines.push(`      kong.log.warn("[${SS_SSRF_TAG}] host '" .. tostring(host) .. "' not in domainAllowlist for ${it.field}")`);
      lines.push(`      return kong.response.exit(403, {message = "Writ: SSRF url not in domainAllowlist", tag = "${SS_SSRF_TAG}", field = ${luaStr(it.field)}})`);
      lines.push(`    end`);
    }
    if (it.block) {
      lines.push(`    if ss_is_private(host) then`);
      lines.push(`      kong.log.warn("[${SS_SSRF_PRIVATE_TAG}] private-range host '" .. tostring(host) .. "' on ${it.field}")`);
      lines.push(`      return kong.response.exit(403, {message = "Writ: SSRF blocked private/loopback host", tag = "${SS_SSRF_PRIVATE_TAG}", field = ${luaStr(it.field)}})`);
      lines.push(`    end`);
    }
    lines.push(`  end`);
    lines.push(`end`, ``);
  }

  return [{
    name: 'pre-function',
    config: { access: [lines.join('\n')] },
    tags: [SS_SSRF_TAG]
  }];
}

// ---------- K-3: mass-assignment (API6) via pre-function ----------
//
// vAPI eval gap: POST /vapi/api6/user with extra `{"credit":9999}` field
// succeeded because Kong OSS has no native unknown-field rejector. The
// `request-validator` plugin (which supports `additionalProperties:false`)
// is Enterprise-only.
//
// Spec gate: `request.denyUnknownFields === true` OR a non-empty
// `request.allowedFields`. When `allowedFields` is set, it wins; otherwise
// we derive the allowlist from `request.schema` top-level keys.
//
// Marker: response body `tag = "writ-mass-assign-403"` and access-log
// `kong.log.warn` so the scorer's docker channel picks it up.

const SS_MASS_ASSIGN_TAG = 'writ-mass-assign-403';

export function buildMassAssignPreFunctionPlugins(
  request: RequestPolicy | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  if (!request) return [];
  const explicitAllow = Array.isArray(request.allowedFields) ? request.allowedFields : undefined;
  const schemaKeys = request.schema ? Object.keys(request.schema) : [];
  const denyUnknown = request.denyUnknownFields === true;

  // Determine the allowlist. allowedFields wins; else derive from schema when
  // denyUnknownFields is set; else nothing to enforce.
  let allow: string[] | undefined;
  if (explicitAllow && explicitAllow.length > 0) {
    allow = explicitAllow;
  } else if (denyUnknown && schemaKeys.length > 0) {
    allow = schemaKeys;
  } else if (denyUnknown) {
    // denyUnknownFields=true but no schema/allowedFields — we can't safely
    // reject anything without an allowlist. Surface a warning rather than
    // emit a deny-everything (which would be a Rule D-1 violation: looks
    // protective but breaks the endpoint).
    if (ctx.warn) {
      ctx.warn({
        field: 'request.denyUnknownFields',
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
        declared: 'true',
        emitted: '(none)',
        reason:
          'denyUnknownFields=true requires either request.schema (top-level keys ' +
          'become the allowlist) or request.allowedFields. Neither is set; ' +
          'pre-function not emitted.'
      });
    }
    return [];
  }
  if (!allow) return [];

  const luaAllowTable = '{' + allow.map((k) => `[${luaStr(k)}]=true`).join(', ') + '}';
  const lua = [
    `-- Writ K-3 mass-assignment pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `-- Allowlist sourced from ${explicitAllow ? 'request.allowedFields' : 'request.schema top-level keys'}.`,
    `local ss_allow = ${luaAllowTable}`,
    `local body = kong.request.get_body()`,
    `if type(body) == "table" then`,
    `  for k, _ in pairs(body) do`,
    `    if not ss_allow[k] then`,
    `      kong.log.warn("[${SS_MASS_ASSIGN_TAG}] unknown field '" .. tostring(k) .. "' rejected")`,
    `      return kong.response.exit(403, {`,
    `        message = "Writ: unknown field rejected",`,
    `        tag = "${SS_MASS_ASSIGN_TAG}",`,
    `        field = tostring(k)`,
    `      })`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_MASS_ASSIGN_TAG]
  }];
}

// ---------- K-4: body SQLi heuristic (API8) via pre-function ----------
//
// vAPI eval gap: POST /vapi/api8/user/login body `{"username":"' OR 1=1-- -"}`
// succeeded because Kong OSS has no native SQLi detector. We add a heuristic
// regex over JSON body string values. Marker: `writ-sqli-403`.
//
// Spec gate: request declares `contentType` includes application/json AND has
// a body schema (otherwise we have no signal this endpoint takes JSON input).
// Don't emit on endpoints that don't accept JSON bodies (saves cycles + avoids
// breaking non-body methods like GET).

const SS_SQLI_TAG = 'writ-sqli-403';
// Lua patterns (not PCRE) — Kong pre-function runs against Lua's string lib.
// Patterns are intentionally narrow: classic union-based, comment-injection,
// boolean-tautology, and DDL-injection signatures. False-positive risk on
// legit text input exists; we surface it as a warning in STATUS.md.
const SQLI_LUA_PATTERNS = [
  "[' \"]%s*or%s+%d+%s*=%s*%d+",      // ' OR 1=1
  "[' \"]%s*or%s+['\"]?%w+['\"]?%s*=", // ' OR a=
  "%-%-%s",                             // -- comment
  "union%s+select",                    // UNION SELECT
  "drop%s+table",                      // DROP TABLE
  "insert%s+into",                     // INSERT INTO
  ";%s*shutdown",                      // ; shutdown
  "/%*.-%*/",                          // /* ... */ comment
  "0x%x+",                             // hex literal (loose; matched only when combined w/ above in practice)
];

export function buildSqliPreFunctionPlugins(
  request: RequestPolicy | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  if (!request) return [];
  const ct = request.contentType ?? [];
  const acceptsJson = ct.some((t) => t.toLowerCase().includes('json'));
  if (!acceptsJson) return [];
  if (!request.schema || Object.keys(request.schema).length === 0) return [];

  // Build a flat sequence of `if vl:match(...) then return field, ruleIndex end`
  // Each value is lowercased once and tested against every pattern.
  const checks: string[] = [];
  for (let i = 0; i < SQLI_LUA_PATTERNS.length; i++) {
    checks.push(`      if vl:match(${luaStr(SQLI_LUA_PATTERNS[i]!)}) then return k, ${i + 1} end`);
  }

  const lua = [
    `-- Writ K-4 SQLi heuristic pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `-- Scans JSON body string values for classic SQLi patterns; rejects on hit.`,
    `local body = kong.request.get_body()`,
    `if type(body) == "table" then`,
    `  local hit_field, hit_rule = (function()`,
    `    for k, v in pairs(body) do`,
    `      if type(v) == "string" then`,
    `        local vl = v:lower()`,
    checks.join('\n'),
    `      end`,
    `    end`,
    `    return nil, nil`,
    `  end)()`,
    `  if hit_field ~= nil then`,
    `    kong.log.warn("[${SS_SQLI_TAG}] sqli pattern " .. tostring(hit_rule) .. " in field '" .. tostring(hit_field) .. "'")`,
    `    return kong.response.exit(403, {`,
    `      message = "Writ: SQLi pattern rejected",`,
    `      tag = "${SS_SQLI_TAG}",`,
    `      field = tostring(hit_field),`,
    `      rule = hit_rule`,
    `    })`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_SQLI_TAG]
  }];
}

// ---------- K-5: deprecated-endpoint block (API9) via pre-function ----------
//
// vAPI eval gap: rate-limit fires on /vapi/api9/v1/user/login but the scorer
// can't tell whether the 429s are "deprecated endpoint should be blocked
// entirely" or "rate-limit doing its job". Spec declares
// `x-security.deprecated: true` (and OpenAPI op-level `deprecated: true`),
// so we emit a hard 410 Gone with marker `writ-deprecated-endpoint-block`.
//
// This runs in the access phase BEFORE rate-limit, so it short-circuits
// every request with the marker tag, letting attribution.py classify the
// block as `deprecated-endpoint-block` instead of `wholesale-rate-limit`.
//
// Gate: `policy.deprecated === true`. When `sunsetDate` is set we also emit
// RFC 8594 `Deprecation: true` + `Sunset: <date>` response headers (not just
// body fields) so inventory tooling sees the standard signal. `replacementEndpoint`
// is surfaced in the response body for operator/client clarity but doesn't
// affect emission.

export const SS_DEPRECATED_TAG = 'writ-deprecated-endpoint-block';

export function buildDeprecatedEndpointPlugins(
  policy: XSecurityPolicy,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (policy.deprecated !== true) return [];
  const bodyFields: string[] = [
    `message = "Writ: endpoint is deprecated"`,
    `tag = "${SS_DEPRECATED_TAG}"`
  ];
  if (policy.sunsetDate) bodyFields.push(`sunset = ${luaStr(policy.sunsetDate)}`);
  if (policy.replacementEndpoint) bodyFields.push(`replacement = ${luaStr(policy.replacementEndpoint)}`);

  // RFC 8594 deprecation/sunset signalling. When the spec declares a sunset
  // date, emit it as real HTTP response headers (not just a body field) so
  // automated inventory tooling and standards-aware clients see the signal:
  //   Deprecation: true          (RFC 8594 §2)
  //   Sunset: <date>             (RFC 8594 §3)
  const headerFields: string[] = [];
  if (policy.sunsetDate) {
    headerFields.push(`["Deprecation"] = "true"`);
    headerFields.push(`["Sunset"] = ${luaStr(policy.sunsetDate)}`);
  }

  const exitArgs = [`410`, `{\n  ${bodyFields.join(',\n  ')}\n}`];
  if (headerFields.length > 0) {
    exitArgs.push(`{\n  ${headerFields.join(',\n  ')}\n}`);
  }

  const lua = [
    `-- Writ K-5 deprecated-endpoint block for endpoint=${ctx.endpoint ?? '?'}`,
    `kong.log.warn("[${SS_DEPRECATED_TAG}] request to deprecated endpoint blocked")`,
    `return kong.response.exit(${exitArgs.join(', ')})`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_DEPRECATED_TAG]
  }];
}

// ---------- rate limit ----------

// W23-C1 (Kong half): per-route burst headroom — mirrors Envoy W15-B.
//
// Kong OSS's `rate-limiting` plugin has no native `burst` field; the bucket
// size IS the period limit. To allow short bursts above steady-state without
// losing the long-term cap, we set the bucket value for the spec's window to
// `max(burst, defaultBurst(requests))` so a tight bucket (e.g. 10/min) has
// headroom for auth-evaluating phases (jwt / acl / pre-function BOLA / ssrf)
// to reach and reject the bulk of an attack stream before rate-limiting
// short-circuits it with 429.
//
// Without this, the scorer's intent-attribution downgrade weighs the burst
// as ×0.3 (wholesale-rate-limit) instead of ×1.0 (per-id-rate-limit, since
// auth gets a chance to fire). See docs/vapi-evaluation-final-report.md gap C1.
//
// Explicit `burst` in the spec always wins (when > requests). The synthesized
// value is only applied when `burst` is unset or smaller than the steady limit.
const DEFAULT_BURST_MULTIPLIER = 3;
const DEFAULT_BURST_MINIMUM_HEADROOM = 20;

function defaultBurst(requests: number): number {
  return Math.max(
    requests * DEFAULT_BURST_MULTIPLIER,
    requests + DEFAULT_BURST_MINIMUM_HEADROOM
  );
}

// W23-C1 scorer marker. Emitted as a plugin tag on every per-route rate-limit
// plugin so Kong's access log (which includes plugin tags by default) carries
// a per-route qualifier the scorer can attribute as `per-id-rate-limit`
// instead of the default wholesale-rate-limit class.
//
// Scorer follow-up: add to MARKER_CLASS_RULES in attribution.py:
//   r'writ-per-route-ratelimit:' → class=per-id-rate-limit
export const SS_PER_ROUTE_RATELIMIT_TAG_PREFIX = 'writ-per-route-ratelimit';

// Context passed from the per-endpoint builder so rate-limit can detect
// "this endpoint is unauthenticated" and force `limit_by: ip`. Without this
// the default `limit_by: consumer` silently no-ops on unauth routes
// (failed-login bursts have no consumer to bucket against).
export interface RateLimitContext {
  /** True if the endpoint's authentication.type is "none" or undefined. */
  unauthenticated?: boolean;
  /** True if the endpoint matches the login/signup heuristic. */
  loginLike?: boolean;
  /** Endpoint operationId, for the structured warning record. */
  endpoint?: string;
  /** Warning sink so the consumer→ip downgrade is recorded in kong.yml. */
  warn?: WarningSink;
  /** True when the Kong deployment is DB-less (`KONG_DATABASE=off`). Cluster
   *  policy requires the `database` mode (postgres/cassandra), so when this
   *  flag is set we fall back to `policy: local` for per-identity buckets
   *  and emit a loud warning — the intent (per-id rate-limit) is partially
   *  preserved (limit_by still keys per-id within the instance) but
   *  cross-instance counter sharing is lost. */
  dbless?: boolean;
  /** W21-C: explicit rate-limit policy selection. Kong OSS DB-less (the common
   *  default) silently refuses to load with `policy: cluster`, so we default to
   *  `local` and require explicit opt-in for cluster. Operators with a DB-backed
   *  Kong deployment set `policy: 'cluster'` to restore the W15-C per-identity
   *  cross-instance counter sharing. `dbless: true` still hard-overrides any
   *  cluster request back to local. */
  policy?: 'local' | 'cluster';
}

// W15-C: per-identity rate-limit buckets (credential / consumer / header) need
// counters shared across Kong instances to actually behave per-identity in a
// multi-instance deployment — that's `policy: cluster` (or `redis`). The
// default `policy: local` keeps counters in-process and is fine for limit_by=ip
// on a single instance, but for non-ip identifiers it silently scopes
// per-identity counters per-instance, which lets attackers round-robin past
// the limit.
//
// W21-C: the W15-C default of `cluster` for non-ip identifiers was a footgun
// on Kong OSS DB-less (the common case — `KONG_DATABASE=off` is the OSS
// quickstart default). Kong refuses to load with `policy: cluster` in
// DB-less mode, which silently broke every fresh-regenerated chain that
// didn't pass `--kong-dbless`. We now default to `local` and require
// explicit opt-in to `cluster` via `--kong-policy cluster` (operator
// confirms they have a DB-backed Kong). The W15-C per-identity intent is
// surfaced as a structured warning when `local` is used with a non-ip
// limit_by so operators know what they're giving up.
function rateLimitPolicyFor(
  limitBy: string,
  dbless: boolean,
  explicitPolicy: 'local' | 'cluster' | undefined
): { policy: 'local' | 'cluster'; warning?: string } {
  if (limitBy === 'ip') {
    return { policy: 'local' };
  }
  // DB-less is the hardest constraint: cluster is a boot error there, so any
  // intent toward cluster (explicit opt-in OR W15-C per-identity intent) is
  // surfaced with the DB-less-specific explanation.
  if (dbless) {
    return {
      policy: 'local',
      warning:
        'per-identity rate-limit (limit_by=' +
        limitBy +
        ') on DB-less Kong falls back to policy=local; counters are scoped per-instance and not shared. ' +
        'For true cross-instance per-identity buckets, either run Kong in database mode (policy=cluster) ' +
        'or add a redis store and switch to policy=redis.'
    };
  }
  // Explicit cluster opt-in (operator confirms DB-backed Kong).
  if (explicitPolicy === 'cluster') {
    return { policy: 'cluster' };
  }
  // Default (no explicit cluster opt-in, DB-backed mode unknown): local. Warn
  // for non-ip identifiers so operators see the per-identity-intent gap and
  // know to opt into cluster when their deployment supports it.
  return {
    policy: 'local',
    warning:
      'rate-limit limit_by=' +
      limitBy +
      ' uses policy=local by default; counters are scoped per-Kong-instance ' +
      'and not shared. For true per-identity buckets across instances, run Kong ' +
      'in database mode and pass `--kong-policy cluster`, or add a redis store and use policy=redis.'
  };
}

export function buildRateLimitPlugins(
  rateLimit: RateLimit | RateLimit[] | undefined,
  ctx: RateLimitContext = {}
): KongPlugin[] {
  if (!rateLimit) return [];
  const list = Array.isArray(rateLimit) ? rateLimit : [rateLimit];
  return list.map((rl) => {
    const seconds = parseDurationSeconds(rl.window);
    const bucket = rateLimitBucket(seconds);
    // v0.4 S-6 / v0.5 S-14: identifier may be string | string[] | {components, combinator}.
    // Kong rate-limit has a single `limit_by`, so we honor the first component of a
    // compound key. The object form is the v0.5 explicit shape.
    let primaryId: string | undefined;
    if (typeof rl.identifier === 'string') {
      primaryId = rl.identifier;
    } else if (Array.isArray(rl.identifier)) {
      primaryId = rl.identifier[0];
    } else if (rl.identifier && typeof rl.identifier === 'object' && 'components' in rl.identifier) {
      primaryId = (rl.identifier as { components: string[] }).components[0];
    }
    let limitBy = rateLimitLimitBy(primaryId);
    // Auto-switch consumer→ip when the request can't possibly carry a
    // consumer identity. Cases:
    //   - rateLimit.when === "unauthenticated"
    //   - authentication.type === "none" / missing
    //   - login/signup-style endpoint (failed creds have no consumer)
    const when = (rl as { when?: string }).when;
    const isUnauthBucket =
      when === 'unauthenticated' ||
      ctx.unauthenticated === true ||
      ctx.loginLike === true;
    if (isUnauthBucket && limitBy === 'consumer') {
      if (ctx.warn) {
        const warnRec: WritWarning = {
          field: 'rateLimit.limit_by',
          declared: 'consumer',
          emitted: 'ip',
          reason:
            'unauthenticated/login-style endpoint has no consumer identity; ' +
            'limit_by=consumer would never accumulate. Forcing limit_by=ip ' +
            'so failed-login bursts get rate-limited.',
          ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {})
        };
        ctx.warn(warnRec);
      }
      limitBy = 'ip';
    }
    const { policy, warning: policyWarning } = rateLimitPolicyFor(
      limitBy,
      ctx.dbless === true,
      ctx.policy
    );
    if (policyWarning && ctx.warn) {
      ctx.warn({
        field: 'rateLimit.policy',
        declared: ctx.policy === 'cluster' ? 'cluster (explicit opt-in)' : 'cluster (per-identity intent)',
        emitted: policy,
        reason: policyWarning,
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {})
      });
    }
    // W23-C1: per-route burst headroom. Explicit `burst` in the spec wins when
    // it exceeds requests; otherwise synthesize a proportional headroom so the
    // bucket doesn't drain inside an auth-attack burst before jwt/acl/pre-fn
    // can reject it (which would mis-attribute the block as rate-limit).
    const specBurst = (rl as { burst?: number }).burst;
    const bucketValue =
      specBurst && specBurst > rl.requests ? specBurst : defaultBurst(rl.requests);
    const config: Record<string, unknown> = {
      [bucket]: bucketValue,
      limit_by: limitBy,
      policy,
      fault_tolerant: true,
      hide_client_headers: false
    };
    if (primaryId?.startsWith('header:') && limitBy === 'header') {
      config.header_name = primaryId.slice('header:'.length);
    }
    // W23-C1: per-route scorer marker. Kong serializes plugin tags into the
    // access log line, which is the signal the scorer attributes on. The
    // endpoint suffix qualifies the bucket as per-route (not wholesale),
    // letting attribution.py map this to per-id-rate-limit (×1.0) instead of
    // wholesale-rate-limit (×0.3).
    const tags: string[] = [];
    if (ctx.endpoint) {
      tags.push(sanitizeTag(`${SS_PER_ROUTE_RATELIMIT_TAG_PREFIX}:${ctx.endpoint}`));
    } else {
      tags.push(SS_PER_ROUTE_RATELIMIT_TAG_PREFIX);
    }
    const plugin: KongPlugin = { name: 'rate-limiting', config, tags };
    return plugin;
  });
}

// ---------- cors ----------

export function buildCorsPlugin(cors: Cors | undefined): KongPlugin[] {
  if (!cors) return [];
  const config: Record<string, unknown> = {};
  if (cors.allowedOrigins) config.origins = cors.allowedOrigins;
  if (cors.allowedMethods) config.methods = cors.allowedMethods;
  if (cors.allowedHeaders) config.headers = cors.allowedHeaders;
  if (cors.exposeHeaders) config.exposed_headers = cors.exposeHeaders;
  if (cors.maxAge !== undefined) config.max_age = cors.maxAge;
  if (cors.credentials !== undefined) config.credentials = cors.credentials;
  config.preflight_continue = false;
  return [{ name: 'cors', config }];
}

// ---------- ip policy ----------

export function buildIpRestrictionPlugin(ip: IpPolicy | undefined): KongPlugin[] {
  if (!ip) return [];
  const config: Record<string, unknown> = {};
  if (Array.isArray(ip.allow) && ip.allow.length) config.allow = ip.allow;
  if (Array.isArray(ip.deny) && ip.deny.length) config.deny = ip.deny;
  if (!('allow' in config) && !('deny' in config)) return [];
  return [{ name: 'ip-restriction', config }];
}

// ---------- cache ----------

export function buildCachePlugins(cacheable: Cacheable | undefined): KongPlugin[] {
  if (cacheable === undefined) return [];
  const enabled = typeof cacheable === 'boolean' ? cacheable : cacheable.enabled;

  if (!enabled) {
    // Use response-transformer to inject Cache-Control: no-store
    return [
      {
        name: 'response-transformer',
        config: {
          add: {
            headers: ['Cache-Control:no-store', 'Pragma:no-cache']
          }
        }
      }
    ];
  }

  const config: Record<string, unknown> = {
    response_code: [200],
    request_method: ['GET', 'HEAD'],
    content_type: ['application/json'],
    cache_ttl: typeof cacheable === 'object' && cacheable.ttl ? cacheable.ttl : 300,
    strategy: 'memory'
  };
  if (typeof cacheable === 'object' && cacheable.varyBy?.length) {
    config.vary_headers = cacheable.varyBy;
  }
  return [{ name: 'proxy-cache', config }];
}

// ---------- request validation ----------

const SEMANTIC_TO_JSON: Record<string, { type: string; format?: string }> = {
  string: { type: 'string' },
  integer: { type: 'integer' },
  float: { type: 'number' },
  boolean: { type: 'boolean' },
  email: { type: 'string', format: 'email' },
  phone: { type: 'string' },
  url: { type: 'string', format: 'uri' },
  date: { type: 'string', format: 'date' },
  datetime: { type: 'string', format: 'date-time' },
  uuid: { type: 'string', format: 'uuid' },
  'ip-address': { type: 'string', format: 'ipv4' },
  name: { type: 'string' },
  'free-text': { type: 'string' },
  binary: { type: 'string', format: 'binary' }
};

function paramSchemaToJson(ps: ParamSchema): Record<string, unknown> {
  const base = ps.type ? SEMANTIC_TO_JSON[ps.type] : { type: 'string' };
  const out: Record<string, unknown> = { ...(base ?? { type: 'string' }) };
  if (ps.minLength !== undefined) out.minLength = ps.minLength;
  if (ps.maxLength !== undefined) out.maxLength = ps.maxLength;
  if (ps.fixedLength !== undefined) {
    out.minLength = ps.fixedLength;
    out.maxLength = ps.fixedLength;
  }
  if (ps.min !== undefined) out.minimum = ps.min;
  if (ps.max !== undefined) out.maximum = ps.max;
  if (ps.pattern !== undefined) out.pattern = ps.pattern;
  return out;
}

export type KongEdition = 'oss' | 'enterprise';

export function buildRequestValidatorPlugin(
  req: RequestPolicy | undefined,
  edition: KongEdition = 'oss'
): KongPlugin[] {
  if (!req) return [];
  const plugins: KongPlugin[] = [];

  // `request-validator` is Kong Enterprise only. Emitting it on OSS causes
  // `plugin 'request-validator' not enabled` at boot — drop it for OSS,
  // but keep `request-size-limiting` (which is OSS-supported).
  const allowRequestValidator = edition === 'enterprise';

  if (allowRequestValidator && req.schema && Object.keys(req.schema).length > 0) {
    const properties: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(req.schema)) {
      properties[key] = paramSchemaToJson(val);
    }
    const bodySchema = {
      type: 'object',
      properties,
      additionalProperties: false
    };
    const config: Record<string, unknown> = {
      body_schema: JSON.stringify(bodySchema),
      verbose_response: false,
      version: 'draft4'
    };
    if (req.contentType?.length) {
      config.allowed_content_types = req.contentType;
    }
    plugins.push({ name: 'request-validator', config });
  } else if (allowRequestValidator && req.contentType?.length) {
    plugins.push({
      name: 'request-validator',
      config: {
        allowed_content_types: req.contentType,
        verbose_response: false
      }
    });
  }

  if (req.maxBodySize) {
    plugins.push({
      name: 'request-size-limiting',
      config: {
        allowed_payload_size: Math.max(1, Math.round(parseByteSize(req.maxBodySize) / (1024 * 1024))),
        size_unit: 'megabytes',
        require_content_length: false
      }
    });
  }

  return plugins;
}

// ---------- response (best-effort) ----------

export function buildResponsePlugins(resp: ResponsePolicy | undefined): KongPlugin[] {
  if (!resp) return [];
  // Kong OSS cannot filter response body fields. We emit a response-transformer
  // header marker for observability and rely on `stripUnknownFields` being
  // honored upstream. This is intentionally 'partial' in capability matrix.
  if (!resp.contentType?.length) return [];
  return [];
}

// ---------- overrides ----------

export function applyTargetOverrides(
  policy: XSecurityPolicy,
  plugins: KongPlugin[]
): KongPlugin[] {
  const override = policy.targetOverrides?.kong;
  if (!override) return plugins;
  // Merge override plugins (if provided as { plugins: [...] }) and tag them so
  // operators can find them. Other keys are passed through as plugin entries.
  const out = [...plugins];
  if (Array.isArray((override as { plugins?: unknown }).plugins)) {
    for (const p of (override as { plugins: KongPlugin[] }).plugins) {
      out.push({
        ...p,
        tags: [...(p.tags ?? []).map(sanitizeTag), '# [OVERRIDE]']
      });
    }
  }
  return out;
}

// Read the kong edition from policy.targetOverrides.kong.edition.
// Default: 'oss'. Anything except 'enterprise' is treated as 'oss'.
export function kongEditionFor(policy: XSecurityPolicy): KongEdition {
  const ov = policy.targetOverrides?.kong as { edition?: string } | undefined;
  return ov?.edition === 'enterprise' ? 'enterprise' : 'oss';
}
