/**
 * Coraza WAF v3.x rule builders.
 *
 * Each builder emits a ModSecurity-compatible directive string (with leading
 * `# comment` lines explaining provenance) that Coraza can parse via
 * `coraza.NewWAFConfig().WithDirectives(...)`.
 *
 * Rule ID convention:
 *   base = 100000 + (endpointHash % 9000) * 10
 *   each rule slot adds 0..9 (slots reserved per category below).
 * This keeps x-security rule IDs comfortably above the OWASP CRS range
 * (typically 9xxxxx) while staying below 200000 and giving every endpoint
 * a stable, collision-resistant block.
 */

import type { EndpointIR } from '@x-security/core';
import type { XSecurityPolicy, ParamSchema, RateLimit, IpPolicy, SemanticType } from '@x-security/schema';
import {
  CORAZA_GO_PROFILE,
  type CorazaEngineProfile,
  type EngineWarning,
} from './profiles.js';
import { buildIdentityRules } from './identity-rules.js';
import { buildCorsRules } from './cors-rules.js';
import {
  buildOutputSanitizationRules,
  buildDataExposurePiiRules,
} from './data-exposure-rules.js';
import { buildLifecycleRules } from './lifecycle-rules.js';
import { buildCsrfRules } from './csrf-rules.js';
import { buildDuplicateParamRules } from './duplicate-param-rules.js';
import { buildResponseContentTypeRules } from './response-content-type-rules.js';
import {
  buildSerializeByRules,
  buildGraphqlStaticLimitRules,
  buildResidualScaffolding,
} from './v08-residual-rules.js';
import {
  buildPasswordPolicyRules,
  buildAccountLockoutRules,
  buildForbidArrayRootRules,
  buildIdempotencyKeyRules,
  buildLoggingRules,
} from './v07-rules.js';

const BASE_ID = 100000;

/** Stable non-negative 32-bit hash for the endpoint identity. */
export function endpointHash(method: string, path: string): number {
  let h = 2166136261 >>> 0;
  const s = `${method} ${path}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

/** Per-endpoint ID block size — each endpoint gets this many reserved IDs. */
const SLOT_STRIDE = 30;

/**
 * Dedicated ID base for the body-field allowlist (mass-assignment defense).
 * Lives outside the per-endpoint `BASE_ID + slot*SLOT_STRIDE` range so adding
 * this category did not require widening the existing stride (which would
 * have shifted every previously-emitted rule ID).
 *
 * Range: 400000..408999 (9000 slots × 1 ID each). Stays comfortably below
 * the 600k mark and well above the per-endpoint primary range.
 */
const BODY_ALLOWLIST_BASE_ID = 400000;

/**
 * C-1: Response-body inspection rule IDs (phase 4, API3 BOPLA defense).
 * Range 420000..428999 (1 ID per endpoint per field constraint, FNV-1a-hash
 * keyed). Disjoint from the per-endpoint primary range (100000–369999),
 * body-allowlist range (400000–408999), and JSON-body-processor range
 * (410000–418999).
 */
const RESPONSE_INSPECT_BASE_ID = 420000;

/** Rule-id "slot" base for an endpoint. */
export function ruleBase(endpoint: EndpointIR): number {
  const slot = endpointHash(endpoint.method, endpoint.path) % 9000;
  return BASE_ID + slot * SLOT_STRIDE;
}

/**
 * Slot offsets reserved per category. Each endpoint owns a block of
 * {@link SLOT_STRIDE} contiguous IDs; categories are positioned so rate-limit
 * has room for its multi-rule chain (initcol/setvar/check, plus optional
 * burst) without colliding with schema-validation IDs.
 */
export const SLOT = {
  scope: 0,     // path/method match flag (tx.x_security_match)
  ctype: 1,     // content-type allowlist
  bodySize: 2,  // max body size (directive, not SecRule)
  auth: 3,      // missing auth header
  ipAllow: 4,   // ip allowlist
  ipDeny: 5,    // ip denylist
  // 6..15 reserved for rate-limit rules (multiple RL entries × up to 6 IDs each).
  rate: 6,
  schema: 16,   // first schema-validation rule (consumes IDs 16..29)
} as const;

/** Number of rule IDs consumed by one rate-limit entry without burst. */
const RL_IDS_PRIMARY = 3;
/** Number of rule IDs consumed by one rate-limit entry with burst. */
const RL_IDS_WITH_BURST = 6;

/**
 * W19-A: SSRF url-allowlist rule IDs. Two IDs per (endpoint, field):
 *   980000+slot*2  → host not in domainAllowlist (tag x-security-rule-ssrf-403)
 *   980000+slot*2+1→ host matches private-range pattern (tag x-security-rule-ssrf-private-403)
 * Disjoint from every other range (per-endpoint primary 100000-369999,
 * body-allowlist 400000-408999, response-inspect 420000-428999, SQLi
 * 430000+). Hash-keyed for collision resistance.
 */
const SSRF_BASE_ID = 980000;

/**
 * Private/loopback/link-local host prefix patterns the SecRule denies on when
 * blockPrivateRanges:true. ModSecurity's @rx evaluates against the raw arg
 * value; we anchor to the URL host position by matching after `://`.
 *
 * W21-B: the IPv6 literal-bracket prefix is expressed as a single-char class
 * `[\[]` rather than `\[`. The SecRule arg parser strips unknown backslash
 * escapes (`\X` → `X`), so emitting `\[` reaches the Go regexp compiler as a
 * bare `[`, opening an unterminated character class and crashing rule load
 * at SPOA startup ("error parsing regexp: missing closing ]"). A
 * single-char class survives the strip because `[`/`]` are not
 * backslash-prefixed, and Go RE2 treats `[[]` as a class matching literal `[`.
 */
const SSRF_PRIVATE_HOST_RX =
  '(?i)(?:^|//)(?:' +
  '10\\.|127\\.|0\\.0\\.0\\.0|169\\.254\\.|192\\.168\\.|' +
  '172\\.(?:1[6-9]|2[0-9]|3[0-1])\\.|' +
  'localhost|internal-only|' +
  '[\\[](?:::1|fc|fd|fe80)' +
  ')';

/** Escape a string for safe inclusion inside a ModSecurity quoted operator arg. */
function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Escape a regex string for inclusion as an `@rx`/`!@rx` arg.
 *
 * Unlike {@link esc}, this does NOT double existing backslashes — they are
 * part of the regex syntax (e.g. `\.` to match a literal dot) and
 * libmodsecurity3 / Coraza pass the @rx argument straight to the regex
 * compiler without an unescape pass. Doubling them turns `\.` into `\\.`
 * which the compiler reads as "literal backslash followed by .com" — the
 * pattern then never matches a real URL.
 *
 * Verified via modsec debug log: rule 980498 evaluated the regex
 * `(?i)^(?:[a-z][...]*:)?//(?:roottusk\\.com)(?:[/:?#]|$)` (two backslashes,
 * pre-fix) against `https://roottusk.com/x` and returned no match, so the
 * `!@rx` allowlist denied the legitimate request. Switching to single-
 * backslash emission lets the regex match correctly.
 *
 * We still escape `"` because a literal double-quote inside the SecRule arg
 * would terminate the quoted action string.
 */
function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}

/** Convert ByteSize ("1MB", "50KB", "1024") → bytes. Returns NaN if unparseable. */
export function parseByteSize(v: string | undefined): number {
  if (!v) return NaN;
  const m = /^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?$/i.exec(v.trim());
  if (!m) return NaN;
  const n = Number(m[1]);
  const unit = (m[2] ?? 'B').toUpperCase();
  const mult = unit === 'GB' ? 1024 ** 3 : unit === 'MB' ? 1024 ** 2 : unit === 'KB' ? 1024 : 1;
  return Math.round(n * mult);
}

/** Convert Duration ("5m", "30s", "1h") → seconds. Returns NaN if unparseable. */
export function parseDurationSec(v: string | undefined): number {
  if (!v) return NaN;
  const m = /^(\d+)\s*(s|m|h|d)?$/i.exec(v.trim());
  if (!m) return NaN;
  const n = Number(m[1]);
  const unit = (m[2] ?? 's').toLowerCase();
  return unit === 'd' ? n * 86400 : unit === 'h' ? n * 3600 : unit === 'm' ? n * 60 : n;
}

/**
 * Build the ModSecurity regex used to match a path template.
 * Replaces `{param}` segments with `[^/]+`. Anchors fully.
 */
export function pathRegex(path: string): string {
  const escaped = path.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  const withParams = escaped.replace(/\\\{[^/]+?\\\}/g, '[^/]+');
  return `^${withParams}$`;
}

interface RuleCtx {
  endpoint: EndpointIR;
  base: number;
  tag: string; // shared msg tag, e.g. "x-security/POST /api/auth/login"
}

function header(comment: string): string {
  return comment
    .split('\n')
    .map((l) => `# ${l}`)
    .join('\n');
}

/**
 * Scope marker rule. Sets tx.ss_match=1 when the request matches this endpoint
 * (method + path). All subsequent x-security rules for this endpoint chain off
 * REQUEST_URI/REQUEST_METHOD directly rather than this flag (Coraza chained
 * SecRules with `setvar` semantics are simpler to keep stateless), but we
 * still emit it as a no-op informational tag for traceability.
 */
export function buildScopeMarker(ctx: RuleCtx): string {
  const { endpoint, base, tag } = ctx;
  const id = base + SLOT.scope;
  return [
    header(`endpoint scope marker for ${endpoint.method} ${endpoint.path}`),
    `SecAction "id:${id},phase:1,pass,nolog,tag:'${esc(tag)}'"`,
  ].join('\n');
}

/**
 * Chain-terminator action suffix.
 *
 * libmodsecurity3 (modsec-nginx/apache) requires every chained child SecRule
 * to carry an actions arg, even just `"t:none"`. Coraza-Go accepts bare
 * terminators, and the existing golden snapshot depends on that bareness —
 * so we only append the suffix when the engine demands it.
 */
function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

/** Content-Type allowlist: REQUEST_HEADERS:Content-Type must match regex. */
export function buildContentType(
  ctx: RuleCtx,
  allowed: string[],
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string | null {
  if (!allowed.length) return null;
  const { endpoint, base, tag } = ctx;
  const id = base + SLOT.ctype;
  // Build alternation of escaped, anchored-loose regex (mime allowed with params).
  const alt = allowed
    .map((c) => c.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
  const term = chainTerm(profile);
  return [
    header(`request.contentType allowlist for ${endpoint.method} ${endpoint.path}`),
    `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:415,msg:'x-security: unsupported Content-Type',tag:'${esc(tag)}',chain"`,
    `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
    `    SecRule REQUEST_HEADERS:Content-Type "!@rx ^(${alt})(;.*)?$"${term}`,
  ].join('\n');
}

/**
 * Max body size — Coraza supports SecRequestBodyLimit *globally*, so we emit
 * the smallest cap as a top-level directive AND, per-endpoint, an explicit
 * `&REQUEST_BODY @gt N` check so that smaller per-endpoint limits are
 * enforced even when the global cap is higher.
 */
export function buildBodySize(
  ctx: RuleCtx,
  bytes: number,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string {
  const { endpoint, base, tag } = ctx;
  const id = base + SLOT.bodySize;
  const term = chainTerm(profile);
  return [
    header(`request.maxBodySize=${bytes} bytes for ${endpoint.method} ${endpoint.path}`),
    `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:413,msg:'x-security: request body exceeds endpoint limit',tag:'${esc(tag)}',chain"`,
    `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
    `    SecRule REQUEST_HEADERS:Content-Length "@gt ${bytes}"${term}`,
  ].join('\n');
}

/** Authentication: require Authorization (or custom) header when type != none. */
export function buildAuth(
  ctx: RuleCtx,
  headerName: string,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string {
  const { endpoint, base, tag } = ctx;
  const id = base + SLOT.auth;
  const hdr = headerName || 'Authorization';
  const term = chainTerm(profile);
  return [
    header(`authentication required (${hdr}) for ${endpoint.method} ${endpoint.path}`),
    `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:401,msg:'x-security: missing ${esc(hdr)} header',tag:'${esc(tag)}',chain"`,
    `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
    `    SecRule &REQUEST_HEADERS:${hdr} "@eq 0"${term}`,
  ].join('\n');
}

/** IP allow/deny via @ipMatch. allow → deny anything NOT in list. */
export function buildIpPolicy(
  ctx: RuleCtx,
  ipPolicy: IpPolicy,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const { endpoint, base, tag } = ctx;
  const out: string[] = [];
  const term = chainTerm(profile);
  const allow = Array.isArray(ipPolicy.allow) ? ipPolicy.allow : undefined;
  const deny = Array.isArray(ipPolicy.deny) ? ipPolicy.deny : undefined;
  if (allow && allow.length) {
    const id = base + SLOT.ipAllow;
    out.push(
      [
        header(`ipPolicy.allow for ${endpoint.method} ${endpoint.path}`),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:403,msg:'x-security: source IP not in allowlist',tag:'${esc(tag)}',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
        `    SecRule REMOTE_ADDR "!@ipMatch ${allow.join(',')}"${term}`,
      ].join('\n')
    );
  }
  if (deny && deny.length) {
    const id = base + SLOT.ipDeny;
    out.push(
      [
        header(`ipPolicy.deny for ${endpoint.method} ${endpoint.path}`),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:403,msg:'x-security: source IP in denylist',tag:'${esc(tag)}',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
        `    SecRule REMOTE_ADDR "@ipMatch ${deny.join(',')}"${term}`,
      ].join('\n')
    );
  }
  return out;
}

/** Resolved collection + counter variable for a rate-limit identifier. */
interface RateLimitTarget {
  /** Display label for the comment header. */
  label: string;
  /**
   * `initcol` argument — `<collection>=<key>` (e.g. `ip=%{REMOTE_ADDR}`,
   * `user=%{REQUEST_HEADERS.Authorization}`).
   *
   * `null` means the identifier could not be resolved (e.g. unauthenticated
   * `user-id`), in which case the entire rate-limit rule is skipped.
   */
  initcol: string | null;
  /**
   * Collection name (in the `setvar:<col>.<var>` form). One of the
   * profile's `legalCollections` for the chosen engine. Must match the
   * collection in {@link initcol}.
   */
  collection: 'ip' | 'user' | 'global' | 'resource' | 'session' | 'tx';
  /** A warning to surface alongside this target (downgrade explanation). */
  warning?: EngineWarning;
}

/**
 * Map a x-security rate-limit identifier to the Coraza collection + key it
 * should be stored under.
 *
 * Coraza supports persistent collections `ip`, `user`, `global`, `resource`,
 * `session` (per ModSecurity v3 semantics). We map:
 *
 *   - `ip` (default)              → `initcol:ip=%{REMOTE_ADDR}`, stored in `ip.*`
 *   - `user-id`                   → `initcol:user=%{REQUEST_HEADERS.Authorization}`, `user.*`
 *   - `api-key`                   → `initcol:user=%{REQUEST_HEADERS.X-API-Key}`, `user.*`
 *   - `header:<Name>`             → `initcol:user=%{REQUEST_HEADERS.<Name>}`, `user.*`
 *   - `fingerprint`               → falls back to IP (no native fingerprint signal)
 *
 * The `user` collection is keyed by an arbitrary string — using the
 * Authorization or API-key header value gives per-principal counters that
 * persist across requests, which is the behavior the x-security contract
 * implies.
 */
function resolveRateLimitTarget(
  identifier: string,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  endpointId = '*'
): RateLimitTarget {
  // IP-keyed counters. libmodsec3 (modsec-nginx/apache) supports `ip` as a
  // true persistent collection — emit `initcol:ip=...` directly. Coraza-Go /
  // Coraza-SPOA's runtime enforces setvar TX-only (verified: ghcr.io/corazawaf/
  // coraza-spoa rejects setvar:ip.X with "expected collection TX" at WAF init);
  // cross-request enforcement on those engines requires HAProxy stick-tables,
  // and we downgrade to a TX-only per-transaction counter with a loud warning.
  if (identifier === 'ip' || identifier === 'fingerprint') {
    if (!profile.legalCollections.has('ip') && profile.legalCollections.has('tx')) {
      return {
        label: identifier,
        initcol: 'tx=%{REMOTE_ADDR}',
        collection: 'tx',
        warning: {
          severity: 'downgrade',
          engine: profile.name,
          endpoint: endpointId,
          reason: `rateLimit.identifier=${identifier}: ${profile.name} only honors setvar on the TX collection (per-transaction); cross-request counters are not enforced. Move rate-limiting to HAProxy stick-tables for true cross-request enforcement.`,
          detail: { from: 'ip', to: 'tx', identifier },
        },
      };
    }
    return {
      label: identifier,
      initcol: 'ip=%{REMOTE_ADDR}',
      collection: 'ip',
    };
  }

  // Identity-keyed counters (`user-id`, `api-key`, `header:<name>`) want a
  // `user` collection on Coraza-Go but libmodsecurity3 rejects anything
  // outside {ip, global, resource}. When the engine can't express
  // per-principal counters, we downgrade to a `global=` collection (still a
  // counter, but a single shared one keyed by the header value) and emit a
  // structured `downgrade` warning so the operator knows the rate-limit is
  // now coarser than the spec asked for. **Never silently re-key to `ip`** —
  // that would mask a credential-stuffing attacker who rotates IPs.
  const buildIdentityTarget = (label: string, headerExpr: string): RateLimitTarget => {
    if (profile.supportsArbitraryCollection || profile.legalCollections.has('user')) {
      return {
        label,
        initcol: `user=${headerExpr}`,
        collection: 'user',
      };
    }
    // Engines that only honor `setvar:TX.*` (Coraza v3 / coraza-spoa):
    // downgrade `user` → `tx`. TX is per-transaction so the cross-request
    // counter semantic is lost; this is a real downgrade we surface loudly.
    // Per-principal isolation is preserved inside the transaction via the
    // header interpolation in the var name.
    if (profile.legalCollections.has('tx')) {
      return {
        label,
        initcol: `tx=${headerExpr}`,
        collection: 'tx',
        warning: {
          severity: 'downgrade',
          engine: profile.name,
          endpoint: endpointId,
          reason: `rateLimit.identifier=${label}: ${profile.name} only honors setvar on the TX collection (per-transaction); cross-request counters are not enforced. Move rate-limiting to HAProxy stick-tables for true cross-request enforcement.`,
          detail: { from: 'user', to: 'tx', identifier: label },
        },
      };
    }
    // libmodsecurity3 path: downgrade `user` → `global`. The `global`
    // collection is process-wide but the `setvar` key includes the header
    // value via `%{...}` interpolation, so we still get a per-principal
    // counter at the cost of a single shared collection namespace.
    return {
      label,
      initcol: `global=${headerExpr}`,
      collection: 'global',
      warning: {
        severity: 'downgrade',
        engine: profile.name,
        endpoint: endpointId,
        reason: `rateLimit.identifier=${label}: engine collection 'user' not supported on ${profile.name}; downgraded to 'global' (still per-principal via header interpolation, but shares namespace with other rules)`,
        detail: { from: 'user', to: 'global', identifier: label },
      },
    };
  };

  if (identifier === 'user-id') {
    return buildIdentityTarget('user-id', '%{REQUEST_HEADERS.Authorization}');
  }
  if (identifier === 'api-key') {
    return buildIdentityTarget('api-key', '%{REQUEST_HEADERS.X-API-Key}');
  }
  if (identifier.startsWith('header:')) {
    const name = identifier.slice('header:'.length).trim();
    if (!name) {
      return {
        label: identifier,
        initcol: 'ip=%{REMOTE_ADDR}',
        collection: 'ip',
      };
    }
    return buildIdentityTarget(`header:${name}`, `%{REQUEST_HEADERS.${name}}`);
  }
  // Unknown identifier — fall back to IP-keyed counter.
  return {
    label: identifier,
    initcol: 'ip=%{REMOTE_ADDR}',
    collection: 'ip',
  };
}

/** Sanitize an operationId so it is safe to use as a ModSecurity variable name. */
function safeVarName(name: string): string {
  return name.replace(/[^A-Za-z0-9_]/g, '_');
}

/**
 * How many rule IDs a single rate-limit entry will consume — needed by
 * callers that must allocate non-overlapping ID blocks across multiple
 * rate-limit entries on the same endpoint.
 */
export function rateLimitIdCount(rl: RateLimit): number {
  return typeof rl.burst === 'number' && rl.burst > 0 ? RL_IDS_WITH_BURST : RL_IDS_PRIMARY;
}

/**
 * Rate-limit emission using the canonical Coraza v3 / ModSecurity collection
 * pattern: a separate `initcol` rule, a separate counter rule
 * (`setvar` + `expirevar`), and a separate `@gt` check rule that actually
 * issues the 429. This pattern is what the OWASP CRS DOS rules use
 * (id range 912xxx) and is the only form that gives correct cross-request
 * persistence in Coraza.
 *
 * For each entry we emit 3 SecRules (or 6 with `burst`):
 *
 *   1. `initcol` rule (phase:1, pass, nolog) — opens the persistent collection
 *      for this principal (IP / user / api-key / arbitrary header). Scoped to
 *      method + path so we do not pay the cost on every request.
 *   2. counter rule (phase:1, pass, nolog) — `setvar:<col>.<var>=+1` plus
 *      `expirevar:<col>.<var>=<window>`. Increments on every matching request
 *      and refreshes the TTL so the counter rolls forward.
 *   3. check rule (phase:1, deny, status:429) — `@gt requests`. Fires only
 *      after the counter has exceeded the configured threshold.
 *
 * When `burst` is supplied we emit a second 3-rule block with a 1-second
 * window that enforces the short-window burst cap. Conceptually: "no more
 * than N requests / window AND no more than `burst` requests / second".
 *
 * @param ctx           Rule-emission context (endpoint + base ID + tag).
 * @param rl            The rate-limit policy to emit.
 * @param idOffset      Offset from `SLOT.rate` for this entry. Callers must
 *                      pre-allocate so multiple rate-limit entries on the
 *                      same endpoint do not collide. Defaults to 0.
 */
export function buildRateLimit(
  ctx: RuleCtx,
  rl: RateLimit,
  idOffset = 0,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string {
  const { endpoint, base, tag } = ctx;
  const window = parseDurationSec(rl.window) || 60;
  // v0.4/v0.5: identifier widened to string | string[] | {components, combinator}.
  // Coraza emits a single SecRule collection; composite keys aren't expressible
  // without a custom Lua plugin, so we use the first component and surface a
  // generator warning for the dropped components.
  const rawId = rl.identifier ?? 'ip';
  let identifier: string;
  if (typeof rawId === 'string') {
    identifier = rawId;
  } else if (Array.isArray(rawId)) {
    identifier = rawId[0]!;
  } else {
    // v0.5 object form { components, combinator }
    identifier = rawId.components[0]!;
  }
  const target = resolveRateLimitTarget(identifier, profile, `${endpoint.method} ${endpoint.path}`);
  if (target.warning && warnings) warnings.push(target.warning);
  const counterKey = `rl_${safeVarName(endpoint.operationId)}`;
  const pathRx = pathRegex(endpoint.path);
  const startId = base + SLOT.rate + idOffset;

  // Primary window counter.
  const initcolId = startId;
  const counterId = startId + 1;
  const checkId = startId + 2;
  const col = target.collection;
  // libmodsecurity3 requires every chained child SecRule to carry an actions
  // argument (even a no-op like `t:none`); without it the parser reports
  // "Expecting an action, got: SecRule …". Coraza-Go accepts chain children
  // with no actions arg, so we keep them bare there to preserve the existing
  // golden snapshot.
  const chainTerm = profile.legalCollections.has('user') ? '' : ' "t:none"';

  const lines: string[] = [
    header(
      `rateLimit ${rl.requests}/${rl.window} (identifier=${target.label}) for ${endpoint.method} ${endpoint.path}\n` +
        `pattern: initcol → setvar/expirevar → @gt check (Coraza v3 collection semantics)`
    ),
    // 1. initcol — open the persistent collection for this principal.
    `SecRule REQUEST_URI "@rx ${pathRx}" "id:${initcolId},phase:1,pass,nolog,tag:'${esc(tag)}',initcol:${target.initcol},chain"`,
    `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${chainTerm}`,
    // 2. counter — increment + refresh expiry.
    `SecRule REQUEST_URI "@rx ${pathRx}" "id:${counterId},phase:1,pass,nolog,tag:'${esc(tag)}',setvar:${col}.${counterKey}=+1,expirevar:${col}.${counterKey}=${window},chain"`,
    `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${chainTerm}`,
    // 3. check — deny when counter exceeds the configured limit.
    `SecRule REQUEST_URI "@rx ${pathRx}" "id:${checkId},phase:1,deny,status:429,msg:'x-security: rate limit exceeded (${rl.requests}/${esc(rl.window)})',tag:'${esc(tag)}',log,chain"`,
    `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
    `    SecRule ${col.toUpperCase()}:${counterKey} "@gt ${rl.requests}"${chainTerm}`,
  ];

  // Optional burst counter — short-window cap (1 second) that catches spikes
  // even when the primary window has plenty of room.
  if (typeof rl.burst === 'number' && rl.burst > 0) {
    const burstCounterKey = `${counterKey}_burst`;
    const burstInitId = startId + 3;
    const burstCounterId = startId + 4;
    const burstCheckId = startId + 5;
    lines.push(
      header(
        `rateLimit burst=${rl.burst}/1s (identifier=${target.label}) for ${endpoint.method} ${endpoint.path}`
      ),
      `SecRule REQUEST_URI "@rx ${pathRx}" "id:${burstInitId},phase:1,pass,nolog,tag:'${esc(tag)}',initcol:${target.initcol},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${chainTerm}`,
      `SecRule REQUEST_URI "@rx ${pathRx}" "id:${burstCounterId},phase:1,pass,nolog,tag:'${esc(tag)}',setvar:${col}.${burstCounterKey}=+1,expirevar:${col}.${burstCounterKey}=1,chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${chainTerm}`,
      `SecRule REQUEST_URI "@rx ${pathRx}" "id:${burstCheckId},phase:1,deny,status:429,msg:'x-security: rate limit burst exceeded (${rl.burst}/1s)',tag:'${esc(tag)}',log,chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule ${col.toUpperCase()}:${burstCounterKey} "@gt ${rl.burst}"${chainTerm}`
    );
  }

  return lines.join('\n');
}

/**
 * OPP-2: semantic-type → validation regex for request.schema field-type
 * enforcement (API8 input validation). Every entry is a positive-format
 * regex; the emitted SecRule uses `!@rx` so a value that does NOT match the
 * format is denied (400). RE2-safe — no lookaround, no backreferences — so
 * the same pattern loads on Coraza-Go/SPOA (RE2) and libmodsecurity3 (PCRE).
 *
 * Coverage rationale for the 'full' claim on `request.schema.type`:
 * the 14 SemanticTypes split into format-bearing types (listed here, each
 * gets an enforcing rule) and format-free types — `string`, `name`,
 * `free-text`, `binary` — which by definition impose no syntactic constraint
 * (any byte sequence is a valid `string`/`binary`; `name`/`free-text` is
 * arbitrary prose). Those four are listed in {@link UNCONSTRAINED_TYPES} so
 * the set is provably exhaustive: every SemanticType is either enforced here
 * or explicitly recorded as having nothing to enforce. There is no silent
 * fall-through — an unhandled future type would be absent from both sets.
 */
const TYPE_VALIDATION_RX: Partial<Record<SemanticType, { rx: string; what: string }>> = {
  email: { rx: '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$', what: 'a valid email' },
  uuid: {
    rx: '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    what: 'a valid UUID',
  },
  integer: { rx: '^-?\\d+$', what: 'an integer' },
  float: { rx: '^-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?$', what: 'a number' },
  boolean: { rx: '^(?:true|false)$', what: 'a boolean' },
  // RFC3339 date / datetime. The datetime rx accepts an optional time +
  // timezone offset (Z or ±HH:MM). RE2-safe.
  date: { rx: '^\\d{4}-\\d{2}-\\d{2}$', what: 'a date (YYYY-MM-DD)' },
  datetime: {
    rx: '^\\d{4}-\\d{2}-\\d{2}[Tt]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:[Zz]|[+-]\\d{2}:\\d{2})?$',
    what: 'an RFC3339 datetime',
  },
  // IPv4 dotted-quad OR a compact IPv6 hextet form. Coarse on IPv6 (does not
  // reject every malformed compression) but rejects non-address text.
  'ip-address': {
    rx: '^(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)$',
    what: 'an IP address',
  },
  // E.164-ish phone: optional leading +, 7–15 digits, separators allowed.
  phone: { rx: '^\\+?[0-9][0-9 ().-]{5,18}$', what: 'a phone number' },
  // url is enforced by the dedicated SSRF/url-allowlist path (buildSsrfRules)
  // when domainAllowlist/blockPrivateRanges are set; here we still require a
  // scheme://host shape so a bare non-URL string is rejected.
  url: { rx: '^[a-zA-Z][a-zA-Z0-9+.-]*://[^\\s]+$', what: 'a URL' },
};

/**
 * Format-free SemanticTypes: these impose no syntactic constraint, so there
 * is intentionally no enforcing rule. Kept as an explicit set (not a silent
 * default) so {@link TYPE_VALIDATION_RX} ∪ this set provably covers every
 * SemanticType — see the comment on TYPE_VALIDATION_RX.
 */
const UNCONSTRAINED_TYPES: ReadonlySet<SemanticType> = new Set<SemanticType>([
  'string',
  'name',
  'free-text',
  'binary',
]);

/** Build schema validation rules from request.schema. Returns rule list (consumes IDs ≥ base+SLOT.schema). */
export function buildSchemaRules(
  ctx: RuleCtx,
  schema: Record<string, ParamSchema>,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const { endpoint, base, tag } = ctx;
  const rules: string[] = [];
  let nextId = base + SLOT.schema;
  const term = chainTerm(profile);

  for (const [field, ps] of Object.entries(schema)) {
    if (typeof ps.minLength === 'number') {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.minLength=${ps.minLength} for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} too short',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "@lt ${ps.minLength}" "t:length"`,
        ].join('\n')
      );
    }
    if (typeof ps.maxLength === 'number') {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.maxLength=${ps.maxLength} for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} too long',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "@gt ${ps.maxLength}" "t:length"`,
        ].join('\n')
      );
    }
    if (typeof ps.fixedLength === 'number') {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.fixedLength=${ps.fixedLength} for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} wrong length',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "!@eq ${ps.fixedLength}" "t:length"`,
        ].join('\n')
      );
    }
    if (typeof ps.min === 'number') {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.min=${ps.min} for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} below min',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "@lt ${ps.min}"${term}`,
        ].join('\n')
      );
    }
    if (typeof ps.max === 'number') {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.max=${ps.max} for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} above max',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "@gt ${ps.max}"${term}`,
        ].join('\n')
      );
    }
    if (ps.pattern) {
      const id = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.pattern for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} pattern mismatch',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field} "!@rx ${esc(ps.pattern)}"${term}`,
        ].join('\n')
      );
    }
    // OPP-2 (API8): semantic-type format enforcement. Every format-bearing
    // type emits a `!@rx <format>` deny rule (table-driven, RE2-safe). The
    // url type additionally relies on buildSsrfRules for allowlist/SSRF.
    // Format-free types (string/name/free-text/binary) are recorded in
    // UNCONSTRAINED_TYPES and intentionally emit nothing — there is no
    // syntactic constraint to enforce. Keeping both sets exhaustive is what
    // lets the capability matrix mark request.schema.type as 'full'.
    if (ps.type) {
      const spec = TYPE_VALIDATION_RX[ps.type];
      if (spec) {
        const id = nextId++;
        rules.push(
          [
            header(`request.schema.${field}.type=${ps.type} for ${endpoint.method} ${endpoint.path}`),
            `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security: field ${esc(field)} not ${spec.what}',tag:'${esc(tag)}',chain"`,
            // REQUEST_FILENAME (path-only), not REQUEST_URI (path+query): an
            // anchored `^/path$` against REQUEST_URI never matches once the
            // request carries a query string, so the type check would silently
            // never fire (same W22-B defect the SSRF chain fixed). url-typed
            // fields in particular always arrive with `?url=...`.
            `  SecRule REQUEST_FILENAME "@rx ${pathRegex(endpoint.path)}" "chain"`,
            `    SecRule ARGS:${field} "!@rx ${escRx(spec.rx)}"${term}`,
          ].join('\n')
        );
      }
      // else: ps.type ∈ UNCONSTRAINED_TYPES → no enforceable format (no-op).
    }
    if (ps.allowedMimeTypes && ps.allowedMimeTypes.length) {
      // OPP-2 (API8): allowedMimeTypes is enforced on TWO surfaces, each its
      // own enforcing rule so the field genuinely rejects a disallowed MIME:
      //   1. request Content-Type header — denies the whole request 415 when
      //      the declared body MIME is outside the set. This is the surface
      //      that actually fires for non-multipart bodies (JSON/form/raw),
      //      where there is no FILES collection to inspect.
      //   2. multipart per-file part MIME (FILES_TMP_CONTENT / FILES) — denies
      //      when an uploaded part for this field carries a disallowed MIME.
      // The header rule allows trailing `;charset=...` / `;boundary=...`.
      const alt = ps.allowedMimeTypes
        .map((c) => c.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('|');
      const ctId = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.allowedMimeTypes (request Content-Type) for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${ctId},phase:1,deny,status:415,msg:'x-security: field ${esc(field)} Content-Type not in allowedMimeTypes',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule REQUEST_HEADERS:Content-Type "!@rx ^(${alt})(;.*)?$"${term}`,
        ].join('\n')
      );
      const fileId = nextId++;
      rules.push(
        [
          header(`request.schema.${field}.allowedMimeTypes (multipart part MIME) for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${fileId},phase:2,deny,status:415,msg:'x-security: field ${esc(field)} upload MIME not allowed',tag:'${esc(tag)}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule FILES_TMP_CONTENT:${field}|FILES:${field} "!@rx ^(${alt})$"${term}`,
        ].join('\n')
      );
    }
  }
  return rules;
}

/**
 * W19-A: SSRF url-allowlist SecRules. For each url-typed request.schema
 * param with `domainAllowlist` and/or `blockPrivateRanges:true`, emit:
 *
 *   980000+slot*2     domainAllowlist  — deny if URL host ∉ allowlist
 *   980000+slot*2+1   blockPrivateRanges — deny if host matches private prefix
 *
 * The SecRule inspects ARGS:<field> (which covers both query-string and JSON
 * body fields once the body processor has run). Phase 2, status 403, tagged
 * `x-security-rule-ssrf-403` / `x-security-rule-ssrf-private-403` so the
 * scorer's intent-attribution maps it to defense-class `url-allowlist`.
 */
export function buildSsrfRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  phase: 1 | 2 = 2
): string[] {
  const schema = endpoint.policy.request?.schema;
  if (!schema) return [];
  const term = chainTerm(profile);
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rules: string[] = [];
  // Slot range [0, 4500) leaves room for 2 IDs per endpoint within [980000, 989999).
  const slot = endpointHash(endpoint.method, endpoint.path) % 4500;
  let offset = 0;

  for (const [field, ps] of Object.entries(schema)) {
    if (!ps || ps.type !== 'url') continue;
    const hasAllow = Array.isArray(ps.domainAllowlist) && ps.domainAllowlist.length > 0;
    const hasBlock = ps.blockPrivateRanges === true;
    if (!hasAllow && !hasBlock) continue;

    if (hasAllow) {
      const id = SSRF_BASE_ID + slot * 2 + offset++;
      // Allowlist regex: anchor after scheme `://`, accept any of the declared
      // hostnames (case-insensitive), terminated by `/`, `:`, `?`, `#`, or end.
      const alt = (ps.domainAllowlist as string[])
        .map((d) => d.toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('|');
      const allowRx = `(?i)^(?:[a-z][a-z0-9+.-]*:)?//(?:${alt})(?:[/:?#]|$)`;
      rules.push(
        [
          header(`W19-A SSRF: ${field} must match domainAllowlist for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:${phase},deny,status:403,msg:'x-security: ${esc(field)} host not in domainAllowlist',tag:'${esc(tag)}',tag:'x-security-rule-ssrf-403',chain"`,
          // W22-B: REQUEST_FILENAME (path-only), not REQUEST_URI. libmodsec3's
          // REQUEST_URI is path *+ query string* — an anchored `^/path$` rx
          // never matches once the endpoint receives the very ?url= it is
          // meant to inspect. Verified runtime via modsec debug log
          // (incident: /tmp/vapi-test/fixes/v22-bunkerweb-ssrf-runtime.md).
          // REQUEST_FILENAME is path-only on libmodsec3 and Coraza.
          `  SecRule REQUEST_FILENAME "@rx ${pathRegex(endpoint.path)}" "chain"`,
          // W22-B: escRx, not esc — see comment on escRx. Doubling backslashes
          // breaks the regex (`\.` → `\\.` which matches a literal backslash).
          `    SecRule ARGS:${field} "!@rx ${escRx(allowRx)}"${term}`,
        ].join('\n')
      );
    }

    if (hasBlock) {
      const id = SSRF_BASE_ID + slot * 2 + offset++;
      rules.push(
        [
          header(`W19-A SSRF: ${field} blockPrivateRanges for ${endpoint.method} ${endpoint.path}`),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:${phase},deny,status:403,msg:'x-security: ${esc(field)} resolves to private/loopback host',tag:'${esc(tag)}',tag:'x-security-rule-ssrf-private-403',chain"`,
          // W22-B: REQUEST_FILENAME — see comment on the domainAllowlist rule above.
          `  SecRule REQUEST_FILENAME "@rx ${pathRegex(endpoint.path)}" "chain"`,
          // W22-B: escRx — see comment on escRx. Same reasoning as the allowlist rule.
          `    SecRule ARGS:${field} "@rx ${escRx(SSRF_PRIVATE_HOST_RX)}"${term}`,
        ].join('\n')
      );
    }
  }
  return rules;
}

/** Regex matching JSON-family Content-Type values (application/json, application/vnd.api+json, …). */
const JSON_CONTENT_TYPE_RX = /^application\/(?:json|vnd\.[\w.+-]+\+json)\b/i;

/**
 * Whether any of the declared content types is a JSON variant. Recognises
 * `application/json` and structured-syntax-suffix variants like
 * `application/vnd.api+json`.
 */
function hasJsonContentType(contentTypes: readonly string[] | undefined): boolean {
  if (!contentTypes || contentTypes.length === 0) return false;
  return contentTypes.some((c) => JSON_CONTENT_TYPE_RX.test(c.trim()));
}

/**
 * Per-endpoint JSON body-processor directive (wave-8).
 *
 * Coraza-SPOA / Coraza-Go don't auto-route JSON bodies through the JSON parser
 * the way ModSecurity-nginx's bundled `setup.conf` does (id:200001). Without
 * `ctl:requestBodyProcessor=JSON` at phase 1, `ARGS_NAMES` stays empty for
 * application/json requests and every phase-2 schema / allowlist rule misses.
 *
 * We emit the directive for **every** endpoint whose `request.contentType`
 * declares a JSON variant, on **every** engine profile. On modsec-nginx /
 * modsec-apache this duplicates the bundled id:200001 ctl, which is harmless
 * (setting the same processor twice is idempotent) and makes the artifact
 * engine-portable.
 *
 * Rule ID lives in the dedicated `BODY_ALLOWLIST_BASE_ID + 10000` range
 * (410000–418999), one ID per endpoint via FNV-1a hashing.
 */
export function buildJsonBodyProcessor(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string | null {
  const policy = endpoint.policy;
  if (!hasJsonContentType(policy.request?.contentType)) return null;
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const ctlId = BODY_ALLOWLIST_BASE_ID + 10000 + (endpointHash(endpoint.method, endpoint.path) % 9000);
  const term = chainTerm(profile);
  return [
    header(
      `enable JSON body processor for ${endpoint.method} ${endpoint.path}\n` +
        `engine=${profile.name}: SPOE/Coraza-Go don't auto-parse JSON bodies the way\n` +
        `modsec-nginx's bundled setup.conf does; this ctl forces ARGS_NAMES to be\n` +
        `populated for application/json (and vnd.*+json) so phase-2 schema /\n` +
        `allowlist rules can see the body keys. Redundant-but-harmless on\n` +
        `libmodsecurity3 engines (bundled id:200001 already sets the same processor).`
    ),
    `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${ctlId},phase:1,pass,nolog,tag:'${esc(tag)}',chain"`,
    `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
    `    SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(json|vnd\\.[\\w.+-]+\\+json)\\b" "ctl:requestBodyProcessor=JSON${term ? ',t:none' : ''}"`,
  ].join('\n');
}

/**
 * Body-field allowlist (mass-assignment defense, OWASP API6).
 *
 * Emits a SecRule chain that, scoped to this endpoint's method + path,
 * inspects `ARGS_NAMES` (the names of all parsed body fields when
 * `Content-Type: application/json`) and denies 403 if any field is not in
 * the allowlist. Coraza's JSON body parser exposes top-level JSON keys via
 * `ARGS_NAMES` when `SecRequestBodyAccess On` is set (already the default
 * in the engine globals); nested object keys are NOT enforced — only the
 * top-level field names.
 *
 * The allowlist is sourced as:
 *   1. `request.allowedFields` if present (authoritative).
 *   2. otherwise the top-level keys of `request.schema` when
 *      `request.denyUnknownFields === true`.
 *
 * If neither produces a non-empty list, no rule is emitted.
 */
export function buildBodyFieldAllowlistRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const policy = endpoint.policy;
  const req = policy.request;
  if (!req) return [];

  // Source the allowlist. allowedFields wins; otherwise derive from schema
  // keys iff denyUnknownFields is explicitly true.
  let fields: string[] | null = null;
  if (Array.isArray(req.allowedFields) && req.allowedFields.length > 0) {
    fields = req.allowedFields;
  } else if (req.denyUnknownFields === true && req.schema) {
    const schemaKeys = Object.keys(req.schema);
    if (schemaKeys.length > 0) fields = schemaKeys;
  }
  if (!fields) return [];

  // Restrict to identifier-safe field names. ARGS_NAMES values are matched
  // case-insensitively via t:lowercase, so we lowercase the allowlist too.
  // Anything with whitespace or quotes would break the SecRule arg; drop it
  // (and surface it in the header comment).
  const safe: string[] = [];
  const dropped: string[] = [];
  for (const f of fields) {
    if (typeof f === 'string' && /^[A-Za-z0-9_.\-]+$/.test(f)) {
      safe.push(f.toLowerCase());
    } else {
      dropped.push(String(f));
    }
  }
  if (safe.length === 0) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  // Dedicated ID range so we did not have to widen SLOT_STRIDE (which would
  // have shifted every previously-emitted rule ID across all categories).
  const id = BODY_ALLOWLIST_BASE_ID + (endpointHash(endpoint.method, endpoint.path) % 9000);
  // ARGS_NAMES, when populated by the JSON body parser, contains entries of
  // the form `json.<key>` for each top-level body key. We match against that
  // exact shape using a negative anchored alternation. (Coraza v3 emits the
  // same `json.<key>` naming as libmodsecurity3.)
  const alt = safe.join('|');
  const argsRegex = `^json\\.(${alt})$`;
  const source =
    Array.isArray(req.allowedFields) && req.allowedFields.length > 0
      ? 'request.allowedFields'
      : 'request.denyUnknownFields (allowlist derived from request.schema keys)';
  const headerLines = [
    `${source} for ${endpoint.method} ${endpoint.path}`,
    `top-level JSON body keys must be one of: ${safe.join(', ')}`,
    `mechanism: ARGS_NAMES !@rx ^json\\.(allowlist)$ (JSON body parser emits names as json.<key>)`,
    `scope: chained behind a Content-Type: application/json guard so the json.<key>`,
    `  selector is always valid — query-string / form-encoded args (bare names) do`,
    `  NOT trip the allowlist and produce a false 403.`,
    `limitation: only top-level field names are enforced; nested object keys pass through`,
    `  (mass-assignment is a top-level-binding attack, so the top-level allowlist is`,
    `  the operative defense; nested overposting is out of scope for ARGS_NAMES).`,
  ];
  if (dropped.length > 0) {
    headerLines.push(`dropped non-identifier-safe field names: ${dropped.join(', ')}`);
  }

  const out: string[] = [];
  // Wave-8: the ctl:requestBodyProcessor=JSON directive that this allowlist
  // depends on is now emitted by `buildJsonBodyProcessor` for any endpoint
  // with a JSON content-type, on every engine. Operators relying on this
  // allowlist must also declare `request.contentType: [application/json]`
  // so the ctl rule fires — same precondition as before, just hoisted to a
  // dedicated rule instead of inlined per allowlist.

  const term = chainTerm(profile);
  out.push(
    [
      header(headerLines.join('\n')),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: request body contains field outside allowlist (mass-assignment)',tag:'${esc(tag)}',tag:'x-security-api6-mass-assignment',chain"`,
      `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
      // Content-Type guard: only enforce the json.<key> allowlist when the body
      // is actually JSON. Without this, a POST carrying query-string/form args
      // (bare ARGS_NAMES, no json. prefix) trips `!@rx ^json\.(...)$` and 403s
      // every legitimate request — the defect that capped this field at partial.
      `    SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:json|vnd\\.[\\w.+-]+\\+json)\\b" "chain${term ? ',t:none' : ''}"`,
      `      SecRule ARGS_NAMES "!@rx ${argsRegex}" "t:none,t:lowercase"`,
    ].join('\n')
  );
  return out;
}

/**
 * C-1: Response-body inspection rules (OWASP API3 — BOPLA / data exposure).
 *
 * When the spec declares `response.schema.<field>.maxLength` (or similar
 * per-field constraint) we emit a phase-4 SecRule that inspects
 * `RESPONSE_BODY` for the leaking shape and denies / 500s on match. When
 * `response.stripUnknownFields: true` is declared, we emit a deny-on-unknown
 * rule and surface a structured `skip` warning (true field stripping
 * requires a Lua plugin — ModSecurity has no native rewriter).
 *
 * Honest scope:
 *  - The matchers are regex-over-JSON-body, not real JSON parsers. Nested
 *    structures, unicode-escaped quotes, and pretty-printing trip them.
 *    Operators should treat these as a defense-in-depth signal, not a
 *    bullet-proof schema validator. The truth bar (per Rule D-1) is "the
 *    rule fires on the obvious leak the corpus tests for"; we document the
 *    failure modes here and in STATUS.md.
 *  - When the engine profile reports `supportsResponseBodyAccess: false`
 *    (no current profile does), the entire emission is skipped and a
 *    structured `skip` warning is surfaced.
 *
 * Returns the rule strings plus the list of warnings emitted (cost-of-doing-
 * business plus skips/downgrades).
 */
export function buildResponseInspectionRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const policy = endpoint.policy;
  const resp = policy.response;
  if (!resp) return [];

  const hasFieldConstraints =
    resp.schema && Object.values(resp.schema).some((s) => fieldHasResponseConstraint(s));
  const stripUnknown = resp.stripUnknownFields === true;
  // W24-D: when the endpoint declares its response is application/json, the
  // body must never contain raw `<script>` / `javascript:` — those signal a
  // stored-XSS leak (user-stored HTML being echoed inside what should be a
  // JSON document). This is the only phase-4 signal we have for stored-XSS
  // class attacks since the spec has no `response.xssGuard` primitive yet.
  const jsonResponseContentType =
    Array.isArray(resp.contentType) &&
    resp.contentType.some((ct) => /^application\/(?:json|vnd\.[\w.+-]+\+json)\b/i.test(ct));
  if (!hasFieldConstraints && !stripUnknown && !jsonResponseContentType) return [];

  if (!profile.supportsResponseBodyAccess) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: `${endpoint.method} ${endpoint.path}`,
      reason:
        `response.schema / response.stripUnknownFields declared but engine profile ${profile.name} ` +
        `does not implement SecResponseBodyAccess; phase-4 inspection skipped.`,
    });
    return [];
  }

  // Honest perf-cost warning — Coraza-Go / Coraza-SPOA carry an additional
  // body-copy step for response inspection. The libmodsecurity3 engines incur
  // ~10-15% throughput hit per Trustwave's published benchmarks; SPOE adds
  // its own SPOA round-trip on the response path.
  warnings?.push({
    severity: 'downgrade',
    engine: profile.name,
    endpoint: `${endpoint.method} ${endpoint.path}`,
    reason:
      `response inspection enabled (phase 4); expect ~10-15% throughput cost on libmodsecurity3 ` +
      `and an extra SPOE round-trip on coraza-spoa. Acceptable for high-value endpoints; ` +
      `disable response.schema on hot paths if latency budget is tight.`,
    detail: { mechanism: 'SecResponseBodyAccess', phase: 4 },
  });

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const base = RESPONSE_INSPECT_BASE_ID + (endpointHash(endpoint.method, endpoint.path) % 9000) * 1;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const rules: string[] = [];
  let nextId = base;

  // Per-field constraints (currently: maxLength → too-long-string leak).
  // We anchor on the JSON shape `"<field>":"<value>"` and fire if the value
  // length exceeds the cap. This is a heuristic — see header comment.
  if (resp.schema) {
    for (const [field, ps] of Object.entries(resp.schema)) {
      if (!fieldHasResponseConstraint(ps)) continue;
      if (typeof ps.maxLength === 'number' && ps.maxLength > 0) {
        const id = nextId++;
        // Coraza-Go (RE2) rejects {N,} repetition counts > 1000 by default
        // (regexp/syntax.MaxRepeatCount). ModSecurity (PCRE) is permissive
        // and accepts arbitrary counts. Clamp only when the target engine is
        // RE2-backed; the libmodsec3 engines get the literal `maxLength` so
        // operators see the exact boundary in their audit log.
        const isRE2 = profile.name === 'coraza-go' || profile.name === 'coraza-spoa';
        const cap = isRE2 ? Math.min(ps.maxLength, 999) : ps.maxLength;
        rules.push(
          [
            header(
              `C-1 response.schema.${field}.maxLength=${ps.maxLength} for ${endpoint.method} ${endpoint.path}\n` +
                `phase:4 inspects RESPONSE_BODY for "${field}":"<value of length > ${cap}>". ` +
                `Heuristic regex-over-JSON; nested / escaped values may not match.`
            ),
            `SecRule REQUEST_URI "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security: response.${esc(field)} exceeds maxLength=${ps.maxLength} (data exposure)',tag:'${esc(tag)}',tag:'x-security-api3-bopla',chain"`,
            `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
            `    SecRule RESPONSE_BODY "@rx \\x22${esc(field)}\\x22\\s*:\\s*\\x22[^\\x22]{${cap + 1},}\\x22"${term}`,
          ].join('\n')
        );
      }
      // Pattern constraint — W10-1: RE2 (Coraza-Go's regex engine) does NOT
      // support negative lookahead `(?!...)`. We split the check into two
      // chained rules:
      //   A. capture the field value into TX:x_security_<field>
      //   B. deny when the captured value does not match the required pattern
      //      (`!@rx <pattern>` — inversion removes the lookahead need)
      if (ps.pattern) {
        const captureId = nextId++;
        const denyId = nextId++;
        const txVar = `x_security_${safeVarName(field)}`;
        rules.push(
          [
            header(
              `C-1 response.schema.${field}.pattern for ${endpoint.method} ${endpoint.path}\n` +
                `phase:4 rule A: extract response.${field} value into TX:${txVar} for the inverse-rx check`
            ),
            `SecRule REQUEST_URI "@rx ${pathRx}" "id:${captureId},phase:4,pass,nolog,chain"`,
            `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
            `    SecRule RESPONSE_BODY "@rx \\x22${esc(field)}\\x22\\s*:\\s*\\x22([^\\x22]*)\\x22" "capture,setvar:tx.${txVar}=%{TX.1}${term ? ',t:none' : ''}"`,
          ].join('\n')
        );
        rules.push(
          [
            header(
              `C-1 response.schema.${field}.pattern (deny) for ${endpoint.method} ${endpoint.path}\n` +
                `phase:4 rule B: deny when TX:${txVar} does not match the required pattern (RE2-safe; no lookahead)`
            ),
            `SecRule TX:${txVar} "!@rx ${esc(ps.pattern)}" "id:${denyId},phase:4,deny,status:500,msg:'x-security: response.${esc(field)} pattern mismatch (data exposure)',tag:'${esc(tag)}',tag:'x-security-api3-bopla'"`,
          ].join('\n')
        );
      }
    }
  }

  // W24-D: stored-XSS guard. Endpoints that declare their response as
  // application/json get a phase-4 rule that denies if RESPONSE_BODY contains
  // `<script` (case-insensitive) or `javascript:` — both are textbook
  // stored-XSS leakage shapes that have no legitimate place inside a JSON
  // response document. RE2-safe (no lookaheads). Covers the vAPI stickynotes
  // class where POST stores a `<script>` payload and GET echoes it back.
  if (jsonResponseContentType) {
    const id = nextId++;
    rules.push(
      [
        header(
          `C-1 stored-XSS guard for ${endpoint.method} ${endpoint.path}\n` +
            `phase:4 — response.contentType is application/json, so raw <script> or\n` +
            `javascript: URIs in the body indicate a stored-XSS echo. msg carries\n` +
            `'x-security-xss-stored' for scorer attribution.`
        ),
        // REQUEST_FILENAME (path-only) — REQUEST_URI on Coraza/libmodsec3
        // includes the query string, so an anchored `^/path$` rx fails for
        // any request carrying `?foo=bar`. The vAPI XSS attack hits
        // /vapi/stickynotes?format=html; REQUEST_FILENAME strips the query
        // and matches cleanly. (Same fix W22-B applied to the SSRF rules.)
        `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security: stored-XSS payload in JSON response body',tag:'${esc(tag)}',tag:'x-security-xss-stored',chain"`,
        `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
        `    SecRule RESPONSE_BODY "@rx (?i)(?:<script\\b|javascript:)"${term}`,
      ].join('\n')
    );
  }

  // stripUnknownFields → emit a deny-on-unknown rule + structured warning
  // that full strip requires a Lua / response-rewrite plugin.
  if (stripUnknown && resp.schema) {
    const declared = Object.keys(resp.schema).filter((k) =>
      /^[A-Za-z0-9_]+$/.test(k)
    );
    if (declared.length > 0) {
      // W10-1: the deny-on-unknown emission uses a negative-lookahead regex
      // over RESPONSE_BODY. RE2 (Coraza-Go's engine) does not support
      // lookahead — emitting it would crash the rule load. Skip + warn on
      // engines that lack PCRE; libmodsec3 (PCRE) keeps the existing rule.
      const isRE2Engine = profile.name === 'coraza-go' || profile.name === 'coraza-spoa';
      if (isRE2Engine) {
        warnings?.push({
          severity: 'skip',
          engine: profile.name,
          endpoint: `${endpoint.method} ${endpoint.path}`,
          reason:
            `response.stripUnknownFields: true requires a negative-lookahead regex which ${profile.name} ` +
            `(RE2-backed) does not support; deny-on-unknown rule skipped. Move enforcement to an upstream ` +
            `libmodsecurity3 layer or a SPOA Lua transformer.`,
          detail: { declaredKeys: declared.length, action: 'skip-on-re2' },
        });
      } else {
        const id = nextId++;
        warnings?.push({
          severity: 'downgrade',
          engine: profile.name,
          endpoint: `${endpoint.method} ${endpoint.path}`,
          reason:
            `response.stripUnknownFields: true requested, but ModSecurity/Coraza has no body-rewrite ` +
            `primitive. Emitted a deny-on-unknown rule instead (response with a top-level JSON key ` +
            `outside the declared schema → 500). For true field stripping, deploy a Lua/SPOA-side ` +
            `transformer.`,
          detail: { declaredKeys: declared.length, action: 'deny-on-unknown' },
        });
        const allowAlt = declared.join('|');
        rules.push(
          [
            header(
              `C-1 response.stripUnknownFields=true for ${endpoint.method} ${endpoint.path}\n` +
                `declared keys: ${declared.join(', ')}\n` +
                `phase:4 denies when the response body contains a top-level JSON key NOT in the declared set.\n` +
                `Note: this is a deny-on-unknown rule, NOT a strip — true stripping requires a Lua plugin.\n` +
                `PCRE-only (uses negative lookahead); RE2-backed engines (coraza-go/spoa) skip this rule.`
            ),
            `SecRule REQUEST_URI "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security: response contains undeclared field (stripUnknownFields)',tag:'${esc(tag)}',tag:'x-security-api3-bopla',chain"`,
            `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
            `    SecRule RESPONSE_BODY "@rx \\x22(?!(?:${allowAlt})\\x22)[A-Za-z_][A-Za-z0-9_]*\\x22\\s*:"${term}`,
          ].join('\n')
        );
      }
    }
  }

  return rules;
}

/** A response-schema entry is enforceable in phase-4 if it has at least one
 *  of the supported constraints (maxLength / pattern). minLength etc. are
 *  not response-side concerns (the response either contains the field or not). */
function fieldHasResponseConstraint(ps: ParamSchema): boolean {
  return (typeof ps.maxLength === 'number' && ps.maxLength > 0) || typeof ps.pattern === 'string';
}

/**
 * W19: per-arg injection-hardening rules driven by
 * `request.schema.<field>.injectionGuard`.
 *
 * The author declares which injection sinks a field flows into; x-security
 * compiles one enforcing phase-2 rule per (field, sink). This PROMOTES the
 * former W10-8 latent heuristic — which inferred SQLi targets from
 * `ps.type==='string'` and so fired on every string field whether or not it
 * reached a database — to an explicit, author-attested signal. Gating on
 * `injectionGuard.includes('sql')` instead of the string-type guess removes
 * the blanket false-positive surface: only fields the spec says are sink-bound
 * are hardened.
 *
 * Emission is NOT content-type gated: an injection arg can arrive in the query
 * string / form body (e.g. DVRESTaurant `?parameters=` RCE) just as easily as
 * in a JSON body. The selector therefore targets BOTH `ARGS:<field>` (matches
 * query-string and url-encoded form args) AND `ARGS:json.<field>` (matches the
 * JSON body processor's keys — Coraza-Go/SPOA populate JSON body keys as
 * `json.<field>`, verified empirically against ghcr.io/corazawaf/coraza-spoa:main;
 * see the same multi-target rationale at the SSRF emitter, rules.ts:812). Both
 * variants share one phase-2 rule so injectionGuard enforces regardless of where
 * the arg lands. Findings carry the x-security-native `x-security-injection` tag
 * plus a per-sink tag so the reporter can attribute them to SSEC-INJECTION.
 *
 * Per-sink operator (Rule D-1 — every sink emits a real enforcing matcher, no
 * placeholder):
 *   - sql            → `@detectSQLi` (Coraza's built-in libinjection-equivalent)
 *   - os-command     → `!@rx` shell-metachar denylist (rejects `; | & $ \` etc.)
 *   - code-eval      → same shell/eval-metachar denylist (the `eval`/`exec`
 *                      surface shares the metacharacter alphabet with os-command)
 *   - nosql          → `@rx` Mongo operator-token denylist (`$where`, `$gt`,
 *                      `$ne`, `$regex`, …) — JSON operator-injection markers
 *   - xpath / ldap   → `@rx` query-metachar denylist (xpath: `'"()[]/=`,
 *                      ldap: `()|&*` plus the `\NN` byte-escape form)
 *
 * The `!@rx` (negated) form on os-command/code-eval is allowlist-style: the
 * field must match the safe-charset pattern or it is denied. The `@rx`
 * (positive-match) form on the others denies when an attack token IS present.
 * Both genuinely block the payload at write time.
 *
 * Rule IDs live in the dedicated 430000..438999 range (already reserved for
 * the W10-8 emission). Each (field, sink) is FNV-1a keyed by
 * `<method>|<path>|<field>|<sink>` to stay collision-resistant across
 * endpoints and across the six sinks on one field.
 */
const INJECTION_GUARD_BASE_ID = 430000;

type InjectionSink = NonNullable<ParamSchema['injectionGuard']>[number];

/**
 * Per-sink rule body. Each entry returns the SecRule action tag + the matcher
 * line for the `ARGS:json.<field>` selector. `tagSuffix` keys the reporter's
 * per-sink attribution; `msg` is operator-facing. `category` selects the
 * x-security-native attribution class tag the reporter probes: every sink maps
 * to `x-security-injection` (→ SSEC-INJECTION) EXCEPT `ai-prompt`, which carries
 * `x-security-prompt` (→ the distinct SSEC-PROMPT class — v0.7). One synthetic
 * id per threat class; LLM prompt-injection is not lumped under generic
 * injection.
 *
 * sql / xss are special-cased to `@detectSQLi` / `@detectXSS` (dedicated
 * operators, not regexes — engine-capability gated). Every other sink is a
 * plain regex denylist/allowlist supported on all four shipping engines. We
 * keep the shell-metachar alphabet shared between os-command and code-eval
 * because an eval/exec sink is reachable by the same shell control characters
 * once the payload lands in a `system()`/`exec()`-family call.
 */
const INJECTION_SINK_MATCHERS: Record<
  InjectionSink,
  { tagSuffix: string; msg: string; operator: string; category: 'injection' | 'prompt' }
> = {
  sql: {
    tagSuffix: 'sqli',
    msg: 'SQL injection',
    operator: '@detectSQLi',
    category: 'injection',
  },
  // Negated allowlist: deny unless the value is free of shell control chars.
  // Rejects ; | & $ ` ( ) < > newline and backslash — the os-command/code-eval
  // metacharacter set used to chain or substitute commands.
  'os-command': {
    tagSuffix: 'os-command',
    msg: 'OS command injection',
    operator: '!@rx ^[^;|&$`()<>\\\\\\n\\r]*$',
    category: 'injection',
  },
  'code-eval': {
    tagSuffix: 'code-eval',
    msg: 'code-eval injection',
    operator: '!@rx ^[^;|&$`()<>\\\\\\n\\r]*$',
    category: 'injection',
  },
  // Positive denylist of Mongo/NoSQL operator tokens that appear in
  // operator-injection payloads ($where/$gt/$ne/$regex/$in/$nin/$or/$and).
  nosql: {
    tagSuffix: 'nosql',
    msg: 'NoSQL operator injection',
    operator: '@rx (?i)\\$(?:where|gt|gte|lt|lte|ne|nin|in|or|and|not|regex|expr|function)\\b',
    category: 'injection',
  },
  // XPath query metacharacters: quotes, brackets, parens, slash, equals, the
  // node-axis colon-colon, and the boolean operators `and`/`or` as word tokens.
  xpath: {
    tagSuffix: 'xpath',
    msg: 'XPath injection',
    operator: '@rx (?:[\'"()\\[\\]/=]|::|(?i)\\b(?:and|or)\\b)',
    category: 'injection',
  },
  // LDAP filter metacharacters: parens, the boolean `& |`, the wildcard `*`,
  // the NUL/byte-escape `\NN` form, and the `=` attribute separator.
  ldap: {
    tagSuffix: 'ldap',
    msg: 'LDAP injection',
    operator: '@rx (?:[()&|*=]|\\\\[0-9A-Fa-f]{2})',
    category: 'injection',
  },
  // Cross-site scripting: `@detectXSS` is libmodsecurity3 / Coraza-Go's native
  // XSS operator (libinjection-xss equivalent), gated on profile.supportsDetectXSS
  // exactly like sql is gated on supportsDetectSQLi.
  xss: {
    tagSuffix: 'xss',
    msg: 'XSS',
    operator: '@detectXSS',
    category: 'injection',
  },
  // v0.7: unsafe-deserialization preamble denylist. Denies when the field
  // carries a recognizable serialized-object framing byte sequence — the
  // language-native markers an insecure deserializer would rehydrate into a
  // gadget chain: node-serialize's `_$$ND_FUNC$$_` function wrapper, a Java
  // ObjectStream base64 header (`rO0` = the `0xACED0005` magic), a PHP
  // serialized-object preamble (`O:<len>:"`), and the python pickle protocol-2
  // opcode frame (`\x80\x02..` → `\x80[\x02-\x05]`). A plain `@rx` denylist,
  // supported on every engine. Attributed to SSEC-INJECTION.
  deserialization: {
    tagSuffix: 'deserialization',
    // The PHP `O:<len>:"` preamble ends in a double-quote; it is emitted as
    // `\"` so it survives ModSecurity's quoted-operator-argument parsing
    // (a bare `"` would terminate the SecRule operator string mid-regex).
    msg: 'unsafe deserialization payload',
    operator:
      '@rx (?:_\\$\\$ND_FUNC\\$\\$_|rO0[A-Za-z0-9+/]|O:\\d+:\\"|\\x80[\\x02-\\x05])',
    category: 'injection',
  },
  // v0.7: LLM prompt-injection heuristic denylist. Denies when the field
  // carries jailbreak / system-prompt-leak / role-override markers an attacker
  // uses to subvert a downstream model: "ignore (previous|above) instructions",
  // a fake "system:" / "assistant:" role turn, "you are now ...", DAN /
  // developer-mode jailbreak tokens, and "reveal/print your (system )prompt".
  // Plain `@rx`, supported on every engine. Distinct attribution: SSEC-PROMPT,
  // NOT SSEC-INJECTION (one synthetic id per threat class).
  'ai-prompt': {
    tagSuffix: 'ai-prompt',
    msg: 'LLM prompt injection',
    operator:
      '@rx (?i)(?:ignore\\s+(?:all\\s+)?(?:previous|above|prior)\\s+(?:instructions|prompts)|(?:^|\\n)\\s*(?:system|assistant)\\s*:|you\\s+are\\s+now\\b|developer\\s+mode|\\bDAN\\b|(?:reveal|print|show|repeat)\\s+(?:your\\s+)?(?:system\\s+)?prompt)',
    category: 'prompt',
  },
};

/**
 * Stable, deterministic sink ordering so the emitted rules (and golden
 * snapshot) don't reorder when the author shuffles the `injectionGuard` array.
 */
const INJECTION_SINK_ORDER: readonly InjectionSink[] = [
  'sql',
  'nosql',
  'os-command',
  'code-eval',
  'xpath',
  'ldap',
  'xss',
  'deserialization',
  'ai-prompt',
];

export function buildSqliHeuristics(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const policy = endpoint.policy;
  const req = policy.request;
  if (!req || !req.schema) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const term = chainTerm(profile);
  const out: string[] = [];

  for (const [field, ps] of Object.entries(req.schema)) {
    const guards = ps.injectionGuard;
    if (!guards || guards.length === 0) continue;

    for (const sink of INJECTION_SINK_ORDER) {
      if (!guards.includes(sink)) continue;
      // `@detectSQLi` / `@detectXSS` are the only sinks needing an engine
      // capability flag; every other sink is a plain regex the engine always
      // supports. Skip the rule (rather than emit a dead one) on a profile
      // lacking the operator — never silently downgrade to a placeholder
      // (Rule D-1).
      if (sink === 'sql' && !profile.supportsDetectSQLi) continue;
      if (sink === 'xss' && !profile.supportsDetectXSS) continue;

      const m = INJECTION_SINK_MATCHERS[sink];
      const idSeed = endpointHash(`${endpoint.method}|${endpoint.path}|${field}|${sink}`, '');
      const id = INJECTION_GUARD_BASE_ID + (idSeed % 9000);
      // `category` selects the x-security-native attribution-class tag the
      // reporter probes: `x-security-injection` → SSEC-INJECTION for every sink
      // except `ai-prompt`, which carries `x-security-prompt` → SSEC-PROMPT.
      const classTag = `x-security-${m.category}`;
      const ssecId = m.category === 'prompt' ? 'SSEC-PROMPT' : 'SSEC-INJECTION';
      out.push(
        [
          header(
            `W19 injection guard (${sink}) on request.schema.${field} for ${endpoint.method} ${endpoint.path}\n` +
              `Author-declared injectionGuard sink; phase:2 denies the payload at write\n` +
              `time over the body/query field. Attributed to ${ssecId} by the reporter.`
          ),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: ${m.msg} detected in ${esc(field)}',tag:'${esc(tag)}',tag:'${classTag}',tag:'${classTag}-${m.tagSuffix}',chain"`,
          `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
          `    SecRule ARGS:${field}|ARGS:json.${field} "${m.operator}"${term}`,
        ].join('\n')
      );
    }
  }
  return out;
}

/**
 * W24-D: stored-XSS heuristic on request-side free-text fields.
 *
 * Why request-side: coraza-spoa's SPOE wiring does not propagate response
 * bodies to the WAF (response_check=false, no req.body equivalent for
 * responses). Phase:4 RESPONSE_BODY rules emit but never fire there. The
 * effective defense is blocking the payload at *write* time — any free-text
 * JSON field carrying a literal `<script` or `javascript:` URI is rejected
 * before it lands in storage, neutralizing the GET-side echo entirely.
 *
 * Gated on `request.contentType: [application/json]` + a free-text-typed
 * field (the only field shape with legitimate XSS-as-text risk). Plain
 * `string` fields aren't included because they often carry HTML-looking
 * configuration values legitimately (CSS selectors, regex patterns).
 *
 * Rule IDs live in 440000..448999 (dedicated, FNV-1a keyed by
 * `<method>|<path>|<field>|xss`).
 */
const XSS_HEURISTIC_BASE_ID = 440000;

export function buildXssHeuristics(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const policy = endpoint.policy;
  const req = policy.request;
  if (!req || !req.schema) return [];
  if (!hasJsonContentType(req.contentType)) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const term = chainTerm(profile);
  const out: string[] = [];

  for (const [field, ps] of Object.entries(req.schema)) {
    // Only free-text fields (the spec primitive that explicitly says
    // "user-supplied prose") get the XSS guard. Limits FP rate on
    // structured string fields.
    if (ps.type !== 'free-text') continue;
    const idSeed = endpointHash(`${endpoint.method}|${endpoint.path}|${field}|xss`, '');
    const id = XSS_HEURISTIC_BASE_ID + (idSeed % 9000);
    out.push(
      [
        header(
          `W24-D stored-XSS guard on request.schema.${field} for ${endpoint.method} ${endpoint.path}\n` +
            `phase:2 — denies when the free-text field carries a literal <script tag\n` +
            `or javascript: URI. Stops the payload at write time so the GET-side echo\n` +
            `(which coraza-spoa cannot inspect — no response body via SPOE) is moot.`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: stored-XSS payload in ${esc(field)}',tag:'${esc(tag)}',tag:'x-security-xss-stored',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRegex(endpoint.path)}" "chain"`,
        `    SecRule ARGS:json.${field} "@rx (?i)(?:<script\\b|javascript:)"${term}`,
      ].join('\n')
    );
  }
  return out;
}

/** Top-level (non-endpoint) directives shared across the WAF. */
export interface TopDirectives {
  /** Smallest maxBodySize across all endpoints, in bytes. */
  globalBodyLimit: number | null;
}

export function buildPolicyRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const policy: XSecurityPolicy = endpoint.policy;
  const base = ruleBase(endpoint);
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const ctx: RuleCtx = { endpoint, base, tag };

  const out: string[] = [];
  out.push(buildScopeMarker(ctx));

  if (policy.request?.contentType?.length) {
    const r = buildContentType(ctx, policy.request.contentType, profile);
    if (r) out.push(r);
    // Wave-8: emit the JSON body-processor ctl directive immediately after the
    // content-type allowlist so phase-2 schema / mass-assignment rules can see
    // top-level body keys on Coraza-SPOA / Coraza-Go (which otherwise leave
    // ARGS_NAMES empty for application/json requests).
    const jsonCtl = buildJsonBodyProcessor(endpoint, profile);
    if (jsonCtl) out.push(jsonCtl);
  }

  const bytes = parseByteSize(policy.request?.maxBodySize);
  if (Number.isFinite(bytes) && bytes > 0) {
    out.push(buildBodySize(ctx, bytes, profile));
  }

  if (policy.authentication && policy.authentication.type !== 'none') {
    out.push(buildAuth(ctx, policy.authentication.headerName ?? 'Authorization', profile));
  }

  if (policy.ipPolicy) {
    out.push(...buildIpPolicy(ctx, policy.ipPolicy, profile));
  }

  const rls = Array.isArray(policy.rateLimit) ? policy.rateLimit : policy.rateLimit ? [policy.rateLimit] : [];
  let rlOffset = 0;
  for (const rl of rls) {
    out.push(buildRateLimit(ctx, rl, rlOffset, profile, warnings));
    rlOffset += rateLimitIdCount(rl);
  }

  if (policy.request?.schema) {
    out.push(...buildSchemaRules(ctx, policy.request.schema, profile));
  }

  out.push(...buildBodyFieldAllowlistRules(endpoint, profile));

  // W19-A: SSRF url-allowlist / blockPrivateRanges on url-typed request params.
  out.push(...buildSsrfRules(endpoint, profile));

  // B1: identity-aware authz (BOLA/BFLA) — lifted from W13-C identity-conf.
  out.push(...buildIdentityRules(endpoint, profile));

  // W19: per-arg injection guards (sql/nosql/os-command/code-eval/xpath/ldap)
  // driven by request.schema.<field>.injectionGuard, on JSON-body endpoints.
  out.push(...buildSqliHeuristics(endpoint, profile));

  // W24-D: stored-XSS heuristic on request-side free-text fields. Stops the
  // payload at write time because coraza-spoa cannot inspect response bodies.
  out.push(...buildXssHeuristics(endpoint, profile));

  // C-1: phase-4 response-body inspection (API3 BOPLA / data exposure).
  out.push(...buildResponseInspectionRules(endpoint, profile, warnings));

  // C-3: CORS origin allowlist + preflight enforcement (id:339 / id:332).
  out.push(...buildCorsRules(endpoint, profile));

  // C-2A: output sanitization (id:268) gated on response.errorScrubbing.
  out.push(...buildOutputSanitizationRules(endpoint, profile, warnings));

  // C-2B: PII / sensitive-field data-exposure filter (id:428) on response.schema.
  out.push(...buildDataExposurePiiRules(endpoint, profile, warnings));

  // Lifecycle: deprecated (id:269) / sunsetDate (id:270) / replacementEndpoint (id:271).
  out.push(...buildLifecycleRules(endpoint, profile));

  // CSRF (id:272) — state-changing methods only.
  out.push(...buildCsrfRules(endpoint, profile));

  // HPP: duplicateParamPolicy='reject' (id:275).
  out.push(...buildDuplicateParamRules(endpoint, profile));

  // response.contentType allowlist (id:276).
  out.push(...buildResponseContentTypeRules(endpoint, profile));

  // v0.8 (API6): request.serializeBy + concurrencyLimit — crude edge
  // serialization cap (partial; NOT in-handler atomicity).
  out.push(...buildSerializeByRules(endpoint, profile, warnings));

  // v0.8 (API4): graphql.staticLimits — coarse non-parsing GraphQL guards
  // (partial: disableIntrospection / maxAliases / batchLimit).
  out.push(...buildGraphqlStaticLimitRules(endpoint, profile, warnings));

  // v0.8: override-only / advisory scaffolding (NOT enforced) —
  // graphql.operations[].authz (API1/API5) + request.dataAtRest (SSEC-STORAGE).
  out.push(...buildResidualScaffolding(endpoint));

  // v0.7 edge-enforceable residuals (profile-gated; see v07-rules.ts):
  //   passwordPolicy (full) / accountLockout (full where persistent named
  //   collection / partial else) / forbidArrayRoot (full where response-body
  //   access / unsupported else) / idempotencyKey (partial) / logging (partial).
  out.push(...buildPasswordPolicyRules(endpoint, profile));
  out.push(...buildAccountLockoutRules(endpoint, profile, warnings));
  out.push(...buildForbidArrayRootRules(endpoint, profile, warnings));
  out.push(...buildIdempotencyKeyRules(endpoint, profile, warnings));
  out.push(...buildLoggingRules(endpoint, profile));

  return out;
}
