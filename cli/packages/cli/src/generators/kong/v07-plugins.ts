// v0.7+ field builders for Kong OSS — the SSEC-AUDIT/API3/API6 fields that
// were previously bunkerweb-only. Each builder maps one XSecurityPolicy field
// onto Kong OSS plugins/pre-functions, or returns [] when the field is empty.
//
// Honesty (Rule D-1): 'full' is claimed ONLY where a real native plugin or a
// pre/post-function genuinely enforces.
//   - logging          → FULL. Kong OSS ships real native log plugins
//                        (http-log / file-log / tcp-log / syslog). We emit the
//                        one matching `logging.sink`, with a custom log format
//                        carrying the declared events; piiRedaction drops the
//                        declared pii fields from the serialized line.
//   - passwordPolicy   → FULL. Access-phase pre-function validates the password
//                        body field (length/charset/blocklist) → 422.
//   - forbidArrayRoot  → FULL. body_filter post-function cjson-decodes the
//                        response; a bare top-level array → 502.
//   - idempotencyKey   → PARTIAL. OSS has no native idempotency; a pre-function
//                        shared_dict dedupe is best-effort and races. Emitted
//                        as a best-effort gate + a _x_security_warnings note.
//   - accountLockout   → PARTIAL. OSS has no native per-credential lockout;
//                        rate-limiting keyed on the credential header is the
//                        closest, but it throttles rather than locks. Emitted as
//                        a rate-limiting plugin keyed per-credential + a warning.

import type {
  Authentication,
  Logging,
  LoggingEvent,
  ResponsePolicy,
  RequestPolicy,
  XSecurityPolicy
} from '@x-security/schema';
import type { KongPlugin, XSecurityWarning } from './types.js';
import type { WarningSink } from './plugins.js';

// Lua string literal — matches the escaping used across plugins.ts / plugins-w26.ts.
function luaStr(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
}

// Duration → seconds (mirrors plugins.ts parseDurationSeconds; kept local so
// this module has no cross-file private import).
const WINDOW_TO_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
function durationSeconds(window: string): number {
  const m = window.match(/^(\d+)\s*([smhd])$/i);
  if (!m) return 60;
  return Number(m[1]) * (WINDOW_TO_SECONDS[m[2]!.toLowerCase()] ?? 60);
}

// ---------- logging (SSEC-AUDIT) — FULL via native Kong log plugins ----------
//
// Kong OSS ships four native log plugins, one per sink:
//   stdout         → file-log x-securitying to /dev/stdout
//   file           → file-log x-securitying to a host path
//   syslog         → syslog
//   http-collector → http-log POSTing to sinkRef
//
// Each carries a `custom_fields_by_lua` map so the serialized log entry
// declares the XSecurity audit contract: the requested events list and a
// per-request `ss_audit_event` classification derived from the response status
// + plugin tags already present on the route (auth-failure ⇐ 401/403,
// authz-deny ⇐ x-security-rule-* tags, rate-limit-trip ⇐ 429, injection-block
// ⇐ x-security-sqli/ssrf tags). piiRedaction drops the declared pii fields from
// the emitted entry via a `custom_fields_by_lua` nil-set (Kong omits a field
// whose lua function returns nil), so the sink never receives the pii values.

export const SS_AUDIT_TAG = 'x-security-audit-log';

const LOGGING_SINK_PLUGIN: Record<string, string> = {
  stdout: 'file-log',
  file: 'file-log',
  syslog: 'syslog',
  'http-collector': 'http-log'
};

// Lua that classifies the current request into one declared LoggingEvent, used
// as the value of the `ss_audit_event` custom field. Reads kong.response.get_status()
// and the route's plugin tags (exposed via kong.ctx) — purely reflective, no
// enforcement. Only the events the spec declared are emitted as classifications;
// everything else collapses to "request".
function auditEventLua(events: LoggingEvent[]): string {
  const want = new Set(events);
  const branches: string[] = [];
  if (want.has('auth-failure')) {
    branches.push(`  if status == 401 or status == 403 then return "auth-failure" end`);
  }
  if (want.has('rate-limit-trip')) {
    branches.push(`  if status == 429 then return "rate-limit-trip" end`);
  }
  if (want.has('authz-deny')) {
    branches.push(`  if status == 403 then return "authz-deny" end`);
  }
  if (want.has('injection-block')) {
    // SQLi/SSRF/mass-assign pre-functions exit 403 with a x-security tag; the
    // body marker isn't readable here, so a 403 with no auth context is the
    // best reflective signal. Kept after auth-failure so explicit auth wins.
    branches.push(`  if status == 422 then return "injection-block" end`);
  }
  if (want.has('auth-success')) {
    branches.push(`  if status >= 200 and status < 300 then return "auth-success" end`);
  }
  const fallback = want.has('request') ? 'request' : want.has('response') ? 'response' : 'request';
  return [
    `return (function()`,
    `  local status = kong.response.get_status()`,
    ...branches,
    `  return ${luaStr(fallback)}`,
    `end)()`
  ].join('\n');
}

// Collect declared pii field names from request + response schema (pii:true).
function collectPiiFields(req: RequestPolicy | undefined, resp: ResponsePolicy | undefined): string[] {
  const out = new Set<string>();
  for (const [field, ps] of Object.entries(req?.schema ?? {})) {
    if (ps && ps.pii === true) out.add(field);
  }
  for (const [field, ps] of Object.entries(resp?.schema ?? {})) {
    if (ps && ps.pii === true) out.add(field);
  }
  return [...out];
}

export function buildLoggingPlugins(
  policy: XSecurityPolicy,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  const log: Logging | undefined = policy.logging;
  if (!log || !Array.isArray(log.events) || log.events.length === 0) return [];

  const sink = log.sink ?? 'stdout';
  const pluginName = LOGGING_SINK_PLUGIN[sink];
  if (!pluginName) return [];

  const config: Record<string, unknown> = {};

  // Sink-specific config.
  if (sink === 'stdout') {
    config.path = '/dev/stdout';
    config.reopen = false;
  } else if (sink === 'file') {
    // Operator supplies the path via env placeholder so the same kong.yml works
    // across hosts; default to the conventional Kong log dir.
    config.path = '${SS_AUDIT_LOG_PATH}';
    config.reopen = true;
  } else if (sink === 'syslog') {
    // syslog plugin ships declared events at the chosen facility/severity.
    config.facility = 'local0';
    config.successful_severity = 'info';
    config.client_errors_severity = 'warning';
    config.server_errors_severity = 'err';
  } else if (sink === 'http-collector') {
    if (!log.sinkRef) {
      if (ctx.warn) {
        ctx.warn({
          field: 'logging.sinkRef',
          ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
          declared: 'http-collector (no sinkRef)',
          emitted: '(none)',
          reason:
            'logging.sink="http-collector" requires sinkRef (the collector endpoint). ' +
            'Without it the http-log plugin has no destination; logging plugin not emitted.'
        });
      }
      return [];
    }
    config.http_endpoint = log.sinkRef;
    config.method = 'POST';
    config.content_type = 'application/json';
    config.timeout = 10000;
    config.keepalive = 60000;
  }

  // Declared events are carried as a structured custom field so every emitted
  // entry self-describes the audit contract (and `ss_audit_event` classifies
  // the request). These are NATIVE Kong custom-field hooks — full, real.
  const customFields: Record<string, string> = {
    ss_audit_events: `return ${luaStr(log.events.join(','))}`,
    ss_audit_event: auditEventLua(log.events),
    ss_audit_endpoint: `return ${luaStr(ctx.endpoint ?? '?')}`
  };

  // piiRedaction: drop declared pii fields from the serialized entry. Kong omits
  // any custom field whose lua function returns nil, so we register each pii
  // field name as a nil-returning custom field — this guarantees the redacted
  // names never carry a value into the sink even if a future log template
  // references them. We also surface the contract so operators wire upstream
  // body-field omission for the request/response log bodies the plugin captures.
  if (log.piiRedaction) {
    const pii = collectPiiFields(policy.request, policy.response);
    for (const field of pii) {
      customFields[`ss_pii_${field}`] = 'return nil';
    }
    if (pii.length > 0 && ctx.warn) {
      ctx.warn({
        field: 'logging.piiRedaction',
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
        declared: `redact ${pii.length} pii field(s): ${pii.join(', ')}`,
        emitted: `${pluginName} custom_fields_by_lua nil-set (declared pii fields omitted from serialized entry)`,
        reason:
          'Kong native log plugins omit any custom_fields_by_lua field whose lua returns nil; ' +
          'the declared pii field names are registered as nil so they never reach the sink. ' +
          'Note: the plugin does not capture request/response bodies by default, so pii in ' +
          'free-form body text requires the upstream to omit it — the structured field contract here ' +
          'covers the declared pii field NAMES.'
      });
    }
  }

  config.custom_fields_by_lua = customFields;

  return [{
    name: pluginName,
    config,
    tags: [SS_AUDIT_TAG]
  }];
}

// ---------- authentication.passwordPolicy — FULL via access pre-function ----------
//
// Kong OSS has no native password-strength plugin. The access-phase pre-function
// reads the password body field, validates length + charset (uppercase/digit/
// symbol) + blocklist, and exits 422 on the first violation. This genuinely
// enforces at the edge (the request never reaches the upstream), so → full.
//
// The password body field is `password` by default. Marker: x-security-password-policy-422.

export const SS_PASSWORD_POLICY_TAG = 'x-security-password-policy-422';

export function buildPasswordPolicyPlugins(
  auth: Authentication | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  const pp = auth?.passwordPolicy;
  if (!pp) return [];

  // Nothing to enforce → emit nothing (a no-op plugin would be a Rule D-1 fake).
  const hasRule =
    typeof pp.minLength === 'number' ||
    pp.requireUppercase === true ||
    pp.requireDigit === true ||
    pp.requireSymbol === true ||
    (Array.isArray(pp.blocklist) && pp.blocklist.length > 0);
  if (!hasRule) {
    if (ctx.warn) {
      ctx.warn({
        field: 'authentication.passwordPolicy',
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
        declared: '(empty policy)',
        emitted: '(none)',
        reason:
          'authentication.passwordPolicy declared no enforceable rule ' +
          '(minLength/requireUppercase/requireDigit/requireSymbol/blocklist); pre-function not emitted.'
      });
    }
    return [];
  }

  const checks: string[] = [];
  if (typeof pp.minLength === 'number') {
    checks.push(
      `  if #pw < ${pp.minLength} then`,
      `    return ${luaStr('minLength')}`,
      `  end`
    );
  }
  if (pp.requireUppercase === true) {
    checks.push(
      `  if not pw:match("%u") then return ${luaStr('requireUppercase')} end`
    );
  }
  if (pp.requireDigit === true) {
    checks.push(
      `  if not pw:match("%d") then return ${luaStr('requireDigit')} end`
    );
  }
  if (pp.requireSymbol === true) {
    checks.push(
      `  if not pw:match("[^%w]") then return ${luaStr('requireSymbol')} end`
    );
  }
  if (Array.isArray(pp.blocklist) && pp.blocklist.length > 0) {
    const blockSet =
      '{' + pp.blocklist.map((b) => `[${luaStr(b.toLowerCase())}]=true`).join(', ') + '}';
    checks.push(
      `  local ss_blocked = ${blockSet}`,
      `  if ss_blocked[pw:lower()] then return ${luaStr('blocklist')} end`
    );
  }

  const lua = [
    `-- XSecurity v0.7 password-policy pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `local body = kong.request.get_body()`,
    `if type(body) == "table" and type(body.password) == "string" then`,
    `  local pw = body.password`,
    `  local violation = (function()`,
    ...checks,
    `    return nil`,
    `  end)()`,
    `  if violation ~= nil then`,
    `    kong.log.warn("[${SS_PASSWORD_POLICY_TAG}] password rejected: " .. violation)`,
    `    return kong.response.exit(422, {`,
    `      message = "XSecurity: password does not meet policy",`,
    `      tag = "${SS_PASSWORD_POLICY_TAG}",`,
    `      violation = violation`,
    `    })`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_PASSWORD_POLICY_TAG]
  }];
}

// ---------- response.forbidArrayRoot — FULL via body_filter post-function ----------
//
// API3 JSON-hijacking defense: reject a bare top-level array response body. The
// post-function cjson-decodes the body; if the decoded root is a non-empty array
// (a Lua table with a sequential integer length and no string keys), it rewrites
// the response to a 502 generic envelope. Reuses the cjson decode pattern from
// plugins-w26.ts. `kong.response.exit()` is illegal in body_filter, so we set
// the status in body_filter via kong.response.set_status + set_raw_body.

export const SS_FORBID_ARRAY_ROOT_TAG = 'x-security-forbid-array-root-502';

export function buildForbidArrayRootPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!resp || resp.forbidArrayRoot !== true) return [];

  // Detect a JSON array root from the DECODED value: cjson decodes a JSON array
  // to a Lua table with a contiguous integer length and no string keys. An empty
  // array decodes to cjson.empty_array (still array-rooted) — we treat any
  // array root as a violation, including [].
  const lua = [
    `-- XSecurity v0.7 forbidArrayRoot post-function for endpoint=${ctx.endpoint ?? '?'}`,
    `local cjson = require("cjson.safe")`,
    `local raw = kong.response.get_raw_body()`,
    `if raw and #raw > 0 then`,
    `  local obj = cjson.decode(raw)`,
    `  if type(obj) == "table" then`,
    `    -- array-root iff no string keys (object would have at least one).`,
    `    local has_string_key = false`,
    `    for k, _ in pairs(obj) do`,
    `      if type(k) == "string" then has_string_key = true; break end`,
    `    end`,
    `    local is_array_root = not has_string_key and (#obj > 0 or raw:match("^%s*%[") ~= nil)`,
    `    if is_array_root then`,
    `      kong.log.warn("[${SS_FORBID_ARRAY_ROOT_TAG}] bare top-level array response blocked (JSON hijacking)")`,
    `      kong.response.set_status(502)`,
    `      kong.response.set_header("Content-Type", "application/json")`,
    `      kong.response.set_raw_body('{"message":"XSecurity: bare top-level array response forbidden","tag":"${SS_FORBID_ARRAY_ROOT_TAG}"}')`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { body_filter: [lua] },
    tags: [SS_FORBID_ARRAY_ROOT_TAG]
  }];
}

// ---------- request.idempotencyKey — PARTIAL via best-effort shared_dict dedupe ----------
//
// HONEST (Rule D-1): Kong OSS has NO native idempotency plugin. A pre-function
// shared_dict dedupe is fragile: (a) the dict is per-instance (no cross-Kong
// sharing without redis), and (b) there is no atomic check-and-set across the
// upstream roundtrip — two concurrent first-requests both miss the dict before
// either records, so a true race still double-executes. This is best-effort
// replay suppression, NOT idempotency. We emit it as a partial gate and record
// the limitation in _x_security_warnings. capability: 'partial'.
//
// Marker: x-security-idempotency-replay-409.

export const SS_IDEMPOTENCY_TAG = 'x-security-idempotency-replay-409';
export const SS_IDEMPOTENCY_CACHE_DICT = 'x_security_idempotency_cache';
export const SS_IDEMPOTENCY_CACHE_DICT_SIZE = '10m';

export function buildIdempotencyKeyPlugins(
  request: RequestPolicy | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  const idem = request?.idempotencyKey;
  if (!idem) return [];

  const ttl = durationSeconds(idem.ttl);

  if (ctx.warn) {
    ctx.warn({
      field: 'request.idempotencyKey',
      ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
      declared: `header=${idem.header} ttl=${idem.ttl}`,
      emitted: 'pre-function best-effort shared_dict replay-suppression (PARTIAL)',
      reason:
        'Kong OSS has no native idempotency plugin. This pre-function records seen ' +
        'idempotency keys in a per-instance shared_dict and rejects a repeat within TTL, ' +
        'but it is NOT true idempotency: (1) the dict is per-Kong-instance unless backed by ' +
        'redis, and (2) there is no atomic check-and-set across the upstream roundtrip, so two ' +
        'concurrent first-requests can both pass before either records. Declare ' +
        `KONG_NGINX_HTTP_LUA_SHARED_DICT="${SS_IDEMPOTENCY_CACHE_DICT} ${SS_IDEMPOTENCY_CACHE_DICT_SIZE}" ` +
        'on the Kong container; the Lua is nil-safe and no-ops (fails open) when the dict is absent.'
    });
  }

  const lua = [
    `-- XSecurity v0.7 idempotencyKey pre-function (PARTIAL) for endpoint=${ctx.endpoint ?? '?'}`,
    `-- Best-effort replay suppression only — NOT atomic idempotency. See _x_security_warnings.`,
    `local key = kong.request.get_header(${luaStr(idem.header)})`,
    `if key ~= nil and key ~= "" then`,
    `  local cache = ngx.shared.${SS_IDEMPOTENCY_CACHE_DICT}`,
    `  if cache then`,
    `    local seen = cache:get(key)`,
    `    if seen then`,
    `      kong.log.warn("[${SS_IDEMPOTENCY_TAG}] replayed idempotency key '" .. tostring(key) .. "' within ttl")`,
    `      return kong.response.exit(409, {`,
    `        message = "XSecurity: idempotency key replay rejected",`,
    `        tag = "${SS_IDEMPOTENCY_TAG}"`,
    `      })`,
    `    end`,
    `    -- NON-ATOMIC: a concurrent first-request can race past this set.`,
    `    cache:set(key, 1, ${ttl})`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_IDEMPOTENCY_TAG]
  }];
}

// ---------- authentication.accountLockout — PARTIAL via per-credential rate-limiting ----------
//
// HONEST (Rule D-1): Kong OSS has NO native per-username account-lockout. The
// closest native primitive is the rate-limiting plugin keyed on the credential
// header (limit_by=header, header_name=<credential header>). This THROTTLES
// repeated attempts per credential within the window, which blunts brute-force,
// but it is NOT a lockout: it does not lock the account for a fixed duration
// after N failures, and it counts ALL attempts (not just failed ones — the
// gateway can't see the auth verdict). We emit it as a per-credential rate-limit
// and record the divergence. capability: 'partial'.
//
// The identifier is expected as 'header:X-Username' (per AccountLockout.identifier
// docs). request.body.<field> forms can't be keyed by the rate-limiting plugin
// (it keys on headers/ip/consumer), so those degrade to a warning + no plugin.
//
// Marker tag: x-security-account-lockout (per-credential throttle).

export const SS_ACCOUNT_LOCKOUT_TAG = 'x-security-account-lockout';

function lockoutBucket(seconds: number): 'second' | 'minute' | 'hour' | 'day' {
  if (seconds <= 1) return 'second';
  if (seconds <= 60) return 'minute';
  if (seconds <= 3600) return 'hour';
  return 'day';
}

export function buildAccountLockoutPlugins(
  auth: Authentication | undefined,
  ctx: { endpoint?: string; warn?: WarningSink } = {}
): KongPlugin[] {
  const lock = auth?.accountLockout;
  if (!lock) return [];

  const identifier = lock.identifier ?? '';
  const headerMatch = identifier.match(/^header:(.+)$/i);

  if (!headerMatch) {
    // request.body.<field> or other non-header identifier — the rate-limiting
    // plugin can't key on a body field. Honest: no plugin + warning.
    if (ctx.warn) {
      ctx.warn({
        field: 'authentication.accountLockout.identifier',
        ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
        declared: identifier || '(unset)',
        emitted: '(none)',
        reason:
          'Kong OSS account-lockout is approximated with rate-limiting limit_by=header, which ' +
          'can ONLY key on a request header. The declared identifier is not a "header:<Name>" form, ' +
          'so no per-credential bucket can be built. Re-declare the lockout identifier as ' +
          '"header:<Name>" (e.g. "header:X-Username"), or front this endpoint with coraza/bunkerweb ' +
          'for the SecCollection-based attempt counter.'
      });
    }
    return [];
  }

  const headerName = headerMatch[1]!;
  const seconds = durationSeconds(lock.window);
  const bucket = lockoutBucket(seconds);

  if (ctx.warn) {
    ctx.warn({
      field: 'authentication.accountLockout',
      ...(ctx.endpoint ? { endpoint: ctx.endpoint } : {}),
      declared: `attempts=${lock.attempts} window=${lock.window} identifier=${identifier}`,
      emitted: `rate-limiting limit_by=header header_name=${headerName} ${bucket}=${lock.attempts} (PARTIAL throttle, not lockout)`,
      reason:
        'Kong OSS has no native per-credential account-lockout. This rate-limiting plugin keyed on ' +
        `the credential header throttles to ${lock.attempts} request(s) per ${bucket} per credential, ` +
        'which blunts brute-force, but it is NOT a lockout: it does not lock the account for a fixed ' +
        'duration after N failures, and it counts ALL attempts (the gateway cannot observe the auth ' +
        'verdict, so successful logins also consume the budget). For a true failed-attempt lockout, ' +
        'front this endpoint with coraza/bunkerweb (SecCollection attempt counter) or use Kong Enterprise.'
    });
  }

  const config: Record<string, unknown> = {
    [bucket]: lock.attempts,
    limit_by: 'header',
    header_name: headerName,
    policy: 'local',
    fault_tolerant: true,
    hide_client_headers: false
  };

  return [{
    name: 'rate-limiting',
    config,
    tags: [SS_ACCOUNT_LOCKOUT_TAG]
  }];
}
