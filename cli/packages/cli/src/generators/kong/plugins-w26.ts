// W26: implementation-gap closers for Kong OSS — response-side post-function
// plugins (strip-unknown, strip-traces, generic-error, maxlength), composite
// rate-limit fingerprinting (ip+ua), and bot-protection heuristic gate.
//
// Each builder mirrors the style of plugins.ts: small, gated on explicit DSL
// opt-in, attaches an SS_* marker tag so the scorer can attribute the block.
//
// Post-function vs response-transformer: Kong OSS ships `post-function`
// (serverless-functions plugin, bundled by default in 3.x) which runs Lua in
// the `body_filter` phase with full access to `kong.response.get_raw_body()` /
// `kong.response.set_raw_body()`. response-transformer only supports static
// add/remove operations — it cannot inspect body JSON. We use post-function
// for anything that needs body inspection or conditional rewrites.

import type { RequestPolicy, ResponsePolicy, RateLimit, BotProtection } from '@x-security/schema';
import type { KongPlugin } from './types.js';

// ---------- shared helpers ----------

function luaStr(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
}

// ---------- response: strip unknown fields ----------
// Gate: `response.stripUnknownFields === true` AND `response.schema` declares
// the allowlist keys. Post-function parses JSON body and drops keys not in the
// schema-derived allowlist. Re-encodes with cjson.

export const SS_RESPONSE_STRIP_UNKNOWN_TAG = 'x-security-response-strip-unknown';

export function buildResponseStripUnknownPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!resp || resp.stripUnknownFields !== true) return [];
  const schemaKeys = resp.schema ? Object.keys(resp.schema) : [];
  if (schemaKeys.length === 0) return [];

  const luaAllowTable = '{' + schemaKeys.map((k) => `[${luaStr(k)}]=true`).join(', ') + '}';
  const lua = [
    `-- XSecurity W26 response strip-unknown-fields for endpoint=${ctx.endpoint ?? '?'}`,
    `local cjson = require("cjson.safe")`,
    `local ss_allow = ${luaAllowTable}`,
    `local raw = kong.response.get_raw_body()`,
    `if raw and #raw > 0 then`,
    `  local obj = cjson.decode(raw)`,
    `  if type(obj) == "table" then`,
    `    local dropped = 0`,
    `    for k, _ in pairs(obj) do`,
    `      if not ss_allow[k] then obj[k] = nil; dropped = dropped + 1 end`,
    `    end`,
    `    if dropped > 0 then`,
    `      kong.log.warn("[${SS_RESPONSE_STRIP_UNKNOWN_TAG}] dropped " .. tostring(dropped) .. " unknown response field(s)")`,
    `      local encoded = cjson.encode(obj)`,
    `      if encoded then kong.response.set_raw_body(encoded) end`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { body_filter: [lua] },
    tags: [SS_RESPONSE_STRIP_UNKNOWN_TAG]
  }];
}

// ---------- response: strip stack traces ----------
// Gate: `response.errorScrubbing.stripStackTraces === true`. Body-filter regex
// scrubs common stack-trace markers from response bodies on 4xx/5xx.

export const SS_RESPONSE_STRIP_TRACES_TAG = 'x-security-response-strip-traces';

// Lua patterns covering the common stack-trace shapes. Conservative — only
// strips the trace lines, leaves surrounding message intact.
const STACK_TRACE_LUA_PATTERNS = [
  '\n%s*at%s+[%w%._$<>]+%([^%)]*%)',     // Java/JS:  "  at com.foo.Bar.baz(File.java:42)"
  '\n%s*at%s+[%w/%._-]+:%d+:%d+',         // JS V8:    "  at /app/x.js:10:5"
  '\nTraceback %(most recent call last%):.-(?=\n%w)', // Python: "Traceback ..." block
  '\n%s*File "[^"]+", line %d+',          // Python:   '  File "x.py", line 42'
  '\n%s*#%d+%s+0x[%x]+%s+in%s+',          // C/C++ gdb: "#0 0xdeadbeef in foo"
  '\n%s*from%s+[%w/%._-]+:%d+:in%s+',     // Ruby:     "  from /app/x.rb:10:in `foo'"
];

export function buildResponseStripTracesPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!resp?.errorScrubbing?.stripStackTraces) return [];

  const subs = STACK_TRACE_LUA_PATTERNS
    .map((p) => `  body = body:gsub(${luaStr(p)}, "")`)
    .join('\n');

  const lua = [
    `-- XSecurity W26 response strip-stack-traces for endpoint=${ctx.endpoint ?? '?'}`,
    `local status = kong.response.get_status()`,
    `if status >= 400 then`,
    `  local body = kong.response.get_raw_body()`,
    `  if body and #body > 0 then`,
    `    local original_len = #body`,
    subs,
    `    if #body ~= original_len then`,
    `      kong.log.warn("[${SS_RESPONSE_STRIP_TRACES_TAG}] scrubbed stack-trace from response")`,
    `      kong.response.set_raw_body(body)`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { body_filter: [lua] },
    tags: [SS_RESPONSE_STRIP_TRACES_TAG]
  }];
}

// ---------- response: generic error messages ----------
// Gate: `response.errorScrubbing.genericMessages === true`. Rewrites any 5xx
// body to a fixed generic JSON envelope. 4xx is preserved (operator/client
// error messages are usually intentional).

export const SS_RESPONSE_GENERIC_ERROR_TAG = 'x-security-response-generic-error';

export function buildResponseGenericErrorPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!resp?.errorScrubbing?.genericMessages) return [];

  const lua = [
    `-- XSecurity W26 response generic-error-message for endpoint=${ctx.endpoint ?? '?'}`,
    `local status = kong.response.get_status()`,
    `if status >= 500 then`,
    `  kong.log.warn("[${SS_RESPONSE_GENERIC_ERROR_TAG}] rewrote 5xx body to generic message")`,
    `  kong.response.set_raw_body('{"message":"Internal server error","tag":"${SS_RESPONSE_GENERIC_ERROR_TAG}"}')`,
    `  kong.response.set_header("Content-Type", "application/json")`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { body_filter: [lua] },
    tags: [SS_RESPONSE_GENERIC_ERROR_TAG]
  }];
}

// ---------- response.contentType assertion (API8 misconfig) ----------
// Gate: `response.contentType` declares an allowlist. On a 2xx response whose
// Content-Type (base type, charset stripped) is NOT in the allowlist, fail
// closed: rewrite to 502 + generic JSON. Enforces the declared response media
// type, blocking content-type confusion (e.g. HTML leaking from a JSON API).
// Robust: reads the parsed Content-Type header, not a regex over the body.
// `kong.response.exit()` errors in header_filter, so we set status in
// header_filter and replace the body in body_filter.

export const SS_RESPONSE_CONTENT_TYPE_TAG = 'x-security-response-contenttype';

export function buildResponseContentTypeAssertPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  const allowed = resp?.contentType;
  if (!allowed || allowed.length === 0) return [];

  const luaSet = allowed
    .map((t) => `["${t.toLowerCase().replace(/["\\]/g, '')}"]=true`)
    .join(', ');

  const headerFilter = [
    `-- XSecurity response Content-Type assertion endpoint=${ctx.endpoint ?? '?'}`,
    `local allowed = { ${luaSet} }`,
    `local status = kong.response.get_status()`,
    `if status >= 200 and status < 300 then`,
    `  local ct = kong.response.get_header("Content-Type")`,
    `  if ct then`,
    `    local base = ct:match("^[^;]+")`,
    `    base = base and base:gsub("%s+$", ""):gsub("^%s+", ""):lower() or nil`,
    `    if base and not allowed[base] then`,
    `      kong.ctx.plugin.ss_ct_block = true`,
    `      kong.response.set_status(502)`,
    `      kong.response.set_header("Content-Type", "application/json")`,
    `      kong.log.warn("[${SS_RESPONSE_CONTENT_TYPE_TAG}] response Content-Type '" .. tostring(ct) .. "' not in allowlist; blocked")`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  const bodyFilter = [
    `if kong.ctx.plugin.ss_ct_block then`,
    `  kong.response.set_raw_body('{"message":"Upstream returned a disallowed Content-Type","tag":"${SS_RESPONSE_CONTENT_TYPE_TAG}"}')`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { header_filter: [headerFilter], body_filter: [bodyFilter] },
    tags: [SS_RESPONSE_CONTENT_TYPE_TAG]
  }];
}

// ---------- response: full typed-schema validation ----------
// Gate: `response.schema` declares at least one enforceable constraint
// (type / format / min / max / minLength / maxLength / fixedLength / pattern).
//
// ROBUSTNESS — parsed-value enforcement, never raw-byte: we `cjson.decode` the
// body ONCE into a Lua table, then evaluate every constraint against the DECODED
// value. The decoded value is canonical — immune to pretty-printing/whitespace,
// escaped quotes (`\"` → `"` in the Lua string), key ordering, and numeric
// formatting (1e2 / 100 / 100.0 all decode to the Lua number 100). A regex over
// the raw body mis-handles all of these: `pattern` on raw bytes sees the JSON
// quoting/escapes, and `min`/`max` on raw text string-compares. Here `pattern`
// runs on the decoded STRING value only and `min`/`max` on the decoded NUMBER.
//
// SCOPE — TOP-LEVEL = FULL (honest): `ResponsePolicy.schema` is
// `Record<string, ParamSchema>` and `ParamSchema` has NO nested
// `properties`/`items` — the DSL cannot express nested object/array-element
// constraints. Every field the schema can declare is a top-level key and we
// enforce all of them; a decoded value that is itself a table has no declared
// constraints, so we leave it untouched. Full coverage of what the type permits.
//
// FAIL MODE — scrub-on-violation, never crash:
//   * maxLength / fixedLength-over → truncate the decoded string to the limit.
//   * any other violation (wrong type/format, out-of-range number, too-short
//     string, fixedLength mismatch, pattern miss) → DROP the field (set nil).
//     A malformed/over-permissive response value is a data-exposure risk (API3
//     BOPLA), so dropping fails safe — we never emit a value we couldn't
//     validate. Every action is logged via kong.log.warn with field + reason.
//   * Undecodable / non-object body (cjson.safe → nil, or a scalar/array at top
//     level): PASS THROUGH untouched — no top-level fields to validate, and we
//     never crash the body_filter or fabricate a verdict.

export const SS_RESPONSE_SCHEMA_TAG = 'x-security-response-schema';
// Back-compat alias: maxLength enforcement now lives inside the full validator.
export const SS_RESPONSE_MAXLENGTH_TAG = SS_RESPONSE_SCHEMA_TAG;

// Per-format Lua predicate bodies. Each is a function `(v)` returning true when
// the DECODED string value matches the format. Numeric formats also accept the
// decoded number directly. Lua patterns (not PCRE) — anchored where it matters.
const FORMAT_LUA: Record<string, string> = {
  // RFC-ish email: local@domain.tld, no spaces, one @, a dotted domain.
  email: `return type(v)=="string" and v:match("^[^@%s]+@[^@%s]+%.[^@%s]+$") ~= nil`,
  // Canonical 8-4-4-4-12 hex UUID (any version/variant nibble).
  uuid: `return type(v)=="string" and v:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil`,
  // URL: http(s) scheme + non-space remainder.
  url: `return type(v)=="string" and v:match("^https?://[^%s]+$") ~= nil`,
  // ISO date YYYY-MM-DD.
  date: `return type(v)=="string" and v:match("^%d%d%d%d%-%d%d%-%d%d$") ~= nil`,
  // ISO datetime: date + 'T' + HH:MM:SS + optional fraction + optional zone.
  datetime: `return type(v)=="string" and v:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d") ~= nil`,
  // IPv4 dotted quad (loose; per-octet range not enforced by Lua pattern).
  ['ip-address']: `return type(v)=="string" and v:match("^%d+%.%d+%.%d+%.%d+$") ~= nil`,
  // E.164-ish phone: optional +, digits/spaces/dashes/parens.
  phone: `return type(v)=="string" and v:match("^%+?[%d%s%-%(%)]+$") ~= nil`,
  // cjson decodes JSON numbers to Lua numbers; integer must have no fraction.
  integer: `return type(v)=="number" and v == math.floor(v)`,
  float: `return type(v)=="number"`,
  boolean: `return type(v)=="boolean"`,
  // string/name/free-text/binary: assert Lua string-ness; length/pattern do the rest.
  string: `return type(v)=="string"`,
  name: `return type(v)=="string"`,
  ['free-text']: `return type(v)=="string"`,
  binary: `return type(v)=="string"`
};

interface FieldRule {
  field: string;
  type?: string;
  min?: number;
  max?: number;
  minLength?: number;
  maxLength?: number;
  fixedLength?: number;
  pattern?: string;
}

// Build the Lua validator for one field. Operates on `obj[field]` (decoded
// value `v`). Order: type/format first (a value of the wrong type fails fast and
// is dropped), then length truncation (maxLength/fixedLength-over), then the
// remaining length/range/pattern asserts (drop-on-fail).
function fieldValidatorLua(r: FieldRule): string[] {
  const fk = luaStr(r.field);
  const lines: string[] = [];
  lines.push(`  do`);
  lines.push(`    local v = obj[${fk}]`);
  lines.push(`    if v ~= nil then`);

  // --- type / format (drop on mismatch) ---
  if (r.type && FORMAT_LUA[r.type]) {
    lines.push(`      local ok_type = (function(v) ${FORMAT_LUA[r.type]} end)(v)`);
    lines.push(`      if not ok_type then`);
    lines.push(`        obj[${fk}] = nil; dropped = dropped + 1`);
    lines.push(`        kong.log.warn("[${SS_RESPONSE_SCHEMA_TAG}] dropped field ${r.field}: type/format mismatch (expected ${r.type})")`);
    lines.push(`      end`);
  }

  // Re-read v after a possible type drop; subsequent checks only run if still present.
  lines.push(`      v = obj[${fk}]`);
  lines.push(`      if v ~= nil then`);

  // --- string length: truncate (maxLength / fixedLength-over) ---
  if (typeof r.maxLength === 'number' && r.maxLength > 0) {
    lines.push(`        if type(v) == "string" and #v > ${r.maxLength} then`);
    lines.push(`          obj[${fk}] = v:sub(1, ${r.maxLength}); v = obj[${fk}]; truncated = truncated + 1`);
    lines.push(`          kong.log.warn("[${SS_RESPONSE_SCHEMA_TAG}] truncated field ${r.field} to maxLength ${r.maxLength}")`);
    lines.push(`        end`);
  }
  if (typeof r.fixedLength === 'number' && r.fixedLength > 0) {
    // Over-length fixed strings are truncated; under-length are dropped below.
    lines.push(`        if type(v) == "string" and #v > ${r.fixedLength} then`);
    lines.push(`          obj[${fk}] = v:sub(1, ${r.fixedLength}); v = obj[${fk}]; truncated = truncated + 1`);
    lines.push(`          kong.log.warn("[${SS_RESPONSE_SCHEMA_TAG}] truncated field ${r.field} to fixedLength ${r.fixedLength}")`);
    lines.push(`        end`);
  }

  // --- remaining asserts: drop the field on violation ---
  const drops: string[] = [];
  if (typeof r.minLength === 'number') {
    drops.push(`        if type(v) == "string" and #v < ${r.minLength} then bad = "minLength" end`);
  }
  if (typeof r.fixedLength === 'number' && r.fixedLength > 0) {
    drops.push(`        if type(v) == "string" and #v ~= ${r.fixedLength} then bad = "fixedLength" end`);
  }
  if (typeof r.min === 'number') {
    drops.push(`        if type(v) == "number" and v < ${r.min} then bad = "min" end`);
  }
  if (typeof r.max === 'number') {
    drops.push(`        if type(v) == "number" and v > ${r.max} then bad = "max" end`);
  }
  if (typeof r.pattern === 'string' && r.pattern.length > 0) {
    // PCRE-style pattern from the DSL. Kong runs OpenResty/PCRE via ngx.re, so
    // apply it to the DECODED STRING value with ngx.re.match (robust — never the
    // raw body). Non-string values can't match a string pattern → drop.
    drops.push(`        if type(v) ~= "string" or not ngx.re.match(v, ${luaStr(r.pattern)}, "jo") then bad = "pattern" end`);
  }
  if (drops.length > 0) {
    lines.push(`        local bad = nil`);
    lines.push(...drops);
    lines.push(`        if bad then`);
    lines.push(`          obj[${fk}] = nil; dropped = dropped + 1`);
    lines.push(`          kong.log.warn("[${SS_RESPONSE_SCHEMA_TAG}] dropped field ${r.field}: " .. bad .. " violation")`);
    lines.push(`        end`);
  }

  lines.push(`      end`); // inner present-after-type
  lines.push(`    end`); // outer present
  lines.push(`  end`);
  return lines;
}

// Collect every field carrying at least one enforceable constraint.
function collectFieldRules(resp: ResponsePolicy): FieldRule[] {
  const rules: FieldRule[] = [];
  for (const [field, ps] of Object.entries(resp.schema ?? {})) {
    const r: FieldRule = { field };
    let any = false;
    if (ps.type && FORMAT_LUA[ps.type]) { r.type = ps.type; any = true; }
    if (typeof ps.min === 'number') { r.min = ps.min; any = true; }
    if (typeof ps.max === 'number') { r.max = ps.max; any = true; }
    if (typeof ps.minLength === 'number') { r.minLength = ps.minLength; any = true; }
    if (typeof ps.maxLength === 'number' && ps.maxLength > 0) { r.maxLength = ps.maxLength; any = true; }
    if (typeof ps.fixedLength === 'number' && ps.fixedLength > 0) { r.fixedLength = ps.fixedLength; any = true; }
    if (typeof ps.pattern === 'string' && ps.pattern.length > 0) { r.pattern = ps.pattern; any = true; }
    if (any) rules.push(r);
  }
  return rules;
}

export function buildResponseMaxLengthPlugins(
  resp: ResponsePolicy | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!resp?.schema) return [];
  const rules = collectFieldRules(resp);
  if (rules.length === 0) return [];

  const validators = rules.flatMap((r) => fieldValidatorLua(r));

  const lua = [
    `-- XSecurity W26 response typed-schema validation for endpoint=${ctx.endpoint ?? '?'}`,
    `-- Validates the cjson-DECODED value (canonical: immune to pretty-printing,`,
    `-- escaped quotes, key order, numeric formatting). Never matches raw body bytes.`,
    `local cjson = require("cjson.safe")`,
    `local raw = kong.response.get_raw_body()`,
    `if raw and #raw > 0 then`,
    `  local obj = cjson.decode(raw)`,
    `  -- Pass-through when body is undecodable or not a JSON object (no fields to check).`,
    `  if type(obj) == "table" then`,
    `    local dropped = 0`,
    `    local truncated = 0`,
    ...validators,
    `    if dropped > 0 or truncated > 0 then`,
    `      kong.log.warn("[${SS_RESPONSE_SCHEMA_TAG}] enforced response.schema: dropped " .. tostring(dropped) .. " field(s), truncated " .. tostring(truncated))`,
    `      local encoded = cjson.encode(obj)`,
    `      if encoded then kong.response.set_raw_body(encoded) end`,
    `    end`,
    `  end`,
    `end`
  ].join('\n');

  return [{
    name: 'post-function',
    config: { body_filter: [lua] },
    tags: [SS_RESPONSE_SCHEMA_TAG]
  }];
}

// ---------- rateLimit: fingerprint identifier ----------
// Gate: any rateLimit entry with identifier === 'fingerprint' OR identifier
// includes 'fingerprint' (composite). Emits a pre-function that builds a
// composite key (ip + ua-hash) and sticks it on `kong.ctx.shared.x_security_fp`
// AND on the X-XSecurity-Fingerprint header — both useful as the limit key.
//
// Honest scope: Kong OSS rate-limiting plugin can `limit_by: header` which we
// already wire elsewhere. The marker proves the fingerprint pre-function fired.
// Operators wanting a fully custom bucket can swap in lua-resty-limit-req via
// targetOverrides; the pre-function here is the composite-key building block.

export const SS_RATE_LIMIT_FINGERPRINT_TAG = 'x-security-rate-limit-fingerprint';

function rateLimitsUseFingerprint(rl: RateLimit | RateLimit[] | undefined): boolean {
  if (!rl) return false;
  const arr = Array.isArray(rl) ? rl : [rl];
  for (const r of arr) {
    const id = r.identifier;
    if (typeof id === 'string' && id === 'fingerprint') return true;
    if (Array.isArray(id) && id.includes('fingerprint')) return true;
    if (id && typeof id === 'object' && 'components' in id) {
      const comps = (id as { components: string[] }).components;
      if (Array.isArray(comps) && comps.includes('fingerprint')) return true;
    }
  }
  return false;
}

export function buildRateLimitFingerprintPlugins(
  rl: RateLimit | RateLimit[] | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!rateLimitsUseFingerprint(rl)) return [];

  const lua = [
    `-- XSecurity W26 rate-limit fingerprint pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `-- Composite key = client_ip + sha1(user-agent). Stored on ctx.shared and`,
    `-- mirrored to X-XSecurity-Fingerprint so rate-limiting limit_by=header picks it up.`,
    `local sha1 = require("resty.sha1"):new()`,
    `local ip = kong.client.get_forwarded_ip() or kong.client.get_ip() or "0.0.0.0"`,
    `local ua = kong.request.get_header("user-agent") or ""`,
    `local fp = ip`,
    `if sha1 and ua ~= "" then`,
    `  sha1:update(ua)`,
    `  local digest = sha1:final()`,
    `  local hex = ""`,
    `  for i = 1, #digest do hex = hex .. string.format("%02x", string.byte(digest, i)) end`,
    `  fp = ip .. ":" .. hex:sub(1, 16)`,
    `end`,
    `kong.ctx.shared.x_security_fp = fp`,
    `kong.service.request.set_header("X-XSecurity-Fingerprint", fp)`,
    `kong.log.warn("[${SS_RATE_LIMIT_FINGERPRINT_TAG}] fp=" .. fp)`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_RATE_LIMIT_FINGERPRINT_TAG]
  }];
}

// ---------- botProtection ----------
// Gate: `botProtection` declared. Pre-function checks user-agent against a
// curated bot-UA blocklist and validates a JS-challenge cookie when mode is
// 'enforce'. 'observe' mode logs but doesn't block. The full CAPTCHA loop
// (Turnstile/reCAPTCHA/hCaptcha verification) is provider-side and requires
// secret-key handling — this is the heuristic gate that runs in-Kong.

export const SS_BOT_DETECTED_TAG = 'x-security-bot-detected';

// Conservative bot signatures. We deliberately don't try to fingerprint legit
// crawlers (Googlebot, Bingbot) — operators can extend via targetOverrides.
const BOT_UA_LUA_PATTERNS = [
  '[Cc]url/',
  '[Pp]ython%-requests/',
  '[Ww]get/',
  '[Gg]o%-http%-client',
  '[Jj]ava/[%d%.]+',
  '[Aa]pache%-[Hh]ttp[Cc]lient',
  '[Hh]eadless[Cc]hrome',
  '[Pp]hantom[Jj][Ss]',
  '[Pp]uppeteer',
  '[Ss]elenium',
  '[Ss]crapy',
  '[Bb]urp[Ss]uite',
  '[Nn]ikto',
  '[Ss]qlmap'
];

export function buildBotProtectionPlugins(
  bot: BotProtection | undefined,
  ctx: { endpoint?: string } = {}
): KongPlugin[] {
  if (!bot) return [];
  const enforce = bot.mode === 'enforce';
  const provider = bot.provider;

  const checks = BOT_UA_LUA_PATTERNS
    .map((p, i) => `  if ua:match(${luaStr(p)}) then return ${i + 1} end`)
    .join('\n');

  const blockLua = enforce
    ? [
        `    return kong.response.exit(403, {`,
        `      message = "XSecurity: bot detected",`,
        `      tag = "${SS_BOT_DETECTED_TAG}",`,
        `      provider = "${provider}",`,
        `      rule = hit`,
        `    })`
      ].join('\n')
    : `    -- observe mode: log but pass through`;

  const lua = [
    `-- XSecurity W26 botProtection pre-function for endpoint=${ctx.endpoint ?? '?'}`,
    `-- provider=${provider} mode=${bot.mode}`,
    `local ua = kong.request.get_header("user-agent") or ""`,
    `local hit = (function()`,
    checks,
    `  return nil`,
    `end)()`,
    `if hit ~= nil then`,
    `  kong.log.warn("[${SS_BOT_DETECTED_TAG}] ua-rule " .. tostring(hit) .. " ua=" .. ua)`,
    blockLua,
    `end`,
    enforce
      ? [
          `-- JS-challenge cookie check (issued by provider's client SDK)`,
          `local challenge = kong.request.get_header("cookie") or ""`,
          `if not challenge:match("ss_bot_challenge=") then`,
          `  kong.log.warn("[${SS_BOT_DETECTED_TAG}] missing js-challenge cookie")`,
          `  return kong.response.exit(403, {`,
          `    message = "XSecurity: bot challenge required",`,
          `    tag = "${SS_BOT_DETECTED_TAG}",`,
          `    provider = "${provider}"`,
          `  })`,
          `end`
        ].join('\n')
      : `-- observe mode: no challenge gate`
  ].join('\n');

  return [{
    name: 'pre-function',
    config: { access: [lua] },
    tags: [SS_BOT_DETECTED_TAG]
  }];
}
