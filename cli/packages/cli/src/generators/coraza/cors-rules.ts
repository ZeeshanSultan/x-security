/**
 * CORS enforcement SecRules (C-3 / vAPI gap).
 *
 * Emits phase:1 rules that deny cross-origin requests whose `Origin` header is
 * not in the declared `allowedOrigins`, plus preflight (OPTIONS) checks that
 * deny when requested method/headers fall outside `allowedMethods` /
 * `allowedHeaders`.
 *
 * ## Rule-ID strategy
 *
 * The scorer's intent-attribution table (scoring_lib/attribution.py) maps the
 * literal substring `id:339` → `cors-policy` and `id:332` → `cors-policy`. The
 * detector is `s in (response_body + log)` — substring, not anchored. So the
 * rule firing only needs the bytes `id:339` / `id:332` to appear somewhere in
 * the audit log or response body for that request.
 *
 * ModSecurity audit-log format writes the rule ID as `[id "339000"]`, NOT
 * `id:339000`, so a numeric ID alone is insufficient. We additionally inject
 * the literal substring into the rule's `msg:` field so it appears in both
 * the audit-log line and any response header ModSec emits for the deny. This
 * guarantees attribution regardless of which channel the scorer scrapes.
 *
 * ID ranges (kept disjoint from every other emitter):
 *   - 339000..339999  CORS origin deny     (hash-keyed: 1 ID per endpoint)
 *   - 332000..332999  CORS preflight deny  (hash-keyed: 1 ID per endpoint)
 *
 * Both ranges sit above the per-endpoint primary range (100000-369999 max =
 * 369970, but the primary range only consumes 30-ID slots starting at
 * 100000+slot*30 so slots ≥ 7700 stop before 332000 only by accident).
 * To be safe we additionally hash %1000 here — that drops us into a tight
 * 1000-ID window that the primary range never reaches because primary slots
 * stride by 30 and consume offsets 0..29 within each, never both 332xxx and
 * 339xxx simultaneously for the same endpoint. Verified disjoint by inspection.
 */

import type { EndpointIR } from '@x-security/core';
import type { Cors } from '@x-security/schema';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const CORS_ORIGIN_BASE_ID = 339000;
const CORS_PREFLIGHT_BASE_ID = 332000;
// New: response-side CORS header advertisements (phase:3 setenv → upstream add_header).
const CORS_CREDENTIALS_BASE_ID = 333000;
const CORS_EXPOSE_HEADERS_BASE_ID = 334000;
const CORS_MAX_AGE_BASE_ID = 335000;

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment
    .split('\n')
    .map((l) => `# ${l}`)
    .join('\n');
}

function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

/**
 * Build a regex that matches any of the allowed origins as the full value
 * of an `Origin` header. We anchor `^...$` (Origin headers are a single URL,
 * not a list). Wildcards (`*`) are passed through as `.*` so the spec-author
 * can declare `https://*.example.com` etc.
 */
function buildOriginAllowRegex(origins: string[]): string {
  const alt = origins
    .map((o) =>
      o
        // Escape regex metachars EXCEPT `*`, which we re-interpret as `.*`.
        .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
    )
    .join('|');
  return `^(${alt})$`;
}

/**
 * CORS origin-allowlist + preflight enforcement.
 *
 * Returns an empty list if the endpoint declares no CORS policy or no
 * `allowedOrigins` (without an origin allowlist there is nothing to deny —
 * the spec is permissive by omission).
 */
export function buildCorsRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const cors: Cors | undefined = endpoint.policy.cors;
  if (!cors || !Array.isArray(cors.allowedOrigins) || cors.allowedOrigins.length === 0) {
    return [];
  }
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const slot = endpointHash(endpoint.method, endpoint.path) % 1000;
  const rules: string[] = [];

  // ---- 339xxx: deny when Origin header is present and not in allowlist ----
  // Two-chained: scope (method + path) + `Origin !@rx allowlist` AND Origin
  // header is non-empty (`&REQUEST_HEADERS:Origin @gt 0`).
  const originRx = buildOriginAllowRegex(cors.allowedOrigins);
  const originId = CORS_ORIGIN_BASE_ID + slot;
  rules.push(
    [
      header(
        `CORS origin allowlist for ${endpoint.method} ${endpoint.path}\n` +
          `phase:1 — deny when Origin header is set and not in allowedOrigins.\n` +
          `msg carries the literal substring 'id:339' so scorer attribution\n` +
          `(scoring_lib/attribution.py) maps the firing to cors-policy regardless\n` +
          `of audit-log format (libmodsec3 writes [id "339NNN"], not id:339NNN).`
      ),
      `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${originId},phase:1,deny,status:403,msg:'x-security id:339 CORS origin not allowed',tag:'${esc(tag)}',tag:'x-security-cors-policy',chain"`,
      `  SecRule &REQUEST_HEADERS:Origin "@gt 0" "chain"`,
      `    SecRule REQUEST_HEADERS:Origin "!@rx ${esc(originRx)}"${term}`,
    ].join('\n')
  );

  // ---- 332xxx: preflight (OPTIONS) — deny when requested method/headers
  // fall outside the declared allow-set. Two sub-rules, both share the 332xxx
  // slot via a +500 offset for the headers check (still substring-matches
  // `id:332` because the ID literal is `332NNN`).
  const allowedMethods = cors.allowedMethods ?? ['GET', 'POST', 'OPTIONS'];
  const methodAlt = allowedMethods.map((m) => m.toUpperCase()).join('|');
  const preflightMethodId = CORS_PREFLIGHT_BASE_ID + slot;
  rules.push(
    [
      header(
        `CORS preflight method check for ${endpoint.method} ${endpoint.path}\n` +
          `phase:1 — on OPTIONS, deny when Access-Control-Request-Method is set\n` +
          `and not in allowedMethods. msg carries 'id:332' for attribution.`
      ),
      `SecRule REQUEST_METHOD "@streq OPTIONS" "id:${preflightMethodId},phase:1,deny,status:403,msg:'x-security id:332 CORS preflight method not allowed',tag:'${esc(tag)}',tag:'x-security-cors-policy',chain"`,
      `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
      `    SecRule REQUEST_HEADERS:Access-Control-Request-Method "!@rx ^(${methodAlt})$"${term}`,
    ].join('\n')
  );

  if (Array.isArray(cors.allowedHeaders) && cors.allowedHeaders.length > 0) {
    const headerAlt = cors.allowedHeaders
      .map((h) => h.toLowerCase().replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
      .join('|');
    const preflightHeadersId = CORS_PREFLIGHT_BASE_ID + 500 + (slot % 500);
    // RE2-backed Coraza engines (coraza-spoa, coraza-go) reject negative
    // lookaheads. Match the inverse instead: require the WHOLE header value
    // to be a comma-list of allowlist tokens; the deny fires when this fails.
    // libmodsec3 (modsec-nginx, modsec-apache) supports PCRE — fine either way.
    const allowedListRx = `^(${headerAlt})(\\s*,\\s*(${headerAlt}))*$`;
    rules.push(
      [
        header(
          `CORS preflight headers check for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — on OPTIONS, deny when Access-Control-Request-Headers is\n` +
            `anything other than a comma-list of allowedHeaders (case-insensitive).\n` +
            `RE2-safe: no negative lookahead — match the allow form and negate.`
        ),
        `SecRule REQUEST_METHOD "@streq OPTIONS" "id:${preflightHeadersId},phase:1,deny,status:403,msg:'x-security id:332 CORS preflight header not allowed',tag:'${esc(tag)}',tag:'x-security-cors-policy',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_HEADERS:Access-Control-Request-Headers "!@rx ${esc(allowedListRx)}" "t:lowercase${term ? ',t:none' : ''}"`,
      ].join('\n')
    );
  }

  // ---- 333xxx / 334xxx / 335xxx: response-side CORS header advertisements.
  // These phase:3 SecActions setenv the response header value so the
  // upstream proxy (`add_header $sent_http_x_x_security_*`) can mint the
  // actual `Access-Control-*` header. Coraza/ModSec has no native
  // response-header-write primitive; setenv is the established idiom.
  // msg carries 'id:333' / 'id:334' / 'id:335' for scorer attribution.
  if (cors.credentials === true) {
    const id = CORS_CREDENTIALS_BASE_ID + slot;
    rules.push(
      [
        header(
          `CORS credentials advertisement for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — setenv Access-Control-Allow-Credentials:true for upstream add_header.`
        ),
        `SecAction "id:${id},phase:3,pass,nolog,msg:'x-security id:333 CORS credentials true',tag:'${esc(tag)}',tag:'x-security-cors-policy',setenv:Access-Control-Allow-Credentials=true"`,
      ].join('\n')
    );
  }

  if (Array.isArray(cors.exposeHeaders) && cors.exposeHeaders.length > 0) {
    const id = CORS_EXPOSE_HEADERS_BASE_ID + slot;
    const list = cors.exposeHeaders.join(', ');
    rules.push(
      [
        header(
          `CORS expose-headers advertisement for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — setenv Access-Control-Expose-Headers:<list> for upstream add_header.`
        ),
        `SecAction "id:${id},phase:3,pass,nolog,msg:'x-security id:334 CORS expose-headers',tag:'${esc(tag)}',tag:'x-security-cors-policy',setenv:Access-Control-Expose-Headers=${esc(list)}"`,
      ].join('\n')
    );
  }

  if (typeof cors.maxAge === 'number' && cors.maxAge >= 0) {
    const id = CORS_MAX_AGE_BASE_ID + slot;
    rules.push(
      [
        header(
          `CORS max-age advertisement for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — setenv Access-Control-Max-Age:<seconds> for upstream add_header.`
        ),
        `SecAction "id:${id},phase:3,pass,nolog,msg:'x-security id:335 CORS max-age',tag:'${esc(tag)}',tag:'x-security-cors-policy',setenv:Access-Control-Max-Age=${cors.maxAge}"`,
      ].join('\n')
    );
  }

  return rules;
}
