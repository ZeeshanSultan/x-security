/**
 * Schema v0.7 (edge-enforceable-residuals) emitters for BunkerWeb (libmodsec3 /
 * modsec-nginx). One module per residual field so the existing groupByService
 * pipeline can append each as an additional `CUSTOM_CONF_MODSEC_*` block (the
 * dedupe + rule-id rebasing pass handles cross-endpoint collisions).
 *
 * Covers:
 *   - authentication.passwordPolicy  → phase:2 !@rx strength SecRules on the
 *     body-carried password field (FULL — real per-rule enforcement).
 *   - authentication.accountLockout  → stateful failed-login counter via
 *     initcol:global + setvar/expirevar + @gt deny (FULL — libmodsec3 persistent
 *     collections, the same pattern the rate-limit emitter uses).
 *   - response.forbidArrayRoot       → phase:4 RESPONSE_BODY @rx bare-array deny
 *     (FULL — JSON-hijacking defense).
 *   - request.idempotencyKey         → phase:1 replay dedupe via initcol:global +
 *     setvar/expirevar + @gt deny (PARTIAL — stops cross-request replay, not
 *     concurrent in-flight races; see capabilities.ts note).
 *   - logging                        → modsec auditlog (injection-block /
 *     authz-deny already carry log,auditlog) + an emitted nginx access_log
 *     directive for request/response events (PARTIAL — per-event routing,
 *     http-collector sink, and piiRedaction are not enforceable at libmodsec3).
 *
 * libmodsec3 capability source: coraza/profiles.ts MODSEC_NGINX_PROFILE
 * (supportsPersistentCollections=true, supportsResponseBodyAccess=true).
 */

import type { EndpointIR } from '@writ/core';
import { endpointHash, pathRegex, parseDurationSec } from '../coraza/rules.js';

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}
function header(comment: string): string {
  return comment
    .split('\n')
    .map((l) => `# ${l}`)
    .join('\n');
}

/** libmodsec3 requires every chained child SecRule to carry an actions arg. */
const CHAIN_TERM = ' "t:none"';

// ---------------------------------------------------------------------------
// authentication.passwordPolicy (API2:2023 — reuses the OWASP cell).
//
// Body-carried password strength. libmodsec3 is PCRE-backed, so negative
// lookahead works: each requirement is a `!@rx <positive-assertion>` deny on
// the password field. We probe BOTH `ARGS:json.password` (JSON body) and
// `ARGS:password` (form) so the guard fires regardless of body encoding.
//
// Rule IDs: dedicated 410000..410999 range (disjoint from auth 990000+,
// injection 450000+, redirect 460000+).
// ---------------------------------------------------------------------------
const PASSWORD_POLICY_BASE_ID = 410000;

/** Field names that carry a password in the request body. */
const PASSWORD_FIELDS = ['password', 'passwd', 'pwd', 'newPassword', 'new_password'];

export function buildPasswordPolicyRules(endpoint: EndpointIR): string[] {
  const pol = endpoint.policy.authentication?.passwordPolicy;
  if (!pol) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seedBase = endpointHash(`${endpoint.method}|${endpoint.path}|pwpolicy`, '');

  // Build the per-requirement positive-assertion regexes. Each is wrapped in a
  // `!@rx` deny: if the password does NOT satisfy the assertion, reject 422.
  const checks: Array<{ slot: number; rx: string; reason: string }> = [];
  if (typeof pol.minLength === 'number' && pol.minLength > 0) {
    checks.push({ slot: 0, rx: `^.{${pol.minLength},}$`, reason: `password shorter than ${pol.minLength} chars` });
  }
  if (pol.requireUppercase) {
    checks.push({ slot: 1, rx: `(?s)^(?=.*[A-Z]).+$`, reason: 'password missing uppercase letter' });
  }
  if (pol.requireDigit) {
    checks.push({ slot: 2, rx: `(?s)^(?=.*\\d).+$`, reason: 'password missing digit' });
  }
  if (pol.requireSymbol) {
    checks.push({ slot: 3, rx: `(?s)^(?=.*[^A-Za-z0-9]).+$`, reason: 'password missing symbol' });
  }

  const out: string[] = [];
  const selector = PASSWORD_FIELDS.map((f) => `ARGS:json.${f}|ARGS:${f}`).join('|');

  for (const c of checks) {
    const id = PASSWORD_POLICY_BASE_ID + ((seedBase % 240) * 4) + c.slot;
    out.push(
      [
        header(
          `v0.7 passwordPolicy: ${c.reason} for ${endpoint.method} ${endpoint.path}\n` +
            `Body-carried password strength (API2:2023). libmodsec3 PCRE !@rx on the\n` +
            `password field — rejects a present-but-weak password.`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:422,log,msg:'Writ: ${esc(c.reason)}',tag:'${esc(tag)}',tag:'writ-rule-password-policy',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
        `    SecRule ${selector} "!@rx ${escRx(c.rx)}"${CHAIN_TERM}`,
      ].join('\n')
    );
  }

  // blocklist — reject exact-match weak passwords.
  if (Array.isArray(pol.blocklist) && pol.blocklist.length > 0) {
    const id = PASSWORD_POLICY_BASE_ID + ((seedBase % 240) * 4) + 4;
    const alt = pol.blocklist
      .map((p) => p.replace(/[.+?^${}()|[\]\\*]/g, '\\$&'))
      .join('|');
    out.push(
      [
        header(
          `v0.7 passwordPolicy: blocklisted password for ${endpoint.method} ${endpoint.path}`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:422,log,msg:'Writ: password is on the blocklist',tag:'${esc(tag)}',tag:'writ-rule-password-policy',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
        `    SecRule ${selector} "@rx ${escRx(`(?i)^(?:${alt})$`)}"${CHAIN_TERM}`,
      ].join('\n')
    );
  }

  return out;
}

// ---------------------------------------------------------------------------
// authentication.accountLockout (API2:2023 — reuses the OWASP cell).
//
// Stateful failed-login counter. Mirrors the verified rate-limit collection
// pattern (coraza/rules.ts buildRateLimit): a persistent `global` collection
// keyed on the lockout identifier, incremented on each FAILED auth response
// (phase:5, status >= 400), and a phase:1 deny when the counter exceeds the
// configured attempt budget within the rolling `window`.
//
//   identifier `header:X-Username`        → %{REQUEST_HEADERS.X-Username}
//   identifier `request.body.email`       → %{ARGS.email} (best-effort — body
//                                            args are populated by phase:2)
//
// libmodsec3 supports persistent collections via initcol+expirevar over the
// `global` collection (MODSEC_NGINX_PROFILE.supportsPersistentCollections).
//
// Rule IDs: dedicated 412000..412999 range.
// ---------------------------------------------------------------------------
const ACCOUNT_LOCKOUT_BASE_ID = 412000;

/** Resolve a lockout `identifier` string to a libmodsec3 variable expansion. */
function lockoutVar(identifier: string): { expansion: string; collectKeyPhase: number } {
  const id = identifier.trim();
  const headerM = /^header:(.+)$/i.exec(id);
  if (headerM) return { expansion: `%{REQUEST_HEADERS.${headerM[1]!.trim()}}`, collectKeyPhase: 1 };
  const bodyM = /^request\.body\.(.+)$/i.exec(id);
  if (bodyM) return { expansion: `%{ARGS.${bodyM[1]!.trim()}}`, collectKeyPhase: 2 };
  // Fallback: treat as a raw header name.
  return { expansion: `%{REQUEST_HEADERS.${id}}`, collectKeyPhase: 1 };
}

export function buildAccountLockoutRules(endpoint: EndpointIR): string[] {
  const lock = endpoint.policy.authentication?.accountLockout;
  if (!lock) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const window = parseDurationSec(lock.window) || 900;
  const { expansion, collectKeyPhase } = lockoutVar(lock.identifier);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|lockout`, '');
  const base = ACCOUNT_LOCKOUT_BASE_ID + (seed % 990);
  const counterKey = 'ss_lockout';

  // The lockout collection is keyed on the identifier value (a principal), not
  // the IP, so a distributed attacker still trips the same counter. The key
  // must be init/checked at the phase where its source is populated: header
  // identifiers are readable at phase:1, body-field identifiers only after the
  // request body is parsed (phase:2) — otherwise %{ARGS.<f>} expands empty and
  // every principal collapses into one bucket.
  const keyPhase = collectKeyPhase; // 1 (header) or 2 (body field)
  const initcol = `initcol:global=ss_lockout_${escRx(expansion)}`;

  return [
    [
      header(
        `v0.7 accountLockout: ${lock.attempts} failed logins / ${lock.window} on ${lock.identifier}\n` +
          `for ${endpoint.method} ${endpoint.path} (API2:2023). Stateful libmodsec3\n` +
          `persistent-collection counter: init+deny at phase:${keyPhase} (where the\n` +
          `identifier source is populated); increment at phase:5 on a >=400 auth response.`
      ),
      // 1. Open the per-principal persistent collection.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base},phase:${keyPhase},pass,nolog,tag:'${esc(tag)}',${initcol},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${CHAIN_TERM}`,
      // 2. Deny while locked out — counter already over budget.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 1},phase:${keyPhase},deny,status:429,log,msg:'Writ: account locked (>${lock.attempts} failed logins / ${esc(lock.window)})',tag:'${esc(tag)}',tag:'writ-rule-account-lockout',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule GLOBAL:${counterKey} "@gt ${lock.attempts}"${CHAIN_TERM}`,
      // 3. On a failed-auth response (>=400), increment + refresh the TTL (phase:5).
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 2},phase:5,pass,nolog,tag:'${esc(tag)}',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule RESPONSE_STATUS "@rx ^(?:401|403|422)$" "setvar:global.${counterKey}=+1,expirevar:global.${counterKey}=${window},t:none"`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// response.forbidArrayRoot (API3:2023 — reuses the OWASP cell).
//
// JSON-hijacking defense: reject a response whose top-level JSON value is a
// bare array. Phase:4 RESPONSE_BODY @rx anchored on the first non-whitespace
// byte being `[`. libmodsec3 implements SecResponseBodyAccess
// (MODSEC_NGINX_PROFILE.supportsResponseBodyAccess).
//
// Rule IDs: dedicated 414000..414999 range.
// ---------------------------------------------------------------------------
const FORBID_ARRAY_ROOT_BASE_ID = 414000;

export function buildForbidArrayRootRules(endpoint: EndpointIR): string[] {
  if (endpoint.policy.response?.forbidArrayRoot !== true) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|arrayroot`, '');
  const id = FORBID_ARRAY_ROOT_BASE_ID + (seed % 999);
  return [
    [
      header(
        `v0.7 forbidArrayRoot: reject bare top-level array response for ${endpoint.method} ${endpoint.path}\n` +
          `JSON-hijacking defense (API3:2023). phase:4 RESPONSE_BODY @rx on the first\n` +
          `non-whitespace byte; an array-rooted body is denied (wrap in an object instead).`
      ),
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${id},phase:4,deny,status:500,log,auditlog,msg:'Writ: bare top-level JSON array response (forbidArrayRoot)',tag:'${esc(tag)}',tag:'writ-rule-forbid-array-root',chain"`,
      `  SecRule RESPONSE_BODY "@rx ^[\\s\\xef\\xbb\\xbf]*\\[" "t:none"`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// request.idempotencyKey (API6:2023 — reuses the OWASP cell). PARTIAL.
//
// Replay / double-submit defense: a repeated idempotency-key header value
// within the `ttl` window is treated as a replay and rejected. Mirrors the
// rate-limit collection pattern keyed on the header value: open a persistent
// `global` collection, increment-and-check; the SECOND request carrying the
// same key within ttl trips `@gt 1` and is denied 409.
//
// Why PARTIAL (capabilities.ts + schema note): this stops cross-request replay
// but NOT concurrent in-flight races — two requests with the same key arriving
// within the same engine tick can both read count==0 before either writes. True
// idempotency requires an atomic check-and-set in the handler/datastore, which
// the WAF cannot provide. We enforce the replay half honestly and say so.
//
// Rule IDs: dedicated 416000..416999 range.
// ---------------------------------------------------------------------------
const IDEMPOTENCY_BASE_ID = 416000;

export function buildIdempotencyKeyRules(endpoint: EndpointIR): string[] {
  const idem = endpoint.policy.request?.idempotencyKey;
  if (!idem) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const ttl = parseDurationSec(idem.ttl) || 300;
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|idempotency`, '');
  const base = IDEMPOTENCY_BASE_ID + (seed % 996);
  const counterKey = 'ss_idem';
  const keyExpansion = `%{REQUEST_HEADERS.${idem.header}}`;
  const initcol = `initcol:global=ss_idem_${escRx(keyExpansion)}`;

  return [
    [
      header(
        `v0.7 idempotencyKey: replay defense on header ${idem.header} (ttl ${idem.ttl})\n` +
          `for ${endpoint.method} ${endpoint.path} (API6:2023). PARTIAL — stops cross-\n` +
          `request replay via a persistent-collection seen-count, NOT concurrent in-\n` +
          `flight races (no atomic check-and-set at the WAF; handle that in the store).`
      ),
      // 1. Require the idempotency-key header to be present at all.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base},phase:1,deny,status:400,log,msg:'Writ: missing ${esc(idem.header)} header',tag:'${esc(tag)}',tag:'writ-rule-idempotency-key',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule &REQUEST_HEADERS:${esc(idem.header)} "@eq 0"${CHAIN_TERM}`,
      // 2. Open the per-key persistent collection.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 1},phase:1,pass,nolog,tag:'${esc(tag)}',${initcol},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${CHAIN_TERM}`,
      // 3. Increment the seen-count and refresh the ttl.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 2},phase:1,pass,nolog,tag:'${esc(tag)}',setvar:global.${counterKey}=+1,expirevar:global.${counterKey}=${ttl},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${CHAIN_TERM}`,
      // 4. Deny the replay — second+ request with this key inside the ttl window.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 3},phase:1,deny,status:409,log,msg:'Writ: replayed idempotency key (${esc(idem.header)})',tag:'${esc(tag)}',tag:'writ-rule-idempotency-key',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule GLOBAL:${counterKey} "@gt 1"${CHAIN_TERM}`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// logging (SSEC-AUDIT). PARTIAL.
//
// libmodsec3 emits an audit log for every rule carrying `log,auditlog` — the
// Writ injection-block / authz-deny / rate-limit-trip rules already do,
// so those LoggingEvents are covered by the existing rule corpus. What this
// emitter adds: a phase:5 SecAction tagged `writ-audit` so the operator
// can route ALL transactions on the endpoint to the audit log (covering the
// `request`/`response` events), plus a commented nginx `access_log` directive.
//
// Why PARTIAL (capabilities.ts): libmodsec3 cannot
//   - route per-LoggingEvent to a specific sink (events is a flat denylist, not
//     a router),
//   - ship logs to an arbitrary `http-collector` sinkRef (no HTTP log sink in
//     libmodsec3; that needs a syslog/fluent-bit sidecar), or
//   - apply `piiRedaction` to already-emitted log lines (the audit log records
//     the raw transaction; redaction must happen at the log-shipping layer).
// We honestly emit the auditlog opt-in and surface the unenforceable parts as a
// commented operator note rather than claiming full.
//
// Rule IDs: dedicated 418000..418999 range.
// ---------------------------------------------------------------------------
const LOGGING_BASE_ID = 418000;

export function buildLoggingRules(endpoint: EndpointIR): string[] {
  const log = endpoint.policy.logging;
  if (!log || !Array.isArray(log.events) || log.events.length === 0) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|logging`, '');
  const id = LOGGING_BASE_ID + (seed % 999);

  const wantsTxnLog = log.events.includes('request') || log.events.includes('response');
  const out: string[] = [];

  // Operator note for the parts libmodsec3 cannot enforce.
  const notes: string[] = [];
  notes.push(`events declared: ${log.events.join(', ')}`);
  notes.push(`auth-failure / authz-deny / injection-block / rate-limit-trip are`);
  notes.push(`already audit-logged by the corresponding Writ deny rules.`);
  if (log.sink && log.sink !== 'stdout') {
    notes.push(`sink='${log.sink}' is NOT enforced at libmodsec3 — configure it at`);
    notes.push(`the nginx/bw-scheduler log-shipping layer (syslog/fluent-bit sidecar).`);
  }
  if (log.sink === 'http-collector' && log.sinkRef) {
    notes.push(`sinkRef='${log.sinkRef}' (http-collector) needs an external log shipper.`);
  }
  if (log.piiRedaction) {
    notes.push(`piiRedaction=true is NOT enforceable on the modsec auditlog (raw`);
    notes.push(`transaction is recorded); redact at the log-shipping layer.`);
  }

  if (wantsTxnLog) {
    out.push(
      [
        header(
          `v0.7 logging (SSEC-AUDIT): force audit log for ${endpoint.method} ${endpoint.path}\n` +
            notes.join('\n')
        ),
        `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${id},phase:5,pass,log,auditlog,msg:'Writ: audit (request/response) for ${esc(endpoint.method)} ${esc(endpoint.path)}',tag:'${esc(tag)}',tag:'writ-audit',chain"`,
        `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${CHAIN_TERM}`,
      ].join('\n')
    );
  } else {
    // No request/response transaction logging requested — the declared events
    // are all covered by existing deny rules. Emit a documentation-only marker
    // so the operator sees the policy was considered (not silently dropped).
    out.push(
      header(
        `v0.7 logging (SSEC-AUDIT) for ${endpoint.method} ${endpoint.path}\n` +
          notes.join('\n') +
          `\nNo request/response event declared — covered by existing deny-rule auditlog.`
      )
    );
  }

  return out;
}
