/**
 * Schema v0.7 (edge-enforceable-residuals) emitters for the Coraza/ModSecurity
 * generator. Native ModSecurity-equivalent of the bunkerweb v07-rules.ts pass —
 * every status here is gated on the *active CorazaEngineProfile* so a profile
 * that can't run a mechanism reports 'partial'/'unsupported' honestly (Rule D-1:
 * 'full' ONLY where a real enforcing SecRule is emitted).
 *
 * Covers (XSecurityPolicy fields):
 *   - authentication.passwordPolicy  → phase:2 `!@rx` strength SecRules on the
 *     body-carried password field + blocklist `@rx` deny (FULL on all profiles —
 *     plain @rx, no engine-specific capability needed).
 *   - authentication.accountLockout  → stateful failed-login counter via
 *     initcol/setvar/expirevar + @gt deny. FULL only where the profile supports
 *     a persistent, non-TX collection (supportsPersistentCollections &&
 *     legalCollections has a usable named collection, i.e. 'global'). On the
 *     TX-only coraza-go/spoa engines the counter can't survive across requests,
 *     so it is SKIPPED with a loud warning (matrix → partial).
 *   - response.forbidArrayRoot       → phase:4 RESPONSE_BODY `@rx ^\s*\[` deny.
 *     FULL only where supportsResponseBodyAccess; else SKIPPED + warned.
 *   - request.idempotencyKey         → require the header + stateful replay
 *     dedupe via a persistent seen-counter. PARTIAL (stops cross-request replay,
 *     not concurrent in-flight races). The header-presence check is FULL on every
 *     profile; the stateful dedupe half needs the same persistent-collection
 *     capability as accountLockout (skipped + warned where unavailable).
 *   - logging                        → SecAuditLog opt-in (SecAuditLogParts /
 *     per-event log actions). PARTIAL — per-event routing, arbitrary sinks, and
 *     piiRedaction-on-emitted-lines are not enforceable at the WAF; surfaced as
 *     an operator note rather than faked.
 *
 * Helpers (esc/escRx/header/chainTerm) are self-contained, mirroring
 * v08-residual-rules.ts, so this module doesn't reach into rules.ts internals.
 *
 * ID ranges (disjoint from every other x-security range — per-endpoint primary
 * 100000-369999, body-allowlist 400000-408999, response-inspect 420000-428999,
 * SQLi 430000+, SSRF 980000+, CSRF 272000-274999, serialize 286000-287999,
 * graphql 288000-289999):
 *   passwordPolicy   411000..411999
 *   accountLockout   412000..412999
 *   forbidArrayRoot  414000..414999
 *   idempotencyKey   416000..416999
 *   logging          418000..418999
 */

import type { EndpointIR } from '@x-security/core';
import {
  CORAZA_GO_PROFILE,
  type CorazaEngineProfile,
  type EngineWarning,
} from './profiles.js';
import { endpointHash, pathRegex, parseDurationSec } from './rules.js';

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}
function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

/**
 * libmodsecurity3 requires an actions arg on every chained child SecRule; the
 * Coraza-Go-family engines accept a bare chained leaf. Mirrors the rate-limit /
 * serialize path (chainTerm in v08-residual-rules.ts): the libmodsec3 engines
 * are in `legalCollections` WITHOUT `user`, so they get `"t:none"`; coraza-go/
 * spoa (legalCollections={'tx'}) are bare.
 *
 * The distinguishing flag: libmodsec3 engines accept the named `global`
 * collection; coraza-go/spoa only `tx`. We key off that.
 */
function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('global') ? ' "t:none"' : '';
}

/**
 * Whether the engine can host a persistent, cross-request, per-key named
 * collection (the substrate accountLockout + idempotency dedupe need). True
 * only when the engine both supports persistent collections AND accepts a
 * named collection beyond TX (`global`). coraza-go/spoa honor setvar only on
 * the per-transaction TX collection, so a cross-request seen/failed counter
 * genuinely cannot live in the ruleset there.
 */
function supportsStatefulNamedCollection(profile: CorazaEngineProfile): boolean {
  return profile.supportsPersistentCollections && profile.legalCollections.has('global');
}

// ---------------------------------------------------------------------------
// authentication.passwordPolicy (API2:2023). FULL on all profiles.
//
// Body-carried password strength. Coraza & libmodsec3 are both PCRE/RE2 with
// lookahead support for the assertions we use; each requirement is a `!@rx
// <positive-assertion>` deny on the password field → 422. We probe BOTH
// `ARGS:json.password` (JSON body) and `ARGS:password` (form) so the guard
// fires regardless of body encoding.
// ---------------------------------------------------------------------------
const PASSWORD_POLICY_BASE_ID = 411000;

/** Field names that carry a password in the request body. */
const PASSWORD_FIELDS = ['password', 'passwd', 'pwd', 'newPassword', 'new_password'];

export function buildPasswordPolicyRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const pol = endpoint.policy.authentication?.passwordPolicy;
  if (!pol) return [];
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seedBase = endpointHash(endpoint.method, `${endpoint.path}|pwpolicy`);
  const term = chainTerm(profile);

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
            `Body-carried password strength (API2:2023). PCRE !@rx on the password\n` +
            `field — rejects a present-but-weak password. FULL (plain @rx).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:422,log,msg:'x-security: ${esc(c.reason)}',tag:'${esc(tag)}',tag:'x-security-rule-password-policy',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
        `    SecRule ${selector} "!@rx ${escRx(c.rx)}"${term}`,
      ].join('\n')
    );
  }

  if (Array.isArray(pol.blocklist) && pol.blocklist.length > 0) {
    const id = PASSWORD_POLICY_BASE_ID + ((seedBase % 240) * 4) + 4;
    const alt = pol.blocklist.map((p) => p.replace(/[.+?^${}()|[\]\\*]/g, '\\$&')).join('|');
    out.push(
      [
        header(`v0.7 passwordPolicy: blocklisted password for ${endpoint.method} ${endpoint.path}`),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:422,log,msg:'x-security: password is on the blocklist',tag:'${esc(tag)}',tag:'x-security-rule-password-policy',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
        `    SecRule ${selector} "@rx ${escRx(`(?i)^(?:${alt})$`)}"${term}`,
      ].join('\n')
    );
  }

  return out;
}

// ---------------------------------------------------------------------------
// authentication.accountLockout (API2:2023).
//
// Stateful failed-login counter. A persistent named collection keyed on the
// lockout identifier, incremented on each FAILED auth response (phase:5,
// status in {401,403,422}), and a deny when the counter exceeds the attempt
// budget within the rolling `window` → 429.
//
// FULL only where supportsStatefulNamedCollection(profile) (libmodsec3 engines:
// initcol:global + expirevar). On coraza-go/spoa (TX-only setvar) the counter
// cannot survive across requests, so we SKIP and warn loudly (matrix → partial)
// instead of emitting a TX-collection counter that resets every request and
// would never trip — that would be a Rule D-1 masked-quality trap.
// ---------------------------------------------------------------------------
const ACCOUNT_LOCKOUT_BASE_ID = 412000;

/** Resolve a lockout `identifier` string to a ModSecurity variable expansion. */
function lockoutVar(identifier: string): { expansion: string; keyPhase: number } {
  const id = identifier.trim();
  const headerM = /^header:(.+)$/i.exec(id);
  if (headerM) return { expansion: `%{REQUEST_HEADERS.${headerM[1]!.trim()}}`, keyPhase: 1 };
  const bodyM = /^request\.body\.(.+)$/i.exec(id);
  if (bodyM) return { expansion: `%{ARGS.${bodyM[1]!.trim()}}`, keyPhase: 2 };
  return { expansion: `%{REQUEST_HEADERS.${id}}`, keyPhase: 1 };
}

export function buildAccountLockoutRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const lock = endpoint.policy.authentication?.accountLockout;
  if (!lock) return [];
  const epId = `${endpoint.method} ${endpoint.path}`;

  if (!supportsStatefulNamedCollection(profile)) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: epId,
      reason:
        `authentication.accountLockout: ${profile.name} only honors setvar on the per-transaction TX collection — a cross-request failed-login counter cannot live in the ruleset. Move lockout to HAProxy stick-tables / the upstream auth service. (partial)`,
      detail: { capKey: 'authentication.accountLockout', need: 'persistent-named-collection' },
    });
    return [];
  }

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const window = parseDurationSec(lock.window) || 900;
  const { expansion, keyPhase } = lockoutVar(lock.identifier);
  const seed = endpointHash(endpoint.method, `${endpoint.path}|lockout`);
  const base = ACCOUNT_LOCKOUT_BASE_ID + (seed % 990);
  const counterKey = 'ss_lockout';
  const term = chainTerm(profile);
  const initcol = `initcol:global=ss_lockout_${escRx(expansion)}`;

  return [
    [
      header(
        `v0.7 accountLockout: ${lock.attempts} failed logins / ${lock.window} on ${lock.identifier}\n` +
          `for ${endpoint.method} ${endpoint.path} (API2:2023). Stateful persistent-\n` +
          `collection counter: init+deny at phase:${keyPhase} (where the identifier source is\n` +
          `populated); increment at phase:5 on a >=400 auth response. FULL on ${profile.name}.`
      ),
      // 1. Open the per-principal persistent collection.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base},phase:${keyPhase},pass,nolog,tag:'${esc(tag)}',${initcol},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${term}`,
      // 2. Deny while locked out — counter already over budget.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 1},phase:${keyPhase},deny,status:429,log,msg:'x-security: account locked (>${lock.attempts} failed logins / ${esc(lock.window)})',tag:'${esc(tag)}',tag:'x-security-rule-account-lockout',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule GLOBAL:${counterKey} "@gt ${lock.attempts}"${term}`,
      // 3. On a failed-auth response (>=400), increment + refresh the TTL (phase:5).
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 2},phase:5,pass,nolog,tag:'${esc(tag)}',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule RESPONSE_STATUS "@rx ^(?:401|403|422)$" "setvar:global.${counterKey}=+1,expirevar:global.${counterKey}=${window},t:none"`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// response.forbidArrayRoot (API3:2023).
//
// JSON-hijacking defense: reject a response whose top-level JSON value is a
// bare array. Phase:4 RESPONSE_BODY @rx anchored on the first non-whitespace
// byte being `[`. FULL only where supportsResponseBodyAccess; else SKIPPED +
// warned (no response body, no phase:4 — the honest answer is unsupported).
// ---------------------------------------------------------------------------
const FORBID_ARRAY_ROOT_BASE_ID = 414000;

export function buildForbidArrayRootRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  if (endpoint.policy.response?.forbidArrayRoot !== true) return [];
  const epId = `${endpoint.method} ${endpoint.path}`;

  if (!profile.supportsResponseBodyAccess) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: epId,
      reason:
        `response.forbidArrayRoot: ${profile.name} has no phase:4 RESPONSE_BODY access — a bare top-level JSON array cannot be inspected at the WAF. Reject array-root responses in the upstream serializer. (unsupported)`,
      detail: { capKey: 'response.forbidArrayRoot', need: 'response-body-access' },
    });
    return [];
  }

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(endpoint.method, `${endpoint.path}|arrayroot`);
  const id = FORBID_ARRAY_ROOT_BASE_ID + (seed % 999);
  const term = chainTerm(profile);
  return [
    [
      header(
        `v0.7 forbidArrayRoot: reject bare top-level array response for ${endpoint.method} ${endpoint.path}\n` +
          `JSON-hijacking defense (API3:2023). phase:4 RESPONSE_BODY @rx on the first\n` +
          `non-whitespace byte; an array-rooted body is denied (wrap in an object instead).\n` +
          `FULL on ${profile.name} (supportsResponseBodyAccess).`
      ),
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${id},phase:4,deny,status:500,log,auditlog,msg:'x-security: bare top-level JSON array response (forbidArrayRoot)',tag:'${esc(tag)}',tag:'x-security-rule-forbid-array-root',chain"`,
      `  SecRule RESPONSE_BODY "@rx ^[\\s\\xef\\xbb\\xbf]*\\["${term}`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// request.idempotencyKey (API6:2023). PARTIAL.
//
// Replay / double-submit defense. Two halves:
//   (a) require the header to be present at all → 400. FULL on every profile
//       (plain &REQUEST_HEADERS presence check, no state).
//   (b) dedupe a repeated header value within `ttl` → 409. Needs a persistent
//       per-key seen-counter (same substrate as accountLockout); emitted only
//       where supportsStatefulNamedCollection. Where unavailable we still emit
//       (a) and warn that the dedupe half was skipped.
//
// PARTIAL overall (even where (b) is emitted): stops cross-request replay but
// NOT concurrent in-flight races — two requests with the same key in the same
// engine tick can both read count==0 before either writes. True idempotency
// needs an atomic check-and-set in the handler/datastore; the WAF can't.
// ---------------------------------------------------------------------------
const IDEMPOTENCY_BASE_ID = 416000;

export function buildIdempotencyKeyRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const idem = endpoint.policy.request?.idempotencyKey;
  if (!idem) return [];
  const epId = `${endpoint.method} ${endpoint.path}`;
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const ttl = parseDurationSec(idem.ttl) || 300;
  const seed = endpointHash(endpoint.method, `${endpoint.path}|idempotency`);
  const base = IDEMPOTENCY_BASE_ID + (seed % 996);
  const counterKey = 'ss_idem';
  const term = chainTerm(profile);
  const stateful = supportsStatefulNamedCollection(profile);

  const rules: string[] = [];

  // (a) Require the idempotency-key header to be present — FULL everywhere.
  rules.push(
    [
      header(
        `v0.7 idempotencyKey: require header ${idem.header} for ${endpoint.method} ${endpoint.path}\n` +
          `(API6:2023). Header-presence check — FULL on ${profile.name}.`
      ),
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base},phase:1,deny,status:400,log,msg:'x-security: missing ${esc(idem.header)} header',tag:'${esc(tag)}',tag:'x-security-rule-idempotency-key',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule &REQUEST_HEADERS:${esc(idem.header)} "@eq 0"${term}`,
    ].join('\n')
  );

  // (b) Stateful replay dedupe — only where a persistent named collection exists.
  if (!stateful) {
    warnings?.push({
      severity: 'downgrade',
      engine: profile.name,
      endpoint: epId,
      reason:
        `request.idempotencyKey: header presence is enforced, but ${profile.name} only honors setvar on the per-transaction TX collection — the cross-request replay-dedupe counter cannot live in the ruleset. Dedupe in the upstream/store. (partial — presence only)`,
      detail: { capKey: 'request.idempotencyKey', need: 'persistent-named-collection' },
    });
    return rules;
  }

  const keyExpansion = `%{REQUEST_HEADERS.${idem.header}}`;
  const initcol = `initcol:global=ss_idem_${escRx(keyExpansion)}`;
  rules.push(
    [
      header(
        `v0.7 idempotencyKey: replay dedupe on header ${idem.header} (ttl ${idem.ttl})\n` +
          `for ${endpoint.method} ${endpoint.path} (API6:2023). PARTIAL — stops cross-\n` +
          `request replay via a persistent-collection seen-count, NOT concurrent in-\n` +
          `flight races (no atomic check-and-set at the WAF; handle that in the store).`
      ),
      // Open the per-key persistent collection.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 1},phase:1,pass,nolog,tag:'${esc(tag)}',${initcol},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${term}`,
      // Increment the seen-count and refresh the ttl.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 2},phase:1,pass,nolog,tag:'${esc(tag)}',setvar:global.${counterKey}=+1,expirevar:global.${counterKey}=${ttl},chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${term}`,
      // Deny the replay — second+ request with this key inside the ttl window.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 3},phase:1,deny,status:409,log,msg:'x-security: replayed idempotency key (${esc(idem.header)})',tag:'${esc(tag)}',tag:'x-security-rule-idempotency-key',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule GLOBAL:${counterKey} "@gt 1"${term}`,
    ].join('\n')
  );

  return rules;
}

// ---------------------------------------------------------------------------
// logging (SSEC-AUDIT). PARTIAL.
//
// ModSecurity emits an audit log for every rule carrying `log,auditlog` — the
// x-security injection-block / authz-deny / rate-limit-trip rules already do,
// so those LoggingEvents are covered. What this emitter adds: a phase:5
// SecRule tagged `x-security-audit` that forces ALL transactions on the
// endpoint into the audit log (covering the `request`/`response` events), plus
// a `ctl:auditLogParts` directive shaping what is recorded — and, when
// piiRedaction is set, a `ctl:auditLogParts=ABIFHZ` that DROPS the request/
// response body parts (C,E,F-bodies) so declared pii body fields never reach
// the audit log in the first place. That is the only honest in-WAF redaction:
// omit the bodies rather than pretend to mask individual fields.
//
// Why PARTIAL: ModSecurity cannot
//   - route per-LoggingEvent to a specific sink (events is a flat list, not a
//     router),
//   - ship logs to an arbitrary `http-collector` sinkRef (no HTTP log sink in
//     the engine; needs a syslog/fluent-bit sidecar), or
//   - field-level-mask pii while keeping the rest of the body (the audit log is
//     part-granular, not field-granular — we can only drop whole body parts).
// We emit the auditlog opt-in + the part-dropping redaction honestly and
// surface the unenforceable parts as a commented operator note.
// ---------------------------------------------------------------------------
const LOGGING_BASE_ID = 418000;

export function buildLoggingRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const log = endpoint.policy.logging;
  if (!log || !Array.isArray(log.events) || log.events.length === 0) return [];
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(endpoint.method, `${endpoint.path}|logging`);
  const id = LOGGING_BASE_ID + (seed % 999);
  const term = chainTerm(profile);

  const wantsTxnLog = log.events.includes('request') || log.events.includes('response');
  const out: string[] = [];

  const notes: string[] = [];
  notes.push(`events declared: ${log.events.join(', ')}`);
  notes.push(`auth-failure / authz-deny / injection-block / rate-limit-trip are`);
  notes.push(`already audit-logged by the corresponding x-security deny rules.`);
  if (log.sink && log.sink !== 'stdout') {
    notes.push(`sink='${log.sink}' is NOT enforced at the WAF — configure it at the`);
    notes.push(`log-shipping layer (SecAuditLogStorageDir + syslog/fluent-bit sidecar).`);
  }
  if (log.sink === 'http-collector' && log.sinkRef) {
    notes.push(`sinkRef='${log.sinkRef}' (http-collector) needs an external log shipper.`);
  }
  if (log.piiRedaction) {
    notes.push(`piiRedaction=true: enforced here by DROPPING the request/response body`);
    notes.push(`audit-log parts (ctl:auditLogParts=ABIFHZ — no C/E/G body parts), so no`);
    notes.push(`pii body field is recorded. Field-level masking (keep body, redact one`);
    notes.push(`field) is NOT possible at the WAF — the audit log is part-granular.`);
  }

  if (wantsTxnLog) {
    // When piiRedaction is on, restrict the recorded audit parts to the
    // non-body set (A=audit header, B=request headers, I=reduced request body
    // [headers only on multipart], F=response headers, H=trailer, Z=terminator)
    // — dropping C (request body), E (intended response body), G (actual
    // response body) so declared pii body fields never land in the log.
    const partsCtl = log.piiRedaction ? ',ctl:auditLogParts=ABIFHZ' : '';
    out.push(
      [
        header(
          `v0.7 logging (SSEC-AUDIT): force audit log for ${endpoint.method} ${endpoint.path}\n` +
            notes.join('\n')
        ),
        `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${id},phase:5,pass,log,auditlog,msg:'x-security: audit (request/response) for ${esc(endpoint.method)} ${esc(endpoint.path)}',tag:'${esc(tag)}',tag:'x-security-audit'${partsCtl},chain"`,
        `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${term}`,
      ].join('\n')
    );
  } else {
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
