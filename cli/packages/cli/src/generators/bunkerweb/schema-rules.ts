/**
 * Request/response schema enforcement for BunkerWeb (libmodsec3 / modsec-nginx).
 *
 * BunkerWeb runs the same libmodsecurity3 engine that the Coraza generator's
 * `modsec-nginx` profile targets: PCRE-backed (so negative lookahead and
 * arbitrary `{N,}` repetition counts are fine) and shipping the bundled JSON
 * body processor (setup.conf id:200001) plus `SecResponseBodyAccess On`. That
 * means the Coraza SecRule emitters are byte-for-byte valid here — we reuse
 * them under `MODSEC_NGINX_PROFILE` instead of re-deriving the rule shapes.
 *
 * Closes drift on:
 *   - request.schema typed constraints (minLength/maxLength/min/max/pattern/
 *     type) → phase:2 `@lt`/`@gt`/`@rx` SecRules (OWASP API8 + API6).
 *   - request.schema.allowedMimeTypes → phase:2 415 SecRule on FILES content
 *     type (completes the Content-Type allowlist beyond the response-side
 *     ALLOWED_MIME_TYPES setting).
 *   - request.denyUnknownFields / request.allowedFields → phase:2 403 SecRule
 *     rejecting body keys outside the allowlist (mass-assignment, API6).
 *   - response.schema typed constraints → phase:4 RESPONSE_BODY SecRules
 *     (data exposure, API3).
 */

import type { EndpointIR } from '@writ/core';
import {
  buildSchemaRules,
  buildBodyFieldAllowlistRules,
  buildJsonBodyProcessor,
  buildResponseInspectionRules,
  ruleBase,
  endpointHash,
  pathRegex,
} from '../coraza/rules.js';
import { MODSEC_NGINX_PROFILE } from '../coraza/profiles.js';

/**
 * Local SecRule-arg escapers. The Coraza module keeps `esc`/`escRx`/`header`
 * private, and we own only `bunkerweb/**` this wave, so we re-derive them here
 * with identical semantics (see coraza/rules.ts for the rationale on why `escRx`
 * must NOT double backslashes).
 */
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

/**
 * libmodsec3 (BunkerWeb's engine) is in `legalCollections` without `user`, so
 * the Coraza chainTerm appends `"t:none"` to the chained leaf rule. We mirror
 * that exactly to keep transforms off the chained operand (raw byte match).
 */
const CHAIN_TERM = ' "t:none"';

/**
 * Typed request.schema constraint SecRules (phase:2, @lt/@gt/@rx). Reuses the
 * Coraza `buildSchemaRules` emitter under the libmodsec3 profile BunkerWeb runs.
 */
export function buildRequestSchemaRules(endpoint: EndpointIR): string[] {
  const schema = endpoint.policy.request?.schema;
  if (!schema || Object.keys(schema).length === 0) return [];
  const ctx = {
    endpoint,
    base: ruleBase(endpoint),
    tag: `writ/${endpoint.method} ${endpoint.path}`,
  };
  return buildSchemaRules(ctx, schema, MODSEC_NGINX_PROFILE);
}

/**
 * The JSON body processor `ctl` rule that ARGS-based schema rules and the
 * ARGS_NAMES body-key allowlist depend on. On libmodsec3 the bundled setup.conf
 * already enables it, so this is redundant-but-harmless (the Coraza emitter
 * documents that explicitly); we still emit it so the dependent rules'
 * precondition is self-contained in the generated file.
 *
 * Only emitted when the endpoint actually has a request.schema or a
 * denyUnknownFields/allowedFields allowlist — a JSON content-type with no body
 * validation has nothing that reads ARGS, so the ctl rule would be dead weight
 * (and would needlessly perturb the auth-block rule-id rebasing pipeline).
 */
export function buildJsonBodyProcessorRule(endpoint: EndpointIR): string[] {
  const req = endpoint.policy.request;
  const hasSchema = req?.schema && Object.keys(req.schema).length > 0;
  const hasAllowlist =
    (Array.isArray(req?.allowedFields) && req.allowedFields.length > 0) ||
    (req?.denyUnknownFields === true && hasSchema);
  if (!hasSchema && !hasAllowlist) return [];
  const rule = buildJsonBodyProcessor(endpoint, MODSEC_NGINX_PROFILE);
  return rule ? [rule] : [];
}

/**
 * Body-field allowlist (mass-assignment / denyUnknownFields). Sources the
 * allowlist from request.allowedFields, else request.schema keys when
 * denyUnknownFields:true — identical contract to the Coraza generator.
 */
export function buildBodyAllowlistRules(endpoint: EndpointIR): string[] {
  return buildBodyFieldAllowlistRules(endpoint, MODSEC_NGINX_PROFILE);
}

/**
 * Response.schema typed-constraint SecRules (phase:4, RESPONSE_BODY). libmodsec3
 * implements SecResponseBodyAccess, so the Coraza phase-4 emitter runs as-is.
 */
export function buildResponseSchemaRules(endpoint: EndpointIR): string[] {
  return buildResponseInspectionRules(endpoint, MODSEC_NGINX_PROFILE);
}

// ---------------------------------------------------------------------------
// W19 (SSEC-INJECTION): per-arg injectionGuard hardening.
//
// `request.schema.<field>.injectionGuard` is an explicit, per-arg opt-in
// declaring which sink(s) a field flows into. For each declared sink we emit a
// native libmodsec3 operator on the field's ARGS selector:
//
//   sql         → @detectSQLi
//   nosql       → !@rx allow-shape is impractical; deny on Mongo/JSON operator
//                 tokens ($where/$ne/$gt/$regex/$function and the bare
//                 `{"$..."` injection shape).
//   os-command  → metachar denylist (; | & ` $( ) > < \n and `$(`/backtick
//                 command substitution).
//   xpath       → XPath metachar/axis denylist (' " [ ] / and `or 1=1`-style
//                 boolean tautology against XPath).
//   ldap        → LDAP filter metachar denylist ( ( ) * \ NUL ).
//   code-eval   → eval/exec/import sink-token denylist for template/code
//                 injection (`__import__`, `eval(`, `exec(`, `;import`, etc.).
//   xss         → @detectXSS (native libmodsec3 XSS operator).
//   deserialization → unsafe-deserialization preamble denylist (node-serialize
//                 `_$$ND_FUNC$$_`, Java `rO0`/`aced0005`, PHP `O:<n>:`, Python
//                 pickle opcodes). Attributed to SSEC-INJECTION.
//   ai-prompt   → LLM prompt-injection heuristic denylist ("ignore previous
//                 instructions", "system prompt", role-override). Attributed to
//                 the distinct SSEC-PROMPT class, NOT SSEC-INJECTION.
//
// Each rule is a 3-link chain: method match → path match → field operator,
// scoped to keep the false-positive surface low (explicit opt-in per field,
// not blanket-on-all-args). Attributed to SSEC-INJECTION (a Writ-native
// category), never to an OWASP-API cell.
//
// Selector: we match BOTH `ARGS:json.<field>` (JSON body, populated by the
// JSON body processor) and `ARGS:<field>` (query string / form) via the
// pipe-separated multi-target form so the guard fires regardless of where the
// declared field arrives.
//
// Rule IDs: dedicated 450000..458999 range (disjoint from SSRF 980000+, SQLi
// heuristic 430000+, XSS 440000+, body-allowlist 400000+, response-inspect
// 420000+). One ID per (endpoint, field, sink), FNV-1a keyed.
// ---------------------------------------------------------------------------
const INJECTION_GUARD_BASE_ID = 450000;

interface SinkRule {
  /** `@op arg` for the chained leaf SecRule (the field operator). */
  operator: string;
  msg: string;
  /** stable per-sink offset so two sinks on one field never collide. */
  slot: number;
  /**
   * Attribution tag. All sinks ride `writ-ssec-injection` (SSEC-INJECTION)
   * EXCEPT `ai-prompt`, which is the distinct Writ-native SSEC-PROMPT
   * class (schema v0.7). Defaults to the injection tag when omitted.
   */
  attrTag?: string;
}

function sinkRule(sink: string): SinkRule | null {
  switch (sink) {
    case 'sql':
      return { operator: '@detectSQLi', msg: 'SQL injection', slot: 0 };
    case 'nosql':
      // Mongo/JSON operator-injection tokens. `@rx` (not detectSQLi) because the
      // payload shape is `{"$ne": null}` / `$where`, not SQL syntax.
      return {
        operator:
          '@rx (?i)(?:\\$(?:where|ne|gt|gte|lt|lte|in|nin|regex|expr|function|or|and)\\b|\\{\\s*"?\\$)',
        msg: 'NoSQL/operator injection',
        slot: 1,
      };
    case 'os-command':
      // Shell metacharacters + command substitution.
      return {
        operator: '@rx (?:[;|&`<>]|\\$\\(|\\$\\{|\\|\\||&&|\\n|\\r)',
        msg: 'OS command injection',
        slot: 2,
      };
    case 'xpath':
      // XPath metachars + boolean-tautology injection ( ' or '1'='1 ).
      return {
        operator: "@rx (?i)(?:'\\s*or\\s|\\bor\\s+1\\s*=\\s*1|//|\\[\\s*@|count\\s*\\(|string-length\\s*\\()",
        msg: 'XPath injection',
        slot: 3,
      };
    case 'ldap':
      // LDAP filter metacharacters: ( ) * \ and the wildcard-injection shape.
      return {
        operator: '@rx (?:[()*\\\\\\x00]|\\)\\(|\\*\\))',
        msg: 'LDAP injection',
        slot: 4,
      };
    case 'code-eval':
      // Template / code-eval sink tokens.
      return {
        operator:
          '@rx (?i)(?:__import__|\\beval\\s*\\(|\\bexec\\s*\\(|\\bsystem\\s*\\(|\\bos\\.|\\bsubprocess\\b|\\{\\{.*\\}\\}|<%.*%>)',
        msg: 'Code/template injection',
        slot: 5,
      };
    case 'xss':
      // Native libmodsec3 XSS operator (libinjection-xss equivalent), the same
      // engine capability as @detectSQLi. bunkerweb targets libmodsec3 only, so
      // this is always available here.
      return { operator: '@detectXSS', msg: 'XSS', slot: 6 };
    case 'deserialization':
      // Unsafe-deserialization payload preambles across the common runtimes:
      //   node-serialize → `_$$ND_FUNC$$_`
      //   Java ObjectInputStream stream header → `rO0` (base64 of 0xaced0005)
      //     or the raw `\xac\xed\x00\x05` magic
      //   PHP serialized object → `O:<digits>:"`  /  `a:<digits>:{`
      //   Python pickle → opcode preamble `\x80\x04` / `(dp` / `c__builtin__`
      return {
        operator:
          '@rx (?i)(?:_\\$\\$ND_FUNC\\$\\$_|rO0[A-Za-z0-9+/]|\\xac\\xed\\x00\\x05|O:\\d+:"|a:\\d+:\\{|c__builtin__|\\bcos\\b\\s*\\n?system|\\(dp\\d|\\x80\\x04)',
        msg: 'Unsafe deserialization payload',
        slot: 7,
      };
    case 'ai-prompt':
      // LLM prompt-injection heuristic denylist. Attributed to SSEC-PROMPT (the
      // distinct Writ-native class), NOT SSEC-INJECTION.
      return {
        operator:
          '@rx (?i)(?:ignore\\s+(?:all\\s+)?(?:previous|prior|above)\\s+instructions|disregard\\s+(?:the\\s+)?(?:previous|above|system)|system\\s+prompt|you\\s+are\\s+now\\s+|act\\s+as\\s+(?:a\\s+)?(?:dan|developer\\s+mode)|reveal\\s+(?:your\\s+)?(?:system\\s+)?prompt|new\\s+instructions?\\s*:)',
        msg: 'LLM prompt injection',
        slot: 8,
        attrTag: 'writ-ssec-prompt',
      };
    default:
      return null;
  }
}

export function buildInjectionGuardRules(endpoint: EndpointIR): string[] {
  const schema = endpoint.policy.request?.schema;
  if (!schema || Object.keys(schema).length === 0) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const out: string[] = [];

  for (const [field, ps] of Object.entries(schema)) {
    const guards = ps?.injectionGuard;
    if (!Array.isArray(guards) || guards.length === 0) continue;
    for (const sink of guards) {
      const def = sinkRule(sink);
      if (!def) continue;
      // 9 ID-slots per field (sql..ai-prompt); FNV-1a over method|path|field
      // keeps fields apart. `% 1000` so the (seed%N)*9 product stays inside the
      // 450000..458999 range even at slot 8.
      const seed = endpointHash(`${endpoint.method}|${endpoint.path}|${field}`, '');
      const id = INJECTION_GUARD_BASE_ID + ((seed % 1000) * 9) + def.slot;
      const selector = `ARGS:json.${field}|ARGS:${field}`;
      const attrTag = def.attrTag ?? 'writ-ssec-injection';
      const attrName = attrTag === 'writ-ssec-prompt' ? 'SSEC-PROMPT' : 'SSEC-INJECTION';
      out.push(
        [
          header(
            `W19 injectionGuard[${sink}] on request.schema.${field} for ${endpoint.method} ${endpoint.path}\n` +
              `Native libmodsec3 operator on the declared sink field. Attributed to\n` +
              `${attrName} (Writ-native), not an OWASP-API cell.`
          ),
          `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'Writ: ${esc(def.msg)} in ${esc(field)}',tag:'${esc(tag)}',tag:'${esc(attrTag)}',chain"`,
          `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
          `    SecRule ${selector} "${escRx(def.operator)}"${CHAIN_TERM}`,
        ].join('\n')
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// S-15 (open redirect): request.schema.<field>.redirectAllowedDomains.
//
// Only meaningful for url-typed params. Mirrors the SSRF domainAllowlist rule
// shape (buildSsrfRules) but keyed on `redirectAllowedDomains` instead of
// `domainAllowlist`: the field value must match one of the allowed redirect
// targets (literal host or `*.example.com` glob), else 403.
//
// Rule IDs: dedicated 460000..468999 range.
// ---------------------------------------------------------------------------
const REDIRECT_ALLOWLIST_BASE_ID = 460000;

/** Convert a redirectAllowedDomains entry (literal or `*.example.com` glob) to a host-regex alternation fragment. */
function redirectHostRx(domain: string): string {
  const d = domain.trim().toLowerCase();
  if (d.startsWith('*.')) {
    // `*.example.com` → any subdomain label(s) + the suffix.
    const suffix = d.slice(2).replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    return `(?:[a-z0-9-]+\\.)+${suffix}`;
  }
  return d.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

export function buildRedirectAllowlistRules(endpoint: EndpointIR): string[] {
  const schema = endpoint.policy.request?.schema;
  if (!schema || Object.keys(schema).length === 0) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const out: string[] = [];

  for (const [field, ps] of Object.entries(schema)) {
    if (!ps || ps.type !== 'url') continue;
    const allowed = ps.redirectAllowedDomains;
    if (!Array.isArray(allowed) || allowed.length === 0) continue;
    const alt = allowed.map(redirectHostRx).join('|');
    // Anchor after scheme `://`, accept any allowed host, terminated by /:?# or end.
    const allowRx = `(?i)^(?:[a-z][a-z0-9+.-]*:)?//(?:${alt})(?:[/:?#]|$)`;
    const seed = endpointHash(`${endpoint.method}|${endpoint.path}|${field}|redirect`, '');
    const id = REDIRECT_ALLOWLIST_BASE_ID + (seed % 9000);
    out.push(
      [
        header(
          `S-15 open-redirect: ${field} must match redirectAllowedDomains for ${endpoint.method} ${endpoint.path}`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:403,msg:'Writ: ${esc(field)} redirect target not in redirectAllowedDomains',tag:'${esc(tag)}',tag:'writ-rule-open-redirect-403',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
        `    SecRule ARGS:${field}|ARGS:json.${field} "!@rx ${escRx(allowRx)}"${CHAIN_TERM}`,
      ].join('\n')
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// S-5 (XXE): request.disableExternalEntities / request.disallowXml.
//
// libmodsec3 has no XML-DTD/external-entity toggle exposed as a SecRule action,
// and the bundled XML body processor's entity expansion is engine-config, not
// per-route. The enforceable, route-scoped defense BunkerWeb CAN emit is a
// phase:1 SecRule that rejects XML-family Content-Type entirely:
//
//   disallowXml: true            → reject application/xml, text/xml,
//                                  application/*+xml (the documented contract).
//   disableExternalEntities:true → there is no per-route libmodsec3 directive
//                                  to disable only external-entity resolution
//                                  while still accepting XML, so we enforce it
//                                  the only honest way at the WAF edge: reject
//                                  the XML body so no DTD is ever parsed. This
//                                  is strictly stronger than the field asks
//                                  (no XML at all > no external entities) and
//                                  we say so in the emitted comment.
//
// Rule IDs: dedicated 470000..478999 range.
// ---------------------------------------------------------------------------
const XXE_BASE_ID = 470000;

/** Matches application/xml, text/xml, application/*+xml (structured-suffix). */
const XML_CONTENT_TYPE_RX = '(?i)^(?:application|text)/(?:[\\w.+-]+\\+)?xml\\b';

export function buildXxeRules(endpoint: EndpointIR): string[] {
  const req = endpoint.policy.request;
  if (!req) return [];
  const disallowXml = req.disallowXml === true;
  const disableEntities = req.disableExternalEntities === true;
  if (!disallowXml && !disableEntities) return [];

  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|xxe`, '');
  const id = XXE_BASE_ID + (seed % 9000);

  const reason = disallowXml
    ? 'XML content-type disallowed (request.disallowXml)'
    : 'XML rejected to prevent external-entity resolution (request.disableExternalEntities); no per-route libmodsec3 XXE-only toggle exists, so we reject XML entirely';

  return [
    [
      header(
        `S-5 XXE: reject XML body for ${endpoint.method} ${endpoint.path}\n${reason}`
      ),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:415,msg:'Writ: ${esc(reason)}',tag:'${esc(tag)}',tag:'writ-rule-xxe-415',chain"`,
      `  SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "chain"`,
      `    SecRule REQUEST_HEADERS:Content-Type "@rx ${escRx(XML_CONTENT_TYPE_RX)}"${CHAIN_TERM}`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// S-3 (path canonicalization): request.pathCanonicalization.
//
// libmodsec3 normalizes the URI via the `t:normalisePathWin` / `t:normalisePath`
// transformations. When the spec opts in, we emit a phase:1 SecRule that denies
// any request whose raw REQUEST_URI still differs from its normalised form —
// i.e. it carries traversal (`../`, `..\`), double-slash, or percent-encoded
// path separators. The normalised path is what every later Writ rule's
// `@rx ^/path$` matches against, so this rule guarantees the canonical form
// can't be bypassed with `/api/..//admin` style obfuscation.
//
// We match on the presence of un-canonical sequences directly (raw REQUEST_URI
// @rx) rather than comparing two transformed copies, because libmodsec3 has no
// "compare REQUEST_URI to t:normalisePath(REQUEST_URI)" operator — the honest
// edge enforcement is to reject the obfuscated forms outright.
//
// Rule IDs: dedicated 480000..488999 range.
// ---------------------------------------------------------------------------
const PATH_CANON_BASE_ID = 480000;

/** Path-traversal / separator-obfuscation sequences a canonical path never contains. */
const PATH_TRAVERSAL_RX =
  '(?i)(?:\\.\\./|\\.\\.\\\\|%2e%2e|%2f|%5c|//|/\\./|\\\\)';

export function buildPathCanonicalizationRules(endpoint: EndpointIR): string[] {
  if (endpoint.policy.request?.pathCanonicalization !== true) return [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|pathcanon`, '');
  const id = PATH_CANON_BASE_ID + (seed % 9000);
  return [
    [
      header(
        `S-3 pathCanonicalization: reject non-canonical path for ${endpoint.method} ${endpoint.path}\n` +
          `Denies traversal / double-slash / percent-encoded separators so the\n` +
          `canonical path every later SecRule matches against can't be bypassed.`
      ),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:400,msg:'Writ: non-canonical request path',tag:'${esc(tag)}',tag:'writ-rule-path-canon-400',chain"`,
      `  SecRule REQUEST_URI "@rx ${escRx(PATH_TRAVERSAL_RX)}"${CHAIN_TERM}`,
    ].join('\n'),
  ];
}
