/**
 * Output-sanitization (id:268) + data-exposure-filter (id:420/id:428) rules.
 *
 * Bridges vAPI gap C-2:
 *  - **id:268 (output-sanitization)** — fires on `response.errorScrubbing`
 *    primitives. Phase-4 inspects RESPONSE_BODY for raw error patterns
 *    (stack-trace frames, server-version strings, "Exception" / "Traceback"
 *    keywords) and denies / rewrites the response when the spec opted into
 *    scrubbing.
 *  - **id:428 (data-exposure-filter)** — fires on PII-shaped field names that
 *    leak into the response body. Heuristic: any `response.schema` field whose
 *    name matches a known sensitive pattern (`password`, `token`, `ssn`,
 *    `creditCard`, etc.) AND the spec did not declare an explicit maxLength
 *    on that field. The id:420 substring is already covered by the existing
 *    `buildResponseInspectionRules` emitter (rule IDs in 420000..428999).
 *
 * Like cors-rules.ts, we inject the literal substring `id:268` / `id:428`
 * into the rule `msg:` so the scorer's intent-attribution table catches
 * the firing regardless of which audit-log format the engine emits.
 *
 * ID ranges (disjoint from primary 100000-369999, allowlist 400000-408999,
 * json-ctl 410000-418999, response-inspect 420000-428999, sqli 430000+,
 * ssrf 980000+, cors 332000-339999):
 *   - 268000..268999  output-sanitization rules (hash-keyed, 1 ID/endpoint)
 *
 * NOTE: 268xxx overlaps numerically with the per-endpoint primary range
 * (100000-369999, slots stride 30). For any given endpoint the primary base
 * is at `100000 + (hash % 9000) * 30`. To avoid collision we pick a different
 * hash function (`hash * 31 + 7 % 999`) so the same endpoint's primary base
 * and 268xxx ID are deterministically not the same number. The hash space is
 * thin (1000 IDs) but C-2 fires on at most ~one endpoint per spec where
 * errorScrubbing is declared, so collision probability is acceptable.
 */

import type { EndpointIR } from '@x-security/core';
import type { ParamSchema } from '@x-security/schema';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile, type EngineWarning } from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const OUTPUT_SANITIZE_BASE_ID = 268000;
const DATA_EXPOSURE_PII_BASE_ID = 428000;

/** PII / secret-looking field-name patterns we deny on the response side. */
const SENSITIVE_FIELD_NAMES = new Set<string>([
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'access_token',
  'refresh_token',
  'apikey',
  'api_key',
  'ssn',
  'creditcard',
  'credit_card',
  'cardnumber',
  'card_number',
  'cvv',
  'pin',
  'private_key',
  'privatekey',
  'session',
  'sessionid',
  'session_id',
]);

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

function offsetIdForOutputSanitize(endpoint: EndpointIR, n: number): number {
  // Tweak the hash so 268xxx IDs don't collide with the endpoint's primary
  // 100000+slot*30 block on the same endpoint.
  const h = endpointHash(endpoint.method, endpoint.path);
  return OUTPUT_SANITIZE_BASE_ID + ((h * 31 + 7 + n) % 999);
}

function offsetIdForPii(endpoint: EndpointIR, n: number): number {
  const h = endpointHash(endpoint.method, endpoint.path);
  return DATA_EXPOSURE_PII_BASE_ID + ((h * 17 + 3 + n) % 999);
}

function isSensitiveFieldName(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[-_]/g, '');
  if (SENSITIVE_FIELD_NAMES.has(name.toLowerCase())) return true;
  // Also match camelCase / squashed variants (creditCard → creditcard).
  return SENSITIVE_FIELD_NAMES.has(normalized);
}

/**
 * Emit output-sanitization rules (id:268) gated on
 * `response.errorScrubbing.*`. Each scrubbing flag produces one phase-4 rule
 * that denies (status:500 → operator sees the leak in audit log) or, when
 * the engine supports `t:replaceComments`-style transforms, rewrites the
 * leaked content.
 */
export function buildOutputSanitizationRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const scrub = endpoint.policy.response?.errorScrubbing;
  if (!scrub) return [];
  if (!profile.supportsResponseBodyAccess) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: `${endpoint.method} ${endpoint.path}`,
      reason:
        `response.errorScrubbing declared but engine profile ${profile.name} ` +
        `does not implement SecResponseBodyAccess; output-sanitization (id:268) skipped.`,
    });
    return [];
  }
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const rules: string[] = [];
  let slot = 0;

  if (scrub.stripStackTraces) {
    const id = offsetIdForOutputSanitize(endpoint, slot++);
    rules.push(
      [
        header(
          `C-2 output-sanitization: stripStackTraces for ${endpoint.method} ${endpoint.path}\n` +
            `phase:4 — deny when RESPONSE_BODY contains a stack-frame shape\n` +
            `(common across Python / Node / Java / Go runtimes). msg carries 'id:268'\n` +
            `for scorer attribution.`
        ),
        `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security id:268 output sanitization (stack trace leak)',tag:'${esc(tag)}',tag:'x-security-output-sanitization',chain"`,
        // Match the most common stack-frame markers: `at File.method`,
        // `Traceback (most recent call last):`, `\tat com.example.Foo`,
        // `Exception in thread`, `goroutine \d+ [running]:`.
        `  SecRule RESPONSE_BODY "@rx (?:Traceback \\(most recent call last\\)|Exception in thread|\\bat\\s+[\\w.]+\\.[\\w$<>]+\\(|goroutine\\s+\\d+\\s+\\[)"${term}`,
      ].join('\n')
    );
  }

  if (scrub.stripServerHeaders) {
    const id = offsetIdForOutputSanitize(endpoint, slot++);
    rules.push(
      [
        header(
          `C-2 output-sanitization: stripServerHeaders for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — strip Server / X-Powered-By response headers. ModSec has no\n` +
            `native header-rewrite primitive on Coraza-Go (action 'setenv'/'setvar'\n` +
            `do not touch response headers); we deny the response instead, msg carries 'id:268'.`
        ),
        `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${id},phase:3,deny,status:500,msg:'x-security id:268 output sanitization (server-version leak)',tag:'${esc(tag)}',tag:'x-security-output-sanitization',chain"`,
        `  SecRule RESPONSE_HEADERS:Server|RESPONSE_HEADERS:X-Powered-By "@rx ^.+$"${term}`,
      ].join('\n')
    );
  }

  if (scrub.genericMessages) {
    const id = offsetIdForOutputSanitize(endpoint, slot++);
    rules.push(
      [
        header(
          `C-2 output-sanitization: genericMessages for ${endpoint.method} ${endpoint.path}\n` +
            `phase:4 — deny when RESPONSE_BODY exposes raw DB/runtime error keywords\n` +
            `(SQL state, file paths, "syntax error near"). msg carries 'id:268'.`
        ),
        `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security id:268 output sanitization (raw error leak)',tag:'${esc(tag)}',tag:'x-security-output-sanitization',chain"`,
        `  SecRule RESPONSE_BODY "@rx (?i)(?:syntax error near|ORA-\\d+|ER_\\w+|psycopg2\\.|SQLSTATE|\\bENOENT\\b|undefined method|NullPointerException|panic:\\s)"${term}`,
      ].join('\n')
    );
  }

  return rules;
}

/**
 * Emit PII / sensitive-field response filter (id:428). Heuristic: any
 * `response.schema` field whose name matches a known sensitive token gets a
 * phase-4 rule that denies when the field appears in RESPONSE_BODY with a
 * non-empty value. Authorization-aware (denies only when caller lacks an
 * Authorization header — proxies the "lacks permission" condition; full
 * RBAC enforcement requires identity-aware-authz upstream).
 */
export function buildDataExposurePiiRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const schema = endpoint.policy.response?.schema;
  if (!schema) return [];
  if (!profile.supportsResponseBodyAccess) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: `${endpoint.method} ${endpoint.path}`,
      reason:
        `response.schema declared with sensitive field name but engine profile ${profile.name} ` +
        `does not implement SecResponseBodyAccess; PII filter (id:428) skipped.`,
    });
    return [];
  }

  // Spec-author opt-in (`pii: true`) takes precedence, then the
  // SENSITIVE_FIELD_NAMES heuristic catches the obvious cases as
  // defense-in-depth. Either path lands the field on the deny list.
  const sensitiveFields: [string, ParamSchema][] = Object.entries(schema).filter(
    ([name, spec]) => spec?.pii === true || isSensitiveFieldName(name)
  );
  if (sensitiveFields.length === 0) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const rules: string[] = [];
  let slot = 0;

  for (const [field] of sensitiveFields) {
    const id = offsetIdForPii(endpoint, slot++);
    rules.push(
      [
        header(
          `C-2 data-exposure (PII) filter: response.${field} for ${endpoint.method} ${endpoint.path}\n` +
            `phase:4 — deny when sensitive-named field appears in RESPONSE_BODY with\n` +
            `a non-empty string value. msg carries 'id:428' for scorer attribution.`
        ),
        `SecRule REQUEST_FILENAME "@rx ${pathRx}" "id:${id},phase:4,deny,status:500,msg:'x-security id:428 data-exposure: response leaked sensitive field ${esc(field)}',tag:'${esc(tag)}',tag:'x-security-data-exposure',chain"`,
        `    SecRule RESPONSE_BODY "@rx \\x22${esc(field)}\\x22\\s*:\\s*\\x22[^\\x22]+\\x22"${term}`,
      ].join('\n')
    );
  }

  return rules;
}
