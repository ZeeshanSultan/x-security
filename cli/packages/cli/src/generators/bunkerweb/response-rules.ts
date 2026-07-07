/**
 * Response-phase SecRules + header-strip settings.
 *
 * Closes drift on:
 *   - `request.schema.<field>.pii` → phase:4 SecRule denies when sensitive
 *     field leaks into RESPONSE_BODY (id:428xxx).
 *   - `response.errorScrubbing.stripStackTraces` → phase:4 SecRule denies
 *     when stack-frame patterns appear (id:268xxx).
 *   - `response.errorScrubbing.stripServerHeaders` → BunkerWeb `REMOVE_HEADERS`
 *     setting (preferred over a SecRule; the BW core handler scrubs the
 *     headers before the response leaves the proxy).
 *
 * libmodsec3 on BunkerWeb supports SecResponseBodyAccess + RESPONSE_BODY (see
 * coraza/profiles.ts MODSEC_NGINX_PROFILE.supportsResponseBodyAccess=true).
 *
 * Tag conventions mirror the Coraza generator's id:268 / id:428 emissions so
 * `e2e/scoring/scoring_lib/attribution.py` maps both engines the same way.
 */

import type { EndpointIR } from '@x-security/core';
import type { ParamSchema } from '@x-security/schema';
import type { SettingMap } from './settings.js';

const OUTPUT_SANITIZE_BASE = 268000;
const DATA_EXPOSURE_PII_BASE = 428000;

/** PII / secret-shaped field-name patterns — kept in sync with
 *  packages/cli/src/generators/coraza/data-exposure-rules.ts. */
const SENSITIVE_FIELD_NAMES = new Set<string>([
  'password', 'passwd', 'pwd', 'secret', 'token',
  'access_token', 'refresh_token', 'apikey', 'api_key',
  'ssn', 'creditcard', 'credit_card', 'cardnumber', 'card_number',
  'cvv', 'pin', 'private_key', 'privatekey',
  'session', 'sessionid', 'session_id',
]);

function escMsec(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}

function pathRegex(p: string): string {
  const parts = p.split('/').filter((s) => s.length > 0);
  const rebuilt = parts
    .map((seg) => {
      if (/^\{[^}]+\}$/.test(seg)) return '[^/]+';
      return seg.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return `^/${rebuilt}$`;
}

function stableHash(method: string, path: string): number {
  let h = 0;
  const s = `${method} ${path}`;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function isSensitiveFieldName(name: string): boolean {
  const normalized = name.toLowerCase().replace(/[-_]/g, '');
  if (SENSITIVE_FIELD_NAMES.has(name.toLowerCase())) return true;
  return SENSITIVE_FIELD_NAMES.has(normalized);
}

/**
 * Collect PII-flagged fields from either request.schema (spec-author opt-in
 * via `pii: true`) or response.schema (heuristic + opt-in). Both surfaces
 * are interesting: a request-side `pii: true` flag signals the field is
 * sensitive and should never be reflected in the response either.
 */
function collectSensitiveFields(endpoint: EndpointIR): string[] {
  const out = new Set<string>();
  const collect = (schema: Record<string, ParamSchema> | undefined) => {
    if (!schema) return;
    for (const [name, spec] of Object.entries(schema)) {
      if (spec?.pii === true || isSensitiveFieldName(name)) out.add(name);
    }
  };
  collect(endpoint.policy.request?.schema);
  collect(endpoint.policy.response?.schema);
  return Array.from(out);
}

/**
 * Emit PII response-body SecRules (id:428xxx). One rule per sensitive field.
 */
export function buildPiiResponseRules(endpoint: EndpointIR): string[] {
  const fields = collectSensitiveFields(endpoint);
  if (fields.length === 0) return [];

  const pathRx = pathRegex(endpoint.path);
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const h = stableHash(endpoint.method, endpoint.path);
  const rules: string[] = [];

  fields.forEach((field, i) => {
    const id = DATA_EXPOSURE_PII_BASE + ((h * 17 + 3 + i) % 999);
    rules.push(
      [
        `# x-security-generated response PII filter (id:428)`,
        `# Source: ${endpoint.method} ${endpoint.path}, field: ${field}`,
        `SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "id:${id},phase:4,deny,status:500,log,auditlog,msg:'x-security id:428 data-exposure: response leaked sensitive field ${escMsec(field)}',tag:'${escMsec(tag)}',tag:'x-security-data-exposure',chain"`,
        `  SecRule RESPONSE_BODY "@rx \\"${escMsec(field)}\\"\\s*:\\s*\\"[^\\"]+\\"" "t:none"`,
      ].join('\n')
    );
  });

  return rules;
}

/**
 * Emit stripStackTraces SecRule (id:268xxx). Denies (500) when a stack-frame
 * pattern appears in RESPONSE_BODY — operator sees the leak in the audit log
 * and tracebacks never reach the client.
 */
export function buildErrorScrubbingRules(endpoint: EndpointIR): string[] {
  const scrub = endpoint.policy.response?.errorScrubbing;
  if (!scrub) return [];

  const pathRx = pathRegex(endpoint.path);
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const h = stableHash(endpoint.method, endpoint.path);
  const rules: string[] = [];
  let slot = 0;

  if (scrub.stripStackTraces) {
    const id = OUTPUT_SANITIZE_BASE + ((h * 31 + 7 + slot++) % 999);
    rules.push(
      [
        `# x-security-generated response error-scrubbing (id:268, stack traces)`,
        `# Source: ${endpoint.method} ${endpoint.path}`,
        `SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "id:${id},phase:4,deny,status:500,log,auditlog,msg:'x-security id:268 output sanitization (stack trace leak)',tag:'${escMsec(tag)}',tag:'x-security-output-sanitization',chain"`,
        // Common stack-frame markers across Python / Node / Java / Go.
        // RE2-safe: only character classes + non-capturing groups + bounded \\d+.
        `  SecRule RESPONSE_BODY "@rx (?:Traceback \\(most recent call last\\)|Exception in thread|\\bat\\s+[\\w.]+\\.[\\w$<>]+\\(|goroutine\\s+\\d+\\s+\\[)" "t:none"`,
      ].join('\n')
    );
  }

  if (scrub.genericMessages) {
    const id = OUTPUT_SANITIZE_BASE + ((h * 31 + 7 + slot++) % 999);
    rules.push(
      [
        `# x-security-generated response error-scrubbing (id:268, generic messages)`,
        `# Source: ${endpoint.method} ${endpoint.path}`,
        `SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "id:${id},phase:4,deny,status:500,log,auditlog,msg:'x-security id:268 output sanitization (raw error leak)',tag:'${escMsec(tag)}',tag:'x-security-output-sanitization',chain"`,
        `  SecRule RESPONSE_BODY "@rx (?i)(?:syntax error near|ORA-\\d+|ER_\\w+|psycopg2\\.|SQLSTATE|\\bENOENT\\b|undefined method|NullPointerException|panic:\\s)" "t:none"`,
      ].join('\n')
    );
  }

  return rules;
}

/**
 * Build BunkerWeb header-strip settings for stripServerHeaders. BW's
 * REMOVE_HEADERS setting takes a space-separated list of response headers to
 * strip; the core handler removes them before the response leaves the proxy
 * (faster than a phase:3 SecRule and the only way to actually mutate response
 * headers under libmodsec3, which lacks header-rewrite primitives).
 */
export function buildErrorScrubbingSettings(endpoint: EndpointIR): SettingMap {
  const scrub = endpoint.policy.response?.errorScrubbing;
  if (!scrub?.stripServerHeaders) return {};
  return {
    REMOVE_HEADERS: 'Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version',
  };
}

export const __test = {
  OUTPUT_SANITIZE_BASE,
  DATA_EXPOSURE_PII_BASE,
  SENSITIVE_FIELD_NAMES,
  collectSensitiveFields,
  isSensitiveFieldName,
  pathRegex,
};
