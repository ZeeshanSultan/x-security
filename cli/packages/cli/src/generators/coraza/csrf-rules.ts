/**
 * CSRF enforcement SecRules.
 *
 * Supports three Csrf.method shapes from `packages/schema/src/types.ts`:
 *
 *   - `origin-check`   — Origin header must match `allowedOrigins`. Deny on
 *                        state-changing method when Origin missing OR not in list.
 *   - `double-submit`  — Both `tokenCookie` and `tokenHeader` must be present
 *                        AND equal. We can verify presence + non-empty on both;
 *                        cookie/header equality requires capturing the cookie
 *                        into TX and comparing with `@streq %{TX.<var>}`.
 *   - `custom-header`  — `tokenHeader` must be present (the value is opaque to
 *                        the WAF; the application validates).
 *
 * State-changing methods = POST, PUT, PATCH, DELETE.
 *
 * Design decision (token mechanism): for `double-submit` we emit two chained
 * rules — first captures the cookie value to TX, second denies when the
 * header value differs. Both rules are gated on (method ∈ state-changing
 * AND path matches). RE2-safe (no lookaheads, no backreferences). For
 * `custom-header` we only verify the header is present and non-empty since
 * the secret material is opaque to the WAF.
 *
 * ID range: 272000..274999 (1000 per method × 3 sub-rules, hash-keyed).
 */

import type { EndpointIR } from '@x-security/core';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const CSRF_BASE_ID = 272000;
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

function buildOriginAllowRegex(origins: string[]): string {
  const alt = origins
    .map((o) => o.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*'))
    .join('|');
  return `^(${alt})$`;
}

export function buildCsrfRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const csrf = endpoint.policy.csrf;
  if (!csrf) return [];
  if (!STATE_CHANGING.has(endpoint.method.toUpperCase())) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const slot = endpointHash(endpoint.method, endpoint.path) % 1000;
  const rules: string[] = [];

  if (csrf.method === 'origin-check') {
    const origins = csrf.allowedOrigins ?? [];
    if (origins.length === 0) return [];
    const originRx = buildOriginAllowRegex(origins);
    const id = CSRF_BASE_ID + slot;
    rules.push(
      [
        header(
          `csrf: origin-check for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — deny when Origin missing or not in allowedOrigins.\n` +
            `msg carries 'id:272' substring (x-security-csrf).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:403,msg:'x-security id:272 CSRF origin not allowed',tag:'${esc(tag)}',tag:'x-security-csrf',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_HEADERS:Origin "!@rx ${esc(originRx)}"${term}`,
      ].join('\n')
    );
  } else if (csrf.method === 'double-submit') {
    const cookieName = csrf.tokenCookie;
    const headerName = csrf.tokenHeader;
    if (!cookieName || !headerName) return [];
    const captureId = CSRF_BASE_ID + 1000 + slot;
    const denyId = CSRF_BASE_ID + 2000 + slot;
    const txVar = `x_security_csrf_${slot}`;
    rules.push(
      [
        header(
          `csrf: double-submit capture for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — capture cookie '${esc(cookieName)}' into TX:${txVar} for the equality check.`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${captureId},phase:1,pass,nolog,tag:'${esc(tag)}',tag:'x-security-csrf',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_COOKIES:${cookieName} "@rx .+" "capture,setvar:tx.${txVar}=%{MATCHED_VAR}${term ? ',t:none' : ''}"`,
      ].join('\n')
    );
    rules.push(
      [
        header(
          `csrf: double-submit verify for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — deny when header '${esc(headerName)}' missing OR != TX:${txVar}.\n` +
            `msg carries 'id:272' substring (x-security-csrf).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${denyId},phase:1,deny,status:403,msg:'x-security id:272 CSRF token mismatch',tag:'${esc(tag)}',tag:'x-security-csrf',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_HEADERS:${headerName} "!@streq %{TX.${txVar}}"${term}`,
      ].join('\n')
    );
  } else if (csrf.method === 'custom-header') {
    const headerName = csrf.tokenHeader;
    if (!headerName) return [];
    const id = CSRF_BASE_ID + slot;
    rules.push(
      [
        header(
          `csrf: custom-header for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — deny when '${esc(headerName)}' header missing/empty.\n` +
            `msg carries 'id:272' substring (x-security-csrf).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:403,msg:'x-security id:272 CSRF custom header missing',tag:'${esc(tag)}',tag:'x-security-csrf',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule &REQUEST_HEADERS:${headerName} "@eq 0"${term}`,
      ].join('\n')
    );
  }

  return rules;
}
