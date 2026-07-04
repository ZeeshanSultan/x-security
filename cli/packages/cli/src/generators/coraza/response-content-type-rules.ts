/**
 * response.contentType allowlist enforcement.
 *
 * Phase:3 (response-headers) SecRule that denies when the upstream emitted
 * a Content-Type outside the declared allowlist. Catches the case where a
 * spec'd JSON endpoint accidentally serves text/html (the classic
 * stored-XSS smuggling vector).
 *
 * ID range: 276000..276999 (hash-keyed per endpoint).
 */

import type { EndpointIR } from '@writ/core';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const RESPONSE_CT_BASE_ID = 276000;

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

export function buildResponseContentTypeRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const resp = endpoint.policy.response;
  if (!resp || !Array.isArray(resp.contentType) || resp.contentType.length === 0) return [];

  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const slot = endpointHash(endpoint.method, endpoint.path) % 1000;
  const id = RESPONSE_CT_BASE_ID + slot;

  // Allowlist regex: anchor, allow MIME params (`;.*`). RE2-safe.
  const alt = resp.contentType
    .map((c) => c.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
  const allowRx = `^(${alt})(;.*)?$`;

  return [
    [
      header(
        `response.contentType allowlist for ${endpoint.method} ${endpoint.path}\n` +
          `phase:3 — deny when RESPONSE_HEADERS:Content-Type not in allowlist.\n` +
          `msg carries 'id:276' substring (writ-response-ct).`
      ),
      `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:3,deny,status:500,msg:'Writ id:276 response content-type not allowed',tag:'${esc(tag)}',tag:'writ-response-ct',chain"`,
      `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
      `    SecRule RESPONSE_HEADERS:Content-Type "!@rx ${esc(allowRx)}"${term}`,
    ].join('\n'),
  ];
}
