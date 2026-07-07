/**
 * HTTP Parameter Pollution (HPP) defense — request.duplicateParamPolicy='reject'.
 *
 * Coraza/ModSec exposes `&ARGS_NAMES:<field>` as the count of occurrences of
 * a given parameter name. When the spec author opts into 'reject' policy we
 * emit one SecRule per declared schema field that denies when the field
 * appears more than once.
 *
 * Only emitted when `request.duplicateParamPolicy === 'reject'` AND there is
 * a `request.schema` declaring at least one named parameter. The 'first' /
 * 'last' policies are handled by the application layer (the WAF cannot
 * rewrite the request body; it can only deny).
 *
 * ID range: 275000..275999 (hash-keyed `(endpoint, field)`).
 */

import type { EndpointIR } from '@x-security/core';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const DUPLICATE_PARAM_BASE_ID = 275000;

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

export function buildDuplicateParamRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const req = endpoint.policy.request;
  if (!req || req.duplicateParamPolicy !== 'reject') return [];
  if (!req.schema) return [];

  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const rules: string[] = [];

  for (const field of Object.keys(req.schema)) {
    // Identifier-safe: ARGS_NAMES selectors don't tolerate whitespace/quotes.
    if (!/^[A-Za-z0-9_.\-]+$/.test(field)) continue;
    const idSeed = endpointHash(`${endpoint.method}|${endpoint.path}|${field}|dup`, '');
    const id = DUPLICATE_PARAM_BASE_ID + (idSeed % 1000);
    rules.push(
      [
        header(
          `request.duplicateParamPolicy=reject for ${endpoint.method} ${endpoint.path} field=${field}\n` +
            `phase:2 — deny when ARGS:${field} appears more than once (HPP defense).\n` +
            `msg carries 'id:275' substring (x-security-hpp-reject).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:400,msg:'x-security id:275 duplicate parameter ${esc(field)}',tag:'${esc(tag)}',tag:'x-security-hpp-reject',chain"`,
        `  SecRule REQUEST_FILENAME "@rx ${pathRx}" "chain"`,
        `    SecRule &ARGS:${field} "@gt 1"${term}`,
      ].join('\n')
    );
  }

  return rules;
}
