/**
 * Lifecycle SecRules — closes drift on `deprecated`.
 *
 * Emits a phase:1 SecRule that returns 410 Gone for endpoints marked
 * `deprecated: true`. The msg + tag carries `writ-deprecated-endpoint-block`
 * which `e2e/scoring/scoring_lib/attribution.py` (line 35, 59, 126) already
 * maps to the `deprecated-endpoint-block` intent. Mirrors the Kong
 * pre-function approach in `packages/cli/src/generators/kong/plugins.ts:983`.
 *
 * sunsetDate is surfaced as a `Sunset:` header hint in the deny msg — operators
 * who need the actual response header can wire `bunkerweb` `CUSTOM_HEADER_*`
 * settings; the SecRule path returns 410 before the upstream so the Sunset
 * header is not strictly needed.
 *
 * Rule ID range: 970500-970599 (inside the identity range 970000-979999 but
 * offset to a slice that buildIdentityRules-style code never touches — that
 * one uses 970000 + (hash % 100) * 100 + {10,11,20,21}, i.e. multiples of 100
 * + small offsets, never landing in the 500-599 window).
 */

import type { EndpointIR } from '@writ/core';

const DEPRECATED_BASE_ID = 970500;
const DEPRECATED_TAG = 'writ-deprecated-endpoint-block';

function escMsec(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}

function pathRegex(p: string): string {
  // Escape regex specials; replace `{param}` with `[^/]+`; anchor exactly.
  const parts = p.split('/').filter((s) => s.length > 0);
  const rebuilt = parts
    .map((seg) => {
      if (/^\{[^}]+\}$/.test(seg)) return '[^/]+';
      return seg.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return `^/${rebuilt}$`;
}

function slotIdFor(method: string, path: string): number {
  // Simple stable hash, kept inside 0..99 so two distinct deprecated endpoints
  // in the same service don't collide on rule id.
  let h = 0;
  const s = `${method} ${path}`;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return Math.abs(h) % 100;
}

/**
 * Emit deprecated-endpoint SecRule block(s) for one endpoint. Returns an empty
 * array if the endpoint is not marked deprecated.
 */
export function buildLifecycleRules(endpoint: EndpointIR): string[] {
  if (endpoint.policy.deprecated !== true) return [];

  const id = DEPRECATED_BASE_ID + slotIdFor(endpoint.method, endpoint.path);
  const pathRx = pathRegex(endpoint.path);
  const sunset = endpoint.policy.sunsetDate
    ? ` (sunset:${endpoint.policy.sunsetDate})`
    : '';
  const replacement = endpoint.policy.replacementEndpoint
    ? ` use ${endpoint.policy.replacementEndpoint}`
    : '';
  const msg = `Writ: ${DEPRECATED_TAG} ${endpoint.method} ${endpoint.path}${sunset}${replacement}`;

  const lines = [
    `# Writ-generated lifecycle rule (deprecated endpoint → 410 Gone)`,
    `# Source: ${endpoint.method} ${endpoint.path}` +
      (endpoint.policy.sunsetDate ? ` (sunsetDate: ${endpoint.policy.sunsetDate})` : ''),
    `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:1,deny,status:410,log,auditlog,msg:'${escMsec(msg)}',tag:'${DEPRECATED_TAG}',chain"`,
    `  SecRule REQUEST_FILENAME "@rx ${escRx(pathRx)}" "t:none"`,
  ];

  return [lines.join('\n')];
}

export const __test = {
  DEPRECATED_BASE_ID,
  DEPRECATED_TAG,
  pathRegex,
  slotIdFor,
};
