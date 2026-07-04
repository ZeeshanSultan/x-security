/**
 * Endpoint-lifecycle SecActions: `deprecated`, `sunsetDate`,
 * `replacementEndpoint`.
 *
 * ID ranges (disjoint from every other emitter):
 *   - 269000..269999  deprecated → phase:1 deny 410 (hash-keyed per endpoint)
 *   - 270000..270999  sunsetDate → phase:3 setenv Sunset response header
 *   - 271000..271999  replacementEndpoint → phase:3 setenv Link response header
 *
 * Design decision: when `deprecated:true` we emit a phase:1 SecAction that
 * denies with HTTP 410 Gone — this is the standard RFC 8594 disposition for
 * a deprecated-and-removed endpoint. If the operator wants soft-deprecation
 * (still serve, advertise Sunset only), they should set `sunsetDate` /
 * `replacementEndpoint` without setting `deprecated:true`.
 *
 * The Sunset / Link headers are emitted via `setenv:Header:value`. On
 * libmodsecurity3 + the Coraza ResponseRules path, `setenv` adds an
 * env variable that the upstream proxy (nginx/Apache `add_header`,
 * HAProxy `http-response set-header`) reads back to mint the actual
 * response header. This is the established Coraza idiom for response-side
 * header rewrites since the WAF itself has no native header-write primitive.
 * Operators get the directive lines documented in WARNINGS for the
 * upstream hookup.
 */

import type { EndpointIR } from '@writ/core';
import { CORAZA_GO_PROFILE, type CorazaEngineProfile } from './profiles.js';
import { endpointHash } from './rules.js';

const DEPRECATED_BASE_ID = 269000;
const SUNSET_BASE_ID = 270000;
const REPLACEMENT_BASE_ID = 271000;

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

export function buildLifecycleRules(
  endpoint: EndpointIR,
  _profile: CorazaEngineProfile = CORAZA_GO_PROFILE
): string[] {
  const policy = endpoint.policy;
  const rules: string[] = [];
  const tag = `writ/${endpoint.method} ${endpoint.path}`;
  const slot = endpointHash(endpoint.method, endpoint.path) % 1000;

  if (policy.deprecated === true) {
    const id = DEPRECATED_BASE_ID + slot;
    rules.push(
      [
        header(
          `lifecycle: endpoint deprecated for ${endpoint.method} ${endpoint.path}\n` +
            `phase:1 — deny with HTTP 410 Gone per RFC 8594 deprecation disposition.\n` +
            `msg carries 'id:269' substring for scorer attribution (writ-lifecycle-410).`
        ),
        `SecAction "id:${id},phase:1,deny,status:410,msg:'Writ id:269 endpoint deprecated',tag:'${esc(tag)}',tag:'writ-lifecycle-410'"`,
      ].join('\n')
    );
  }

  if (typeof policy.sunsetDate === 'string' && policy.sunsetDate.length > 0) {
    const id = SUNSET_BASE_ID + slot;
    rules.push(
      [
        header(
          `lifecycle: Sunset header for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — setenv:Sunset=<iso> so the upstream proxy can add_header it.\n` +
            `msg carries 'id:270' substring (writ-lifecycle-sunset).`
        ),
        `SecAction "id:${id},phase:3,pass,nolog,msg:'Writ id:270 sunset header',tag:'${esc(tag)}',tag:'writ-lifecycle-sunset',setenv:Sunset=${esc(policy.sunsetDate)}"`,
      ].join('\n')
    );
  }

  if (typeof policy.replacementEndpoint === 'string' && policy.replacementEndpoint.length > 0) {
    const id = REPLACEMENT_BASE_ID + slot;
    // RFC 5988 / RFC 8594 successor-version link relation.
    const linkValue = `<${policy.replacementEndpoint}>; rel="successor-version"`;
    rules.push(
      [
        header(
          `lifecycle: Link successor-version for ${endpoint.method} ${endpoint.path}\n` +
            `phase:3 — setenv:Link=<replacement>; rel="successor-version" per RFC 8594.\n` +
            `msg carries 'id:271' substring (writ-lifecycle-replacement).`
        ),
        `SecAction "id:${id},phase:3,pass,nolog,msg:'Writ id:271 replacement endpoint',tag:'${esc(tag)}',tag:'writ-lifecycle-replacement',setenv:Link=${esc(linkValue)}"`,
      ].join('\n')
    );
  }

  return rules;
}
