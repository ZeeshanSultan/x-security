// Cloudflare per-field capability matrix.
//
// Single source of truth for "how well does Cloudflare support this v0.3
// x-security field?" — referenced by the compiler when it decides whether
// to emit a native ruleset rule, a Worker artifact, or just a provenance
// note. Also consumed by `capabilities()` for the @writ/core
// `Generator` contract.
//
// Decisions follow `packages/schema/docs/v0.3-additions.md`:
//   - full          → native Cloudflare primitive (Wirefilter / Transform / Cache Rule)
//   - partial       → native primitive covers the easy case; edge cases need Worker
//   - override-only → no native lowering; customer must supply
//                     `targetOverrides.cloudflare.<field>` OR accept a Worker stub
//   - unsupported   → Cloudflare cannot express this; compiler surfaces and stops

import type { CapabilityMatrix } from '@writ/core';
import type { CfCapability, ShadowModeSupportEntry } from './types.js';

/**
 * Per-field decision table for v0.3 additions. Pre-v0.3 fields already
 * landed natively (auth, ipPolicy, cors, request.contentType, etc.) — they
 * stay implicitly 'full' and aren't re-declared here unless v0.3 changed
 * something.
 */
export const CF_CAPABILITIES: Readonly<Record<string, CfCapability>> = Object.freeze({
  // --- Pre-v0.3 baseline (kept for completeness; touched fields only) ---
  'authentication': 'full',
  'authentication.type': 'full',
  'authorization': 'partial',
  'rateLimit': 'full',
  'cors': 'full',
  'ipPolicy.allow': 'full',
  'ipPolicy.deny': 'full',
  'request.contentType': 'full',
  'request.maxBodySize': 'full',

  // --- v0.3: authorization / authentication (5) ---
  // PW-1: jwt.* claim refs cannot be evaluated by Wirefilter — Worker only.
  //       request.* refs map cleanly to Wirefilter. → partial.
  'authorization.rules[].value.ref': 'partial',
  // Required for bearer-jwt. Cloudflare Access JWT validator can express
  // an algorithm whitelist; raw Cloudflare WAF cannot. Treat as
  // override-only AND hard-error if missing on a bearer-jwt policy.
  'authentication.allowedAlgorithms': 'override-only',
  // Subrequest + JSON parse → Worker only.
  'authorization.resourceLookup': 'override-only',
  // origin-check → Wirefilter full; double-submit / custom-header → partial
  // (needs Worker for the token compare).
  'csrf': 'partial',
  'csrf.method=origin-check': 'full',
  'csrf.method=double-submit': 'partial',
  'csrf.method=custom-header': 'partial',
  // Transform Rule Set-Cookie rewrite for httpOnly/secure/sameSite; path/domain
  // appending is best-effort.
  'response.cookies.defaults': 'partial',

  // --- v0.3: request hardening (7) ---
  // No native body-field-deny in WAF — Worker schema-validator.
  'request.denyUnknownFields': 'override-only',
  // No native HMAC/Ed25519 verify in WAF — Worker with crypto.subtle.
  'request.signature': 'override-only',
  // Wirefilter `http.host in {...}`.
  'request.allowedHosts': 'full',
  // Wirefilter can detect *whether* params repeat, can't enforce first/last
  // pick natively. 'reject' is full, 'first'/'last' degrade to Worker.
  'request.duplicateParamPolicy': 'partial',
  'request.duplicateParamPolicy=reject': 'full',
  'request.duplicateParamPolicy=first': 'partial',
  'request.duplicateParamPolicy=last': 'partial',
  // Wirefilter regex on header values. CR/LF/NUL detectable natively.
  'request.headerInjectionGuard': 'full',
  // CF normalizes paths by default; double-encoded edge cases need a Transform Rule.
  'request.pathCanonicalization': 'partial',
  // Binary uploads: extension/double-extension expressible via Wirefilter regex
  // on filename. Magic-byte sniff is Worker-only.
  'request.schema.<param>.extensionAllowlist': 'partial',
  'request.schema.<param>.denyDoubleExtension': 'partial',
  'request.schema.<param>.magicByteCheck': 'override-only',

  // --- v0.3: response / cache (2) ---
  // Each sub-field maps 1:1 to a Modify-Response-Header Transform Rule.
  'response.headers': 'full',
  'response.headers.csp': 'full',
  'response.headers.hsts': 'full',
  'response.headers.frameOptions': 'full',
  'response.headers.contentTypeOptions': 'full',
  'response.headers.referrerPolicy': 'full',
  'response.headers.permissionsPolicy': 'full',
  'response.headers.coop': 'full',
  'response.headers.coep': 'full',
  'response.headers.corp': 'full',
  'response.headers.cacheControl': 'full',
  // Cache Rules custom cache key supports removing headers from the key.
  'cacheable.unkeyedHeadersStrip': 'partial',

  // --- v0.3: protocol-specific (3) ---
  // No native GraphQL parsing in CF WAF.
  'graphql': 'override-only',
  'graphql.maxDepth': 'override-only',
  'graphql.maxComplexity': 'override-only',
  'graphql.maxAliases': 'override-only',
  'graphql.batchLimit': 'override-only',
  'graphql.disableIntrospection': 'override-only',
  'graphql.allowedOperations': 'override-only',
  // Handshake origin check is full (Wirefilter on Upgrade request).
  // Per-message rate / size / connection cap require Durable Objects.
  'websocket': 'partial',
  'websocket.allowedOrigins': 'full',
  'websocket.maxMessageSize': 'override-only',
  'websocket.messageRateLimit': 'override-only',
  'websocket.maxConnectionsPerIdentifier': 'override-only',
  'websocket.idleTimeout': 'override-only',
  // Turnstile is native — everything else is Worker + siteverify.
  'botProtection': 'partial',
  'botProtection.provider=turnstile': 'full',
  'botProtection.provider=recaptcha': 'override-only',
  'botProtection.provider=hcaptcha': 'override-only'
});

/**
 * Per-field observe-mode classification.
 * - 'simulatable': the field's would-be block in enforce becomes a Cloudflare
 *   `log` (Custom Rules) / Rate Limit log-only mode / Worker would-block log
 *   in observe. The customer sees what would have been blocked without
 *   affecting live traffic.
 * - 'always-applied': the field doesn't have an action — it's a Transform Rule
 *   (response-header injection, Set-Cookie defaults, cache-key strip) which
 *   ALWAYS applies regardless of mode. The customer needs to know "observe"
 *   doesn't mean "absolutely nothing changes."
 * - 'partial': sub-fields split — e.g. botProtection turnstile in observe
 *   degrades the challenge to `log`, but the customer's existing Turnstile
 *   widget on origin pages keeps running.
 */
export const CF_SHADOW_MODE_SUPPORT: Readonly<Record<string, ShadowModeSupportEntry>> = Object.freeze({
  // Blocking rules — simulatable: observe flips to `log`.
  'authentication': { support: 'simulatable', note: 'observe: action=log; enforce: action=block (or challenge for mTLS).' },
  'authentication.type': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'authorization': { support: 'simulatable', note: 'observe: log; enforce: block (when ref evaluable at WAF).' },
  'authorization.rules[].value.ref': { support: 'simulatable', note: 'observe: log; enforce: block. jwt.* refs require Worker — Worker honors SHADOW_MODE.' },
  'authorization.resourceLookup': { support: 'simulatable', note: 'Worker emits — Worker reads SHADOW_MODE env binding to log vs deny.' },
  'authentication.allowedAlgorithms': { support: 'simulatable', note: 'Worker emits — JWT alg violations are logged in observe.' },
  'ipPolicy.allow': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'ipPolicy.deny': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'cors': { support: 'partial', note: 'origin block rule: simulatable. Response-header injection (Allow-Methods): always-applied.' },
  'request.contentType': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.maxBodySize': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.allowedHosts': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.duplicateParamPolicy': { support: 'simulatable', note: 'reject: observe=log, enforce=block. first/last: Worker — honors SHADOW_MODE.' },
  'request.headerInjectionGuard': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.pathCanonicalization': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.denyUnknownFields': { support: 'simulatable', note: 'Worker emits — honors SHADOW_MODE binding.' },
  'request.signature': { support: 'simulatable', note: 'Worker emits — honors SHADOW_MODE binding.' },
  'request.schema.<param>.extensionAllowlist': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.schema.<param>.denyDoubleExtension': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'request.schema.<param>.magicByteCheck': { support: 'simulatable', note: 'Worker emits — honors SHADOW_MODE binding.' },
  'rateLimit': { support: 'partial', note: 'observe: action=log, but counters still increment + mitigation_timeout still triggers downstream effects; full no-impact simulation requires `mode: "simulate"` if customer is on a plan that supports it.' },
  'csrf': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'csrf.method=origin-check': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'csrf.method=double-submit': { support: 'simulatable', note: 'observe: log; enforce: block. Token-value compare in Worker honors SHADOW_MODE.' },
  'csrf.method=custom-header': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'graphql': { support: 'simulatable', note: 'Worker emits — depth/complexity violations are logged in observe.' },
  'websocket': { support: 'partial', note: 'handshake origin-check: simulatable. Durable Object per-message caps: simulatable (Worker honors SHADOW_MODE).' },
  'websocket.allowedOrigins': { support: 'simulatable', note: 'observe: log; enforce: block.' },
  'botProtection': { support: 'partial', note: 'turnstile: observe=log, enforce=managed_challenge. recaptcha/hcaptcha: Worker honors SHADOW_MODE.' },
  'botProtection.provider=turnstile': { support: 'simulatable', note: 'observe: log; enforce: managed_challenge.' },
  'botProtection.provider=recaptcha': { support: 'simulatable', note: 'Worker emits — honors SHADOW_MODE binding.' },
  'botProtection.provider=hcaptcha': { support: 'simulatable', note: 'Worker emits — honors SHADOW_MODE binding.' },

  // Always-applied — Transform Rules / Cache Rules don't have an action.
  // These fields ARE applied during observe. Customer needs to know.
  'response.headers': { support: 'always-applied', note: 'Response Header Modification is a Transform Rule — always applied; no action to demote in observe.' },
  'response.headers.csp': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.hsts': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.frameOptions': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.contentTypeOptions': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.referrerPolicy': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.permissionsPolicy': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.coop': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.coep': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.corp': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.headers.cacheControl': { support: 'always-applied', note: 'Always applied; no action to demote in observe.' },
  'response.cookies.defaults': { support: 'always-applied', note: 'Set-Cookie rewrite is a Transform Rule — always applied; no action to demote.' },
  'cacheable.unkeyedHeadersStrip': { support: 'always-applied', note: 'Cache Rule cache-key strip + request-transform strip — always applied; no action.' }
});

/** Generator-contract capability matrix view. */
export function capabilities(): CapabilityMatrix {
  return { fields: { ...CF_CAPABILITIES } };
}

export function lookupCapability(field: string): CfCapability | undefined {
  return CF_CAPABILITIES[field];
}

export function lookupShadowModeSupport(field: string): ShadowModeSupportEntry | undefined {
  return CF_SHADOW_MODE_SUPPORT[field];
}
