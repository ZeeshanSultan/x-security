// AWS API Gateway per-field capability matrix.
//
// Single source of truth for "how well does the aws-apigw compiler enforce
// this v0.3 x-security field?" — consumed by `capabilities()` for the
// @writ/core `Generator` contract (the CLI feasibility/report registry).
//
// D-1 (security product): every level here MUST mirror what the compiler
// genuinely emits. The provenance comment on each entry names the emitter
// (file + the `pushCapability(...)` / `pushRule(...)` call) it was sourced
// from. These are deployment-conditional fulls — the compiler emits the
// primitive that achieves the level when the field is present; it does not
// fabricate coverage. Levels:
//   - full          → a gateway-tier primitive fully enforces the field
//   - partial       → primitive covers the common case; edge cases degrade
//   - override-only → no native lowering; needs targetOverrides.aws-apigw / Lambda
//   - unsupported   → the compiler cannot express this at the gateway tier

import type { CapabilityLevel } from './types.js';

/**
 * Per-field decision table. Keys are XSecurityPolicy field paths matching the
 * CLI feasibility probe keys. Every entry is backed by a real emitter:
 *
 *  v2 layer (WAFv2 rules / Usage Plans — packages/.../v2.ts):
 *    - authentication.{bearer-jwt,api-key,oauth2,basic}  pushRule kind:'auth'
 *    - ipPolicy.{allow,deny}                              pushRule kind:'ip-*'
 *    - cors                                               pushRule kind:'cors-origin'
 *    - request.maxBodySize                                pushRule kind:'body-size'
 *    - request.contentType                                pushRule kind:'content-type'
 *    - rateLimit                                          pushRule kind:'ratelimit-*' / Usage Plan
 *    - mtls                                               b.unsupported (custom-domain only)
 *    - request.schema (no denyUnknownFields)              b.unsupported
 *
 *  v3 layer (pushCapability — packages/.../v3-request.ts + v3.ts):
 *    each level below is the exact `level` argument of the matching
 *    pushCapability(b, '<field>', '<level>', ...) call.
 */
export const AWS_APIGW_CAPABILITIES: Readonly<Record<string, CapabilityLevel>> = Object.freeze({
  // ── authentication ──────────────────────────────────────────────────────
  // v2: WAFv2 enforces Bearer/api-key/oauth2/basic header *presence* only
  // (compileAuth, pushRule kind:'auth'). Full signature/issuer/audience needs
  // a Lambda/Cognito authorizer — partial at the gateway alone.
  'authentication.bearer-jwt': 'partial',
  'authentication.api-key': 'partial',
  'authentication.oauth2': 'partial',
  'authentication.basic': 'partial',
  // v3: validateAuthAllowedAlgorithms → pushCapability('authentication.allowedAlgorithms','full', Lambda authorizer).
  'authentication.allowedAlgorithms': 'full',

  // ── authorization ───────────────────────────────────────────────────────
  // v3: compileRuleRefAuthorization → pushCapability(...,'authorization.rules[].value(RuleRef)','full').
  // The RuleRef path is how rule-based authz is enforced (Lambda authorizer
  // dereferences JWT claims → IAM policy). Expose under the probe key.
  'authorization.rule-based': 'full',
  // v3: compileResourceLookup → pushCapability('authorization.resourceLookup','full', Lambda authorizer).
  'authorization.resourceLookup': 'full',

  // ── rate limiting ───────────────────────────────────────────────────────
  // v2: emitRateLimit → WAFv2 RateBasedStatement (IP/forwarded-IP) or Usage
  // Plan throttle+quota for api-key. Composite keys/sub-100 limits degrade
  // (warnings) but the core rate limit is enforced → full.
  'rateLimit': 'full',

  // ── cors ────────────────────────────────────────────────────────────────
  // v2: compileCors → WAFv2 origin-block rule (MEDIUM confidence; allowedMethods
  // is a response-header concern WAF can't set) → partial.
  'cors': 'partial',

  // ── ipPolicy ────────────────────────────────────────────────────────────
  // v2: compileIpPolicy → WAFv2 IPSet ALLOW/DENY rules (HIGH).
  'ipPolicy.allow': 'full',
  'ipPolicy.deny': 'full',

  // ── request hardening ───────────────────────────────────────────────────
  // v2: compileRequest → WAFv2 content-type STARTS_WITH allowlist (HIGH).
  'request.contentType': 'full',
  // v2: compileRequest → WAFv2 body-size rule (HIGH).
  'request.maxBodySize': 'full',
  // v3: compileDenyUnknownFields → pushCapability('request.denyUnknownFields','full',
  // API Gateway request validator + JSON Schema model, additionalProperties:false).
  'request.denyUnknownFields': 'full',
  // v3: the same denyUnknownFields path emits a typed JSON Schema body model
  // (paramSchemaToJsonSchema → minLength/maxLength/pattern/min/max/type per field).
  // When denyUnknownFields is set the per-field constraints are fully enforced
  // by the request validator → full. Probe API6/API8 key.
  'request.schema': 'full',
  // v3: compileBinaryParamHardening → pushCapability('request.schema.<binary>','partial',
  // Lambda authorizer + extension regex). Magic-byte sniff is Lambda-side.
  'request.schema.binary': 'partial',
  // v3: compileRequestSignature → pushCapability('request.signature','full', Lambda authorizer HMAC verify).
  'request.signature': 'full',
  // v3: compileAllowedHosts → pushCapability('request.allowedHosts','full', WAFv2 Host header match).
  'request.allowedHosts': 'full',
  // v3: compileDuplicateParamPolicy → pushCapability('request.duplicateParamPolicy','partial', Lambda authorizer).
  'request.duplicateParamPolicy': 'partial',
  // v3: compileHeaderInjectionGuard → pushCapability('request.headerInjectionGuard','full', WAFv2 regex on header values).
  'request.headerInjectionGuard': 'full',
  // v3: compilePathCanonicalization → pushCapability(...,'partial'/'full', WAFv2 regex (+CloudFront)).
  // REGIONAL scope (the compiler default) emits 'partial'; CLOUDFRONT yields 'full'.
  // The registry loads without a deploy scope, so report the conservative level.
  'request.pathCanonicalization': 'partial',

  // ── csrf ────────────────────────────────────────────────────────────────
  // v3: compileCsrf → pushCapability('csrf','partial', WAFv2 origin allowlist OR Lambda authorizer).
  'csrf': 'partial',

  // ── response / cache ────────────────────────────────────────────────────
  // v3: compileResponseHeaders → pushCapability('response.headers','partial',
  // Gateway Responses (4xx/5xx) + integration response (2xx); full needs CloudFront).
  'response.headers': 'partial',
  // v3: compileResponseCookies → pushCapability('response.cookies.defaults','partial', integration response VTL).
  'response.cookies.defaults': 'partial',
  // v3: compileUnkeyedHeadersStrip → pushCapability('cacheable.unkeyedHeadersStrip','partial', CloudFront cache policy).
  'cacheable.unkeyedHeadersStrip': 'partial',

  // ── protocol-specific ───────────────────────────────────────────────────
  // v3: compileGraphql → pushCapability('graphql','partial', Lambda authorizer AST walker).
  'graphql': 'partial',
  // v3: compileWebsocket → pushCapability('websocket','partial', API GW WebSocket $connect + WAFv2 + Lambda).
  'websocket': 'partial',
  // v3: compileBotProtectionV3 → pushCapability('botProtection','override-only', Lambda siteverify).
  'botProtection': 'override-only',

  // ── explicitly unsupported at the gateway tier ──────────────────────────
  // v2: compileAuth mtls → b.unsupported (configured at custom-domain truststore, not WAF).
  'mtls': 'unsupported',
  // No native deprecation/sunset primitive in API Gateway/WAFv2.
  'deprecated': 'unsupported',
  'sunsetDate': 'unsupported',
  // No request-side timeout primitive (integration timeout is fixed, not policy-driven).
  'timeout': 'unsupported',
  // No response-body shaping in API Gateway/WAFv2 (no stripUnknownFields on responses).
  'response.schema': 'unsupported',
  'response.stripUnknownFields': 'unsupported'
});

/** Generator-contract capability matrix view. */
export function capabilities(): { fields: Record<string, CapabilityLevel> } {
  return { fields: { ...AWS_APIGW_CAPABILITIES } };
}

export function lookupCapability(field: string): CapabilityLevel | undefined {
  return AWS_APIGW_CAPABILITIES[field];
}
