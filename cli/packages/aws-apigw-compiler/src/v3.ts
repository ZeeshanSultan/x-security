import type {
  BotProtection,
  Cacheable,
  CookieDefaults,
  GraphqlPolicy,
  ResponsePolicy,
  WebsocketPolicy
} from '@writ/schema';
import { parseByteSize, parseDurationSeconds } from './statements.js';
import { isObserveMode } from './shared.js';
import { noteObserveMode, pushAuthorizer, pushCapability, type V3Builder } from './v3-shared.js';
import {
  compileAllowedHosts,
  compileBinaryParamHardening,
  compileCsrf,
  compileDenyUnknownFields,
  compileDuplicateParamPolicy,
  compileHeaderInjectionGuard,
  compilePathCanonicalization,
  compileRequestSignature,
  compileResourceLookup,
  compileRuleRefAuthorization,
  validateAuthAllowedAlgorithms
} from './v3-request.js';
import type { WafStatement, WebSocketRouteSpec } from './types.js';

export type { V3Builder } from './v3-shared.js';

/** Drive all v0.3-specific emitters for one endpoint. */
export function compileV3(b: V3Builder, baseMatch: WafStatement): void {
  const policy = b.endpoint.policy ?? {};

  // Request-side (in v3-request.ts).
  validateAuthAllowedAlgorithms(b, policy.authentication);
  compileRuleRefAuthorization(b, policy.authentication, policy.authorization);
  compileResourceLookup(b, policy.authorization);
  compileCsrf(b, policy.csrf, baseMatch);
  compileDenyUnknownFields(b, policy.request);
  compileRequestSignature(b, policy.request?.signature);
  compileAllowedHosts(b, policy.request?.allowedHosts, baseMatch);
  compileDuplicateParamPolicy(b, policy.request?.duplicateParamPolicy);
  compileHeaderInjectionGuard(b, policy.request?.headerInjectionGuard, baseMatch);
  compilePathCanonicalization(b, policy.request?.pathCanonicalization);
  compileBinaryParamHardening(b, policy.request);

  // Response / cache / protocol (this file).
  compileResponseCookies(b, policy.response);
  compileResponseHeaders(b, policy.response);
  compileUnkeyedHeadersStrip(b, policy.cacheable);
  compileGraphql(b, policy.graphql);
  compileWebsocket(b, policy.websocket);
  compileBotProtectionV3(b, policy.botProtection);
}

// ────────────────────────────────────────────────────────────────────────────
// #5 — response.cookies.defaults
// ────────────────────────────────────────────────────────────────────────────

function compileResponseCookies(b: V3Builder, resp: ResponsePolicy | undefined): void {
  const defaults = resp?.cookies?.defaults;
  if (!defaults) return;
  const vtl = cookieDefaultsVtl(defaults);
  b.integrationResponses.push({
    StatusCode: 'default',
    ResponseParameters: {},
    ResponseTemplates: { 'application/json': vtl },
    writ: { endpoint_id: b.eid, source_field: 'response.cookies.defaults' }
  });
  pushCapability(b, 'response.cookies.defaults', 'partial', 'Lambda integration response mapping',
    'Gateway fills missing attributes via VTL; pre-existing flags preserved.',
    'always-applied');
  if (isObserveMode(b.mode)) {
    noteObserveMode(b, 'response.cookies.defaults', 'always-applied',
      'Integration response VTL is always applied; observe-mode does not suppress cookie attribute defaults.');
  }
}

function cookieDefaultsVtl(d: CookieDefaults): string {
  const attrs: string[] = [];
  if (d.httpOnly) attrs.push('HttpOnly');
  if (d.secure) attrs.push('Secure');
  if (d.sameSite) attrs.push(`SameSite=${d.sameSite}`);
  if (d.path) attrs.push(`Path=${d.path}`);
  if (d.domain) attrs.push(`Domain=${d.domain}`);
  if (typeof d.maxAge === 'number') attrs.push(`Max-Age=${d.maxAge}`);
  return `## writ: append cookie attrs if absent: ${attrs.join('; ')}`;
}

// ────────────────────────────────────────────────────────────────────────────
// #13 — response.headers
// ────────────────────────────────────────────────────────────────────────────

function compileResponseHeaders(b: V3Builder, resp: ResponsePolicy | undefined): void {
  const h = resp?.headers;
  if (!h) return;
  const params: Record<string, string> = {};
  const add = (name: string, value: string | undefined): void => {
    if (typeof value === 'string' && value.length > 0) {
      params[`gatewayresponse.header.${name}`] = `'${escapeSingleQuotes(value)}'`;
    }
  };
  add('Content-Security-Policy', h.csp);
  if (h.hsts) {
    const parts = [`max-age=${h.hsts.maxAge}`];
    if (h.hsts.includeSubDomains) parts.push('includeSubDomains');
    if (h.hsts.preload) parts.push('preload');
    add('Strict-Transport-Security', parts.join('; '));
  }
  add('X-Frame-Options', h.frameOptions);
  add('X-Content-Type-Options', h.contentTypeOptions);
  add('Referrer-Policy', h.referrerPolicy);
  add('Permissions-Policy', h.permissionsPolicy);
  add('Cross-Origin-Opener-Policy', h.coop);
  add('Cross-Origin-Embedder-Policy', h.coep);
  add('Cross-Origin-Resource-Policy', h.corp);
  add('Cache-Control', h.cacheControl);

  if (Object.keys(params).length === 0) return;

  for (const responseType of ['DEFAULT_4XX', 'DEFAULT_5XX']) {
    b.gatewayResponses.push({
      ResponseType: responseType,
      ResponseParameters: params,
      writ: { endpoint_id: b.eid, source_field: 'response.headers' }
    });
  }
  const integrationParams: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) {
    const headerName = k.replace('gatewayresponse.header.', '');
    integrationParams[`method.response.header.${headerName}`] = v;
  }
  b.integrationResponses.push({
    StatusCode: '200',
    ResponseParameters: integrationParams,
    writ: { endpoint_id: b.eid, source_field: 'response.headers' }
  });

  pushCapability(b, 'response.headers', 'partial', 'Gateway Responses (4xx/5xx) + integration response (2xx)',
    'Full coverage requires CloudFront response-headers policy in front.',
    'always-applied');
  if (isObserveMode(b.mode)) {
    noteObserveMode(b, 'response.headers', 'always-applied',
      'Gateway Responses + integration response mapping + (when scope=CLOUDFRONT) CloudFront response-headers policy ' +
      'are always applied; observe-mode does not suppress response-header injection.');
  }
  if (b.scope !== 'CLOUDFRONT') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'response.headers',
      message:
        '2xx response headers are emitted via integration response mapping. For uniform coverage across all ' +
        'response codes (including Lambda-generated errors), front the API with CloudFront and use a ' +
        'response-headers policy.',
      severity: 'info'
    });
  }
}

function escapeSingleQuotes(s: string): string {
  return s.replace(/'/g, "\\'");
}

// ────────────────────────────────────────────────────────────────────────────
// #14 — cacheable.unkeyedHeadersStrip
// ────────────────────────────────────────────────────────────────────────────

function compileUnkeyedHeadersStrip(b: V3Builder, cache: Cacheable | undefined): void {
  if (!cache || typeof cache === 'boolean') return;
  const strip = cache.unkeyedHeadersStrip;
  if (!strip || strip.length === 0) return;
  b.cloudFrontCachePolicies.push({
    Name: `${b.prefix}-${b.ehash}-cache-policy`.slice(0, 64),
    ParametersInCacheKeyAndForwardedToOrigin: {
      HeadersConfig: { HeaderBehavior: 'none' },
      CookiesConfig: { CookieBehavior: 'none' },
      QueryStringsConfig: { QueryStringBehavior: 'all' },
      EnableAcceptEncodingGzip: true,
      EnableAcceptEncodingBrotli: true
    },
    StrippedRequestHeaders: [...strip],
    writ: { endpoint_id: b.eid, source_field: 'cacheable.unkeyedHeadersStrip' }
  });
  if (b.scope !== 'CLOUDFRONT') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'cacheable.unkeyedHeadersStrip',
      message:
        'API Gateway cache is keyed on path only and cannot strip request headers from the key. ' +
        'Emitted a CloudFront cache policy; front the API with CloudFront to take effect.',
      severity: 'warn'
    });
  }
  pushCapability(b, 'cacheable.unkeyedHeadersStrip', 'partial', 'CloudFront cache policy',
    'API GW native cache is path-keyed only; CloudFront policy provides true unkeyed header stripping.',
    'always-applied');
  if (isObserveMode(b.mode)) {
    noteObserveMode(b, 'cacheable.unkeyedHeadersStrip', 'always-applied',
      'CloudFront cache policy is always applied; observe-mode does not suppress header stripping.');
  }
}

// ────────────────────────────────────────────────────────────────────────────
// #15 — graphql
// ────────────────────────────────────────────────────────────────────────────

function compileGraphql(b: V3Builder, gql: GraphqlPolicy | undefined): void {
  if (!gql) return;
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-graphql`,
    Type: 'REQUEST',
    IdentitySource: [`$request.body`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: 'graphql-limits',
      config: {
        maxDepth: gql.maxDepth,
        maxComplexity: gql.maxComplexity,
        maxAliases: gql.maxAliases,
        batchLimit: gql.batchLimit,
        disableIntrospection: gql.disableIntrospection,
        allowedOperations: gql.allowedOperations
      }
    },
    writ: { endpoint_id: b.eid, source_field: 'graphql' }
  });
  pushCapability(b, 'graphql', 'partial', 'Lambda authorizer (graphql-armor or AST walker)',
    'API Gateway has no GraphQL-aware primitive; AppSync is out of scope for this compiler.',
    'simulatable');
  b.warnings.push({
    endpoint_id: b.eid,
    field: 'graphql',
    message:
      'GraphQL depth/complexity/alias limits require a Lambda authorizer that parses the body. ' +
      'If on AppSync, consider EvaluationRules instead.',
    severity: 'info'
  });
}

// ────────────────────────────────────────────────────────────────────────────
// #16 — websocket
// ────────────────────────────────────────────────────────────────────────────

function compileWebsocket(b: V3Builder, ws: WebsocketPolicy | undefined): void {
  if (!ws) return;
  let maxBytes: number | undefined;
  if (ws.maxMessageSize) {
    try { maxBytes = parseByteSize(ws.maxMessageSize); } catch { /* leave undefined */ }
  }
  let idleSec: number | undefined;
  if (ws.idleTimeout) {
    try { idleSec = parseDurationSeconds(ws.idleTimeout); } catch { /* leave undefined */ }
  }
  if (typeof maxBytes === 'number' && maxBytes > 128 * 1024) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'websocket.maxMessageSize',
      message: 'API Gateway WebSocket APIs cap message size at 128KB; ' +
        `${ws.maxMessageSize} exceeds the platform max.`,
      severity: 'warn'
    });
  }
  if (typeof idleSec === 'number' && idleSec > 600) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'websocket.idleTimeout',
      message: 'API Gateway WebSocket idle timeout max is 600s (10m); ' +
        `${ws.idleTimeout} will be capped.`,
      severity: 'warn'
    });
  }
  let messageRate: { messages: number; windowSeconds: number } | undefined;
  if (ws.messageRateLimit) {
    try {
      messageRate = {
        messages: ws.messageRateLimit.messages,
        windowSeconds: parseDurationSeconds(ws.messageRateLimit.window)
      };
    } catch { /* leave undefined */ }
  }
  const route: WebSocketRouteSpec = {
    RouteKey: '$connect',
    AllowedOrigins: [...ws.allowedOrigins],
    writ: { endpoint_id: b.eid, source_field: 'websocket' }
  };
  if (typeof idleSec === 'number') route.IdleTimeoutSeconds = idleSec;
  if (typeof ws.maxConnectionsPerIdentifier === 'number') {
    route.MaxConnectionsPerIdentifier = ws.maxConnectionsPerIdentifier;
  }
  if (typeof maxBytes === 'number') route.MaxMessageSizeBytes = maxBytes;
  if (messageRate) route.MessageRateLimit = messageRate;
  b.webSocketRoutes.push(route);
  pushCapability(b, 'websocket', 'partial', 'API GW WebSocket $connect + WAFv2 + Lambda',
    'Origin allowlist on handshake; message-level limits enforced by attached Lambda.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #17 — botProtection (object form, v0.3)
// ────────────────────────────────────────────────────────────────────────────

function compileBotProtectionV3(b: V3Builder, bp: BotProtection | undefined): void {
  if (!bp) return;
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-bot-${bp.provider}`,
    Type: 'REQUEST',
    IdentitySource: [`$request.header.x-bot-token`],
    AuthorizerResultTtlInSeconds: 60,
    template: {
      kind: 'bot-protection-siteverify',
      config: {
        provider: bp.provider,
        secretRef: bp.secretRef,
        threshold: bp.threshold ?? 0.5,
        mode: bp.mode
      }
    },
    writ: { endpoint_id: b.eid, source_field: 'botProtection' }
  });
  pushCapability(b, 'botProtection', 'override-only', 'Lambda authorizer (siteverify)',
    'AWS WAF Bot Control is a different provider; Turnstile/reCAPTCHA/hCaptcha require Lambda siteverify.',
    'simulatable');
  b.warnings.push({
    endpoint_id: b.eid,
    field: 'botProtection',
    message:
      `Provider '${bp.provider}' does not map to AWS Managed Bot Control. ` +
      'Lambda authorizer calls the provider siteverify endpoint; supply the secret via targetOverrides.aws-apigw.',
    severity: 'info'
  });
}
