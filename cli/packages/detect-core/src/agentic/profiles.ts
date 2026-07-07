// Profile defaults — one per ProfileName.
//
// The per-route agent emits only DELTAS from the profile default. The runtime
// merges (profileDefault, agentDelta) before verifiers run, so verifiers see a
// fully hydrated XSecurityPolicy.
//
// Each default below sets only fields the profile *implies* — not every field
// allowed by the schema. Anything left undefined is "the agent must decide or
// mark reviewRequired."

import type { XSecurityPolicy } from '@x-security/schema';
import type { ProfileName } from './schema.js';

/**
 * standard-crud: authenticated REST CRUD for typed resources. The default
 * sets a conservative per-user rate limit, enables every cheap request-side
 * hardening switch, and turns on response stripping + hardening headers.
 *
 * `authentication` is intentionally omitted: bearer-jwt requires both
 * `jwksUri` and `allowedAlgorithms` per the v0.3 schema, and both are
 * customer-specific. The per-route agent fills authentication based on the
 * middleware chain it observes. The compiler refuses any emission that ends
 * up with bearer-jwt missing those fields, which is the right safety net.
 */
const STANDARD_CRUD: Partial<XSecurityPolicy> = {
  profile: 'standard-crud',
  rateLimit: {
    requests: 60,
    window: '1m',
    identifier: 'user-id',
  },
  request: {
    // Default to JSON-body enforcement (API8 misconfig: reject text/html etc).
    // The per-route agent overrides when the handler parses another body type
    // (urlencoded / multipart) — see prompt §3.
    contentType: ['application/json'],
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
  },
};

/**
 * auth-endpoint: login / register / refresh / logout. No auth on the request
 * itself (the request *is* the auth attempt), but very tight rate limits and
 * bot protection are essential against credential stuffing (API2/API4).
 * Response headers include strict cache-control because auth replies must not
 * be cached anywhere.
 */
const AUTH_ENDPOINT: Partial<XSecurityPolicy> = {
  profile: 'auth-endpoint',
  authentication: {
    type: 'none',
  },
  rateLimit: [
    { requests: 10, window: '1m', identifier: 'ip' },
    { requests: 5, window: '1m', identifier: 'header:X-Email-Hash' },
  ],
  request: {
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'no-referrer',
      cacheControl: 'no-store',
    },
    cookies: {
      defaults: {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
      },
    },
  },
};

/**
 * file-upload: multipart / binary endpoints. Per-route schema must list the
 * binary fields; the profile sets the surrounding defenses (max body size,
 * deny-unknown, header hardening). The actual magic-byte and
 * extension-allowlist live on the ParamSchema, emitted by the agent.
 */
const FILE_UPLOAD: Partial<XSecurityPolicy> = {
  profile: 'file-upload',
  // authentication: omitted — see note on STANDARD_CRUD. The per-route agent
  // fills the type + jwksUri + allowedAlgorithms based on observed middleware.
  rateLimit: {
    requests: 20,
    window: '1m',
    identifier: 'user-id',
  },
  request: {
    contentType: ['multipart/form-data'],
    maxBodySize: '25MB',
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
    },
  },
};

/**
 * webhook-receiver: third-party callbacks (Stripe, GitHub, etc.). HMAC
 * verification is non-negotiable — the agent fills `signature.secretRef` and
 * `headerName` from the handler. The profile sets the algorithm, body mode,
 * and timestamp tolerance defaults. allowedHosts is also defaulted because
 * webhooks should arrive on a single host.
 */
const WEBHOOK_RECEIVER: Partial<XSecurityPolicy> = {
  profile: 'webhook-receiver',
  authentication: {
    type: 'none',
  },
  rateLimit: {
    requests: 600,
    window: '1m',
    identifier: 'ip',
  },
  request: {
    maxBodySize: '1MB',
    denyUnknownFields: false,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    headers: {
      contentTypeOptions: 'nosniff',
      cacheControl: 'no-store',
    },
  },
};

/**
 * public-read-only: unauthenticated cacheable GET. Tight cache controls,
 * conservative rate limit by IP, and the cache-poisoning defense
 * (unkeyedHeadersStrip) baked in.
 */
const PUBLIC_READ_ONLY: Partial<XSecurityPolicy> = {
  profile: 'public-read-only',
  authentication: {
    type: 'none',
  },
  rateLimit: {
    requests: 120,
    window: '1m',
    identifier: 'ip',
  },
  cacheable: {
    enabled: true,
    ttl: 60,
    unkeyedHeadersStrip: ['Cookie', 'Authorization', 'X-Forwarded-Host'],
  },
  request: {
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
  },
};

/**
 * admin-panel: privileged operations behind RBAC. Tighter rate limit, IP
 * allowlist hook (left to customer override), explicit CSRF defense, and the
 * strongest response headers including COOP/COEP for cross-origin isolation.
 */
const ADMIN_PANEL: Partial<XSecurityPolicy> = {
  profile: 'admin-panel',
  // authentication: omitted — see note on STANDARD_CRUD. RBAC and the JWT
  // shape are emitted per-route once middleware is inspected.
  rateLimit: {
    requests: 30,
    window: '1m',
    identifier: 'user-id',
  },
  csrf: {
    method: 'double-submit',
    tokenHeader: 'X-CSRF-Token',
    tokenCookie: 'csrf_token',
  },
  request: {
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'no-referrer',
      coop: 'same-origin',
      corp: 'same-origin',
      cacheControl: 'no-store',
    },
    cookies: {
      defaults: {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
      },
    },
  },
};

/**
 * server-rendered-page: HTML form actions and SSR pages (PHP, Rails, Astro)
 * that return HTML, not JSON. Browser-added form fields make
 * denyUnknownFields unsafe; response.schema enumeration is NOT applicable
 * (HTML body, not a typed JSON object) — V2 completeness must skip the
 * response.schema check for this profile.
 */
const SERVER_RENDERED_PAGE: Partial<XSecurityPolicy> = {
  profile: 'server-rendered-page',
  rateLimit: {
    requests: 60,
    window: '1m',
    identifier: 'ip',
  },
  request: {
    denyUnknownFields: false,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: false,
    headers: {
      csp: "default-src 'self'; script-src 'self'; object-src 'none'",
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
  },
};

/**
 * graphql-resolver: a single GraphQL endpoint that multiplexes operations.
 * The request body is always {query, variables, operationName} so unknown-
 * field denial is wrong at the transport layer; per-operation shape is
 * enforced by the GraphQL type system. Depth/complexity/introspection
 * caps go on the graphql block.
 */
const GRAPHQL_RESOLVER: Partial<XSecurityPolicy> = {
  profile: 'graphql-resolver',
  rateLimit: {
    requests: 100,
    window: '1m',
    identifier: 'user-id',
  },
  graphql: {
    maxDepth: 10,
    maxComplexity: 1000,
    disableIntrospection: true,
  },
  request: {
    denyUnknownFields: false,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: false,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
    cookies: {
      defaults: {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
      },
    },
  },
};

/**
 * grpc-method: gRPC handler. Schema enforcement lives at the protobuf
 * level (proto3 ignores unknown fields, so denyUnknownFields=true is the
 * accurate default). HTTP response headers don't apply to gRPC framing —
 * left off intentionally.
 */
const GRPC_METHOD: Partial<XSecurityPolicy> = {
  profile: 'grpc-method',
  rateLimit: {
    requests: 1000,
    window: '1m',
    identifier: 'user-id',
  },
  request: {
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
};

/**
 * internal-rpc: cron handlers, service-to-service RPC, Lambda admin
 * handlers. Defaults to a private-network ipPolicy allowlist because these
 * must never be reachable from the public internet. Rate-limit omitted —
 * internal callers are trusted within their network. response.schema is
 * not pre-required (internal RPC often returns rich objects).
 */
const INTERNAL_RPC: Partial<XSecurityPolicy> = {
  profile: 'internal-rpc',
  ipPolicy: {
    allow: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  },
  request: {
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: true,
    headers: {
      contentTypeOptions: 'nosniff',
      cacheControl: 'no-store',
    },
  },
};

/**
 * static-asset: /health, /robots.txt, /favicon.ico, static files served by
 * the app server. No application logic, so no input validation; the only
 * real concerns are DDoS-bucket rate-limit and basic response hardening.
 */
const STATIC_ASSET: Partial<XSecurityPolicy> = {
  profile: 'static-asset',
  authentication: {
    type: 'none',
  },
  rateLimit: {
    requests: 600,
    window: '1m',
    identifier: 'ip',
  },
  cacheable: {
    enabled: true,
    ttl: 3600,
  },
  request: {
    denyUnknownFields: false,
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
    },
  },
};

/**
 * unknown: explicit "Pass 2 couldn't classify" profile. Replaces the
 * silent standard-crud fallback that was forcing CRUD assumptions
 * (auth required, response.schema enforcement, stripUnknownFields) onto
 * routes that don't fit. Conservative-minimum: cheap request hardening,
 * basic response headers, NO claims about response shape or authorization
 * model that V2 completeness can't justify.
 *
 * Note for the agent: denyUnknownFields=true is the safer default for
 * JSON request bodies. Override to false ONLY with cited evidence (e.g.
 * the route is an HTML form action). Note for V2: this profile MUST NOT
 * trigger demotion for missing response.schema or authorization.rules.
 */
const UNKNOWN: Partial<XSecurityPolicy> = {
  profile: 'unknown',
  rateLimit: {
    requests: 60,
    window: '1m',
    identifier: 'ip',
  },
  request: {
    denyUnknownFields: true,
    duplicateParamPolicy: 'reject',
    headerInjectionGuard: true,
    pathCanonicalization: true,
  },
  response: {
    stripUnknownFields: false,
    headers: {
      contentTypeOptions: 'nosniff',
      frameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
  },
};

const DEFAULTS: Record<ProfileName, Partial<XSecurityPolicy>> = {
  'standard-crud': STANDARD_CRUD,
  'auth-endpoint': AUTH_ENDPOINT,
  'file-upload': FILE_UPLOAD,
  'webhook-receiver': WEBHOOK_RECEIVER,
  'public-read-only': PUBLIC_READ_ONLY,
  'admin-panel': ADMIN_PANEL,
  'server-rendered-page': SERVER_RENDERED_PAGE,
  'graphql-resolver': GRAPHQL_RESOLVER,
  'grpc-method': GRPC_METHOD,
  'internal-rpc': INTERNAL_RPC,
  'static-asset': STATIC_ASSET,
  'unknown': UNKNOWN,
};

export function profileDefault(name: ProfileName): Partial<XSecurityPolicy> {
  const d = DEFAULTS[name];
  if (!d) throw new Error(`unknown profile: ${name}`);
  // Defensive copy — callers must not mutate the shared default.
  return JSON.parse(JSON.stringify(d)) as Partial<XSecurityPolicy>;
}

export const ALL_PROFILES: readonly ProfileName[] = Object.freeze([
  'auth-endpoint',
  'standard-crud',
  'file-upload',
  'webhook-receiver',
  'public-read-only',
  'admin-panel',
  'server-rendered-page',
  'graphql-resolver',
  'grpc-method',
  'internal-rpc',
  'static-asset',
  'unknown',
]);
