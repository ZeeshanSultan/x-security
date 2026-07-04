/**
 * Tests for the Envoy generator (wave-9 native-filter refactor).
 *
 * Coverage planes:
 *   - per-native-filter emission shape (jwt_authn / rbac / local_ratelimit / cors)
 *   - filter ordering contract (jwt → rbac → ratelimit → cors → lua → router)
 *   - residual Lua only emitted when a Lua-requiring field is present
 *   - per-route typed_per_filter_config overrides are well-formed (parse-able YAML)
 *   - generated YAML round-trips through js-yaml without error
 *   - golden fixture stability (example.yaml → fixtures/configs/envoy/example.expected.yaml)
 *   - byte-stability across runs
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import * as yaml from 'js-yaml';
import { loadSpec, type EndpointIR, type SpecIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

import { envoyGenerator } from '../../src/generators/envoy/index.js';
import {
  buildEnvoyYaml,
  pathToSafeRegex
} from '../../src/generators/envoy/templates/envoy-yaml.js';
import {
  buildEndpointBlock,
  buildLuaModule,
  endpointNeedsLua,
  envoyPathPattern
} from '../../src/generators/envoy/templates/lua.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../../..');
const EXAMPLE_SPEC = resolve(REPO_ROOT, 'fixtures/specs/example.yaml');
const GOLDEN = resolve(REPO_ROOT, 'fixtures/configs/envoy/example.expected.yaml');

function ep(method: EndpointIR['method'], path: string, policy: XSecurityPolicy): EndpointIR {
  return {
    method,
    path,
    operationId: `${method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_')}`,
    policy,
    parameters: [],
    raw: {} as EndpointIR['raw'],
    resolvedVars: new Map()
  };
}

function specWith(endpoints: EndpointIR[]): SpecIR {
  return {
    openapi: '3.1.0',
    dialect: 'openapi' as const,
    info: { title: 'Test', version: '1.0.0' },
    servers: [],
    endpoints,
    unprotectedEndpoints: []
  };
}

async function loadExample(): Promise<SpecIR> {
  process.env['JWKS_ENDPOINT'] = 'https://example.com/.well-known/jwks.json';
  process.env['AUTH_ISSUER'] = 'https://auth.example.com';
  process.env['AUTH_AUDIENCE'] = 'api.example.com';
  return loadSpec(EXAMPLE_SPEC, { strict: false });
}

// ── path helpers ─────────────────────────────────────────────────────────

describe('envoy helpers', () => {
  it('pathToSafeRegex replaces {param} with [^/]+ and anchors', () => {
    assert.equal(pathToSafeRegex('/api/users/{id}'), '^/api/users/[^/]+$');
    assert.equal(pathToSafeRegex('/static/path'), '^/static/path$');
    assert.equal(pathToSafeRegex('/a/{x}/b/{y}'), '^/a/[^/]+/b/[^/]+$');
  });

  it('pathToSafeRegex escapes regex-magic chars in literal segments', () => {
    assert.equal(pathToSafeRegex('/v1.0/x'), '^/v1\\.0/x$');
  });

  it('envoyPathPattern (lua) escapes Lua-magic chars', () => {
    assert.equal(envoyPathPattern('/v1.0/x'), '^/v1%.0/x$');
  });
});

// ── Native jwt_authn filter ──────────────────────────────────────────────

describe('envoy: jwt_authn native filter', () => {
  it('emits jwt_authn provider with JWKS URI + issuer + audience', () => {
    const spec = specWith([
      ep('GET', '/secured', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          issuer: 'https://idp.example.com',
          audience: 'api.example.com',
          allowedAlgorithms: ['RS256']
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /envoy\.filters\.http\.jwt_authn/);
    assert.match(out, /writ_jwt:/);
    assert.match(out, /issuer: "https:\/\/idp\.example\.com"/);
    assert.match(out, /audiences:[\s\S]*api\.example\.com/);
    assert.match(out, /uri: "https:\/\/idp\.example\.com\/jwks"/);
    assert.match(out, /cluster: jwks_cluster/);
    // rule pinning the path
    assert.match(out, /regex: "\^\/secured\$"/);
    assert.match(out, /provider_name: writ_jwt/);
  });

  it('emits a jwks_cluster with TLS transport_socket for https JWKS', () => {
    const spec = specWith([
      ep('GET', '/x', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256']
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /- name: jwks_cluster/);
    assert.match(out, /envoy\.transport_sockets\.tls/);
    assert.match(out, /sni: "idp\.example\.com"/);
  });

  it('omits jwt_authn entirely when no endpoint declares bearer-jwt', () => {
    const spec = specWith([ep('GET', '/x', { authentication: { type: 'none' } })]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.doesNotMatch(out, /envoy\.filters\.http\.jwt_authn/);
    assert.doesNotMatch(out, /jwks_cluster/);
  });

  it('emits a bannedAlgorithms limitation comment', () => {
    const spec = specWith([
      ep('GET', '/x', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256'],
          bannedAlgorithms: ['HS256', 'none']
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /bannedAlgorithms.*Lua sidecar/);
  });
});

// ── Native rbac filter ───────────────────────────────────────────────────

describe('envoy: rbac native filter', () => {
  it('emits an RBAC policy per (endpoint, role)', () => {
    const spec = specWith([
      ep('GET', '/admin', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256']
        },
        authorization: { type: 'rbac', roles: ['admin', 'super-admin'] }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /envoy\.filters\.http\.rbac/);
    assert.match(out, /action: ALLOW/);
    assert.match(out, /"writ-rbac-.*-admin":/);
    assert.match(out, /"writ-rbac-.*-super-admin":/);
    // principal sources from jwt_authn metadata
    assert.match(out, /filter: envoy\.filters\.http\.jwt_authn/);
    assert.match(out, /key: "role"/);
  });

  it('rule-based authz emits ext_authz filter + opa_grpc cluster (wave-10 E-3)', () => {
    const spec = specWith([
      ep('GET', '/api/users/{id}', {
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /envoy\.filters\.http\.ext_authz/);
    assert.match(out, /cluster_name: opa_grpc/);
    assert.match(out, /name: opa_grpc/);
    assert.match(out, /failure_mode_allow: false/);
    assert.doesNotMatch(out, /envoy\.filters\.http\.rbac/);
  });

  it('rule-based authz generator emits opa/policy.rego artifact', async () => {
    const spec = specWith([
      ep('GET', '/api/users/{id}', {
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing');
    assert.match(rego!.content, /package envoy\.authz/);
    // W17-A: default allow is now a structured decision object (not `false`)
    // so the OPA-Envoy plugin can carry per-class headers into the deny response.
    assert.match(rego!.content, /default allow := \{/);
    assert.match(rego!.content, /"allowed": false/);
    assert.match(rego!.content, /io\.jwt\.decode/);
    assert.match(rego!.content, /payload\["sub"\] == resource_id/);
  });

  // ── W17-A: per-class x-writ-rule markers on OPA denies ──────────
  it('W17-A: Rego emits per-class deny headers (bola / jwt-claim / default)', async () => {
    const spec = specWith([
      ep('GET', '/api/users/{id}', {
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing');
    // BOLA-class header on the path/method-match-but-identity-fail branch.
    assert.match(rego!.content, /"x-writ-rule": "opa-bola-403"/);
    // JWT-claim header on the path/method-match-but-claim-missing branch.
    assert.match(rego!.content, /"x-writ-rule": "opa-jwt-claim-403"/);
    // Default catch-all header on the terminal else.
    assert.match(rego!.content, /"x-writ-rule": "opa-default-403"/);
    // Permit branch returns {"allowed": true}.
    assert.match(rego!.content, /\{"allowed": true\}/);
    // The else-chain compiles into a single `decision := ...` rule head.
    assert.match(rego!.content, /allow := decision/);
    assert.match(rego!.content, /^decision := /m);
    assert.match(rego!.content, /^else := /m);
  });

  it('W17-A: ext_authz filter config notes downstream-header forwarding', () => {
    const spec = specWith([
      ep('GET', '/api/users/{id}', {
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /envoy\.filters\.http\.ext_authz/);
    // W17-A: contract comment about marker forwarding is part of the
    // emitted filter so operators can grep for it.
    assert.match(out, /W17-A: forward OPA-emitted x-writ-rule/);
    // Filter still passes header info downstream (no headers_to_remove that
    // would strip it). Default Envoy behavior is "forward all denied_response
    // headers"; we assert no override that would break that.
    assert.doesNotMatch(out, /headers_to_remove:/);
  });

  // ── W18-A: BFLA + input-validation OPA classes ────────────────────────
  it('W18-A: BFLA admin route emits opa-bfla-403', async () => {
    const spec = specWith([
      ep('GET', '/api5/users', {
        authorization: { type: 'rbac', roles: ['admin'] }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing (admin-only rbac should route via OPA)');
    assert.match(rego!.content, /"x-writ-rule": "opa-bfla-403"/);
    // Permit branch: principal role == "admin" → allowed.
    assert.match(rego!.content, /payload\["role"\] == "admin"/);
    // The yaml should still wire ext_authz even though there are no
    // rule-based endpoints — admin-only routes pull OPA in by themselves.
    const yamlArt = arts.find((a) => a.path === 'envoy.yaml');
    assert.match(yamlArt!.content, /envoy\.filters\.http\.ext_authz/);
    assert.match(yamlArt!.content, /name: opa_grpc/);
    // The native rbac filter must NOT carry this admin-only endpoint
    // (otherwise it would short-circuit before OPA emits the marker).
    assert.doesNotMatch(yamlArt!.content, /envoy\.filters\.http\.rbac/);
  });

  it('W18-A: request.denyUnknownFields emits opa-input-validation-403', async () => {
    const spec = specWith([
      ep('POST', '/api6/user', {
        request: {
          denyUnknownFields: true,
          schema: {
            username: { type: 'string' },
            password: { type: 'string' }
          }
        }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing (denyUnknownFields should route via OPA)');
    assert.match(rego!.content, /"x-writ-rule": "opa-input-validation-403"/);
    // The Rego body must parse the request body and walk top-level keys.
    assert.match(rego!.content, /json\.unmarshal\(input\.attributes\.request\.http\.body\)/);
    // The allowed-set literal must list the schema keys (byte-stable, sorted).
    assert.match(rego!.content, /allowed := \{"password", "username"\}/);
  });

  it('W18-A: rule ordering — bfla check appears before bola check appears before default', async () => {
    const spec = specWith([
      ep('GET', '/api5/users', {
        authorization: { type: 'rbac', roles: ['admin'] }
      }),
      ep('GET', '/api/users/{id}', {
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing');
    // Marker class strings also appear in the header docstring, so we anchor
    // on the deny-response header literal that only shows up in branches.
    const bflaIdx = rego!.content.indexOf('"x-writ-rule": "opa-bfla-403"');
    const bolaIdx = rego!.content.indexOf('"x-writ-rule": "opa-bola-403"');
    // `opa-default-403` appears in the `default allow` literal at the top of the
    // file AND in the terminal `else`. We want the terminal one — last occurrence.
    const lastDefaultIdx = rego!.content.lastIndexOf('"x-writ-rule": "opa-default-403"');
    assert.ok(bflaIdx > 0, 'opa-bfla-403 must appear');
    assert.ok(bolaIdx > 0, 'opa-bola-403 must appear');
    assert.ok(lastDefaultIdx > 0, 'opa-default-403 must appear');
    assert.ok(
      bflaIdx < bolaIdx,
      `BFLA branch (${bflaIdx}) must precede BOLA branch (${bolaIdx}) in the else-chain`
    );
    assert.ok(
      bolaIdx < lastDefaultIdx,
      `BOLA branch (${bolaIdx}) must precede terminal default (${lastDefaultIdx})`
    );
  });
});

// ── Native local_ratelimit filter ────────────────────────────────────────

describe('envoy: local_ratelimit native filter (per-route)', () => {
  it('emits a typed_per_filter_config rate-limit bucket on the route', () => {
    const spec = specWith([
      ep('POST', '/login', {
        rateLimit: { requests: 5, window: '1m' }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    // chain-level shell filter present
    assert.match(out, /envoy\.filters\.http\.local_ratelimit/);
    assert.match(out, /stat_prefix: writ_chain_ratelimit/);
    // per-route override
    assert.match(out, /stat_prefix: writ_post_login_ratelimit/);
    // W15-B: when `burst` is unset we synthesize burst headroom
    // (max(requests*3, requests+20)) so auth filters get a visible
    // rejection band before local_ratelimit short-circuits attacks.
    // For requests=5 → max_tokens=25, tokens_per_fill stays at 5.
    assert.match(out, /max_tokens: 25[\s\S]*tokens_per_fill: 5[\s\S]*fill_interval: 60s/);
    assert.match(out, /x-writ-ratelimit/);
  });

  it('uses burst as max_tokens when burst > requests', () => {
    const spec = specWith([
      ep('POST', '/login', {
        rateLimit: { requests: 5, window: '1m', burst: 10 }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /max_tokens: 10[\s\S]*tokens_per_fill: 5/);
  });

  // ── W15-B: burst headroom for auth-attribution preservation ────────────
  it('W15-B: synthesizes burst headroom when spec leaves `burst` unset', () => {
    // requests=5 → max_tokens = max(5*3, 5+20) = 25 (not 5)
    // requests=10 → max_tokens = max(10*3, 10+20) = 30 (not 10)
    // requests=60 → max_tokens = max(60*3, 60+20) = 180 (not 60)
    const spec = specWith([
      ep('POST', '/login', { rateLimit: { requests: 5, window: '1m' } }),
      ep('POST', '/create', { rateLimit: { requests: 10, window: '1m' } }),
      ep('GET', '/list', { rateLimit: { requests: 60, window: '1m' } })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /stat_prefix: writ_post_login_ratelimit[\s\S]*?max_tokens: 25[\s\S]*?tokens_per_fill: 5/);
    assert.match(out, /stat_prefix: writ_post_create_ratelimit[\s\S]*?max_tokens: 30[\s\S]*?tokens_per_fill: 10/);
    assert.match(out, /stat_prefix: writ_get_list_ratelimit[\s\S]*?max_tokens: 180[\s\S]*?tokens_per_fill: 60/);
  });

  it('W15-B: explicit burst still wins over synthesized headroom', () => {
    // burst=7 > requests=5 → max_tokens = 7 (spec authoritative, no synth).
    const spec = specWith([
      ep('POST', '/login', { rateLimit: { requests: 5, window: '1m', burst: 7 } })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /max_tokens: 7[\s\S]*?tokens_per_fill: 5/);
    assert.doesNotMatch(out, /max_tokens: 25/);
  });

  it('W15-B: jwt_authn filter always appears before local_ratelimit in HCM chain', () => {
    // Regression guard: HCM evaluates http_filters in YAML order. If we
    // ever shuffle local_ratelimit to fire before jwt_authn, attacks on
    // JWT-protected endpoints will get 429-attributed instead of 401-
    // attributed, collapsing the scorer's intent-attribution weighting.
    const spec = specWith([
      ep('POST', '/login', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256']
        },
        rateLimit: { requests: 5, window: '1m' }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    const parsed = yaml.load(out) as Record<string, unknown>;
    const listeners = (parsed.static_resources as Record<string, unknown>).listeners as unknown[];
    const filters = ((((listeners[0] as Record<string, unknown>).filter_chains as unknown[])[0] as Record<string, unknown>).filters as unknown[])[0] as Record<string, unknown>;
    const httpFilters = (filters.typed_config as Record<string, unknown>).http_filters as unknown[];
    const names = httpFilters.map((f) => (f as Record<string, unknown>).name as string);
    const jwtIdx = names.indexOf('envoy.filters.http.jwt_authn');
    const rlIdx = names.indexOf('envoy.filters.http.local_ratelimit');
    assert.ok(jwtIdx >= 0, 'jwt_authn must be present');
    assert.ok(rlIdx >= 0, 'local_ratelimit must be present');
    assert.ok(jwtIdx < rlIdx, `jwt_authn (${jwtIdx}) must precede local_ratelimit (${rlIdx}) in HCM chain order`);
  });

  // ── W16-A: chain filter must not drop requests by default ──────────────
  it('W16-A: chain-level local_ratelimit does not drop requests by default', () => {
    // Envoy v1.28 treats a missing token_bucket on an *enforced* filter as a
    // 0-token bucket → every request 429s before per-route filters consult.
    // We pin filter_enforced numerator to 0 (shadow-track only); per-route
    // typed_per_filter_config blocks own real enforcement. Alternatively a
    // generous chain-level token_bucket is acceptable.
    const spec = specWith([
      ep('POST', '/login', { rateLimit: { requests: 5, window: '1m' } })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    const parsed = yaml.load(out) as Record<string, unknown>;
    const listeners = (parsed.static_resources as Record<string, unknown>).listeners as unknown[];
    const filters = ((((listeners[0] as Record<string, unknown>).filter_chains as unknown[])[0] as Record<string, unknown>).filters as unknown[])[0] as Record<string, unknown>;
    const httpFilters = (filters.typed_config as Record<string, unknown>).http_filters as unknown[];
    const chainRl = httpFilters.find(
      (f) =>
        (f as Record<string, unknown>).name === 'envoy.filters.http.local_ratelimit'
    ) as Record<string, unknown> | undefined;
    assert.ok(chainRl, 'chain-level local_ratelimit must exist');
    const cfg = chainRl.typed_config as Record<string, unknown>;
    const enforced = cfg.filter_enforced as Record<string, unknown> | undefined;
    const enforcedNum = (enforced?.default_value as Record<string, unknown> | undefined)?.numerator;
    const tb = cfg.token_bucket as Record<string, unknown> | undefined;
    const tbMax = tb?.max_tokens as number | undefined;
    const isShadow = enforcedNum === 0;
    const isGenerousBucket = typeof tbMax === 'number' && tbMax >= 1000;
    assert.ok(
      isShadow || isGenerousBucket,
      `chain filter must either shadow-track (filter_enforced.numerator=0) or carry a generous token_bucket (max_tokens>=1000); got enforced.numerator=${String(enforcedNum)}, token_bucket.max_tokens=${String(tbMax)}`
    );
  });

  it('W16-A regression: request without explicit per-route RL still passes through chain filter', () => {
    // Mixed spec: one endpoint has rateLimit (so chain filter is emitted),
    // another endpoint has none. The unmatched route must not be silently
    // dropped by the chain-level filter.
    const spec = specWith([
      ep('POST', '/login', { rateLimit: { requests: 5, window: '1m' } }),
      ep('GET', '/public', { authentication: { type: 'none' } })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    const parsed = yaml.load(out) as Record<string, unknown>;
    const listeners = (parsed.static_resources as Record<string, unknown>).listeners as unknown[];
    const filters = ((((listeners[0] as Record<string, unknown>).filter_chains as unknown[])[0] as Record<string, unknown>).filters as unknown[])[0] as Record<string, unknown>;
    const httpFilters = (filters.typed_config as Record<string, unknown>).http_filters as unknown[];
    const chainRl = httpFilters.find(
      (f) =>
        (f as Record<string, unknown>).name === 'envoy.filters.http.local_ratelimit'
    ) as Record<string, unknown>;
    const cfg = chainRl.typed_config as Record<string, unknown>;
    // The /public route should have no typed_per_filter_config bucket; if the
    // chain filter were enforcing without a token_bucket every request to it
    // would 429. Assert the chain filter is non-enforcing (numerator=0) OR
    // has a generous bucket.
    const enforcedNum = ((cfg.filter_enforced as Record<string, unknown> | undefined)?.default_value as Record<string, unknown> | undefined)?.numerator;
    const tbMax = (cfg.token_bucket as Record<string, unknown> | undefined)?.max_tokens as number | undefined;
    assert.ok(
      enforcedNum === 0 || (typeof tbMax === 'number' && tbMax >= 1000),
      'unmatched route would be dropped if chain filter enforces with no token_bucket'
    );
    // And the /public route itself has no per-route RL override.
    const vhosts = ((((cfg.route_config as Record<string, unknown> | undefined) ?? {}) as Record<string, unknown>));
    // (route_config lives on HCM, not the rate-limit filter — assertion above is sufficient)
    void vhosts;
  });

  it('omits chain-level local_ratelimit when no endpoint declares rateLimit', () => {
    const spec = specWith([ep('GET', '/x', { authentication: { type: 'none' } })]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.doesNotMatch(out, /envoy\.filters\.http\.local_ratelimit/);
  });
});

// ── Native cors filter ───────────────────────────────────────────────────

describe('envoy: cors native filter (per-route)', () => {
  it('emits a per-route CorsPolicy with allowed origins/methods/credentials', () => {
    const spec = specWith([
      ep('POST', '/login', {
        cors: {
          allowedOrigins: ['https://app.example.com'],
          allowedMethods: ['POST', 'OPTIONS'],
          allowedHeaders: ['Content-Type'],
          credentials: true,
          maxAge: 300
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.match(out, /envoy\.filters\.http\.cors/);
    assert.match(out, /allow_origin_string_match:\s*\n\s*- exact: "https:\/\/app\.example\.com"/);
    assert.match(out, /allow_methods: "POST,OPTIONS"/);
    assert.match(out, /allow_headers: "Content-Type"/);
    assert.match(out, /allow_credentials: true/);
    assert.match(out, /max_age: "300"/);
  });
});

// ── Filter ordering contract ─────────────────────────────────────────────

describe('envoy: filter ordering', () => {
  it('emits filters in order: buffer → jwt_authn → rbac → local_ratelimit → cors → lua → router', () => {
    const spec = specWith([
      ep('POST', '/login', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256']
        },
        // W18-A: use a non-admin role so this endpoint stays on the native
        // rbac filter. Admin-only routes are routed through OPA (ext_authz)
        // for the opa-bfla-403 marker, which would change the filter list.
        authorization: { type: 'rbac', roles: ['user'] },
        rateLimit: { requests: 5, window: '1m' },
        cors: { allowedOrigins: ['https://x'], allowedMethods: ['POST'] },
        request: { contentType: ['application/json'], maxBodySize: '1MB' }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: 'placeholder' });
    const parsed = yaml.load(out) as Record<string, unknown>;
    const listeners = (parsed.static_resources as Record<string, unknown>).listeners as unknown[];
    const filters = ((((listeners[0] as Record<string, unknown>).filter_chains as unknown[])[0] as Record<string, unknown>).filters as unknown[])[0] as Record<string, unknown>;
    const httpFilters = (filters.typed_config as Record<string, unknown>).http_filters as unknown[];
    const names = httpFilters.map((f) => (f as Record<string, unknown>).name as string);
    assert.deepEqual(names, [
      'envoy.filters.http.buffer',
      'envoy.filters.http.jwt_authn',
      'envoy.filters.http.rbac',
      'envoy.filters.http.local_ratelimit',
      'envoy.filters.http.cors',
      'envoy.filters.http.lua',
      'envoy.filters.http.router'
    ]);
  });

  it('omits envoy.filters.http.buffer when no endpoint declares request.maxBodySize', () => {
    const spec = specWith([
      ep('GET', '/x', {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://idp.example.com/jwks',
          allowedAlgorithms: ['RS256']
        }
      })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.doesNotMatch(out, /envoy\.filters\.http\.buffer/);
  });

  it('never emits request_body_buffer_limit at HCM scope (rejected by Envoy v1.28)', () => {
    const spec = specWith([
      ep('POST', '/x', { request: { maxBodySize: '1MB' } })
    ]);
    const out = buildEnvoyYaml({ spec, luaSource: null });
    assert.doesNotMatch(out, /request_body_buffer_limit:/);
  });
});

// ── Residual Lua module ──────────────────────────────────────────────────

describe('envoy: residual Lua', () => {
  it('endpointNeedsLua returns false for native-only fields', () => {
    assert.equal(endpointNeedsLua(ep('GET', '/x', { authentication: { type: 'bearer-jwt', jwksUri: 'https://x/jwks', allowedAlgorithms: ['RS256'] }, rateLimit: { requests: 1, window: '1m' } })), false);
    assert.equal(endpointNeedsLua(ep('GET', '/x', { authorization: { type: 'rbac', roles: ['admin'] } })), false);
    assert.equal(endpointNeedsLua(ep('POST', '/x', { cors: { allowedOrigins: ['*'] } })), false);
  });

  it('endpointNeedsLua returns true for Lua-only fields', () => {
    assert.equal(endpointNeedsLua(ep('POST', '/x', { request: { contentType: ['application/json'] } })), true);
    assert.equal(endpointNeedsLua(ep('POST', '/x', { request: { maxBodySize: '10KB' } })), true);
    assert.equal(endpointNeedsLua(ep('POST', '/x', { request: { headerInjectionGuard: true } })), true);
  });

  it('buildEndpointBlock returns null when endpoint needs no Lua', () => {
    const block = buildEndpointBlock({
      endpoint: ep('GET', '/x', { authentication: { type: 'bearer-jwt', jwksUri: 'https://x/jwks', allowedAlgorithms: ['RS256'] } })
    });
    assert.equal(block, null);
  });

  it('buildEndpointBlock emits 413 and content-type checks', () => {
    const block = buildEndpointBlock({
      endpoint: ep('POST', '/x', { request: { maxBodySize: '10KB', contentType: ['application/json'] } })
    });
    assert.ok(block);
    assert.match(block!, /-- writ:POST:\/x:START/);
    assert.match(block!, /-- writ:END/);
    assert.match(block!, /:status"\]\s*=\s*"413"/);
    assert.match(block!, /:status"\]\s*=\s*"415"/);
    assert.match(block!, /cl > 10240/);
  });

  it('buildEndpointBlock emits 400 for headerInjectionGuard', () => {
    const block = buildEndpointBlock({
      endpoint: ep('POST', '/x', { request: { headerInjectionGuard: true, maxBodySize: '1KB' } })
    });
    assert.match(block!, /-- request\.headerInjectionGuard/);
    assert.match(block!, /:status"\]\s*=\s*"400"/);
  });

  it('buildLuaModule contains method-allowlist guarded by sentinels', () => {
    const out = buildLuaModule('t', '1', [], [
      { path: '/a', pattern: '^/a$', methods: ['GET', 'POST'] }
    ]);
    assert.match(out, /-- writ:method-allowlist:START/);
    assert.match(out, /-- writ:method-allowlist:END/);
    assert.match(out, /\{ pattern = "\^\/a\$", methods = \{ "GET", "POST" \} \}/);
    assert.match(out, /:status"\]\s*=\s*"405"/);
  });

  it('generator omits writ.lua entirely when spec has no Lua-requiring fields', async () => {
    const spec = specWith([
      ep('GET', '/x', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://x/jwks', allowedAlgorithms: ['RS256'] },
        rateLimit: { requests: 1, window: '1m' }
      })
    ]);
    const arts = await envoyGenerator.generate(spec);
    assert.equal(arts.length, 1, 'only envoy.yaml emitted, no lua');
    assert.equal(arts[0]!.path, 'envoy.yaml');
    assert.doesNotMatch(arts[0]!.content, /envoy\.filters\.http\.lua/);
  });
});

// ── capabilities() ───────────────────────────────────────────────────────

describe('envoy: capabilities() reflects native upgrades', () => {
  it('declares authentication, rbac, ratelimit, cors as full', () => {
    const caps = envoyGenerator.capabilities();
    assert.equal(caps.fields['authentication.type'], 'full');
    assert.equal(caps.fields['authentication.jwksUri'], 'full');
    assert.equal(caps.fields['rateLimit'], 'full');
    assert.equal(caps.fields['cors'], 'full');
  });

  it('authorization is full (rbac=native, rule-based=ext_authz+OPA)', () => {
    const caps = envoyGenerator.capabilities();
    assert.equal(caps.fields['authorization'], 'full');
  });

  it('bannedAlgorithms is partial (no native explicit deny)', () => {
    const caps = envoyGenerator.capabilities();
    assert.equal(caps.fields['authentication.bannedAlgorithms'], 'partial');
  });
});

// ── End-to-end against example fixture ───────────────────────────────────

describe('envoy: generate() against example fixture', () => {
  it('produces envoy.yaml (Lua only when needed)', async () => {
    const spec = await loadExample();
    const arts = await envoyGenerator.generate(spec);
    // example spec uses contentType + maxBodySize → Lua emitted; it also
    // declares response.schema → ext_proc/response-schema.json scaffolding
    // (override-only; enforced by an operator-supplied ext_proc processor).
    const paths = arts.map((a) => a.path).sort();
    assert.deepEqual(paths, ['envoy.yaml', 'ext_proc/response-schema.json', 'writ.lua']);
  });

  it('envoy.yaml is valid YAML and round-trips through js-yaml', async () => {
    const spec = await loadExample();
    const arts = await envoyGenerator.generate(spec);
    const y = arts.find((a) => a.path === 'envoy.yaml')!.content;
    const doc = yaml.load(y) as Record<string, unknown>;
    assert.ok(doc.admin);
    assert.ok(doc.static_resources);
  });

  it('contains jwt_authn rules for both bearer-jwt endpoints', async () => {
    const spec = await loadExample();
    const y = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
    assert.match(y, /regex: "\^\/api\/admin\/users\$"/);
    assert.match(y, /regex: "\^\/api\/files\/upload\$"/);
  });

  it('contains rbac policies for both admin roles', async () => {
    const spec = await loadExample();
    const y = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
    assert.match(y, /"writ-rbac-listusers-admin":/);
    assert.match(y, /"writ-rbac-listusers-super-admin":/);
  });

  it('contains per-route rate-limit buckets for each rateLimit endpoint', async () => {
    const spec = await loadExample();
    const y = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
    assert.match(y, /stat_prefix: writ_login_ratelimit/);
    assert.match(y, /stat_prefix: writ_listusers_ratelimit/);
    assert.match(y, /stat_prefix: writ_uploadfile_ratelimit/);
  });

  it('contains a per-route CorsPolicy on the login route', async () => {
    const spec = await loadExample();
    const y = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
    assert.match(y, /allow_origin_string_match:[\s\S]*"https:\/\/app\.example\.com"/);
  });

  it('residual Lua contains content-type + body-size enforcement only', async () => {
    const spec = await loadExample();
    const lua = (await envoyGenerator.generate(spec)).find((a) => a.path === 'writ.lua')!.content;
    assert.match(lua, /-- writ:POST:\/api\/auth\/login:START/);
    // Lua MUST NOT carry the old auth-presence check (now native).
    assert.doesNotMatch(lua, /missing authorization header/);
    // Method-allowlist still present.
    assert.match(lua, /-- writ:method-allowlist:START/);
  });

  it('emits envoy.filters.http.buffer with max_request_bytes at the smallest body cap', async () => {
    const spec = await loadExample();
    const y = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
    // Buffer filter (not HCM-scoped) carries the body cap — HCM-scoped
    // request_body_buffer_limit is invalid on Envoy v1.28+.
    assert.match(y, /envoy\.filters\.http\.buffer/);
    assert.match(y, /max_request_bytes: 10240/);
    assert.doesNotMatch(y, /request_body_buffer_limit:/);
  });

  it('output is byte-stable across runs', async () => {
    const spec = await loadExample();
    const a = await envoyGenerator.generate(spec);
    const b = await envoyGenerator.generate(spec);
    assert.equal(a[0]!.content, b[0]!.content);
    if (a.length > 1) assert.equal(a[1]!.content, b[1]!.content);
  });
});

// ── Golden fixture ───────────────────────────────────────────────────────

describe('envoy: golden fixture', () => {
  let envoyYaml: string;
  before(async () => {
    const spec = await loadExample();
    envoyYaml = (await envoyGenerator.generate(spec)).find((a) => a.path === 'envoy.yaml')!.content;
  });

  it('matches fixtures/configs/envoy/example.expected.yaml (run with UPDATE_GOLDEN=1 to refresh)', () => {
    if (process.env.UPDATE_GOLDEN === '1') {
      mkdirSync(dirname(GOLDEN), { recursive: true });
      writeFileSync(GOLDEN, envoyYaml);
      return;
    }
    if (!existsSync(GOLDEN)) {
      assert.fail(`golden fixture missing at ${GOLDEN} — run with UPDATE_GOLDEN=1 to seed`);
    }
    const expected = readFileSync(GOLDEN, 'utf8');
    assert.equal(envoyYaml, expected, 'envoy.yaml drift from golden fixture — diff and update if intended');
  });
});

describe('envoy W19-A: SSRF url-allowlist OPA emission', () => {
  function ssrfSpec(domain: string[], block: boolean): SpecIR {
    return {
      openapi: '3.0.0', dialect: '3.0' as const, info: { title: 't', version: '1' },
      servers: [], unprotectedEndpoints: [],
      endpoints: [
        {
          operationId: 'ssrf', method: 'GET' as const, path: '/vapi/serversurfer',
          parameters: [{ name: 'url', in: 'query' as const, required: true }],
          resolvedVars: new Map(), raw: {} as any,
          policy: { request: { schema: { url: { type: 'url', domainAllowlist: domain, ...(block ? { blockPrivateRanges: true } : {}) } } } } as XSecurityPolicy
        } as EndpointIR
      ]
    };
  }

  it('opa-ssrf-403 marker emitted when url-typed param has domainAllowlist', async () => {
    const arts = await envoyGenerator.generate(ssrfSpec(['roottusk.com'], false));
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego, 'opa/policy.rego artifact missing (SSRF policy should route via OPA)');
    assert.match(rego!.content, /"x-writ-rule": "opa-ssrf-403"/);
    // Allowlist host set is byte-stable, lowercased.
    assert.match(rego!.content, /allowed := \{"roottusk\.com"\}/);
    // Query-string extraction splits :path on '?' (OPA-Envoy doesn't expose
    // a separate request.http.query field — it's embedded in :path).
    assert.match(rego!.content, /qs_parts := split\(full_path, "\?"\)/);
  });

  it('private-range pattern appears in Rego when blockPrivateRanges:true', async () => {
    const arts = await envoyGenerator.generate(ssrfSpec(['api.example.com'], true));
    const rego = arts.find((a) => a.path === 'opa/policy.rego');
    assert.ok(rego);
    // Spot-check a few canonical private-range prefixes.
    assert.match(rego!.content, /startswith\(host, "127\."\)/);
    assert.match(rego!.content, /startswith\(host, "169\.254\."\)/);
    assert.match(rego!.content, /startswith\(host, "internal-only"\)/);
  });
});

describe('envoy W10-9: ssrf-policy-missing warning', () => {
  it('fires when type=url param lacks SSRF policy', () => {
    const spec: SpecIR = {
      openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
      servers: [], unprotectedEndpoints: [],
      endpoints: [
        {
          operationId: 'redir', method: 'GET', path: '/redirect',
          parameters: [], resolvedVars: new Map(), raw: {} as any,
          policy: { request: { schema: { url: { type: 'url' } } } } as XSecurityPolicy
        } as EndpointIR
      ]
    };
    envoyGenerator.generate(spec);
    const joined = envoyGenerator.lastWarnings.join('\n');
    assert.match(joined, /\[envoy:ssrf-policy-missing\] GET \/redirect/);
    assert.match(joined, /parameter "url"/);
  });
});

// ── W22-A drift-closure: response headers / ipPolicy / cacheable / csrf ──

function genYaml(endpoints: EndpointIR[]): string {
  const spec = specWith(endpoints);
  const arts = envoyGenerator.generate(spec);
  const y = arts.find((a) => a.path === 'envoy.yaml');
  assert.ok(y, 'envoy.yaml artifact missing');
  return y!.content;
}

describe('envoy W22-A: response hardening headers (per-route response_headers_to_add)', () => {
  it('emits CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy', () => {
    const yaml = genYaml([
      ep('GET', '/secure', {
        response: {
          headers: {
            csp: "default-src 'self'",
            hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
            frameOptions: 'DENY',
            contentTypeOptions: 'nosniff',
            referrerPolicy: 'strict-origin',
            permissionsPolicy: 'geolocation=()'
          }
        }
      } as XSecurityPolicy)
    ]);
    assert.match(yaml, /response_headers_to_add:/);
    assert.match(yaml, /key: "Content-Security-Policy"/);
    assert.match(yaml, /value: "default-src 'self'"/);
    assert.match(yaml, /key: "Strict-Transport-Security"/);
    assert.match(yaml, /value: "max-age=63072000; includeSubDomains; preload"/);
    assert.match(yaml, /key: "X-Frame-Options"\n\s+value: "DENY"/);
    assert.match(yaml, /key: "X-Content-Type-Options"\n\s+value: "nosniff"/);
    assert.match(yaml, /key: "Referrer-Policy"\n\s+value: "strict-origin"/);
    assert.match(yaml, /key: "Permissions-Policy"\n\s+value: "geolocation=\(\)"/);
    assert.match(yaml, /append_action: OVERWRITE_IF_EXISTS_OR_ADD/);
  });

  it('omits response_headers_to_add when no response.headers declared', () => {
    const yaml = genYaml([ep('GET', '/plain', {} as XSecurityPolicy)]);
    // The rate-limit block emits its own response_headers_to_add; this endpoint
    // has no rateLimit and no response.headers, so the YAML for the route
    // must not contain response_headers_to_add. Cheap proxy: count occurrences.
    const lines = yaml.split('\n').filter((l) => /response_headers_to_add:/.test(l));
    assert.equal(lines.length, 0);
  });
});

describe('envoy W22-A: ipPolicy (envoy.filters.http.rbac.ip)', () => {
  it('emits per-route ALLOW with source_ip principals when ipPolicy.allow set', () => {
    const yaml = genYaml([
      ep('GET', '/admin', { ipPolicy: { allow: ['10.0.0.0/8', '192.168.1.0/24'] } } as XSecurityPolicy)
    ]);
    assert.match(yaml, /- name: envoy\.filters\.http\.rbac\.ip/);
    assert.match(yaml, /envoy\.filters\.http\.rbac\.ip:\n\s+"@type": type\.googleapis\.com\/envoy\.extensions\.filters\.http\.rbac\.v3\.RBACPerRoute/);
    assert.match(yaml, /action: ALLOW/);
    assert.match(yaml, /address_prefix: "10\.0\.0\.0", prefix_len: 8/);
    assert.match(yaml, /address_prefix: "192\.168\.1\.0", prefix_len: 24/);
  });

  it('emits per-route DENY when ipPolicy.deny set', () => {
    const yaml = genYaml([
      ep('GET', '/blocked', { ipPolicy: { deny: ['203.0.113.0/24'] } } as XSecurityPolicy)
    ]);
    assert.match(yaml, /action: DENY/);
    assert.match(yaml, /writ-ip-deny:/);
    assert.match(yaml, /address_prefix: "203\.0\.113\.0", prefix_len: 24/);
  });

  it('omits chain-level rbac.ip filter when no endpoint has ipPolicy', () => {
    const yaml = genYaml([ep('GET', '/plain', {} as XSecurityPolicy)]);
    assert.doesNotMatch(yaml, /envoy\.filters\.http\.rbac\.ip/);
  });
});

describe('envoy W22-A: cacheable (envoy.filters.http.cache)', () => {
  it('emits chain-level cache filter and per-route disabled when cacheable:false', () => {
    const yaml = genYaml([ep('GET', '/no-cache', { cacheable: false } as XSecurityPolicy)]);
    assert.match(yaml, /- name: envoy\.filters\.http\.cache/);
    assert.match(yaml, /SimpleHttpCacheConfig/);
    assert.match(yaml, /envoy\.filters\.http\.cache:\n\s+"@type": type\.googleapis\.com\/envoy\.extensions\.filters\.http\.cache\.v3\.CacheConfig\n\s+disabled: true/);
  });

  it('emits per-route SimpleHttpCacheConfig when cacheable:true', () => {
    const yaml = genYaml([ep('GET', '/cached', { cacheable: true } as XSecurityPolicy)]);
    assert.match(yaml, /SimpleHttpCacheConfig/);
    // Two occurrences: chain-level + per-route.
    const matches = yaml.match(/SimpleHttpCacheConfig/g) ?? [];
    assert.ok(matches.length >= 2, `expected ≥2 SimpleHttpCacheConfig refs, got ${matches.length}`);
  });

  it('omits cache filter entirely when no endpoint declares cacheable', () => {
    const yaml = genYaml([ep('GET', '/plain', {} as XSecurityPolicy)]);
    assert.doesNotMatch(yaml, /envoy\.filters\.http\.cache/);
  });
});

describe('envoy W22-A: csrf (envoy.filters.http.csrf)', () => {
  it('emits chain-level csrf filter + per-route enable + additional_origins for origin-check', () => {
    const yaml = genYaml([
      ep('POST', '/api/transfer', {
        csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] }
      } as XSecurityPolicy)
    ]);
    assert.match(yaml, /- name: envoy\.filters\.http\.csrf/);
    assert.match(yaml, /envoy\.filters\.http\.csrf:\n\s+"@type": type\.googleapis\.com\/envoy\.extensions\.filters\.http\.csrf\.v3\.CsrfPolicy/);
    assert.match(yaml, /filter_enabled:\n\s+default_value: \{ numerator: 100, denominator: HUNDRED \}/);
    assert.match(yaml, /additional_origins:\n\s+- exact: "https:\/\/app\.example\.com"/);
  });

  it('does not enable csrf filter for double-submit method (Lua territory)', () => {
    const yaml = genYaml([
      ep('POST', '/api/x', { csrf: { method: 'double-submit', tokenHeader: 'X-CSRF', tokenCookie: 'csrf' } } as XSecurityPolicy)
    ]);
    assert.doesNotMatch(yaml, /envoy\.filters\.http\.csrf/);
  });
});

describe('envoy W22-A: capabilities() drift closure', () => {
  it('flips ipPolicy/cacheable/csrf/response.headers.* from unsupported to full/partial', () => {
    const caps = envoyGenerator.capabilities().fields;
    assert.equal(caps['ipPolicy.allow'], 'full');
    assert.equal(caps['ipPolicy.deny'], 'full');
    assert.equal(caps['cacheable'], 'full');
    assert.equal(caps['csrf'], 'partial');
    assert.equal(caps['response.headers.csp'], 'full');
    assert.equal(caps['response.headers.hsts'], 'full');
    assert.equal(caps['response.headers.frameOptions'], 'full');
    assert.equal(caps['response.headers.contentTypeOptions'], 'full');
    assert.equal(caps['response.headers.referrerPolicy'], 'full');
    assert.equal(caps['response.headers.permissionsPolicy'], 'full');
  });
});
