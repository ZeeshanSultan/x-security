// Unit tests for the Envoy verify reader (wave-9 native-filter rev).
//
//   1. reconcile() pure logic — set-diff over the new artifact kinds
//   2. config_dump parsing — collects filter names, jwt rules, rbac policies,
//      stat-prefixes, sentinel markers
//   3. snippet parsing — generator-emitted bootstrap → emitted artifact set

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  envoyReader,
  collectFilterNames,
  collectStatPrefixes,
  collectRbacPolicyNames,
  collectJwtRuleRegexes,
  walkStrings,
  extractSentinels,
  parseEmittedSnippet
} from '../../src/verify/readers/envoy.js';

// ── reconcile() ───────────────────────────────────────────────────────────

test('reconcile: every emitted entity present → ok rows', () => {
  const emitted = [
    { id: 'envoy.filters.http.jwt_authn', kind: 'envoy-http-filter' as const, endpoint: '(http-filters)', label: 'filter envoy.filters.http.jwt_authn' },
    { id: '^/api1/user/[^/]+$', kind: 'envoy-jwt-rule' as const, endpoint: '(jwt) ^/api1/user/[^/]+$', label: 'jwt rule' },
    { id: 'writ_login_ratelimit', kind: 'envoy-ratelimit-route' as const, endpoint: '(ratelimit) writ_login_ratelimit', label: 'rl' }
  ];
  const loaded = [
    { id: 'envoy.filters.http.jwt_authn', kind: 'envoy-http-filter' as const },
    { id: '^/api1/user/[^/]+$', kind: 'envoy-jwt-rule' as const },
    { id: 'writ_login_ratelimit', kind: 'envoy-ratelimit-route' as const }
  ];
  const { rows, diagnostics } = envoyReader.reconcile(emitted, loaded);
  assert.ok(rows.every((r) => r.status === 'ok'));
  assert.equal(diagnostics.length, 0);
});

test('reconcile: missing jwt_authn surfaces a dedicated diagnostic', () => {
  const emitted = [
    { id: 'envoy.filters.http.jwt_authn', kind: 'envoy-http-filter' as const, endpoint: '(http-filters)', label: 'filter envoy.filters.http.jwt_authn' }
  ];
  const loaded = [
    { id: 'envoy.filters.http.router', kind: 'envoy-http-filter' as const }
  ];
  const { diagnostics } = envoyReader.reconcile(emitted, loaded);
  assert.ok(diagnostics.some((d) => /jwt_authn emitted but not present/.test(d)),
    `expected jwt_authn diagnostic, got: ${diagnostics.join(' | ')}`);
});

test('reconcile: zero loaded → bootstrap-not-loaded diagnostic', () => {
  const emitted = [
    { id: 'envoy.filters.http.lua', kind: 'envoy-http-filter' as const, endpoint: '(http-filters)', label: 'lua' }
  ];
  const { diagnostics } = envoyReader.reconcile(emitted, []);
  assert.ok(diagnostics.some((d) => /bootstrap may not have loaded/.test(d)));
});

// ── /config_dump parsing ──────────────────────────────────────────────────

const DUMP = {
  configs: [
    {
      static_listeners: [
        {
          listener: {
            filter_chains: [
              {
                filters: [
                  {
                    name: 'envoy.filters.network.http_connection_manager',
                    typed_config: {
                      route_config: {
                        virtual_hosts: [
                          {
                            routes: [
                              {
                                match: { safe_regex: { regex: '^/login$' }, headers: [{ name: ':method', string_match: { exact: 'POST' } }] },
                                typed_per_filter_config: {
                                  'envoy.filters.http.local_ratelimit': { stat_prefix: 'writ_login_ratelimit' },
                                  'envoy.filters.http.cors': { allow_credentials: true }
                                }
                              }
                            ]
                          }
                        ]
                      },
                      http_filters: [
                        {
                          name: 'envoy.filters.http.jwt_authn',
                          typed_config: {
                            providers: { writ_jwt: {} },
                            rules: [{ match: { safe_regex: { regex: '^/secured$' } } }]
                          }
                        },
                        {
                          name: 'envoy.filters.http.rbac',
                          typed_config: {
                            rules: {
                              action: 'ALLOW',
                              policies: {
                                'writ-rbac-admin': {},
                                'writ-rbac-super': {}
                              }
                            }
                          }
                        },
                        { name: 'envoy.filters.http.local_ratelimit', typed_config: { stat_prefix: 'writ_chain_ratelimit' } },
                        { name: 'envoy.filters.http.cors' },
                        {
                          name: 'envoy.filters.http.lua',
                          typed_config: { inline_code: '-- writ:GET:/api1/user/1:START\nfoo\n-- writ:END' }
                        },
                        { name: 'envoy.filters.http.router' }
                      ]
                    }
                  }
                ]
              }
            ]
          }
        }
      ]
    }
  ]
};

test('collectFilterNames finds every envoy.filters.http.* name', () => {
  const filterNames = new Set<string>();
  collectFilterNames(DUMP, filterNames);
  assert.ok(filterNames.has('envoy.filters.http.jwt_authn'));
  assert.ok(filterNames.has('envoy.filters.http.rbac'));
  assert.ok(filterNames.has('envoy.filters.http.local_ratelimit'));
  assert.ok(filterNames.has('envoy.filters.http.cors'));
  assert.ok(filterNames.has('envoy.filters.http.lua'));
  assert.ok(filterNames.has('envoy.filters.http.router'));
});

test('collectStatPrefixes harvests per-route prefixes', () => {
  const sp = new Set<string>();
  collectStatPrefixes(DUMP, sp);
  assert.ok(sp.has('writ_login_ratelimit'));
  assert.ok(sp.has('writ_chain_ratelimit'));
});

test('collectRbacPolicyNames keys off action+policies map', () => {
  const pol = new Set<string>();
  collectRbacPolicyNames(DUMP, pol);
  assert.deepEqual([...pol].sort(), ['writ-rbac-admin', 'writ-rbac-super']);
});

test('collectJwtRuleRegexes pulls path regexes from jwt_authn rules', () => {
  const r = new Set<string>();
  collectJwtRuleRegexes(DUMP, r);
  assert.ok(r.has('^/secured$'));
});

test('extractSentinels harvests Lua block markers from any string', () => {
  const sentinels = new Set<string>();
  for (const s of walkStrings(DUMP)) for (const k of extractSentinels(s)) sentinels.add(k);
  assert.ok(sentinels.has('GET:/api1/user/1'));
});

// ── Snippet parser ────────────────────────────────────────────────────────

const SAMPLE_BOOTSTRAP = `# generated
admin:
  address:
    socket_address: { address: 0.0.0.0, port_value: 9901 }
static_resources:
  listeners:
    - name: l
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                route_config:
                  virtual_hosts:
                    - routes:
                        - match:
                            safe_regex: { regex: "^/login$" }
                            headers:
                              - name: ":method"
                                string_match: { exact: "POST" }
                          typed_per_filter_config:
                            envoy.filters.http.local_ratelimit:
                              stat_prefix: writ_login_ratelimit
                            envoy.filters.http.cors:
                              allow_credentials: true
                http_filters:
                  - name: envoy.filters.http.jwt_authn
                    typed_config:
                      providers:
                        writ_jwt: {}
                      rules:
                        - match:
                            safe_regex:
                              regex: "^/secured$"
                  - name: envoy.filters.http.rbac
                    typed_config:
                      rules:
                        action: ALLOW
                        policies:
                          policy-a: {}
                  - name: envoy.filters.http.local_ratelimit
                    typed_config:
                      stat_prefix: writ_chain_ratelimit
                  - name: envoy.filters.http.cors
                  - name: envoy.filters.http.lua
                    typed_config:
                      inline_code: |
                        -- writ:POST:/login:START
                        foo
                        -- writ:END
                  - name: envoy.filters.http.router
  clusters: []
`;

test('parseEmittedSnippet harvests all wave-9 artefact kinds', () => {
  const parsed = parseEmittedSnippet(SAMPLE_BOOTSTRAP);
  assert.deepEqual(parsed.filters, [
    'envoy.filters.http.jwt_authn',
    'envoy.filters.http.rbac',
    'envoy.filters.http.local_ratelimit',
    'envoy.filters.http.cors',
    'envoy.filters.http.lua',
    'envoy.filters.http.router'
  ]);
  assert.deepEqual(parsed.jwtRules, ['^/secured$']);
  assert.deepEqual(parsed.rbacPolicies, ['policy-a']);
  assert.deepEqual(parsed.ratelimitStatPrefixes, ['writ_login_ratelimit']);
  assert.deepEqual(parsed.corsRoutes, ['POST ^/login$']);
  assert.deepEqual(parsed.endpointPolicies.sort(), ['POST:/login']);
});

test('verify reader recognizes ext_authz filter emitted for rule-based authz (wave-10 E-3)', async () => {
  const { envoyGenerator } = await import('../../src/generators/envoy/index.js');
  const spec = {
    openapi: '3.1.0',
    dialect: 'openapi' as const,
    info: { title: 'T', version: '1.0.0' },
    servers: [],
    endpoints: [{
      method: 'GET' as const, path: '/api/users/{id}', operationId: 'get_user',
      parameters: [], raw: {} as never, resolvedVars: new Map(),
      policy: {
        authorization: {
          type: 'rule-based' as const,
          resourceLookup: { endpoint: '/users/{id}', identifierFrom: 'request.params.id', expose: ['ownerId'] },
          rules: [{ field: 'resource.ownerId', operator: 'equals' as const, value: { ref: 'jwt.sub' } }]
        }
      }
    }],
    unprotectedEndpoints: []
  };
  const arts = await envoyGenerator.generate(spec);
  const envoyYaml = arts.find((a) => a.path === 'envoy.yaml')!.content;
  const parsed = parseEmittedSnippet(envoyYaml);
  assert.ok(parsed.filters.includes('envoy.filters.http.ext_authz'),
    `expected ext_authz in emitted filters: ${parsed.filters.join(', ')}`);
});

// ── Integration ───────────────────────────────────────────────────────────

function dockerAvailable(): boolean {
  return spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const CHAIN_DIR = path.join(REPO_ROOT, 'e2e', 'fixtures', 'chain-envoy-vapi');
const SPEC_PATH = path.join(REPO_ROOT, 'e2e', 'fixtures', 'chain-vapi', 'openapi.yaml');

test('integration: live envoy chain → ≥90% verify coverage', { skip: !dockerAvailable() || !existsSync(CHAIN_DIR) || !existsSync(SPEC_PATH) }, async () => {
  process.env.JWKS_URI ??= 'https://idp.example.com/.well-known/jwks.json';
  process.env.JWT_ISSUER ??= 'https://idp.example.com';
  process.env.TURNSTILE_SECRET ??= 'realsecret_xyz123';
  process.env.UPSTREAM_HMAC_SECRET ??= 'hmac_real_secret_456';

  const { runVerify } = await import('../../src/verify/index.js');
  try {
    const r = await runVerify(SPEC_PATH, { target: 'envoy', gateway: 'http://127.0.0.1:9901' });
    if (r.exitCode === 3) return;
    assert.equal(r.exitCode, 0, `expected coverage ≥90%, got ${r.report.totals.coveragePct}% — diagnostics: ${r.report.diagnostics.join('; ')}`);
    assert.ok(r.report.totals.coveragePct >= 90);
  } catch (e) {
    if (/ECONNREFUSED|ENOTFOUND/.test((e as Error).message)) return;
    throw e;
  }
});
