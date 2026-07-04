/**
 * Tests for the BunkerWeb generator (R2.3, v6 output shape).
 *
 * Output shape (v6): two artifacts —
 *   - `configs/modsec/writ.conf` (plain ModSec SecRule directives)
 *   - `DEPLOYMENT.md`                  (operator-facing deployment notes + warnings)
 *
 * Dropped in v6: `bunkerweb.yml`, `variables.env`, `plugins/writ/*` (Lua + manifest).
 * Reason: BunkerWeb's libmodsec3 has no Lua support, and the plugin pipeline
 * doesn't apply rules to traffic. See STATUS.md.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import type { EndpointIR, SpecIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

import { bunkerwebGenerator } from '../../src/generators/bunkerweb/index.js';
import {
  buildCorsSettings,
  buildIpPolicySettings,
  buildRateLimitSettings,
  buildRequestSettings,
  buildTimeoutSettings,
  byteSizeToNginx,
  rateLimitToBunkerRate
} from '../../src/generators/bunkerweb/settings.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function ep(
  method: EndpointIR['method'],
  path: string,
  operationId: string,
  policy: XSecurityPolicy
): EndpointIR {
  return {
    method,
    path,
    operationId,
    policy,
    parameters: [],
    raw: {} as EndpointIR['raw'],
    resolvedVars: new Map()
  };
}

function buildExampleSpec(): SpecIR {
  return {
    openapi: '3.1.0',
    dialect: '3.1',
    info: { title: 'Example API', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('POST', '/api/auth/login', 'login', {
        authentication: { type: 'none' },
        rateLimit: { requests: 5, window: '1m', identifier: 'ip', burst: 2 },
        request: { contentType: ['application/json'], maxBodySize: '10KB' },
        timeout: { read: 5000 },
        cacheable: false,
        cors: {
          allowedOrigins: ['https://app.example.com'],
          allowedMethods: ['POST'],
          credentials: true
        }
      }),
      ep('GET', '/api/admin/users', 'listUsers', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://auth/.well-known/jwks.json' },
        authorization: { type: 'rbac', roles: ['admin'] },
        rateLimit: { requests: 30, window: '1m', identifier: 'user-id' },
        timeout: { read: 10000 },
        cacheable: false,
        ipPolicy: { allow: ['10.0.0.0/8'] }
      }),
      ep('POST', '/api/files/upload', 'uploadFile', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://auth/.well-known/jwks.json' },
        rateLimit: { requests: 20, window: '1m', identifier: 'user-id' },
        request: {
          contentType: ['multipart/form-data'],
          maxBodySize: '50MB',
          schema: {
            file: {
              type: 'binary',
              allowedMimeTypes: ['image/png', 'image/jpeg', 'application/pdf'],
              maxSize: '50MB'
            }
          }
        },
        timeout: { read: 30000 },
        cacheable: false
      })
    ],
    unprotectedEndpoints: []
  };
}

/** Silence the structured JWT warnings during tests by stubbing stderr. */
function withSilencedStderr<T>(fn: () => T): T {
  const orig = console.error;
  console.error = () => {};
  try { return fn(); } finally { console.error = orig; }
}

test('byteSizeToNginx normalizes common sizes', () => {
  assert.equal(byteSizeToNginx('10KB'), '10k');
  assert.equal(byteSizeToNginx('50MB'), '50m');
  assert.equal(byteSizeToNginx('1GB'), '1g');
  assert.equal(byteSizeToNginx('512'), '512');
});

test('rateLimitToBunkerRate handles per-second and per-minute windows', () => {
  assert.equal(rateLimitToBunkerRate({ requests: 5, window: '1m' }), '1r/s');
  assert.equal(rateLimitToBunkerRate({ requests: 60, window: '1m' }), '1r/s');
  assert.equal(rateLimitToBunkerRate({ requests: 120, window: '1m' }), '2r/s');
  assert.equal(rateLimitToBunkerRate({ requests: 10, window: '10s' }), '1r/s');
  assert.equal(rateLimitToBunkerRate({ requests: 1000, window: '1h' }), '17r/m');
});

test('buildRateLimitSettings emits per-URL indexed entries', () => {
  const out = buildRateLimitSettings(
    { requests: 5, window: '1m' },
    '/api/auth/login',
    0
  );
  assert.equal(out.USE_LIMIT_REQ, 'yes');
  assert.equal(out.LIMIT_REQ_URL_1, '/api/auth/login');
  assert.equal(out.LIMIT_REQ_RATE_1, '1r/s');
});

test('buildCorsSettings maps allowedOrigins/methods/credentials', () => {
  const out = buildCorsSettings({
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['POST'],
    credentials: true
  });
  assert.equal(out.USE_CORS, 'yes');
  assert.equal(out.CORS_ALLOW_ORIGIN, 'https://app.example.com');
  assert.equal(out.CORS_ALLOW_METHODS, 'POST');
  assert.equal(out.CORS_ALLOW_CREDENTIALS, 'yes');
});

test('buildIpPolicySettings emits whitelist for allow rules', () => {
  const out = buildIpPolicySettings({ allow: ['10.0.0.0/8'] });
  assert.equal(out.USE_WHITELIST, 'yes');
  assert.equal(out.WHITELIST_IP, '10.0.0.0/8');
});

test('buildRequestSettings merges contentType with per-field allowedMimeTypes', () => {
  const out = buildRequestSettings({
    contentType: ['multipart/form-data'],
    maxBodySize: '50MB',
    schema: {
      file: {
        type: 'binary',
        allowedMimeTypes: ['image/png', 'application/pdf']
      }
    }
  });
  assert.equal(out.MAX_CLIENT_SIZE, '50m');
  const mimes = String(out.ALLOWED_MIME_TYPES).split(' ');
  assert.ok(mimes.includes('multipart/form-data'));
  assert.ok(mimes.includes('image/png'));
  assert.ok(mimes.includes('application/pdf'));
});

test('buildTimeoutSettings converts ms → seconds', () => {
  const out = buildTimeoutSettings({ connect: 2000, read: 30000, write: 5000 });
  assert.equal(out.CONNECT_TIMEOUT, '2s');
  assert.equal(out.READ_TIMEOUT, '30s');
  assert.equal(out.SEND_TIMEOUT, '5s');
});

test('v6 output shape: emits configs/modsec/writ.conf + DEPLOYMENT.md only', () => {
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(buildExampleSpec()));
  const paths = arts.map((a) => a.path).sort();
  assert.deepEqual(paths, ['DEPLOYMENT.md', 'configs/modsec/writ.conf']);
  // No deprecated artifacts
  assert.ok(!arts.some((a) => a.path === 'bunkerweb.yml'), 'bunkerweb.yml dropped in v6');
  assert.ok(!arts.some((a) => a.path === 'variables.env'), 'variables.env dropped in v6');
  assert.ok(!arts.some((a) => a.path.startsWith('plugins/')), 'plugins/ dropped in v6');
  assert.ok(!arts.some((a) => a.path.endsWith('jwt-verify.lua')), 'lua verifier dropped in v6');
});

test('v6 modsec conf: contains Writ SecRules with rule IDs in 990000-block', () => {
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(buildExampleSpec()));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  assert.equal(conf.format, 'conf');
  assert.ok(conf.content.includes('SecRule REQUEST_HEADERS:Authorization "@rx ^Bearer (.+)$"'));
  assert.ok(/id:990010\b/.test(conf.content));
  assert.ok(/id:990011\b/.test(conf.content));
  // No SecRuleScript — Lua path is dropped.
  assert.ok(!conf.content.includes('SecRuleScript'), 'SecRuleScript removed in v6 (no libmodsec3 Lua)');
});

test('v6 generator output matches example.expected.conf fixture', () => {
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(buildExampleSpec()));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  const expectedPath = resolve(__dirname, '../../../../fixtures/configs/bunkerweb/example.expected.conf');
  const expected = readFileSync(expectedPath, 'utf8');
  assert.equal(conf.content, expected);
});

test('capabilities matrix: bearer-jwt/oauth2 promoted to full via BW 1.6 nginx_jwt_module', () => {
  const caps = bunkerwebGenerator.capabilities();
  assert.equal(caps.fields['rateLimit'], 'full');
  assert.equal(caps.fields['cors'], 'full');
  // Promoted by drift closure: USE_AUTH_JWT + native chain.
  assert.equal(caps.fields['authentication.type=bearer-jwt'], 'full');
  assert.equal(caps.fields['authentication.type=oauth2'], 'full');
  assert.equal(caps.fields['authentication.jwksUri'], 'full');
  assert.equal(caps.fields['authentication.allowedAlgorithms'], 'full');
  // api-key value-verification still requires upstream layer.
  assert.equal(caps.fields['authentication.type=api-key'], 'partial');
  // Drift closures (W23):
  assert.equal(caps.fields['authorization.type=rbac'], 'full');
  assert.equal(caps.fields['rateLimit.identifier=user-id'], 'full');
  assert.equal(caps.fields['deprecated'], 'full');
  assert.equal(caps.fields['request.schema.pii'], 'full');
  assert.equal(caps.fields['response.errorScrubbing.stripStackTraces'], 'full');
  assert.equal(caps.fields['response.errorScrubbing.stripServerHeaders'], 'full');
});

// ---------------------------------------------------------------------------
// Authentication: header-presence-only chain in v6 (no Lua)
// ---------------------------------------------------------------------------

test('bearer-jwt: emits header-presence SecRule chain only (no SecRuleScript)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/', issuer: 'https://iss/', audience: 'aud-1' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(conf.includes('SecRule REQUEST_HEADERS:Authorization "@rx ^Bearer (.+)$"'));
  assert.ok(conf.includes('Writ: missing bearer token'));
  assert.ok(!conf.includes('SecRuleScript'), 'no Lua script directive in v6');
  assert.ok(!conf.includes('jwt-verify.lua'), 'no Lua path reference in v6');
});

test('bearer-jwt: surfaces structured warning to lastWarnings + DEPLOYMENT.md', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const warnings = bunkerwebGenerator.lastWarnings ?? [];
  assert.ok(
    warnings.some((w) => w.includes('bearer-jwt') && w.includes('libmodsec3 lacks Lua support')),
    `expected JWT warning in lastWarnings, got: ${JSON.stringify(warnings)}`
  );
  const dep = arts.find((a) => a.path === 'DEPLOYMENT.md')!.content;
  assert.ok(dep.includes('libmodsec3 lacks Lua support') || dep.includes('libmodsec3'));
  assert.ok(dep.includes('OIDC sidecar') || dep.includes('Kong'));
});

test('oauth2: emits header-presence chain + scopes annotation (NOT enforced)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('POST', '/admin', 'admin', {
      authentication: { type: 'oauth2', jwksUri: 'https://jwks/', scopes: ['admin:write', 'admin:read'] },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(conf.includes('admin:write admin:read'));
  assert.ok(conf.includes('NOT enforced'));
});

test('api-key: emits header-presence SecRule for the configured header name', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'api-key', headerName: 'X-API-Key' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(conf.includes('SecRule REQUEST_HEADERS:X-API-Key "@rx ^.+$"'));
  assert.ok(conf.includes('Writ: missing API key (X-API-Key)'));
});

test('basic: emits USE_AUTH_BASIC settings hint + Basic-credentials SecRule', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'basic' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(conf.includes('SecRule REQUEST_HEADERS:Authorization "!@rx ^Basic'));
  // Compose-level settings comment block
  assert.ok(conf.includes('USE_AUTH_BASIC=yes'));
});

test('authentication.type=none: emits modsec conf but no SecRule auth rules', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('POST', '/login', 'login', {
      authentication: { type: 'none' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(!conf.includes('SecRule REQUEST_HEADERS:Authorization'), 'no auth rules for type=none');
  assert.ok(!conf.includes('id:990000'), 'no auth-rule IDs for type=none');
});

// ---------------------------------------------------------------------------
// Regression tests for v5 bugs (still relevant in v6 output shape)
// ---------------------------------------------------------------------------

test('Bug #1 regression: identical bearer-jwt rules across many endpoints emit only ONE block', () => {
  const auth = { type: 'bearer-jwt' as const, jwksUri: 'https://jwks/' };
  const endpoints: EndpointIR[] = [];
  for (let i = 0; i < 19; i++) {
    endpoints.push(ep('GET', `/p${i}`, `op${i}`, { authentication: auth, cacheable: false }));
  }
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints,
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  const id990000Count = (conf.match(/id:990000\b/g) ?? []).length;
  assert.equal(id990000Count, 1, `expected 1 occurrence of id:990000, got ${id990000Count}`);
});

test('Bug #1 regression: distinct auth types across endpoints concatenate (no false-positive dedupe)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('GET', '/jwt', 'jwt', { authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/' }, cacheable: false }),
      ep('GET', '/key', 'key', { authentication: { type: 'api-key', headerName: 'X-Key' }, cacheable: false })
    ],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.ok(conf.includes('id:990010'), 'has bearer-jwt rules');
  assert.ok(/id:99\d{4}/.test(conf), 'has rule IDs');
  assert.ok(conf.includes('api_key_present'), 'has api-key check');
});

test('Bug #1 regression: two distinct bearer-jwt configs (different headerName) get distinct rule IDs', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('GET', '/a', 'a', { authentication: { type: 'bearer-jwt', jwksUri: 'https://j/', headerName: 'Authorization' }, cacheable: false }),
      ep('GET', '/b', 'b', { authentication: { type: 'bearer-jwt', jwksUri: 'https://j/', headerName: 'Authorization-Token' }, cacheable: false })
    ],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  const ids = conf.match(/id:99\d{4}\b/g) ?? [];
  const unique = new Set(ids);
  assert.equal(ids.length, unique.size, `duplicate rule IDs detected: ${ids.length} total, ${unique.size} unique`);
  assert.ok(ids.length >= 4, `expected ≥4 rule IDs across two blocks, got ${ids.length}`);
});

test('Bug #3 regression: shared URL across endpoints collapses to one LIMIT_REQ_URL with the stricter rate', () => {
  const url = '/vapi/api1/user/{id}';
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'http://vapi:80' }],
    endpoints: [
      ep('GET', url, 'get', { authentication: { type: 'none' }, cacheable: false,
        rateLimit: { requests: 60, window: '1m', identifier: 'ip' } }),
      ep('PUT', url, 'put', { authentication: { type: 'none' }, cacheable: false,
        rateLimit: { requests: 10, window: '1m', identifier: 'ip' } })
    ],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  // Settings comment block lists LIMIT_REQ_URL_n=<url> — only one entry should reference our path.
  const urlEsc = url.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
  const urlMatches = (conf.match(new RegExp(`LIMIT_REQ_URL_\\d+=${urlEsc}(?=\\s|$)`, 'gm')) ?? []).length;
  assert.equal(urlMatches, 1, `expected one LIMIT_REQ_URL_* for ${url}, got ${urlMatches}\n${conf}`);
});

test('Bug #4 regression: CORS_ALLOW_METHODS unions across multiple endpoints', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('POST', '/a', 'a', { authentication: { type: 'none' }, cacheable: false,
        cors: { allowedOrigins: ['*'], allowedMethods: ['POST'] } }),
      ep('GET', '/b', 'b', { authentication: { type: 'none' }, cacheable: false,
        cors: { allowedOrigins: ['*'], allowedMethods: ['GET', 'OPTIONS'] } })
    ],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  // The settings comment line looks like:  # CORS_ALLOW_METHODS=POST, GET, OPTIONS    # from: ...
  const m = /CORS_ALLOW_METHODS=([^\n]+?)\s{2,}#/.exec(conf);
  assert.ok(m, `CORS_ALLOW_METHODS present, conf: ${conf}`);
  const methods = m![1]!.split(/[,\s]+/).filter(Boolean);
  assert.ok(methods.includes('POST'));
  assert.ok(methods.includes('GET'));
  assert.ok(methods.includes('OPTIONS'));
});

test('Bug #5 regression: mixed JWT issuer across endpoints throws at generate time', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('GET', '/a', 'a', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/', issuer: 'https://iss-a/' },
        cacheable: false
      }),
      ep('GET', '/b', 'b', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/', issuer: 'https://iss-b/' },
        cacheable: false
      })
    ],
    unprotectedEndpoints: []
  };
  assert.throws(() => withSilencedStderr(() => bunkerwebGenerator.generate(spec)), /mixed JWT issuer/);
});

test('Bug #5 regression: mixed JWT audience across endpoints throws at generate time', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      ep('GET', '/a', 'a', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/', audience: 'aud-a' },
        cacheable: false
      }),
      ep('GET', '/b', 'b', {
        authentication: { type: 'bearer-jwt', jwksUri: 'https://jwks/', audience: 'aud-b' },
        cacheable: false
      })
    ],
    unprotectedEndpoints: []
  };
  assert.throws(() => withSilencedStderr(() => bunkerwebGenerator.generate(spec)), /mixed JWT audience/);
});

test('W19-A: domainAllowlist on url-typed param emits SecRule id:980000+ with writ-rule-ssrf-403 tag', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('GET', '/vapi/serversurfer', 'ssrf', {
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'] } } }
      })
    ]
  };
  const arts = bunkerwebGenerator.generate(spec);
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  assert.match(conf.content, /id:98\d{4}/);
  assert.match(conf.content, /tag:'writ-rule-ssrf-403'/);
  assert.match(conf.content, /roottusk/);
});

test('W19-A: blockPrivateRanges emits SecRule with writ-rule-ssrf-private-403 tag', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('POST', '/api/fetch', 'fetch', {
        request: { schema: { url: { type: 'url', blockPrivateRanges: true } } }
      })
    ]
  };
  const arts = bunkerwebGenerator.generate(spec);
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  assert.match(conf.content, /tag:'writ-rule-ssrf-private-403'/);
  // W22-B: single-backslash literal `\.` — libmodsec3 / Coraza do NOT
  // unescape @rx args, so double-backslashes would compile to "literal
  // backslash + .", causing the regex to miss every real private IP.
  assert.match(conf.content, /169\\\.254/);
  assert.match(conf.content, /internal-only/);
});

test('W21-D: SSRF SecRule emitted at phase:1 for query-param URL policies (so it fires before BunkerWeb auth chain)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('GET', '/vapi/serversurfer', 'ssrf', {
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'], blockPrivateRanges: true } } }
      })
    ]
  };
  const arts = bunkerwebGenerator.generate(spec);
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  // Both SSRF rules (allowlist + private-range) must be at phase:1 so they
  // pre-empt BunkerWeb's bundled phase:1 JWT/auth chain that would otherwise
  // wholesale-deny with 401 before any URL validation runs.
  const allowMatch = /id:98\d{4},phase:(\d)[^\n]*writ-rule-ssrf-403/.exec(conf.content);
  const privateMatch = /id:98\d{4},phase:(\d)[^\n]*writ-rule-ssrf-private-403/.exec(conf.content);
  assert.ok(allowMatch, 'expected ssrf allowlist SecRule in BunkerWeb conf');
  assert.ok(privateMatch, 'expected ssrf private-range SecRule in BunkerWeb conf');
  assert.equal(allowMatch[1], '1', `ssrf-403 SecRule must be phase:1, got phase:${allowMatch[1]}`);
  assert.equal(privateMatch[1], '1', `ssrf-private-403 SecRule must be phase:1, got phase:${privateMatch[1]}`);
});

test('W21-D: SSRF SecRule block is emitted before auth header-presence block (same phase:1, declaration order matters)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('GET', '/vapi/serversurfer', 'ssrf', {
        authentication: { type: 'bearer-jwt', tokenHeader: 'Authorization' },
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'] } } }
      })
    ]
  };
  const arts = bunkerwebGenerator.generate(spec);
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  const ssrfIdx = conf.content.indexOf('writ-rule-ssrf-403');
  const authIdx = conf.content.indexOf('missing bearer token');
  assert.ok(ssrfIdx > 0, 'expected ssrf rule in conf');
  assert.ok(authIdx > 0, 'expected auth deny rule in conf');
  assert.ok(
    ssrfIdx < authIdx,
    `SSRF rule must precede auth rule in declaration order (ssrf at ${ssrfIdx}, auth at ${authIdx})`
  );
});

test('W22-B: SSRF chain must target REQUEST_FILENAME (path-only), not REQUEST_URI (path+query)', () => {
  // libmodsecurity3's REQUEST_URI is `<path>?<query>` (e.g.
  // `/vapi/serversurfer?url=http://10.0.0.1/x`), so a path-anchored
  // `^/vapi/serversurfer$` rx never matches when the endpoint receives
  // the very query-param the SSRF rule inspects. REQUEST_FILENAME is
  // path-only on both libmodsec3 and Coraza. Verified with the modsec
  // debug log (audit-log evidence in
  // /tmp/vapi-test/fixes/v22-bunkerweb-ssrf-runtime.md).
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('GET', '/vapi/serversurfer', 'ssrf', {
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'], blockPrivateRanges: true } } }
      })
    ]
  };
  const arts = bunkerwebGenerator.generate(spec);
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!;
  const ssrfBlock = conf.content.slice(
    conf.content.indexOf('writ-rule-ssrf-403'),
    conf.content.indexOf('writ-rule-ssrf-403') + 1200
  );
  // The chain's URI-matching link must use REQUEST_FILENAME.
  assert.match(
    ssrfBlock,
    /SecRule REQUEST_FILENAME "@rx \^\/vapi\/serversurfer\$"/,
    'SSRF chain must inspect REQUEST_FILENAME (path-only), not REQUEST_URI (includes query string)'
  );
  // And must NOT use REQUEST_URI for the path-matching link inside the SSRF
  // chain — anchor on the chain-context "chain"\n  SecRule pattern to scope
  // the assertion narrowly to SSRF and not to unrelated auth-chain rules.
  assert.doesNotMatch(
    ssrfBlock,
    /SecRule REQUEST_URI "@rx \^\/vapi\/serversurfer\$"/,
    'SSRF chain must not chain on REQUEST_URI — libmodsec3 includes query string in REQUEST_URI'
  );
});

test('W21-D regression: Coraza-SPOA SSRF SecRule stays at phase:2 (body access required for JSON body SSRF)', async () => {
  const { corazaGenerator } = await import('../../src/generators/coraza/index.js');
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1' as const,
    info: { title: 't', version: '1' }, servers: [], unprotectedEndpoints: [],
    endpoints: [
      ep('GET', '/vapi/serversurfer', 'ssrf', {
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'], blockPrivateRanges: true } } }
      })
    ]
  };
  const arts = corazaGenerator.generate(spec);
  const conf = arts.find((a) => a.content.includes('writ-rule-ssrf'))!;
  assert.ok(conf, 'expected coraza artifact with ssrf rule');
  const allowMatch = /id:98\d{4},phase:(\d)[^\n]*writ-rule-ssrf-403/.exec(conf.content);
  const privateMatch = /id:98\d{4},phase:(\d)[^\n]*writ-rule-ssrf-private-403/.exec(conf.content);
  assert.ok(allowMatch && privateMatch, 'expected both ssrf SecRules in coraza output');
  assert.equal(allowMatch[1], '2', 'Coraza-SPOA ssrf-403 must remain phase:2');
  assert.equal(privateMatch[1], '2', 'Coraza-SPOA ssrf-private-403 must remain phase:2');
});

// ---------------------------------------------------------------------------
// W23 drift closures: native JWT settings, RBAC multi-role, response PII,
// errorScrubbing, deprecated lifecycle, user-id rate limit.
// ---------------------------------------------------------------------------

test('W23 JWT: bearer-jwt with jwksUri emits USE_AUTH_JWT + JWT_JWKS_URI + JWT_ALGORITHMS', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'bearer-jwt', jwksUri: 'https://issuer/.well-known/jwks.json',
        allowedAlgorithms: ['RS256', 'ES256'], issuer: 'https://issuer/', audience: 'api' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /USE_AUTH_JWT=yes/);
  assert.match(conf, /JWT_JWKS_URI=https:\/\/issuer\/\.well-known\/jwks\.json/);
  assert.match(conf, /JWT_ALGORITHMS=RS256,ES256/);
  assert.match(conf, /JWT_ISSUER=https:\/\/issuer\//);
  assert.match(conf, /JWT_AUDIENCE=api/);
});

test('W23 JWT: default alg list excludes HS* / none when allowedAlgorithms unset', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'bearer-jwt', jwksUri: 'https://issuer/.well-known/jwks.json' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /JWT_ALGORITHMS=RS256,ES256/);
  // Must never emit symmetric or 'none' as a default.
  assert.doesNotMatch(conf, /JWT_ALGORITHMS=[^\n]*\b(?:HS256|HS384|HS512|none)\b/);
});

test('W23 authz: rbac with 2+ roles emits SecRule chained on X-Forwarded-Groups', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/admin', 'op', {
      authentication: { type: 'none' },
      authorization: { type: 'rbac', roles: ['admin', 'operator'] },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /writ-rule-rbac-multi-role/);
  assert.match(conf, /X-Forwarded-Groups/);
  // Allows either admin or operator: alternation rx must include both.
  assert.match(conf, /admin\|operator/);
  // Two rules (missing header + non-matching role).
  const ids = conf.match(/id:9706\d{2}/g) ?? [];
  assert.ok(ids.length >= 2, `expected ≥2 rbac rule ids in 970600-block, got ${ids.length}`);
});

test('W23 authz: single-role rbac does NOT emit multi-role rules (handled by identity emitter elsewhere)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/admin', 'op', {
      authentication: { type: 'none' },
      authorization: { type: 'rbac', roles: ['admin'] },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.doesNotMatch(conf, /writ-rule-rbac-multi-role/);
});

test('W23 response PII: request.schema with pii:true emits id:428 response-body SecRule', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('POST', '/users', 'op', {
      authentication: { type: 'none' },
      request: { schema: { nationalId: { type: 'string', pii: true } } },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /id:428\d{3}/);
  assert.match(conf, /writ-data-exposure/);
  assert.match(conf, /nationalId/);
  assert.match(conf, /RESPONSE_BODY/);
});

test('W23 errorScrubbing: stripStackTraces emits id:268 phase:4 RESPONSE_BODY rule', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'none' },
      response: { errorScrubbing: { stripStackTraces: true } },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /id:268\d{3}/);
  assert.match(conf, /writ-output-sanitization/);
  assert.match(conf, /Traceback/);
});

test('W23 errorScrubbing: stripServerHeaders emits REMOVE_HEADERS setting (Server X-Powered-By)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/p', 'op', {
      authentication: { type: 'none' },
      response: { errorScrubbing: { stripServerHeaders: true } },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /REMOVE_HEADERS=[^\n]*Server/);
  assert.match(conf, /REMOVE_HEADERS=[^\n]*X-Powered-By/);
});

test('W23 deprecated: deprecated:true emits SecRule status:410 with writ-deprecated-endpoint-block tag', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/legacy', 'op', {
      authentication: { type: 'none' },
      deprecated: true,
      sunsetDate: '2026-01-01',
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /status:410/);
  assert.match(conf, /writ-deprecated-endpoint-block/);
  assert.match(conf, /id:9705\d{2}/);
  assert.match(conf, /sunset:2026-01-01|sunsetDate: 2026-01-01/);
});

test('W23 deprecated: non-deprecated endpoints emit no 410 rule', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('GET', '/live', 'op', { authentication: { type: 'none' }, cacheable: false })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.doesNotMatch(conf, /status:410/);
  assert.doesNotMatch(conf, /writ-deprecated-endpoint-block/);
});

test('W23 rateLimit user-id: identifier=user-id emits CUSTOM_CONF_HTTP_LIMIT_REQ_USER_* with $http_x_forwarded_user keying', () => {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep('POST', '/api/expensive', 'op', {
      authentication: { type: 'bearer-jwt', jwksUri: 'https://j/' },
      rateLimit: { requests: 10, window: '1m', identifier: 'user-id' },
      cacheable: false
    })],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  const conf = arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
  assert.match(conf, /CUSTOM_CONF_HTTP_LIMIT_REQ_USER_/);
  assert.match(conf, /limit_req_zone \$http_x_forwarded_user zone=lazy_user_/);
  // Defense-in-depth IP-keyed LIMIT_REQ_URL stays too.
  assert.match(conf, /LIMIT_REQ_URL_\d+=\/api\/expensive/);
});

// ---------------------------------------------------------------------------
// v0.7 edge-enforceable-residuals
// ---------------------------------------------------------------------------

function v07Conf(policy: XSecurityPolicy, method: EndpointIR['method'] = 'POST', path = '/login'): string {
  const spec: SpecIR = {
    openapi: '3.1.0', dialect: '3.1',
    info: { title: 'A', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [ep(method, path, 'op', policy)],
    unprotectedEndpoints: []
  };
  const arts = withSilencedStderr(() => bunkerwebGenerator.generate(spec));
  return arts.find((a) => a.path === 'configs/modsec/writ.conf')!.content;
}

test('v0.7 injectionGuard: deserialization sink emits an @rx preamble denylist (SSEC-INJECTION)', () => {
  const conf = v07Conf({
    authentication: { type: 'none' },
    request: { schema: { blob: { type: 'string', injectionGuard: ['deserialization'] } } },
    cacheable: false
  });
  assert.match(conf, /injectionGuard\[deserialization\]/);
  assert.match(conf, /ND_FUNC/);              // node-serialize preamble
  assert.match(conf, /writ-ssec-injection/);
  assert.match(conf, /Unsafe deserialization payload in blob/);
});

test('v0.7 injectionGuard: ai-prompt sink is attributed to SSEC-PROMPT, not SSEC-INJECTION', () => {
  const conf = v07Conf({
    authentication: { type: 'none' },
    request: { schema: { prompt: { type: 'string', injectionGuard: ['ai-prompt'] } } },
    cacheable: false
  });
  assert.match(conf, /injectionGuard\[ai-prompt\]/);
  assert.match(conf, /writ-ssec-prompt/);
  assert.match(conf, /LLM prompt injection in prompt/);
  // The ai-prompt rule must NOT ride the SSEC-INJECTION tag.
  assert.doesNotMatch(conf, /LLM prompt injection[^\n]*writ-ssec-injection/);
});

test('v0.7 passwordPolicy: emits one !@rx strength SecRule per requirement + a blocklist rule', () => {
  const conf = v07Conf({
    authentication: {
      type: 'basic',
      passwordPolicy: {
        minLength: 12, requireUppercase: true, requireDigit: true, requireSymbol: true,
        blocklist: ['password123']
      }
    },
    cacheable: false
  });
  assert.match(conf, /writ-rule-password-policy/);
  assert.match(conf, /password shorter than 12 chars/);
  assert.match(conf, /missing uppercase letter/);
  assert.match(conf, /missing digit/);
  assert.match(conf, /missing symbol/);
  assert.match(conf, /password is on the blocklist/);
  // strength checks are phase:2 negated assertions on the password field.
  assert.match(conf, /ARGS:json\.password\|ARGS:password/);
});

test('v0.7 accountLockout: header identifier inits the counter at phase:1', () => {
  const conf = v07Conf({
    authentication: {
      type: 'basic',
      accountLockout: { attempts: 5, window: '15m', identifier: 'header:X-Username' }
    },
    cacheable: false
  });
  assert.match(conf, /writ-rule-account-lockout/);
  assert.match(conf, /initcol:global=ss_lockout_%\{REQUEST_HEADERS\.X-Username\}/);
  assert.match(conf, /id:\d+,phase:1,pass,nolog,[^\n]*initcol:global=ss_lockout_/);
  // Increment happens at phase:5 on a failed-auth response status.
  assert.match(conf, /phase:5[^\n]*\n[^\n]*\n[^\n]*RESPONSE_STATUS "@rx \^\(\?:401\|403\|422\)\$"[^\n]*setvar:global\.ss_lockout=\+1/);
});

test('v0.7 accountLockout: body-field identifier inits the counter at phase:2 (key not populated at phase:1)', () => {
  const conf = v07Conf({
    authentication: {
      type: 'basic',
      accountLockout: { attempts: 3, window: '10m', identifier: 'request.body.email' }
    },
    cacheable: false
  });
  assert.match(conf, /initcol:global=ss_lockout_%\{ARGS\.email\}/);
  assert.match(conf, /id:\d+,phase:2,pass,nolog,[^\n]*initcol:global=ss_lockout_%\{ARGS\.email\}/);
});

test('v0.7 forbidArrayRoot: emits a phase:4 RESPONSE_BODY bare-array deny', () => {
  const conf = v07Conf({
    authentication: { type: 'none' },
    response: { forbidArrayRoot: true },
    cacheable: false
  });
  assert.match(conf, /writ-rule-forbid-array-root/);
  assert.match(conf, /phase:4[^\n]*forbidArrayRoot/);
  assert.match(conf, /SecRule RESPONSE_BODY "@rx \^\[\\s/);
});

test('v0.7 idempotencyKey: emits missing-header 400 + persistent-collection replay 409', () => {
  const conf = v07Conf({
    authentication: { type: 'none' },
    request: { idempotencyKey: { header: 'Idempotency-Key', ttl: '5m' } },
    cacheable: false
  }, 'POST', '/transfers');
  assert.match(conf, /writ-rule-idempotency-key/);
  assert.match(conf, /missing Idempotency-Key header/);
  assert.match(conf, /initcol:global=ss_idem_%\{REQUEST_HEADERS\.Idempotency-Key\}/);
  assert.match(conf, /replayed idempotency key/);
  assert.match(conf, /GLOBAL:ss_idem "@gt 1"/);
});

test('v0.7 logging: request/response events emit a phase:5 auditlog opt-in tagged writ-audit', () => {
  const conf = v07Conf({
    authentication: { type: 'none' },
    logging: { events: ['auth-failure', 'request', 'response'], sink: 'http-collector', sinkRef: 'https://logs/', piiRedaction: true },
    cacheable: false
  });
  assert.match(conf, /writ-audit/);
  assert.match(conf, /phase:5,pass,log,auditlog/);
  // Honest operator note: the http-collector sink + piiRedaction are not
  // enforceable at libmodsec3 and must be said so (Rule D-1, no fake full).
  assert.match(conf, /sink='http-collector' is NOT enforced at libmodsec3/);
  assert.match(conf, /piiRedaction=true is NOT enforceable/);
});

test('v0.7 capability matrix: passwordPolicy/accountLockout/forbidArrayRoot=full, idempotencyKey/logging=partial', () => {
  const caps = bunkerwebGenerator.capabilities().fields;
  assert.equal(caps['authentication.passwordPolicy'], 'full');
  assert.equal(caps['authentication.accountLockout'], 'full');
  assert.equal(caps['response.forbidArrayRoot'], 'full');
  assert.equal(caps['request.idempotencyKey'], 'partial');
  assert.equal(caps['logging'], 'partial');
  // injectionGuard cell (rides deserialization + ai-prompt sinks) stays full.
  assert.equal(caps['request.schema.injectionGuard'], 'full');
});

