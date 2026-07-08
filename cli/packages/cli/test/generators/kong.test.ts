import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import { loadSpec } from '@x-security/core';
import { kongGenerator, createKongGenerator } from '../../src/generators/kong/index.ts';
import {
  buildAuthPlugins,
  buildRequestValidatorPlugin,
  buildRuleBasedAuthzPlugins,
  buildSignaturePlugin,
  buildSsrfPreFunctionPlugins,
  buildMassAssignPreFunctionPlugins,
  buildSqliPreFunctionPlugins,
  buildDeprecatedEndpointPlugins,
  sanitizeTag,
  kongEditionFor
} from '../../src/generators/kong/plugins.ts';
import { buildConsumers } from '../../src/generators/kong/consumers.ts';

// Capture stderr writes so we can assert warnings without leaking output into
// the test report. Restores the original writer at end of each test via try/finally.
function captureStderr<T>(fn: () => T): { result: T; warnings: string[] } {
  const warnings: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  (process.stderr as { write: (chunk: string | Uint8Array) => boolean }).write = (chunk) => {
    warnings.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  };
  try {
    return { result: fn(), warnings };
  } finally {
    (process.stderr as { write: typeof original }).write = original;
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '../../../..');
const FIXTURE_SPEC = join(REPO_ROOT, 'fixtures/specs/example.yaml');
const GOLDEN = join(REPO_ROOT, 'fixtures/configs/kong/example.expected.yml');

async function loadFixtureIR() {
  process.env.JWKS_ENDPOINT = 'https://auth.example.com/.well-known/jwks.json';
  process.env.AUTH_ISSUER = 'https://auth.example.com/';
  process.env.AUTH_AUDIENCE = 'api.example.com';
  return loadSpec(FIXTURE_SPEC);
}

test('kong generator: name and target metadata', () => {
  assert.equal(kongGenerator.name, 'kong');
  assert.deepEqual([...kongGenerator.targets], ['kong-oss-3']);
});

test('kong generator: capabilities matrix is honest', () => {
  const caps = kongGenerator.capabilities();
  assert.equal(caps.fields['response.schema'], 'full'); // W31: post-function cjson-decodes + enforces all typed constraints on parsed values
  assert.equal(caps.fields['rateLimit'], 'full');
  assert.equal(caps.fields['authentication.mtls'], 'override-only');
  assert.equal(caps.fields['cors'], 'full');
  assert.equal(caps.fields['targetOverrides.kong'], 'full');
});

test('kong generator: produces single kong.yml artifact', async () => {
  const spec = await loadFixtureIR();
  const artifacts = await kongGenerator.generate(spec);
  assert.equal(artifacts.length, 1);
  assert.equal(artifacts[0]!.path, 'kong.yml');
  assert.equal(artifacts[0]!.format, 'yaml');
});

test('kong generator: emits a service+route per endpoint', async () => {
  const spec = await loadFixtureIR();
  const [artifact] = await kongGenerator.generate(spec);
  const parsed = yamlLoad(artifact!.content) as {
    _format_version: string;
    services: Array<{ name: string; routes: Array<{ methods: string[]; paths: string[] }> }>;
  };
  assert.equal(parsed._format_version, '3.0');
  assert.equal(parsed.services.length, 3);

  const byName = new Map(parsed.services.map((s) => [s.name, s]));
  assert.ok(byName.has('svc_login'));
  assert.ok(byName.has('svc_listUsers'));
  assert.ok(byName.has('svc_uploadFile'));

  const login = byName.get('svc_login')!;
  assert.deepEqual(login.routes[0]!.methods, ['POST']);
  assert.deepEqual(login.routes[0]!.paths, ['/api/auth/login']);
});

test('kong generator: login endpoint has rate-limit + cors + size-limit plugins (OSS suppresses request-validator)', async () => {
  // Pre-existing failure triaged in REPORT-v3 §13: this test originally
  // asserted `request-validator` on OSS, but C-3c suppresses that plugin
  // on OSS (Kong OSS doesn't ship it; emitting it 500s the gateway at boot).
  // Re-anchor the assertion to what OSS actually emits.
  const spec = await loadFixtureIR();
  const [artifact] = await kongGenerator.generate(spec);
  const parsed = yamlLoad(artifact!.content) as {
    services: Array<{ name: string; routes: Array<{ plugins?: Array<{ name: string; config?: Record<string, unknown> }> }> }>;
  };
  const login = parsed.services.find((s) => s.name === 'svc_login')!;
  const pluginNames = (login.routes[0]!.plugins ?? []).map((p) => p.name).sort();
  assert.ok(pluginNames.includes('rate-limiting'));
  assert.ok(pluginNames.includes('cors'));
  assert.ok(pluginNames.includes('request-size-limiting'));
  // cacheable:false → response-transformer with no-store
  assert.ok(pluginNames.includes('response-transformer'));
  // OSS edition: request-validator is enterprise-only — must NOT appear.
  assert.ok(!pluginNames.includes('request-validator'));

  const rl = login.routes[0]!.plugins!.find((p) => p.name === 'rate-limiting')!;
  // W23-C1: bucket value is burst-headroom (max(requests*3, requests+20)),
  // not the raw steady-state. 5 requests/min → burst = max(15, 25) = 25.
  assert.equal((rl.config as { minute: number }).minute, 25);
  assert.equal((rl.config as { limit_by: string }).limit_by, 'ip');
});

test('kong generator: admin endpoint has jwt + acl + ip-restriction plugins', async () => {
  const spec = await loadFixtureIR();
  const [artifact] = await kongGenerator.generate(spec);
  const parsed = yamlLoad(artifact!.content) as {
    services: Array<{ name: string; read_timeout?: number; routes: Array<{ plugins?: Array<{ name: string; config?: Record<string, unknown> }> }> }>;
  };
  const admin = parsed.services.find((s) => s.name === 'svc_listUsers')!;
  assert.equal(admin.read_timeout, 10000);

  const pluginNames = (admin.routes[0]!.plugins ?? []).map((p) => p.name).sort();
  assert.ok(pluginNames.includes('jwt'));
  assert.ok(pluginNames.includes('acl'));
  assert.ok(pluginNames.includes('ip-restriction'));

  const acl = admin.routes[0]!.plugins!.find((p) => p.name === 'acl')!;
  assert.deepEqual((acl.config as { allow: string[] }).allow, ['admin', 'super-admin']);

  const ip = admin.routes[0]!.plugins!.find((p) => p.name === 'ip-restriction')!;
  assert.deepEqual((ip.config as { allow: string[] }).allow, ['10.0.0.0/8']);
});

test('kong generator: snapshot matches golden kong.yml', async () => {
  const spec = await loadFixtureIR();
  // The golden was captured before --with-consumers existed. Use a generator
  // with consumers off so the snapshot remains the spec-only baseline; the
  // consumer-emission path has its own dedicated tests below.
  const legacyGen = createKongGenerator({ withConsumers: false });
  const [artifact] = await legacyGen.generate(spec);
  const generated = yamlLoad(artifact!.content);

  if (!existsSync(GOLDEN)) {
    throw new Error(`Missing golden snapshot: ${GOLDEN}. Generate it first.`);
  }
  const goldenText = await readFile(GOLDEN, 'utf8');
  const expected = yamlLoad(goldenText);
  assert.deepEqual(generated, expected);
});

// ---------- C-3a: tag sanitization ----------
// Kong 3.4 OSS rejects tags containing ':' '/' ',' — `kong.yml` with
// `tags: [jwks=https://idp.example.com/.well-known/jwks.json]` fails to load
// with "invalid tag ... expected printable ascii (except `,` and `/`)".
test('kong C-3a: sanitizeTag replaces colon, slash, comma', () => {
  assert.equal(
    sanitizeTag('jwks=https://idp.example.com/.well-known/jwks.json'),
    'jwks=https___idp.example.com_.well-known_jwks.json'
  );
  assert.equal(sanitizeTag('a,b'), 'a_b');
  assert.equal(sanitizeTag('issuer=https://auth/'), 'issuer=https___auth_');
  // safe chars are preserved
  assert.equal(sanitizeTag('issuer=auth-server.local'), 'issuer=auth-server.local');
});

test('kong C-3a: bearer-jwt plugin tags contain no banned characters', () => {
  const [plugin] = buildAuthPlugins({
    type: 'bearer-jwt',
    jwksUri: 'https://idp.example.com/.well-known/jwks.json',
    issuer: 'https://auth.example.com/',
    audience: 'api.example.com',
    allowedAlgorithms: ['RS256']
  } as any);
  assert.ok(plugin?.tags?.length);
  for (const tag of plugin!.tags!) {
    assert.ok(!/[:/,]/.test(tag), `tag still contains banned char: ${tag}`);
  }
});

// ---------- C-3b: deterministic, unique plugin ids ----------
// When two routes have identical plugin config, Kong computes the same UUID
// primary-key and refuses to load: "uniqueness violation: 'plugins' entity
// with primary key set to ...". We emit explicit `id: <uuidv5>` per plugin.
// Minimal in-memory spec — avoids loading the broken example.yaml fixture.
function makeMinimalSpec(): any {
  const rl = {
    requests: 60,
    window: '1m',
    identifier: 'ip'
  };
  const mkEndpoint = (op: string, path: string) => ({
    operationId: op,
    method: 'GET',
    path,
    policy: { rateLimit: rl }
  });
  return {
    servers: [{ url: 'http://upstream.invalid' }],
    endpoints: [mkEndpoint('opA', '/a'), mkEndpoint('opB', '/b')]
  };
}

test('kong C-3b: every plugin gets a unique deterministic id (identical configs do not collide)', async () => {
  // Both endpoints have IDENTICAL rate-limit config — the exact scenario
  // that triggered "uniqueness violation" on Kong 3.4 before this fix.
  const spec = makeMinimalSpec();
  const [artifact] = await kongGenerator.generate(spec);
  const parsed = yamlLoad(artifact!.content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ id?: string; name: string }> }> }>;
  };
  const ids: string[] = [];
  for (const svc of parsed.services) {
    for (const route of svc.routes) {
      for (const p of route.plugins ?? []) {
        assert.ok(p.id, `plugin ${p.name} missing id`);
        assert.match(p.id!, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
        ids.push(p.id!);
      }
    }
  }
  assert.equal(ids.length, 2);
  assert.equal(new Set(ids).size, 2, `duplicate plugin ids: ${ids.join(',')}`);
});

test('kong C-3b: plugin ids are stable across regenerations', async () => {
  const [a1] = await kongGenerator.generate(makeMinimalSpec());
  const [a2] = await kongGenerator.generate(makeMinimalSpec());
  assert.equal(a1!.content, a2!.content);
});

// ---------- C-3c: request-validator is enterprise-only ----------
// Kong OSS aborts with "plugin 'request-validator' not enabled". The
// generator must skip it by default and only emit it when the operator
// opts in via targetOverrides.kong.edition = "enterprise".
test('kong C-3c: request-validator suppressed on OSS (default)', () => {
  const plugins = buildRequestValidatorPlugin(
    {
      contentType: ['application/json'],
      maxBodySize: '1MB',
      schema: { email: { type: 'email' } }
    } as any,
    'oss'
  );
  assert.equal(plugins.find((p) => p.name === 'request-validator'), undefined);
  // request-size-limiting is OSS-supported and should still be emitted
  assert.ok(plugins.find((p) => p.name === 'request-size-limiting'));
});

test('kong C-3c: request-validator emitted when edition=enterprise', () => {
  const plugins = buildRequestValidatorPlugin(
    {
      contentType: ['application/json'],
      schema: { email: { type: 'email' } }
    } as any,
    'enterprise'
  );
  assert.ok(plugins.find((p) => p.name === 'request-validator'));
});

test('kong C-3c: kongEditionFor reads targetOverrides.kong.edition', () => {
  assert.equal(kongEditionFor({} as any), 'oss');
  assert.equal(kongEditionFor({ targetOverrides: { kong: {} } } as any), 'oss');
  assert.equal(
    kongEditionFor({ targetOverrides: { kong: { edition: 'enterprise' } } } as any),
    'enterprise'
  );
  assert.equal(
    kongEditionFor({ targetOverrides: { kong: { edition: 'oss' } } } as any),
    'oss'
  );
});

// ---------- request.signature → hmac-auth ----------
// Closes the API10 gap where XSecurity's `request.signature` declared HMAC
// verification but the Kong generator emitted no plugin, leaving the upstream
// unprotected. Kong OSS ships `hmac-auth` bundled.

test('kong signature: hmac-sha256 maps to hmac-auth plugin with algorithms list', () => {
  const { result: plugins, warnings } = captureStderr(() =>
    buildSignaturePlugin({
      algorithm: 'hmac-sha256',
      headerName: 'Authorization',
      secretRef: '${UPSTREAM_HMAC_SECRET}',
      body: 'raw'
    } as any)
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'hmac-auth');
  const cfg = plugins[0]!.config as Record<string, unknown>;
  assert.deepEqual(cfg.algorithms, ['hmac-sha256']);
  assert.equal(cfg.validate_request_body, true);
  assert.equal(cfg.hide_credentials, true);
  // Authorization is Kong's native header — no override warning expected.
  assert.equal(warnings.join(''), '');
});

test('kong signature: ed25519 emits no plugin and surfaces a warning (Kong OSS unsupported)', () => {
  const { result: plugins, warnings } = captureStderr(() =>
    buildSignaturePlugin({
      algorithm: 'ed25519',
      headerName: 'Authorization',
      secretRef: '${UPSTREAM_ED_KEY}',
      body: 'raw'
    } as any)
  );
  assert.equal(plugins.length, 0);
  const joined = warnings.join('');
  assert.match(joined, /ed25519/);
  assert.match(joined, /not supported/);
});

test('kong signature: timestampHeader + tolerance produce clock_skew and enforce_headers', () => {
  const { result: plugins } = captureStderr(() =>
    buildSignaturePlugin({
      algorithm: 'hmac-sha256',
      headerName: 'Authorization',
      secretRef: '${S}',
      body: 'raw',
      timestampHeader: 'X-Upstream-Timestamp',
      timestampToleranceSeconds: 300
    } as any)
  );
  const cfg = plugins[0]!.config as Record<string, unknown>;
  assert.equal(cfg.clock_skew, 300);
  assert.deepEqual(cfg.enforce_headers, ['date', 'X-Upstream-Timestamp']);
});

test('kong signature: canonical body emits warning + falls back to raw validation', () => {
  const { result: plugins, warnings } = captureStderr(() =>
    buildSignaturePlugin({
      algorithm: 'hmac-sha256',
      headerName: 'Authorization',
      secretRef: '${S}',
      body: 'canonical'
    } as any)
  );
  const cfg = plugins[0]!.config as Record<string, unknown>;
  assert.equal(cfg.validate_request_body, true);
  assert.match(warnings.join(''), /canonical/);
});

test('kong signature: non-Authorization headerName warns + still attaches plugin (route stays gated)', () => {
  const { result: plugins, warnings } = captureStderr(() =>
    buildSignaturePlugin({
      algorithm: 'hmac-sha256',
      headerName: 'X-Upstream-Signature',
      secretRef: '${S}',
      body: 'raw'
    } as any)
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'hmac-auth');
  assert.match(warnings.join(''), /X-Upstream-Signature/);
  assert.ok(plugins[0]!.tags?.some((t) => t.includes('signature-header-override')));
});

test('kong signature: end-to-end — endpoint with request.signature emits hmac-auth on its route', async () => {
  const spec: any = {
    servers: [{ url: 'http://upstream.invalid' }],
    endpoints: [
      {
        operationId: 'api10_user_flag',
        method: 'GET',
        path: '/vapi/api10/user/flag',
        policy: {
          request: {
            signature: {
              algorithm: 'hmac-sha256',
              headerName: 'Authorization',
              secretRef: '${UPSTREAM_HMAC_SECRET}',
              body: 'raw',
              timestampHeader: 'X-Upstream-Timestamp',
              timestampToleranceSeconds: 300
            }
          }
        }
      }
    ]
  };
  const { result: artifacts } = captureStderr(() => kongGenerator.generate(spec));
  const parsed = yamlLoad((artifacts as any[])[0]!.content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ name: string; config?: any }> }> }>;
  };
  const plugins = parsed.services[0]!.routes[0]!.plugins ?? [];
  const hmac = plugins.find((p) => p.name === 'hmac-auth');
  assert.ok(hmac, 'hmac-auth plugin must be attached to the route');
  assert.deepEqual(hmac!.config.algorithms, ['hmac-sha256']);
  assert.equal(hmac!.config.clock_skew, 300);
});

// ---------- Consumer emission (C-4: --with-consumers) ----------
// OSS Kong's jwt/key-auth/acl/hmac-auth plugins all 401 every request unless a
// Consumer + credential is preconfigured. Without these top-level entities,
// the generated kong.yml is unusable for testing BFLA/ACL enforcement.

function specWithRoles(): any {
  return {
    openapi: '3.0.0',
    dialect: '3.0',
    info: { title: 'consumer-test', version: '1.0' },
    servers: [{ url: 'http://upstream.invalid' }],
    endpoints: [
      {
        operationId: 'listUsers',
        method: 'GET',
        path: '/users',
        policy: {
          authentication: {
            type: 'bearer-jwt',
            issuer: 'https://auth.example.com/',
            audience: 'api.example.com',
            allowedAlgorithms: ['RS256']
          },
          authorization: { type: 'rbac', roles: ['admin', 'user'] }
        }
      }
    ],
    unprotectedEndpoints: []
  };
}

test('kong C-4a: two RBAC roles emit two consumers + matching ACL groups', () => {
  const gen = createKongGenerator({ withConsumers: true });
  const [artifact] = gen.generate(specWithRoles());
  const parsed = yamlLoad((artifact as any).content) as {
    consumers?: Array<{ username: string }>;
    acls?: Array<{ consumer: string; group: string }>;
  };
  assert.ok(parsed.consumers, 'consumers block must be emitted');
  const usernames = parsed.consumers!.map((c) => c.username).sort();
  assert.deepEqual(usernames, ['role_admin', 'role_user']);

  assert.ok(parsed.acls, 'acls block must be emitted');
  // Each consumer maps to an ACL group equal to the role name so the
  // acl plugin's `allow: [admin]` matches.
  const aclPairs = parsed.acls!.map((a) => `${a.consumer}:${a.group}`).sort();
  assert.deepEqual(aclPairs, ['role_admin:admin', 'role_user:user']);
});

test('kong C-4b: bearer-jwt emits jwt_secret with HS256 + STATUS-documented downgrade warning', () => {
  const gen = createKongGenerator({ withConsumers: true });
  const [artifact] = gen.generate(specWithRoles());
  const parsed = yamlLoad((artifact as any).content) as {
    jwt_secrets?: Array<{ consumer: string; algorithm: string; secret: string; key: string }>;
  };
  assert.ok(parsed.jwt_secrets?.length, 'jwt_secrets must be emitted for bearer-jwt');
  for (const js of parsed.jwt_secrets!) {
    // RS256 in the spec is downgraded to HS256 because OSS Kong cannot fetch JWKS.
    assert.equal(js.algorithm, 'HS256', 'OSS Kong downgrade: jwt_secret must be HS256');
    assert.ok(js.secret && js.secret.length > 0, 'jwt_secret must carry a shared secret');
  }
  // jwt_secrets[*].key must be unique (Kong primary key) — duplicates 500 at boot.
  const keys = parsed.jwt_secrets!.map((j) => j.key);
  assert.equal(new Set(keys).size, keys.length, 'jwt_secret keys must be unique');

  const warnings = gen.lastWarnings.join('\n');
  assert.match(warnings, /HS256/, 'generator must warn about the HS256 downgrade');
});

test('kong C-4c: --with-consumers=false round-trips to the legacy empty-consumers behavior', () => {
  const gen = createKongGenerator({ withConsumers: false });
  const [artifact] = gen.generate(specWithRoles());
  const parsed = yamlLoad((artifact as any).content) as Record<string, unknown>;
  assert.equal(parsed.consumers, undefined);
  assert.equal(parsed.jwt_secrets, undefined);
  assert.equal(parsed.keyauth_credentials, undefined);
  assert.equal(parsed.acls, undefined);
  // No warnings either: we didn't emit anything to warn about.
  assert.equal(gen.lastWarnings.length, 0);
});

test('kong C-4d: api-key endpoint emits keyauth_credentials with stable per-role keys', () => {
  const spec: any = specWithRoles();
  spec.endpoints[0].policy.authentication = { type: 'api-key', headerName: 'X-API-Key' };
  const gen = createKongGenerator({ withConsumers: true });
  const [a1] = gen.generate(spec);
  const [a2] = gen.generate(spec);
  // Determinism: same spec → byte-identical output (x-security diff depends on it).
  assert.equal((a1 as any).content, (a2 as any).content);

  const parsed = yamlLoad((a1 as any).content) as {
    keyauth_credentials?: Array<{ consumer: string; key: string }>;
  };
  assert.ok(parsed.keyauth_credentials?.length, 'keyauth_credentials must be emitted');
  const byUser = new Map(parsed.keyauth_credentials!.map((c) => [c.consumer, c.key]));
  assert.ok(byUser.has('role_admin'));
  assert.ok(byUser.has('role_user'));
  // Keys must be distinct per consumer (Kong's key-auth primary key is on `key`).
  const keys = [...byUser.values()];
  assert.equal(new Set(keys).size, keys.length);
});

test('kong C-4e: buildConsumers is a pure function (no spec mutation)', () => {
  const spec = specWithRoles();
  const before = JSON.stringify(spec);
  buildConsumers(spec);
  assert.equal(JSON.stringify(spec), before);
});

// ---------- C-5: deployment-aware upstream URL ----------
// Eliminates the manual `sed` patch the chain demo previously needed to
// point Kong services at `http://coraza:8080`. The generator now owns
// the deployment-shape contract.

function specForDeployment(): any {
  return {
    info: { title: 'deploy-test', version: '1.0' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints: [
      {
        operationId: 'getUser',
        method: 'GET',
        path: '/users/{id}',
        policy: {}
      }
    ],
    unprotectedEndpoints: []
  };
}

test('kong C-5a: deployment=standalone uses spec.servers[0].url (legacy default)', () => {
  const gen = createKongGenerator({ withConsumers: false, deployment: 'standalone' });
  const [art] = gen.generate(specForDeployment());
  const parsed = yamlLoad((art as any).content) as { services: Array<{ url: string }> };
  assert.equal(parsed.services[0]!.url, 'https://api.example.com');
});

test('kong C-5b: deployment=with-coraza rewrites every service URL to http://coraza:8080', () => {
  const gen = createKongGenerator({ withConsumers: false, deployment: 'with-coraza' });
  const spec = specForDeployment();
  spec.endpoints.push({
    operationId: 'createUser',
    method: 'POST',
    path: '/users',
    policy: {}
  });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as { services: Array<{ url: string }> };
  assert.equal(parsed.services.length, 2);
  for (const svc of parsed.services) {
    assert.equal(svc.url, 'http://coraza:8080');
  }
});

test('kong C-5c: deployment=with-istio points services at Envoy sidecar inbound port', () => {
  const gen = createKongGenerator({ withConsumers: false, deployment: 'with-istio' });
  const [art] = gen.generate(specForDeployment());
  const parsed = yamlLoad((art as any).content) as { services: Array<{ url: string }> };
  assert.equal(parsed.services[0]!.url, 'http://localhost:15001');
});

test('kong C-5d: deployment=behind-proxy preserves upstream URL + emits trusted_ips warning', () => {
  const gen = createKongGenerator({ withConsumers: false, deployment: 'behind-proxy' });
  const [art] = gen.generate(specForDeployment());
  const parsed = yamlLoad((art as any).content) as { services: Array<{ url: string }> };
  assert.equal(parsed.services[0]!.url, 'https://api.example.com');
  // Warnings ride on the generator's structured-warnings channel (and the
  // YAML-commented header) — NOT inside the live Kong config (Kong
  // rejects unknown top-level keys).
  assert.ok(
    gen.lastStructuredWarnings.some((w) => w.field === 'deployment.trusted_ips'),
    'behind-proxy must surface a trusted_ips reminder'
  );
  assert.match((art as any).content, /# WARNING: deployment\.trusted_ips/);
});

// ---------- C-6: limit_by auto-switch (unauth credential-stuffing fix) ----------
// REPORT-v3 Open-4 root cause: login endpoints with no consumer use
// `limit_by: consumer` which never accumulates → failed-login bursts are
// never rate-limited. The generator now forces `limit_by: ip` whenever the
// endpoint can't carry a consumer identity.

test('kong C-6a: unauthenticated endpoint forces limit_by=ip (was consumer)', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'publicSearch',
        method: 'GET',
        path: '/public/search',
        policy: {
          authentication: { type: 'none' },
          rateLimit: { requests: 100, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false, deployment: 'standalone' });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ name: string; config?: any }> }> }>;
  };
  const rl = parsed.services[0]!.routes[0]!.plugins!.find((p) => p.name === 'rate-limiting')!;
  assert.equal(rl.config.limit_by, 'ip');
  assert.ok(
    gen.lastStructuredWarnings.some((w) => w.field === 'rateLimit.limit_by'),
    'consumer→ip downgrade must be recorded'
  );
});

test('kong C-6b: login-path heuristic forces limit_by=ip even without explicit auth=none', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'doLogin',
        method: 'POST',
        path: '/api2/user/login',
        policy: {
          // Spec author left this on user-id which is meaningless for an
          // unauthenticated login attempt — the generator must protect
          // the operator from the silent no-op.
          rateLimit: { requests: 5, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ name: string; config?: any }> }> }>;
  };
  const rl = parsed.services[0]!.routes[0]!.plugins!.find((p) => p.name === 'rate-limiting')!;
  assert.equal(rl.config.limit_by, 'ip');
});

test('kong C-6c: operationId contains "signup" → limit_by=ip', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'userSignup',
        method: 'POST',
        path: '/api/auth',
        policy: { rateLimit: { requests: 10, window: '1m', identifier: 'user-id' } }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'ip');
});

test('kong C-6d: authenticated endpoint keeps limit_by=consumer (no false downgrade)', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'getProfile',
        method: 'GET',
        path: '/me',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/' },
          rateLimit: { requests: 60, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'consumer');
});

// ---------- W15-C: rate-limit policy (cluster vs local) per identity intent ----------
//
// Background: Kong's `rate-limiting` plugin defaulted to `policy: local`, which
// keeps counters in-process. For `limit_by: ip` on a single instance that's
// fine, but for per-identity buckets (credential, consumer, header) it scopes
// the counter per-instance — a multi-instance attacker can round-robin past
// the limit. Per identity, `policy: cluster` is the correct default. DB-less
// Kong (`KONG_DATABASE=off`) cannot use cluster policy, so we fall back to
// local AND emit a structured warning instead of silently degrading.

test('kong W15-C-1: rate-limit limit_by=ip → policy=local (single-instance optimization)', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'publicPing',
        method: 'GET',
        path: '/ping',
        policy: {
          authentication: { type: 'none' },
          rateLimit: { requests: 100, window: '1m', identifier: 'ip' }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'ip');
  assert.equal(rl.config.policy, 'local');
  // No policy-downgrade warning for the ip case — local keys per IP correctly.
  assert.equal(
    gen.lastStructuredWarnings.filter((w) => w.field === 'rateLimit.policy').length,
    0
  );
});

test('kong W15-C-2: rate-limit limit_by=jwt-sub (user-id) → policy=cluster (per-identity, opt-in)', () => {
  // W21-C: cluster is now opt-in via {policy:'cluster'}; without it the generator
  // defaults to local (safe for OSS DB-less). When the operator confirms a
  // DB-backed deployment via --kong-policy cluster, the W15-C per-identity
  // cross-instance counter sharing is restored.
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'getProfile',
        method: 'GET',
        path: '/me',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/' },
          rateLimit: { requests: 60, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false, policy: 'cluster' }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'consumer');
  assert.equal(rl.config.policy, 'cluster');
});

test('kong W15-C-3: rate-limit limit_by=api-key → policy=cluster (per-credential, opt-in)', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'listOrders',
        method: 'GET',
        path: '/orders',
        policy: {
          authentication: { type: 'api-key', headerName: 'X-API-Key' },
          rateLimit: { requests: 30, window: '1m', identifier: 'api-key' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false, policy: 'cluster' }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'credential');
  assert.equal(rl.config.policy, 'cluster');
});

test('kong W15-C-4: DB-less mode + non-ip limit_by → policy=local fallback with structured warning', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'getProfile',
        method: 'GET',
        path: '/me',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/' },
          rateLimit: { requests: 60, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false, dbless: true });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rl.config.limit_by, 'consumer');
  assert.equal(rl.config.policy, 'local');
  const policyWarning = gen.lastStructuredWarnings.find((w) => w.field === 'rateLimit.policy');
  assert.ok(policyWarning, 'expected structured warning for DB-less per-identity fallback');
  assert.match(policyWarning!.reason, /DB-less/);
  assert.match(policyWarning!.reason, /cluster/);
});

// ---------- W21-C: default policy=local; SSRF pre-function is cjson-free ----------
//
// Background: W15-C made cluster the default for non-ip identifiers, but Kong
// OSS DB-less (the OSS quickstart default) refuses to load with policy=cluster
// and the chain demo silently broke. W21-C flips the default to local and
// makes cluster opt-in via {policy:'cluster'} so operators only pay the
// per-instance counter penalty when they haven't explicitly confirmed a
// DB-backed deployment.
//
// Bug 1 in the same wave: K-2 SSRF pre-function emitted
// `require("cjson.safe")` which Kong's untrusted_lua sandbox rejects on
// hardened deployments. The pre-function does not need cjson — it uses Kong
// PDK calls + Lua stdlib. The require is removed.

test('kong W21-C-1: K-2 SSRF pre-function does NOT require cjson', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'fetchUrl',
        method: 'GET',
        path: '/proxy',
        parameters: [{ name: 'url', in: 'query' }],
        policy: {
          authentication: { type: 'none' },
          request: {
            schema: {
              url: {
                type: 'url',
                domainAllowlist: ['example.com'],
                blockPrivateRanges: true
              }
            }
          }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const ssrf = parsed.services[0].routes[0].plugins.find(
    (p: any) => p.name === 'pre-function' && (p.tags ?? []).includes('x-security-rule-ssrf-403')
  );
  assert.ok(ssrf, 'expected SSRF pre-function');
  const lua = ssrf.config.access[0] as string;
  assert.doesNotMatch(lua, /require\s*\(?\s*["']cjson/);
});

test('kong W21-C-2: K-2 SSRF pre-function uses kong.request.get_query_arg / get_body', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'fetchUrlQuery',
        method: 'GET',
        path: '/proxy',
        parameters: [{ name: 'url', in: 'query' }],
        policy: {
          authentication: { type: 'none' },
          request: {
            schema: {
              url: { type: 'url', domainAllowlist: ['example.com'] }
            }
          }
        }
      },
      {
        operationId: 'fetchUrlBody',
        method: 'POST',
        path: '/proxy-body',
        parameters: [],
        policy: {
          authentication: { type: 'none' },
          request: {
            schema: {
              callbackUrl: { type: 'url', domainAllowlist: ['example.com'] }
            }
          }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const queryLua = parsed.services[0].routes[0].plugins.find(
    (p: any) => p.name === 'pre-function' && (p.tags ?? []).includes('x-security-rule-ssrf-403')
  ).config.access[0] as string;
  const bodyLua = parsed.services[1].routes[0].plugins.find(
    (p: any) => p.name === 'pre-function' && (p.tags ?? []).includes('x-security-rule-ssrf-403')
  ).config.access[0] as string;
  assert.match(queryLua, /kong\.request\.get_query_arg\("url"\)/);
  assert.match(bodyLua, /kong\.request\.get_body\(\)/);
});

test('kong W21-C-3: default policy is local for OSS (no opt-in); cluster requires explicit opt-in', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'getProfile',
        method: 'GET',
        path: '/me',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/' },
          rateLimit: { requests: 60, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  // Default — no policy opt-in. Expect local + a structured warning telling
  // the operator how to upgrade to cluster.
  const genDefault = createKongGenerator({ withConsumers: false });
  const [artDefault] = genDefault.generate(spec);
  const rlDefault = (yamlLoad((artDefault as any).content) as any)
    .services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rlDefault.config.limit_by, 'consumer');
  assert.equal(rlDefault.config.policy, 'local');
  const defaultWarn = genDefault.lastStructuredWarnings.find(
    (w) => w.field === 'rateLimit.policy'
  );
  assert.ok(defaultWarn, 'expected structured warning when defaulting to local for non-ip');
  assert.match(defaultWarn!.reason, /--kong-policy cluster/);

  // Explicit cluster opt-in restores W15-C behavior.
  const genCluster = createKongGenerator({ withConsumers: false, policy: 'cluster' });
  const [artCluster] = genCluster.generate(spec);
  const rlCluster = (yamlLoad((artCluster as any).content) as any)
    .services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.equal(rlCluster.config.policy, 'cluster');
});

// ---------- C-7: _x_security_warnings top-level block + comment header ----------

test('kong C-7a: HS256 downgrade appears in _x_security_warnings (not just stderr)', () => {
  const spec: any = {
    info: { title: 'jwt-spec' },
    servers: [{ url: 'http://up' }],
    endpoints: [
      {
        operationId: 'getX',
        method: 'GET',
        path: '/x',
        policy: {
          authentication: {
            type: 'bearer-jwt',
            issuer: 'https://idp/',
            allowedAlgorithms: ['RS256']
          },
          authorization: { type: 'rbac', roles: ['admin'] }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: true, edition: 'oss' });
  const [art] = gen.generate(spec);
  const text = (art as any).content as string;
  assert.match(text, /^# WARNING:.*authentication\.allowedAlgorithms/m);
  assert.match(text, /^# _x_security_warnings:/m);
  assert.ok(gen.lastStructuredWarnings.some(
    (w) => w.field === 'authentication.allowedAlgorithms' && w.emitted === 'HS256'
  ));
});

test('kong C-7b: hmac-auth with non-Authorization header records structured warning', () => {
  const spec: any = {
    servers: [{ url: 'http://up' }],
    endpoints: [
      {
        operationId: 'webhook',
        method: 'POST',
        path: '/hook',
        policy: {
          request: {
            signature: {
              algorithm: 'hmac-sha256',
              headerName: 'X-Hub-Signature',
              secretRef: '${S}',
              body: 'raw'
            }
          }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false });
  captureStderr(() => gen.generate(spec));
  assert.ok(gen.lastStructuredWarnings.some(
    (w) => w.field === 'request.signature.headerName' && w.endpoint === 'webhook'
  ));
});

test('kong C-7c: header comment lists every divergence (grep-friendly)', () => {
  const spec: any = {
    info: { title: 't' },
    servers: [{ url: 'http://up' }],
    endpoints: [
      {
        operationId: 'webhook',
        method: 'POST',
        path: '/hook',
        policy: {
          request: { signature: { algorithm: 'ed25519', headerName: 'X-Sig', secretRef: '${S}', body: 'raw' } }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: false, deployment: 'behind-proxy' });
  const { result } = captureStderr(() => gen.generate(spec));
  const text = (result as any[])[0]!.content as string;
  // Two warnings: ed25519 drop + behind-proxy trusted_ips. Both must be
  // grep-able from the comment header.
  const warningLines = text.split('\n').filter((l) => l.startsWith('# WARNING:'));
  assert.ok(warningLines.length >= 2, `expected ≥2 # WARNING lines, got ${warningLines.length}`);
});

// ---------- C-8: --kong-edition enterprise → openid-connect ----------

test('kong C-8a: edition=enterprise + bearer-jwt emits openid-connect plugin (no OSS jwt)', () => {
  const spec: any = {
    info: { title: 'ent' },
    servers: [{ url: 'http://up' }],
    endpoints: [
      {
        operationId: 'getX',
        method: 'GET',
        path: '/x',
        policy: {
          authentication: {
            type: 'bearer-jwt',
            issuer: 'https://idp.example.com/',
            jwksUri: 'https://idp.example.com/.well-known/jwks.json',
            audience: 'api.example.com',
            allowedAlgorithms: ['RS256']
          },
          authorization: { type: 'rbac', roles: ['admin'] }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: true, edition: 'enterprise' });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ name: string; config?: any }> }> }>;
    jwt_secrets?: unknown[];
  };
  const plugins = parsed.services[0]!.routes[0]!.plugins ?? [];
  const oidc = plugins.find((p) => p.name === 'openid-connect');
  assert.ok(oidc, 'enterprise mode must emit openid-connect');
  assert.equal(oidc!.config.bearer_only, true);
  assert.equal(oidc!.config.issuer, 'https://idp.example.com/');
  assert.equal(oidc!.config.jwks_uri, 'https://idp.example.com/.well-known/jwks.json');
  assert.ok(!plugins.find((p) => p.name === 'jwt'), 'OSS jwt plugin must NOT be emitted in enterprise mode');
  // jwt_secrets HS256 downgrade must be skipped — the OIDC plugin does
  // real JWKS, so the shared-secret table would be inert + misleading.
  assert.equal(parsed.jwt_secrets, undefined, 'enterprise mode must skip jwt_secrets');
});

test('kong C-8b: edition=oss (default) keeps current jwt + HS256 jwt_secrets path', () => {
  const spec: any = {
    info: { title: 'oss' },
    servers: [{ url: 'http://up' }],
    endpoints: [
      {
        operationId: 'getX',
        method: 'GET',
        path: '/x',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/', allowedAlgorithms: ['RS256'] },
          authorization: { type: 'rbac', roles: ['admin'] }
        }
      }
    ]
  };
  const gen = createKongGenerator({ withConsumers: true, edition: 'oss' });
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as {
    services: Array<{ routes: Array<{ plugins?: Array<{ name: string }> }> }>;
    jwt_secrets?: Array<{ algorithm: string }>;
  };
  const plugins = parsed.services[0]!.routes[0]!.plugins ?? [];
  assert.ok(plugins.find((p) => p.name === 'jwt'));
  assert.ok(parsed.jwt_secrets?.length);
  assert.equal(parsed.jwt_secrets![0]!.algorithm, 'HS256');
});

// ---------- K-1: authorization.rule-based → pre-function Lua (BOLA) ----------

test('kong K-1a: rule-based + resourceLookup emits pre-function plugin with Lua access snippet', () => {
  const warnings: any[] = [];
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [
        { field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }
      ],
      resourceLookup: {
        endpoint: '/internal/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'getUser', warn: (w) => warnings.push(w) }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'pre-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-rule-bola-403'));
  const access = (plugins[0]!.config as { access: string[] }).access;
  assert.equal(access.length, 1);
  const lua = access[0]!;
  // Principal extraction
  assert.match(lua, /authenticated_credential.*username/);
  // Resource lookup URL has the path param substituted with a Lua expression
  assert.match(lua, /lookup_url = .*"\/internal\/users\/" \.\. tostring/);
  // Comparison + 403 deny with the XSecurity tag
  assert.match(lua, /tostring\(.*ss_resource.*ownerId.*\) ~= tostring/);
  assert.match(lua, /tag = "x-security-rule-bola-403"/);
  assert.match(lua, /kong\.response\.exit\(403/);
  // The cost-of-doing-business warning about resty.http availability is in
  // the snippet so operators see it even without WARNINGS.md.
  assert.match(lua, /resty\.http not available/);
});

test('kong K-1b: rule-based without resourceLookup but rule references resource.* → warning + plugin emitted (fail-closed if no resource)', () => {
  const warnings: any[] = [];
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [
        { field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }
      ]
    } as any,
    { endpoint: 'getUser', warn: (w) => warnings.push(w) }
  );
  assert.equal(plugins.length, 1, 'plugin still emitted so route is gated');
  const w = warnings.find((x) => x.field === 'authorization.resourceLookup');
  assert.ok(w, 'expected a warning about missing resourceLookup');
  assert.match(w.reason, /no resourceLookup/);
});

test('kong K-1c: multiple rules are ANDed (each emits its own if-block + 403)', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [
        { field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } },
        { field: 'tenantId', operator: 'equals', value: { ref: 'jwt.tid' } }
      ],
      resourceLookup: {
        endpoint: '/u/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId', 'tenantId']
      }
    } as any,
    { endpoint: 'getU' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Each rule emits a distinct `rule = N` field and its own exit.
  assert.match(lua, /rule = 1/);
  assert.match(lua, /rule = 2/);
  // exit(403) appears once per rule plus once for the resource-lookup-failed
  // path, so 2 rules → 3 occurrences. The per-rule ones reference `rule = N`.
  const perRuleExitCount = (lua.match(/rule = \d+/g) ?? []).length;
  assert.equal(perRuleExitCount, 2);
});

test('kong K-1d: rule-based with empty rules array → no plugin + warning', () => {
  const warnings: any[] = [];
  const plugins = buildRuleBasedAuthzPlugins(
    { type: 'rule-based', rules: [] } as any,
    { endpoint: 'ep', warn: (w) => warnings.push(w) }
  );
  assert.equal(plugins.length, 0);
  const w = warnings.find((x) => x.field === 'authorization.rules');
  assert.ok(w);
  assert.match(w.reason, /no rules/);
});

test('kong K-1e: principal.id is treated as a synonym for jwt.sub', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [
        { field: 'ownerId', operator: 'equals', value: { ref: 'principal.id' } }
      ],
      resourceLookup: { endpoint: '/u/{id}', identifierFrom: 'request.params.id', expose: ['ownerId'] }
    } as any,
    { endpoint: 'e' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // principal.id resolves through the same fallback chain as jwt.sub
  assert.match(lua, /authenticated_credential and kong\.ctx\.shared\.authenticated_credential\.username/);
});

test('kong K-1f: capability matrix reports authorization.rule-based as full', () => {
  const caps = kongGenerator.capabilities();
  assert.equal(caps.fields['authorization.rule-based'], 'full');
});

test('kong K-1g: end-to-end — endpoint with rule-based authz emits pre-function on its route', () => {
  const gen = createKongGenerator({ withConsumers: false });
  const spec: any = {
    servers: [{ url: 'http://upstream.invalid' }],
    endpoints: [
      {
        operationId: 'getUser',
        method: 'GET',
        path: '/users/{id}',
        policy: {
          authentication: { type: 'bearer-jwt' },
          authorization: {
            type: 'rule-based',
            rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
            resourceLookup: {
              endpoint: '/users/{id}',
              identifierFrom: 'request.params.id',
              expose: ['ownerId']
            }
          }
        }
      }
    ]
  };
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const route = parsed.services[0].routes[0];
  const pf = route.plugins.find((p: any) => p.name === 'pre-function');
  assert.ok(pf, 'pre-function plugin must be attached to the route');
  assert.match(pf.config.access[0], /x-security-rule-bola-403/);
});

// ---------- W10-4 / W10-11: pcall-wrapped lookup + shared_dict cache ----------

test('kong W10-4a: resource lookup is pcall-wrapped and yields 403 (not 500) on any failure', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
      resourceLookup: {
        endpoint: '/internal/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'getUser' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Every external call (require resty.http, request_uri, cjson.decode) is wrapped.
  assert.match(lua, /pcall\(require, "resty\.http"\)/);
  assert.match(lua, /pcall\(function\(\)\s+return httpc:request_uri/);
  assert.match(lua, /pcall\(cjson\.decode/);
  // No bare 500 from the lookup section — failures attribute as 403 with the SS tag.
  assert.ok(!/kong\.response\.exit\(500/.test(lua), 'lookup failures must NOT return 500');
  // Structured 403 with reason codes the scorer can grep.
  assert.match(lua, /reason = "lookup_failed"/);
  assert.match(lua, /reason = "decode_failed"/);
  assert.match(lua, /reason = "resty_http_missing"/);
  // [x-security-bola] log tag is present so docker logs greps work.
  assert.match(lua, /\[x-security-bola\] cache_miss/);
});

test('kong W10-11a: shared_dict cache is consulted before HTTP and populated on miss', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
      resourceLookup: {
        endpoint: '/internal/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'getUser' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Cache lookup happens BEFORE the HTTP block.
  const cacheGetIdx = lua.indexOf('ss_cache:get(ss_cache_key)');
  const httpCallIdx = lua.indexOf('httpc:request_uri');
  assert.ok(cacheGetIdx > 0 && httpCallIdx > 0 && cacheGetIdx < httpCallIdx,
    'cache get must precede httpc:request_uri');
  // Hit path skips the HTTP call (the if-branch references _ss_cached marker).
  assert.match(lua, /ss_cached_owner ~= nil/);
  assert.match(lua, /cache_hit/);
  // Miss path populates the cache after a successful decode.
  assert.match(lua, /ss_cache:set\(ss_cache_key, tostring\(body\.ownerId\), 60\)/);
  // Cache name matches the documented shared_dict.
  assert.match(lua, /ngx\.shared\.x_security_bola_cache/);
});

test('kong W10-11b: cache key combines principal + resource id (no cross-user leakage)', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
      resourceLookup: {
        endpoint: '/internal/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'getUser' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Cache key contains BOTH principal AND the resource identifier — otherwise
  // user A's cached owner of resource X would gate user B's request for X.
  assert.match(lua, /ss_cache_key = tostring\(principal\) \.\. ":" \.\. ss_resource_id/);
  assert.match(lua, /ss_resource_id = tostring\(kong\.request\.get_path_arg\("id"\)/);
});

test('kong W10-11c: pre-function emission records a structured shared_dict warning', () => {
  const warnings: any[] = [];
  buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
      resourceLookup: {
        endpoint: '/internal/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'getUser', warn: (w) => warnings.push(w) }
  );
  const w = warnings.find((x) => x.field === 'authorization.rule-based.cache');
  assert.ok(w, 'must surface a shared_dict warning so operators set KONG_NGINX_HTTP_LUA_SHARED_DICT');
  assert.match(w.emitted, /KONG_NGINX_HTTP_LUA_SHARED_DICT/);
  assert.match(w.reason, /shared_dict/);
});

test('kong W10-11d: cache lookup is nil-safe when ngx.shared.x_security_bola_cache is undeclared', () => {
  const plugins = buildRuleBasedAuthzPlugins(
    {
      type: 'rule-based',
      rules: [{ field: 'ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }],
      resourceLookup: {
        endpoint: '/u/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      }
    } as any,
    { endpoint: 'e' }
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // The `ss_cache and ss_cache:get(...)` short-circuit handles the case where
  // the operator did not set KONG_NGINX_HTTP_LUA_SHARED_DICT — falls through
  // to the HTTP path so the rule still enforces.
  assert.match(lua, /ss_cache and ss_cache:get\(ss_cache_key\) or nil/);
  // Write-side is also gated on cache being non-nil.
  assert.match(lua, /if ss_cache and body\.ownerId/);
});

test('kong C-9: configure() applies deployment + edition (CLI uses this path)', () => {
  const gen = createKongGenerator();
  gen.configure({ deployment: 'with-coraza', edition: 'enterprise', withConsumers: false });
  const spec: any = {
    info: { title: 'c' },
    servers: [{ url: 'https://api' }],
    endpoints: [
      {
        operationId: 'ep',
        method: 'GET',
        path: '/x',
        policy: { authentication: { type: 'bearer-jwt', issuer: 'https://idp/' } }
      }
    ]
  };
  const [art] = gen.generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  assert.equal(parsed.services[0].url, 'http://coraza:8080');
  assert.ok(parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'openid-connect'));
});

test('kong W10-9: ssrf-policy-missing warning fires on url-typed param without policy', () => {
  const gen = createKongGenerator({ withConsumers: false });
  const spec: any = {
    openapi: '3.0.0',
    dialect: '3.0',
    info: { title: 't', version: '1' },
    servers: [],
    unprotectedEndpoints: [],
    endpoints: [
      {
        operationId: 'redir',
        method: 'GET',
        path: '/redirect',
        parameters: [],
        resolvedVars: new Map(),
        raw: {},
        policy: {
          request: { schema: { url: { type: 'url' } } }
        }
      }
    ]
  };
  gen.generate(spec);
  const joined = gen.lastWarnings.join('\n');
  assert.match(joined, /\[kong:ssrf-policy-missing\] GET \/redirect/);
  assert.match(joined, /parameter "url"/);
});

test('kong W10-9: ssrf-policy-missing suppressed when blockPrivateRanges is set', () => {
  const gen = createKongGenerator({ withConsumers: false });
  const spec: any = {
    openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
    servers: [], unprotectedEndpoints: [],
    endpoints: [
      {
        operationId: 'redir', method: 'GET', path: '/redirect',
        parameters: [], resolvedVars: new Map(), raw: {},
        policy: { request: { schema: { url: { type: 'url', blockPrivateRanges: true } } } }
      }
    ]
  };
  gen.generate(spec);
  assert.equal(
    gen.lastWarnings.filter((w) => w.includes('ssrf-policy-missing')).length,
    0
  );
});

// ---------- W19-A: SSRF url-allowlist pre-function ----------

test('kong W19-A: domainAllowlist on url-typed query param emits pre-function with SSRF tag', () => {
  const plugins = buildSsrfPreFunctionPlugins(
    { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'] } } } as any,
    { endpoint: 'serversurfer', params: [{ name: 'url', in: 'query' }] }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'pre-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-rule-ssrf-403'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Pre-function reads the URL from the query string (not body) when the
  // param is bound to `in: query`.
  assert.match(lua, /kong\.request\.get_query_arg\("url"\)/);
  // Allowlist table contains the lowercased declared host.
  assert.match(lua, /\["roottusk\.com"\]=true/);
  assert.match(lua, /kong\.response\.exit\(403/);
  assert.match(lua, /tag = "x-security-rule-ssrf-403"/);
});

test('kong W19-A: blockPrivateRanges emits private-range guard with ssrf-private tag', () => {
  const plugins = buildSsrfPreFunctionPlugins(
    { schema: { url: { type: 'url', blockPrivateRanges: true } } } as any,
    { endpoint: 'fetch', params: [{ name: 'url', in: 'query' }] }
  );
  assert.equal(plugins.length, 1);
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  // Private-range guard fires `ss_is_private(host)` and tags the response.
  assert.match(lua, /ss_is_private\(host\)/);
  assert.match(lua, /tag = "x-security-rule-ssrf-private-403"/);
  // Canonical private prefixes appear in the Lua pattern set.
  assert.match(lua, /\^127%\./);
  assert.match(lua, /internal%-only/);
});

// ---------- W23-C1: per-route rate-limit burst headroom + scorer marker ----------
//
// vAPI eval gap C1: Kong's per-route rate-limit was being attributed as the
// wholesale-rate-limit class (×0.3) because (a) the bucket value matched the
// raw `requests` count, so auth-attack streams drained the bucket inside the
// first burst and got 429-masked, and (b) no marker on the plugin let the
// scorer recognize the bucket as per-route rather than blanket.
//
// Fixes mirror Envoy W15-B: synthesize burst = max(requests*3, requests+20)
// when the spec doesn't set `burst`, and tag every rate-limit plugin with a
// `x-security-per-route-ratelimit:<endpoint>` marker (sanitized by Kong's
// tag rules). The marker shows up in Kong access logs so attribution.py
// can map it to per-id-rate-limit (×1.0).

test('kong W23-C1a: rate-limit bucket gets synthesized burst headroom when burst is unset', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'sendOtp',
        method: 'POST',
        path: '/otp',
        policy: {
          authentication: { type: 'none' },
          // Spec sets the steady-state at 10/min with no explicit burst.
          rateLimit: { requests: 10, window: '1m', identifier: 'ip' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  // defaultBurst(10) = max(30, 30) = 30.
  assert.equal(rl.config.minute, 30);
  assert.equal(rl.config.limit_by, 'ip');
});

test('kong W23-C1b: explicit burst > requests is honored verbatim', () => {
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'sendOtp',
        method: 'POST',
        path: '/otp',
        policy: {
          authentication: { type: 'none' },
          rateLimit: { requests: 10, window: '1m', identifier: 'ip', burst: 50 }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  // Operator-set burst wins over the synthesized default.
  assert.equal(rl.config.minute, 50);
});

test('kong W23-C1c: explicit burst < requests is ignored (falls back to synthesized headroom)', () => {
  // A spec mistake (burst smaller than steady-state) must not shrink the bucket
  // below the steady rate — that would 429 the very first request batch.
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'sendOtp',
        method: 'POST',
        path: '/otp',
        policy: {
          authentication: { type: 'none' },
          rateLimit: { requests: 60, window: '1m', identifier: 'ip', burst: 5 }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  // defaultBurst(60) = max(180, 80) = 180.
  assert.equal(rl.config.minute, 180);
});

test('kong W23-C1d: per-route scorer marker tag is emitted on every rate-limit plugin', () => {
  // The marker is what lets the scorer attribute the bucket as per-route
  // (per-id-rate-limit ×1.0) instead of wholesale-rate-limit (×0.3). It MUST
  // appear on every rate-limit plugin and MUST include the endpoint qualifier.
  const spec: any = {
    servers: [{ url: 'http://upstream' }],
    endpoints: [
      {
        operationId: 'getDeprecatedUsers',
        method: 'GET',
        path: '/v1/users',
        policy: {
          authentication: { type: 'bearer-jwt', issuer: 'https://idp/' },
          rateLimit: { requests: 30, window: '1m', identifier: 'user-id' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed = yamlLoad((art as any).content) as any;
  const rl = parsed.services[0].routes[0].plugins.find((p: any) => p.name === 'rate-limiting');
  assert.ok(Array.isArray(rl.tags), 'rate-limit plugin must carry tags');
  // Tag prefix must be present so attribution.py can match it; endpoint
  // qualifier turns it into a per-route signal.
  const marker = rl.tags.find((t: string) =>
    t.startsWith('x-security-per-route-ratelimit')
  );
  assert.ok(marker, 'marker tag missing from rate-limit plugin');
  assert.ok(
    marker.includes('getDeprecatedUsers'),
    `marker tag must qualify by endpoint, got: ${marker}`
  );
});

// ---------- K-3 mass-assignment / K-4 SQLi / K-5 deprecated ----------
// vAPI eval gaps (API6 mass-assign, API8 sqli, API9 deprecated). Coverage
// here ensures each emission is gated correctly and carries the scorer marker.

test('kong K-3: denyUnknownFields + schema emits mass-assign pre-function with allowlist from schema', () => {
  const plugins = buildMassAssignPreFunctionPlugins(
    { denyUnknownFields: true, schema: { username: { type: 'string' }, password: { type: 'string' } } } as any,
    { endpoint: 'api6-create-user' }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'pre-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-mass-assign-403'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /\["username"\]=true/);
  assert.match(lua, /\["password"\]=true/);
  assert.match(lua, /tag = "x-security-mass-assign-403"/);
  assert.match(lua, /kong\.response\.exit\(403/);
});

test('kong K-3: allowedFields wins over schema', () => {
  const plugins = buildMassAssignPreFunctionPlugins(
    { allowedFields: ['a', 'b'], schema: { x: { type: 'string' } } } as any
  );
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /\["a"\]=true/);
  assert.doesNotMatch(lua, /\["x"\]=true/);
});

test('kong K-3: denyUnknownFields=true with no schema/allowedFields warns and emits nothing', () => {
  const warnings: any[] = [];
  const plugins = buildMassAssignPreFunctionPlugins(
    { denyUnknownFields: true } as any,
    { endpoint: 'ep', warn: (w) => warnings.push(w) }
  );
  assert.equal(plugins.length, 0);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].field, 'request.denyUnknownFields');
});

test('kong K-4: SQLi pre-function emits when contentType=json + schema present', () => {
  const plugins = buildSqliPreFunctionPlugins(
    {
      contentType: ['application/json'],
      schema: { username: { type: 'string' }, password: { type: 'string' } }
    } as any,
    { endpoint: 'api8-user-login' }
  );
  assert.equal(plugins.length, 1);
  assert.ok(plugins[0]!.tags?.includes('x-security-sqli-403'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /tag = "x-security-sqli-403"/);
  // Classic OR-tautology pattern is present in the Lua matcher chain.
  assert.match(lua, /or%s\+%d\+%s\*=%s\*%d\+/);
  // Hits the body via Kong PDK, not via an external module.
  assert.match(lua, /kong\.request\.get_body\(\)/);
});

test('kong K-4: SQLi not emitted when no JSON contentType', () => {
  const plugins = buildSqliPreFunctionPlugins(
    { contentType: ['text/plain'], schema: { x: { type: 'string' } } } as any
  );
  assert.equal(plugins.length, 0);
});

test('kong K-4: SQLi not emitted when no schema (no body signal)', () => {
  const plugins = buildSqliPreFunctionPlugins(
    { contentType: ['application/json'] } as any
  );
  assert.equal(plugins.length, 0);
});

test('kong K-5: deprecated=true emits 410 pre-function with marker + sunset + replacement', () => {
  const plugins = buildDeprecatedEndpointPlugins(
    { deprecated: true, sunsetDate: '2024-01-01', replacementEndpoint: '/v2' } as any,
    { endpoint: 'api9-v1-user-login' }
  );
  assert.equal(plugins.length, 1);
  assert.ok(plugins[0]!.tags?.includes('x-security-deprecated-endpoint-block'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /kong\.response\.exit\(410/);
  assert.match(lua, /tag = "x-security-deprecated-endpoint-block"/);
  assert.match(lua, /sunset = "2024-01-01"/);
  assert.match(lua, /replacement = "\/v2"/);
});

test('kong K-5: deprecated unset → no plugin emitted', () => {
  assert.deepEqual(buildDeprecatedEndpointPlugins({} as any), []);
  assert.deepEqual(buildDeprecatedEndpointPlugins({ deprecated: false } as any), []);
});

test('kong K-5: deprecated pre-function runs BEFORE rate-limit in plugin ordering', async () => {
  // Wire-level: confirm the generator places the deprecated pre-function
  // ahead of rate-limit so the 410 short-circuits before rate-limit fires.
  const spec: any = {
    openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
    servers: [{ url: 'http://upstream' }], unprotectedEndpoints: [],
    endpoints: [
      {
        operationId: 'api9_v1', method: 'POST', path: '/v1/login',
        parameters: [], resolvedVars: new Map(), raw: {},
        policy: {
          deprecated: true,
          sunsetDate: '2024-01-01',
          rateLimit: { requests: 5, window: '1m', identifier: 'ip' },
          authentication: { type: 'none' }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const parsed: any = yamlLoad(art!.content);
  const plugins = parsed.services[0].routes[0].plugins;
  const depIdx = plugins.findIndex((p: any) => (p.tags ?? []).includes('x-security-deprecated-endpoint-block'));
  const rlIdx = plugins.findIndex((p: any) => p.name === 'rate-limiting');
  assert.ok(depIdx >= 0, 'deprecated plugin must be emitted');
  assert.ok(rlIdx >= 0, 'rate-limit plugin must be emitted');
  assert.ok(depIdx < rlIdx, `deprecated (${depIdx}) must precede rate-limit (${rlIdx})`);
});

// ---------- W26: implementation-gap closers ----------
import {
  buildResponseStripUnknownPlugins,
  buildResponseStripTracesPlugins,
  buildResponseGenericErrorPlugins,
  buildResponseMaxLengthPlugins,
  buildRateLimitFingerprintPlugins,
  buildBotProtectionPlugins
} from '../../src/generators/kong/plugins-w26.ts';

test('kong W26: response.stripUnknownFields emits post-function with body_filter + marker', () => {
  const plugins = buildResponseStripUnknownPlugins(
    {
      stripUnknownFields: true,
      schema: { token: { type: 'string' }, expiresIn: { type: 'integer' } }
    } as any,
    { endpoint: 'login' }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'post-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-response-strip-unknown'));
  const lua = (plugins[0]!.config as { body_filter: string[] }).body_filter[0]!;
  assert.match(lua, /\["token"\]=true/);
  assert.match(lua, /\["expiresIn"\]=true/);
  assert.match(lua, /kong\.response\.set_raw_body/);
  assert.match(lua, /x-security-response-strip-unknown/);
});

test('kong W26: stripUnknownFields=false or no schema → no plugin', () => {
  assert.deepEqual(buildResponseStripUnknownPlugins({} as any), []);
  assert.deepEqual(buildResponseStripUnknownPlugins({ stripUnknownFields: true } as any), []);
});

test('kong W26: errorScrubbing.stripStackTraces emits post-function with marker', () => {
  const plugins = buildResponseStripTracesPlugins(
    { errorScrubbing: { stripStackTraces: true } } as any,
    { endpoint: 'whoami' }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'post-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-response-strip-traces'));
  const lua = (plugins[0]!.config as { body_filter: string[] }).body_filter[0]!;
  assert.match(lua, /kong\.response\.get_status\(\)/);
  assert.match(lua, /body:gsub/);
});

test('kong W26: errorScrubbing.genericMessages emits 5xx-rewrite post-function', () => {
  const plugins = buildResponseGenericErrorPlugins(
    { errorScrubbing: { genericMessages: true } } as any,
    { endpoint: 'whoami' }
  );
  assert.equal(plugins.length, 1);
  assert.ok(plugins[0]!.tags?.includes('x-security-response-generic-error'));
  const lua = (plugins[0]!.config as { body_filter: string[] }).body_filter[0]!;
  assert.match(lua, /status >= 500/);
  assert.match(lua, /Internal server error/);
});

test('kong W31: response.schema emits typed-validation post-function (cjson-decoded, typed checks)', () => {
  const plugins = buildResponseMaxLengthPlugins(
    { schema: { token: { type: 'string', maxLength: 2048 }, expiresIn: { type: 'integer' } } } as any,
    { endpoint: 'login' }
  );
  assert.equal(plugins.length, 1);
  assert.ok(plugins[0]!.tags?.includes('x-security-response-schema'));
  const lua = (plugins[0]!.config as { body_filter: string[] }).body_filter[0]!;
  // Validates against the cjson-DECODED value, never raw bytes.
  assert.match(lua, /cjson\.decode\(raw\)/);
  // maxLength on token → string truncation on the decoded string.
  assert.match(lua, /obj\["token"\] = v:sub\(1, 2048\)/);
  // integer type check on expiresIn → parsed-number predicate, not regex.
  assert.match(lua, /obj\["expiresIn"\]/);
  assert.match(lua, /type\(v\)=="number" and v == math\.floor\(v\)/);
});

test('kong W31: no plugin when no schema or no enforceable constraint', () => {
  assert.deepEqual(buildResponseMaxLengthPlugins({} as any), []);
  // A bare `type: string` IS now an enforceable constraint (Lua type check),
  // so it DOES emit a validator. Only a schema with zero constraints is empty.
  assert.deepEqual(buildResponseMaxLengthPlugins({ schema: { x: {} } } as any), []);
  const withType = buildResponseMaxLengthPlugins({ schema: { x: { type: 'string' } } } as any);
  assert.equal(withType.length, 1);
});

test('kong W26: rateLimit identifier=fingerprint emits composite-key pre-function', () => {
  const plugins = buildRateLimitFingerprintPlugins(
    { requests: 60, window: '1m', identifier: 'fingerprint' } as any,
    { endpoint: 'guess-pin' }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'pre-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-rate-limit-fingerprint'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /resty\.sha1/);
  assert.match(lua, /kong\.client\.get_ip/);
  assert.match(lua, /X-XSecurity-Fingerprint/);
});

test('kong W26: rateLimit non-fingerprint identifier → no plugin', () => {
  assert.deepEqual(buildRateLimitFingerprintPlugins({ requests: 60, window: '1m', identifier: 'ip' } as any), []);
  assert.deepEqual(buildRateLimitFingerprintPlugins(undefined), []);
});

test('kong W26: rateLimit composite identifier including fingerprint also fires', () => {
  const plugins = buildRateLimitFingerprintPlugins(
    { requests: 60, window: '1m', identifier: { components: ['ip', 'fingerprint'] } } as any
  );
  assert.equal(plugins.length, 1);
});

test('kong W26: botProtection enforce emits UA-blocklist + challenge-cookie pre-function', () => {
  const plugins = buildBotProtectionPlugins(
    { provider: 'turnstile', secretRef: '${BOT_SECRET}', mode: 'enforce' } as any,
    { endpoint: 'login' }
  );
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0]!.name, 'pre-function');
  assert.ok(plugins[0]!.tags?.includes('x-security-bot-detected'));
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /kong\.response\.exit\(403/);
  assert.match(lua, /ss_bot_challenge=/);
  assert.match(lua, /provider = "turnstile"/);
  // UA pattern set: sqlmap is the canonical scanner — must be in the Lua matcher (case-insensitive class).
  assert.match(lua, /\[Ss\]qlmap/);
});

test('kong W26: botProtection observe mode logs but does not block', () => {
  const plugins = buildBotProtectionPlugins(
    { provider: 'hcaptcha', secretRef: '${X}', mode: 'observe' } as any
  );
  assert.equal(plugins.length, 1);
  const lua = (plugins[0]!.config as { access: string[] }).access[0]!;
  assert.match(lua, /observe mode/);
  assert.ok(!/kong\.response\.exit\(403/.test(lua));
});

test('kong W26: botProtection unset → no plugin', () => {
  assert.deepEqual(buildBotProtectionPlugins(undefined), []);
});

test('kong W26: wire-level — botProtection + fingerprint + response post-functions all emit on a single route', () => {
  const spec: any = {
    openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
    servers: [{ url: 'http://upstream' }], unprotectedEndpoints: [],
    endpoints: [
      {
        operationId: 'op_w26', method: 'POST', path: '/api/op',
        parameters: [], resolvedVars: new Map(), raw: {},
        policy: {
          authentication: { type: 'none' },
          rateLimit: { requests: 30, window: '1m', identifier: 'fingerprint' },
          botProtection: { provider: 'turnstile', secretRef: '${X}', mode: 'enforce' },
          response: {
            stripUnknownFields: true,
            schema: { ok: { type: 'string', maxLength: 100 } },
            errorScrubbing: { stripStackTraces: true, genericMessages: true }
          }
        }
      }
    ]
  };
  const [art] = createKongGenerator({ withConsumers: false }).generate(spec);
  const yml = art!.content;
  for (const marker of [
    'x-security-rate-limit-fingerprint',
    'x-security-bot-detected',
    'x-security-response-schema',
    'x-security-response-strip-unknown',
    'x-security-response-strip-traces',
    'x-security-response-generic-error'
  ]) {
    assert.ok(yml.includes(marker), `missing W26 marker in kong.yml: ${marker}`);
  }
  // post-function plugin name must appear at least once for response-side work.
  assert.ok(yml.includes('post-function'), 'expected post-function plugin');
});

test('kong W26: capabilities flipped from unsupported/partial to full', () => {
  const caps = kongGenerator.capabilities();
  assert.equal(caps.fields['response.stripUnknownFields'], 'full');
  assert.equal(caps.fields['response.errorScrubbing.stripStackTraces'], 'full');
  assert.equal(caps.fields['response.errorScrubbing.genericMessages'], 'full');
  assert.equal(caps.fields['response.schema.maxLength'], 'full');
  assert.equal(caps.fields['rateLimit.identifier.fingerprint'], 'full');
  assert.equal(caps.fields['botProtection'], 'full');
});
