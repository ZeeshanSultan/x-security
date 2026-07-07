/**
 * Tests for the Envoy drift detector.
 *
 * Generates clean artifacts, then:
 *   - clean → 0 issues.
 *   - drop an endpoint block → CRITICAL.
 *   - strip the 401 line from an endpoint block → CRITICAL.
 *   - strip the 413 line from an endpoint block → HIGH.
 *   - remove a rate_limit_descriptors entry from the YAML → CRITICAL.
 *   - add a spurious x-security-tagged block → LOW.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { loadSpec } from '@x-security/core';
import { detectEnvoyDrift } from '../../src/drift/envoy.js';
import { envoyGenerator } from '../../src/generators/envoy/index.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

async function gen(): Promise<{ specYaml: string; lua: string; spec: Awaited<ReturnType<typeof loadSpec>> }> {
  process.env['JWKS_ENDPOINT'] = 'https://example.com/.well-known/jwks.json';
  process.env['AUTH_ISSUER'] = 'https://auth.example.com';
  process.env['AUTH_AUDIENCE'] = 'api.example.com';
  const spec = await loadSpec(SPEC, { strict: false });
  const arts = await Promise.resolve(envoyGenerator.generate(spec));
  return {
    spec,
    specYaml: arts.find((a) => a.path === 'envoy.yaml')!.content,
    // wave-9: x-security.lua only emitted when residual fields are present.
    // The example fixture has contentType/maxBodySize so it IS emitted.
    lua: arts.find((a) => a.path === 'x-security.lua')!.content
  };
}

test('envoy drift: matching config has zero drift', async () => {
  const { spec, specYaml, lua } = await gen();
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: specYaml,
    luaContent: lua
  });
  assert.equal(r.kind, 'drift');
  assert.equal(r.target, 'envoy');
  assert.deepEqual(r.issues, [], `expected clean, got ${JSON.stringify(r.issues, null, 2)}`);
});

test('envoy drift: tampered (removed) endpoint block flagged CRITICAL', async () => {
  const { spec, specYaml, lua } = await gen();
  // Strip the login endpoint block entirely (START..END inclusive).
  const tampered = lua.replace(
    /\s*-- xSecurity:POST:\/api\/auth\/login:START[\s\S]*?-- xSecurity:END\s*/,
    '\n'
  );
  assert.notEqual(tampered, lua, 'sanity: replacement happened');
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: specYaml,
    luaContent: tampered
  });
  const missing = r.issues.find(
    (i) => i.field === 'endpoint' && i.endpoint.includes('/api/auth/login')
  );
  assert.ok(missing, `expected endpoint-missing issue, got ${JSON.stringify(r.issues)}`);
  assert.equal(missing!.severity, 'CRITICAL');
});

test('envoy drift: missing jwt_authn rule for admin endpoint flagged CRITICAL', async () => {
  const { spec, specYaml, lua } = await gen();
  // Wave-9: auth is enforced by native jwt_authn, not Lua. Drift = missing
  // the per-endpoint rule in the jwt_authn provider config.
  const tampered = specYaml.replace(/regex: "\^\/api\/admin\/users\$"/g, 'regex: "^/disabled$"');
  assert.notEqual(tampered, specYaml, 'sanity: jwt rule rewritten');
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: tampered,
    luaContent: lua
  });
  const auth = r.issues.find(
    (i) => i.field === 'authentication' && i.endpoint.includes('/api/admin/users')
  );
  assert.ok(auth, `expected jwt_authn rule-missing issue, got ${JSON.stringify(r.issues)}`);
  assert.equal(auth!.severity, 'CRITICAL');
});

test('envoy drift: missing body-size (413) line in login block flagged HIGH', async () => {
  const { spec, specYaml, lua } = await gen();
  const m = /(-- xSecurity:POST:\/api\/auth\/login:START[\s\S]*?-- xSecurity:END)/.exec(lua);
  assert.ok(m, 'login block located');
  const scrubbed = m![1]!
    .split('\n')
    .filter((l) => !/:status"\]\s*=\s*"413"/.test(l))
    .filter((l) => !/cl > /.test(l))
    .filter((l) => !/request\.maxBodySize=/.test(l))
    .filter((l) => !/local cl =/.test(l))
    .filter((l) => !/exceeds endpoint limit/.test(l))
    .join('\n');
  const tampered = lua.replace(m![1]!, scrubbed);
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: specYaml,
    luaContent: tampered
  });
  const body = r.issues.find(
    (i) => i.field === 'request.maxBodySize' && i.endpoint.includes('/api/auth/login')
  );
  assert.ok(body, `expected body-size-missing issue, got ${JSON.stringify(r.issues)}`);
  assert.equal(body!.severity, 'HIGH');
});

test('envoy drift: missing per-route local_ratelimit stat_prefix flagged CRITICAL', async () => {
  const { spec, specYaml, lua } = await gen();
  // Wave-9: rate-limit lives in route-level typed_per_filter_config.
  // Rename the login route's stat_prefix so the wave-9 detector sees it missing.
  const stripped = specYaml.replace(
    /stat_prefix: x_security_login_ratelimit/,
    'stat_prefix: x_security_disabled'
  );
  assert.notEqual(stripped, specYaml, 'sanity: stat_prefix rewritten');
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: stripped,
    luaContent: lua
  });
  const desc = r.issues.find(
    (i) => i.field === 'rateLimit.descriptor' && /login_ratelimit/.test(i.endpoint)
  );
  assert.ok(desc, `expected rate-limit bucket issue, got ${JSON.stringify(r.issues)}`);
  assert.equal(desc!.severity, 'CRITICAL');
});

test('envoy drift: unknown x-security-tagged block flagged LOW', async () => {
  const { spec, specYaml, lua } = await gen();
  // Inject a bogus endpoint block.
  const bogus =
    '\n    -- xSecurity:DELETE:/api/ghost:START\n' +
    '    if true then end\n' +
    '    -- xSecurity:END\n';
  const tampered = lua + bogus;
  const r = await detectEnvoyDrift(spec, {
    filePath: 'fake.yaml',
    yamlContent: specYaml,
    luaContent: tampered
  });
  const unk = r.issues.find((i) => i.field === 'unknown-endpoint');
  assert.ok(unk, `expected unknown-endpoint issue, got ${JSON.stringify(r.issues)}`);
  assert.equal(unk!.severity, 'LOW');
});
