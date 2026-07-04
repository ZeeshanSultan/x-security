import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSpec } from '../src/loader.js';
import { EnvResolver } from '../src/variables.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const exampleSpec = path.resolve(__dirname, '../../../fixtures/specs/example.yaml');

test('loadSpec parses 3.1 fixture', async () => {
  const ir = await loadSpec(exampleSpec, {
    resolver: new EnvResolver({
      JWKS_ENDPOINT: 'https://auth.example.com/.well-known/jwks.json',
      AUTH_ISSUER: 'https://auth.example.com',
      AUTH_AUDIENCE: 'api'
    })
  });
  assert.equal(ir.dialect, '3.1');
  assert.equal(ir.endpoints.length, 3);

  const login = ir.endpoints.find((e) => e.path === '/api/auth/login')!;
  assert.equal(login.method, 'POST');
  assert.equal(login.policy.rateLimit && !Array.isArray(login.policy.rateLimit)
    ? login.policy.rateLimit.requests
    : null, 5);

  const admin = ir.endpoints.find((e) => e.path === '/api/admin/users')!;
  assert.equal(admin.policy.authentication?.jwksUri, 'https://auth.example.com/.well-known/jwks.json');
  assert.ok(admin.resolvedVars.has('${JWKS_ENDPOINT}'));
});

test('loadSpec collects unprotected endpoints', async () => {
  // The example has all endpoints protected; verify the collector exists
  const ir = await loadSpec(exampleSpec, {
    resolver: new EnvResolver({
      JWKS_ENDPOINT: 'x', AUTH_ISSUER: 'x', AUTH_AUDIENCE: 'x'
    })
  });
  assert.equal(ir.unprotectedEndpoints.length, 0);
});
