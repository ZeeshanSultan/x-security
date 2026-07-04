import test from 'node:test';
import assert from 'node:assert/strict';
import { propose, proposeAnnotationTool } from '../src/tools/propose-annotation.js';
import { lint, lintAnnotationTool } from '../src/tools/lint-annotation.js';
import { checkEndpoint, checkEndpointTool } from '../src/tools/check-endpoint.js';

// ---------------------------------------------------------- propose-annotation

test('propose: admin route requires admin scope and tighter rate limit', () => {
  const { yaml, rationale } = propose({ method: 'POST', path: '/admin/users' });
  assert.match(yaml, /type: bearer-jwt/);
  assert.match(yaml, /scopes: \["admin"\]/);
  assert.match(yaml, /requests: 30/);
  assert.ok(rationale.some((r) => r.includes('admin')));
});

test('propose: login route gets type:none and 5/min rate limit', () => {
  const { yaml } = propose({ method: 'POST', path: '/auth/login' });
  assert.match(yaml, /type: none/);
  assert.match(yaml, /requests: 5/);
});

test('propose: GET with :id param emits IDOR authorization rule', () => {
  const { yaml, rationale } = propose({ method: 'GET', path: '/users/{id}' });
  assert.match(yaml, /authorization:/);
  assert.match(yaml, /API1:2023/);
  assert.ok(rationale.some((r) => r.includes('IDOR')));
});

test('propose: upload route caps body at 10MB and accepts multipart', () => {
  const { yaml } = propose({ method: 'POST', path: '/api/upload' });
  assert.match(yaml, /maxBodySize: "10MB"/);
  assert.match(yaml, /multipart\/form-data/);
});

test('propose: public health endpoint requires no auth', () => {
  const { yaml } = propose({ method: 'GET', path: '/health' });
  assert.match(yaml, /type: none/);
});

test('proposeAnnotationTool: rejects missing fields', async () => {
  await assert.rejects(
    async () => proposeAnnotationTool.handler({ method: 'GET' }),
    /required/
  );
});

test('proposeAnnotationTool: output contains rationale comments and yaml', async () => {
  const out = await proposeAnnotationTool.handler({ method: 'GET', path: '/users/{id}' });
  assert.match(out, /# Proposed x-security for GET \/users\/\{id\}/);
  assert.match(out, /x-security:/);
});

// ---------------------------------------------------------- lint-annotation

test('lint: empty object is invalid (no auth, no rate limit) → LOW', () => {
  const r = lint({ annotation: {} });
  assert.equal(r.confidence, 'LOW');
  assert.ok(r.warnings.length >= 2);
});

test('lint: well-formed policy → HIGH', () => {
  const r = lint({
    annotation: {
      authentication: {
        type: 'bearer-jwt',
        jwksUri: 'https://idp.example.com/.well-known/jwks.json',
        allowedAlgorithms: ['RS256']
      },
      rateLimit: { requests: 60, window: '1m' },
      request: { maxBodySize: '32KB' }
    }
  });
  assert.equal(r.valid, true);
  assert.equal(r.confidence, 'HIGH');
  assert.deepEqual(r.warnings, []);
});

test('lint: bearer-jwt without issuer/jwks warns', () => {
  const r = lint({
    annotation: {
      authentication: { type: 'bearer-jwt' },
      rateLimit: { requests: 60, window: '1m' },
      request: { maxBodySize: '32KB' }
    }
  });
  assert.ok(r.warnings.some((w) => /jwksUri/.test(w)));
});

test('lint: invalid annotation (bad authentication type) → valid:false LOW', () => {
  const r = lint({ annotation: { authentication: { type: 'nonsense' } } });
  assert.equal(r.valid, false);
  assert.equal(r.confidence, 'LOW');
  assert.ok(r.errors.length > 0);
});

test('lintAnnotationTool: serializes errors and warnings as YAML-ish text', async () => {
  const out = await lintAnnotationTool.handler({ annotation: {} });
  assert.match(out, /confidence: LOW/);
  assert.match(out, /warnings:/);
});

// ---------------------------------------------------------- check-endpoint

test('checkEndpoint: missing API key returns soft hint, not error', async () => {
  // Ensure env is clean for this test.
  const saved = process.env.WRIT_API_KEY;
  delete process.env.WRIT_API_KEY;
  try {
    const r = await checkEndpoint({ method: 'GET', path: '/users/{id}' });
    assert.equal(r.configured, false);
    assert.match(r.hint!, /WRIT_API_KEY/);
  } finally {
    if (saved !== undefined) process.env.WRIT_API_KEY = saved;
  }
});

test('checkEndpoint: with API key calls fetcher and surfaces body', async () => {
  const calls: { url: string; auth: string }[] = [];
  const r = await checkEndpoint(
    { method: 'get', path: '/users/{id}', apiKey: 'sk_test_xyz', apiUrl: 'https://api.example.test' },
    async (url, init) => {
      calls.push({ url, auth: init.headers.Authorization ?? '' });
      return { statusCode: 200, body: { endpoint: '/users/{id}', findings: [] } };
    }
  );
  assert.equal(r.configured, true);
  assert.equal(r.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.auth, 'Bearer sk_test_xyz');
  assert.match(calls[0]!.url, /method=GET/);
  assert.match(calls[0]!.url, /path=%2Fusers%2F%7Bid%7D/);
});

test('checkEndpointTool: soft hint when unconfigured', async () => {
  const saved = process.env.WRIT_API_KEY;
  delete process.env.WRIT_API_KEY;
  try {
    const out = await checkEndpointTool.handler({ method: 'GET', path: '/x' });
    assert.match(out, /not-configured/);
  } finally {
    if (saved !== undefined) process.env.WRIT_API_KEY = saved;
  }
});
