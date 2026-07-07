import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compile } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

// ────────────────────────────────────────────────────────────────────────────
// #13 — response.headers
// ────────────────────────────────────────────────────────────────────────────

test('response.headers emits Gateway Responses for 4xx/5xx and integration response for 2xx', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/x',
      policy: {
        response: {
          headers: {
            csp: "default-src 'self'",
            hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
            frameOptions: 'DENY',
            contentTypeOptions: 'nosniff'
          }
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const respTypes = r.gatewayResponses.map(g => g.ResponseType);
  assert.ok(respTypes.includes('DEFAULT_4XX'));
  assert.ok(respTypes.includes('DEFAULT_5XX'));
  const four = r.gatewayResponses.find(g => g.ResponseType === 'DEFAULT_4XX')!;
  assert.match(four.ResponseParameters!['gatewayresponse.header.X-Frame-Options']!, /DENY/);
  assert.match(four.ResponseParameters!['gatewayresponse.header.Strict-Transport-Security']!, /max-age=31536000/);
  // 2xx
  const ir = r.integrationResponses.find(x => x.StatusCode === '200');
  assert.ok(ir);
  assert.ok(ir.ResponseParameters['method.response.header.Content-Security-Policy']);
});

// ────────────────────────────────────────────────────────────────────────────
// #14 — cacheable.unkeyedHeadersStrip
// ────────────────────────────────────────────────────────────────────────────

test('cacheable.unkeyedHeadersStrip emits CloudFront cache policy + warning on REGIONAL', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/cached',
      policy: {
        cacheable: {
          enabled: true,
          ttl: 60,
          unkeyedHeadersStrip: ['Cookie', 'Authorization', 'X-Forwarded-Host']
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.cloudFrontCachePolicies.length, 1);
  assert.deepEqual(r.cloudFrontCachePolicies[0]!.StrippedRequestHeaders,
    ['Cookie', 'Authorization', 'X-Forwarded-Host']);
  assert.ok(r.warnings.some(w => w.field === 'cacheable.unkeyedHeadersStrip'));
});

// ────────────────────────────────────────────────────────────────────────────
// #15 — graphql
// ────────────────────────────────────────────────────────────────────────────

test('graphql policy emits graphql-limits Lambda authorizer (partial)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/graphql',
      policy: {
        graphql: {
          maxDepth: 10,
          maxComplexity: 1000,
          maxAliases: 15,
          batchLimit: 10,
          disableIntrospection: true,
          allowedOperations: ['query', 'mutation']
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'graphql-limits');
  assert.ok(lam);
  assert.equal(lam.template.config['maxDepth'], 10);
  assert.equal(lam.template.config['disableIntrospection'], true);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'graphql' && c.level === 'partial'));
});

// ────────────────────────────────────────────────────────────────────────────
// #16 — websocket
// ────────────────────────────────────────────────────────────────────────────

test('websocket policy emits $connect route spec with origin allowlist', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/ws',
      policy: {
        websocket: {
          allowedOrigins: ['https://app.example.com'],
          maxMessageSize: '64KB',
          messageRateLimit: { messages: 100, window: '1s' },
          maxConnectionsPerIdentifier: 5,
          idleTimeout: '5m'
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.webSocketRoutes.length, 1);
  const ws = r.webSocketRoutes[0]!;
  assert.equal(ws.RouteKey, '$connect');
  assert.deepEqual(ws.AllowedOrigins, ['https://app.example.com']);
  assert.equal(ws.MaxMessageSizeBytes, 65536);
  assert.equal(ws.IdleTimeoutSeconds, 300);
  assert.equal(ws.MaxConnectionsPerIdentifier, 5);
  assert.deepEqual(ws.MessageRateLimit, { messages: 100, windowSeconds: 1 });
});

test('websocket maxMessageSize > 128KB warns (API GW WebSocket cap)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/ws',
      policy: { websocket: { allowedOrigins: ['https://x'], maxMessageSize: '256KB' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(r.warnings.some(w =>
    w.field === 'websocket.maxMessageSize' && /128KB/.test(w.message)
  ));
});

// ────────────────────────────────────────────────────────────────────────────
// #17 — botProtection (object form, v0.3)
// ────────────────────────────────────────────────────────────────────────────

test('botProtection (v0.3 object) emits siteverify Lambda authorizer (override-only)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/signup',
      policy: {
        botProtection: {
          provider: 'turnstile',
          secretRef: '$vault.bots/turnstile-secret',
          threshold: 0.7,
          mode: 'enforce'
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'bot-protection-siteverify');
  assert.ok(lam);
  assert.equal(lam.template.config['provider'], 'turnstile');
  assert.equal(lam.template.config['threshold'], 0.7);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'botProtection' && c.level === 'override-only'));
});

// ────────────────────────────────────────────────────────────────────────────
// TargetOverrides routing
// ────────────────────────────────────────────────────────────────────────────

test('targetOverrides.aws-apigw is accepted by the schema and passes through unchanged', () => {
  const policy = {
    botProtection: {
      provider: 'turnstile' as const,
      secretRef: '$vault.s',
      mode: 'observe' as const
    },
    targetOverrides: {
      'aws-apigw': { lambdaArn: 'arn:aws:lambda:us-east-1:111:function:bot-verify' }
    }
  };
  const spec = makeSpec([makeEndpoint({ method: 'POST', path: '/x', policy })]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.errors.length, 0);
  assert.deepEqual(
    spec.endpoints[0]?.policy?.targetOverrides?.['aws-apigw'],
    { lambdaArn: 'arn:aws:lambda:us-east-1:111:function:bot-verify' }
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Determinism — v0.3 fields included in hash
// ────────────────────────────────────────────────────────────────────────────

test('v0.3 outputs are part of the content hash', () => {
  const ep = makeEndpoint({
    method: 'POST',
    path: '/api/users',
    policy: {
      authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
      request: {
        denyUnknownFields: true,
        schema: { id: { type: 'uuid' } },
        headerInjectionGuard: true,
        allowedHosts: ['api.example.com']
      },
      response: { headers: { csp: "default-src 'self'" } },
      csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] }
    }
  });
  const spec = makeSpec([ep]);
  const a = compile(spec, { mode: 'shadow' });
  const b = compile(spec, { mode: 'shadow' });
  assert.equal(a.contentHash, b.contentHash);
  assert.ok(a.requestValidators.length === 1);
  assert.ok(a.gatewayResponses.length >= 2);
  assert.ok(a.webAclRules.some(r => r.xSecurity.rule_type === 'allowed-hosts'));
});

// ────────────────────────────────────────────────────────────────────────────
// #5 — response.cookies.defaults
// ────────────────────────────────────────────────────────────────────────────

test('response.cookies.defaults emits integration response mapping (partial)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/me',
      policy: {
        response: { cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Strict' } } }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const ir = r.integrationResponses.find(x => x.xSecurity.source_field === 'response.cookies.defaults');
  assert.ok(ir);
  const vtl = ir.ResponseTemplates?.['application/json'] ?? '';
  assert.match(vtl, /HttpOnly/);
  assert.match(vtl, /Secure/);
  assert.match(vtl, /SameSite=Strict/);
});
