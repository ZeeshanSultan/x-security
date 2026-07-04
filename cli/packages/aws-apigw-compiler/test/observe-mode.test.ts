import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compile } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

// ────────────────────────────────────────────────────────────────────────────
// Default mode (rev 3 rollout): mode omitted ⇒ observe.
// ────────────────────────────────────────────────────────────────────────────

test('mode defaults to observe when AwsCompileOptions is omitted', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const r = compile(spec);
  assert.ok(r.webAclRules.length > 0);
  for (const rule of r.webAclRules) {
    assert.ok(rule.Action?.Count !== undefined, `${rule.Name} should have Count action in observe (default)`);
    assert.equal(rule.mode, 'observe');
  }
});

test('mode defaults to observe when options is an empty object', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/x',
      policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const r = compile(spec, {});
  for (const rule of r.webAclRules) {
    assert.equal(rule.mode, 'observe');
  }
});

// ────────────────────────────────────────────────────────────────────────────
// WAFv2 rules: blocking → Count in observe, Block in enforce.
// ────────────────────────────────────────────────────────────────────────────

test('observe-mode demotes WAFv2 Block actions to Count', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        request: { maxBodySize: '1MB', contentType: ['application/json'] },
        ipPolicy: { allow: ['10.0.0.0/8'] }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  assert.ok(observe.webAclRules.length >= 3);
  for (const r of observe.webAclRules) {
    assert.ok(r.Action?.Count !== undefined, `${r.Name} should be Count in observe`);
    assert.equal(r.mode, 'observe');
    assert.match(r.Name, /^writ-observe-/);
  }

  const enforce = compile(spec, { mode: 'enforce' });
  const auth = enforce.webAclRules.find(x => x.writ.rule_type === 'auth')!;
  assert.ok(auth.Action?.Block !== undefined);
  assert.equal(auth.mode, 'enforce');
});

// ────────────────────────────────────────────────────────────────────────────
// Lambda authorizers: stamped with mode + MODE env binding (handler reads
// process.env.MODE to decide Allow+log vs Deny).
// ────────────────────────────────────────────────────────────────────────────

test('Lambda authorizers carry mode + MODE env binding', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/secure',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        request: {
          signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$vault.k' }
        },
        csrf: { method: 'double-submit', tokenHeader: 'x-csrf', tokenCookie: 'csrf' }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  assert.ok(observe.lambdaAuthorizers.length >= 2);
  for (const a of observe.lambdaAuthorizers) {
    assert.equal(a.mode, 'observe');
    assert.deepEqual(a.envBinding, { name: 'MODE', value: 'observe' });
  }

  const enforce = compile(spec, { mode: 'enforce' });
  for (const a of enforce.lambdaAuthorizers) {
    assert.equal(a.mode, 'enforce');
    assert.deepEqual(a.envBinding, { name: 'MODE', value: 'enforce' });
  }
});

// ────────────────────────────────────────────────────────────────────────────
// API Gateway request validators are always-applied — no observe knob.
// ────────────────────────────────────────────────────────────────────────────

test('request.denyUnknownFields emits a warning + observe-mode note in observe', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: {
        request: {
          denyUnknownFields: true,
          schema: { email: { type: 'email' }, name: { type: 'string' } }
        }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  // Validator is still emitted (it's always-applied).
  assert.equal(observe.requestValidators.length, 1);
  // Warning explicitly tells the customer that request validators have no observe knob.
  const w = observe.warnings.find(x => x.field === 'request.denyUnknownFields');
  assert.ok(w, 'expected request-validator warning in observe-mode');
  assert.match(w!.message, /always-on|no native observe knob/i);
  // observeModeNote captures the same.
  const note = observe.observeModeNotes.find(n => n.field === 'request.denyUnknownFields');
  assert.ok(note);
  assert.equal(note!.support, 'always-applied');

  // Enforce mode: validator still emitted, no observe warning.
  const enforce = compile(spec, { mode: 'enforce' });
  assert.equal(enforce.requestValidators.length, 1);
  assert.ok(!enforce.warnings.some(x => x.field === 'request.denyUnknownFields'));
});

// ────────────────────────────────────────────────────────────────────────────
// Always-applied fields (gateway responses, integration responses, CloudFront
// cache policy, response.cookies) emit observeModeNotes in observe.
// ────────────────────────────────────────────────────────────────────────────

test('always-applied response fields carry observeModeNote in observe', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/x',
      policy: {
        response: {
          headers: { csp: "default-src 'self'" },
          cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Lax' } }
        },
        cacheable: { enabled: true, ttl: 60, unkeyedHeadersStrip: ['Cookie'] }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe', scope: 'CLOUDFRONT' });
  const fields = observe.observeModeNotes.map(n => n.field);
  assert.ok(fields.includes('response.headers'));
  assert.ok(fields.includes('response.cookies.defaults'));
  assert.ok(fields.includes('cacheable.unkeyedHeadersStrip'));
  for (const n of observe.observeModeNotes) {
    if (['response.headers', 'response.cookies.defaults', 'cacheable.unkeyedHeadersStrip'].includes(n.field)) {
      assert.equal(n.support, 'always-applied');
    }
  }

  const enforce = compile(spec, { mode: 'enforce', scope: 'CLOUDFRONT' });
  assert.equal(enforce.observeModeNotes.length, 0);
});

// ────────────────────────────────────────────────────────────────────────────
// Capability matrix carries shadowModeSupport entries.
// ────────────────────────────────────────────────────────────────────────────

test('capability matrix entries include shadowModeSupport', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        request: {
          denyUnknownFields: true,
          signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$vault.k' },
          headerInjectionGuard: true,
          allowedHosts: ['api.example.com']
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'observe' });
  // Lambda authorizer for jwt-alg-allowlist: simulatable (honors MODE env).
  const algEntry = r.capabilityMatrix.find(c => c.field === 'authentication.allowedAlgorithms');
  assert.ok(algEntry);
  assert.equal(algEntry!.shadowModeSupport, 'simulatable');

  // Request validator (denyUnknownFields): always-applied.
  const dufEntry = r.capabilityMatrix.find(c => c.field === 'request.denyUnknownFields');
  assert.ok(dufEntry);
  assert.equal(dufEntry!.shadowModeSupport, 'always-applied');

  // Other simulatable entries.
  assert.equal(
    r.capabilityMatrix.find(c => c.field === 'request.signature')?.shadowModeSupport,
    'simulatable'
  );
  assert.equal(
    r.capabilityMatrix.find(c => c.field === 'request.headerInjectionGuard')?.shadowModeSupport,
    'simulatable'
  );
});

// ────────────────────────────────────────────────────────────────────────────
// AWS Managed Bot Control honors observe-mode OverrideAction.
// ────────────────────────────────────────────────────────────────────────────

test('Bot Control OverrideAction is Count in observe, None in enforce', () => {
  const policy = { botProtection: true } as unknown as import('@writ/schema').XSecurityPolicy;
  const observe = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]),
    { mode: 'observe', enableManagedBotControl: true }
  );
  const bcO = observe.webAclRules.find(x => x.writ.rule_type === 'bot-control')!;
  assert.deepEqual(bcO.OverrideAction, { Count: {} });
  assert.equal(bcO.mode, 'observe');

  const enforce = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]),
    { mode: 'enforce', enableManagedBotControl: true }
  );
  const bcE = enforce.webAclRules.find(x => x.writ.rule_type === 'bot-control')!;
  assert.deepEqual(bcE.OverrideAction, { None: {} });
  assert.equal(bcE.mode, 'enforce');
});

// ────────────────────────────────────────────────────────────────────────────
// 'shadow' remains a working alias for 'observe' (back-compat).
// ────────────────────────────────────────────────────────────────────────────

test("legacy 'shadow' mode still demotes Block to Count", () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/x',
      policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const r = compile(spec, { mode: 'shadow' });
  for (const rule of r.webAclRules) {
    assert.ok(rule.Action?.Count !== undefined);
    assert.equal(rule.mode, 'shadow');
    assert.match(rule.Name, /^writ-shadow-/);
  }
  // Lambda authorizers in shadow still bind MODE=observe at runtime.
  const sigSpec = makeSpec([makeEndpoint({
    method: 'POST', path: '/wh',
    policy: { request: { signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$v.s' } } }
  })]);
  const sigOut = compile(sigSpec, { mode: 'shadow' });
  const a = sigOut.lambdaAuthorizers[0]!;
  assert.equal(a.envBinding.value, 'observe');
});
