import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compile, stableStringify } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

test('compile is deterministic for the same input', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/auth/login',
      policy: {
        authentication: { type: 'none' },
        rateLimit: { requests: 500, window: '5m', identifier: 'ip' },
        request: { contentType: ['application/json'], maxBodySize: '10KB' }
      }
    }),
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: {
          type: 'rule-based',
          rules: [{ field: 'userId', operator: 'equals', value: '$ctx.user.id' }]
        }
      }
    })
  ]);
  const a = compile(spec, { mode: 'shadow' });
  const b = compile(spec, { mode: 'shadow' });
  assert.equal(stableStringify(a), stableStringify(b));
  assert.equal(a.contentHash, b.contentHash);
});

test('shadow mode forces every blocking rule action to Count', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin',
      policy: { authentication: { type: 'api-key' }, ipPolicy: { allow: ['10.0.0.0/8'] } }
    })
  ]);
  const result = compile(spec, { mode: 'shadow' });
  assert.ok(result.webAclRules.length > 0);
  for (const r of result.webAclRules) {
    assert.ok(r.Action?.Count !== undefined, `${r.Name} should have Count action in shadow (got ${JSON.stringify(r.Action)})`);
  }
});

test('enforce mode uses Block for auth + body-size + ip-allow', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        request: { maxBodySize: '1MB' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const auth = r.webAclRules.find(x => x.xSecurity.rule_type === 'auth');
  const body = r.webAclRules.find(x => x.xSecurity.rule_type === 'body-size');
  assert.ok(auth && body);
  assert.ok(auth.Action?.Block !== undefined);
  assert.ok(body.Action?.Block !== undefined);
  assert.match(auth.Name, /^x-security-[0-9a-f]{12}-auth$/);
});

test('rule names are stable & sort order is deterministic across input shuffles', () => {
  const ep1 = makeEndpoint({ method: 'GET', path: '/b', policy: { authentication: { type: 'api-key' } } });
  const ep2 = makeEndpoint({ method: 'GET', path: '/a', policy: { authentication: { type: 'api-key' } } });
  const a = compile(makeSpec([ep1, ep2]), { mode: 'shadow' });
  const b = compile(makeSpec([ep2, ep1]), { mode: 'shadow' });
  assert.equal(a.contentHash, b.contentHash);
  // /a's auth rule must come before /b's
  const names = a.webAclRules.map(r => r.Name);
  const idxA = names.findIndex(n => n.endsWith('-auth') && a.webAclRules.find(r => r.Name === n)!.xSecurity.endpoint_id === 'GET_/a');
  const idxB = names.findIndex(n => n.endsWith('-auth') && a.webAclRules.find(r => r.Name === n)!.xSecurity.endpoint_id === 'GET_/b');
  assert.ok(idxA >= 0 && idxB >= 0 && idxA < idxB);
});

test('rate limit: IP identifier → RateBasedStatement', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/login',
      policy: { rateLimit: { requests: 500, window: '5m', identifier: 'ip' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rl = r.webAclRules.find(x => x.xSecurity.rule_type === 'ratelimit-0');
  assert.ok(rl);
  assert.equal(rl.Statement.RateBasedStatement?.AggregateKeyType, 'IP');
  assert.equal(rl.Statement.RateBasedStatement?.Limit, 500);
  assert.equal(rl.Statement.RateBasedStatement?.EvaluationWindowSec, 300);
  assert.equal(r.usagePlans.length, 0);
});

test('rate limit: api-key identifier → Usage Plan (not WAF rule)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/data',
      policy: { rateLimit: { requests: 1000, window: '1h', identifier: 'api-key' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.usagePlans.length, 1);
  // 1000 req / 1h ⇒ rateLimit = max(1, floor(1000/3600)) = 1
  assert.equal(r.usagePlans[0]?.Throttle.RateLimit, 1);
  // No rate-limit WAF rule emitted
  assert.equal(r.webAclRules.filter(x => x.xSecurity.rule_type.startsWith('ratelimit-')).length, 0);
});

test('rate limit: requests<100 is rounded up to AWS minimum with warning', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: { rateLimit: { requests: 10, window: '5m', identifier: 'ip' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rl = r.webAclRules.find(x => x.xSecurity.rule_type === 'ratelimit-0');
  assert.equal(rl?.Statement.RateBasedStatement?.Limit, 100);
  assert.ok(r.warnings.some(w => w.field === 'rateLimit.requests'));
});

test('IDOR/BOLA on ownership-scoped resource → unsupported directive', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: {
          type: 'rule-based',
          rules: [{ field: 'userId', operator: 'equals', value: '$ctx.user.id' }]
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const u = r.unsupportedDirectives.find(d => d.directive.includes('BOLA') || d.directive.includes('IDOR'));
  assert.ok(u, 'expected BOLA/IDOR unsupported entry');
  assert.match(u!.reason, /Lambda authorizer|application layer/i);
});

test('mTLS authentication is unsupported (configured on API GW custom domain)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/secure',
      policy: { authentication: { type: 'mtls' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(r.unsupportedDirectives.some(d => d.directive === 'authentication.mtls'));
});

test('byte-size body cap emits SizeConstraintStatement on Body', () => {
  const spec = makeSpec([
    makeEndpoint({ method: 'POST', path: '/upload', policy: { request: { maxBodySize: '5MB' } } })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const body = r.webAclRules.find(x => x.xSecurity.rule_type === 'body-size');
  assert.ok(body);
  // Drill through AndStatement
  const found = JSON.stringify(body.Statement).includes('"Size":5242880');
  assert.ok(found, `expected size 5242880 inside statement, got ${JSON.stringify(body.Statement)}`);
});

test('CORS: blocks disallowed Origin, methods emit info warning (response headers belong on API GW)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/public',
      policy: {
        cors: { allowedOrigins: ['https://app.example.com'], allowedMethods: ['GET', 'POST'] }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const corsRule = r.webAclRules.find(x => x.xSecurity.rule_type === 'cors-origin');
  assert.ok(corsRule);
  assert.ok(r.warnings.some(w => w.field === 'cors.allowedMethods' && w.severity === 'info'));
});

test('ipPolicy.allow array emits an IPSet + corresponding Block rule', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin',
      policy: { ipPolicy: { allow: ['10.0.0.0/8', '192.168.0.0/16'] } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.ipSets.length, 1);
  assert.equal(r.ipSets[0]?.Addresses.length, 2);
  assert.equal(r.ipSets[0]?.IPAddressVersion, 'IPV4');
  assert.ok(r.webAclRules.find(x => x.xSecurity.rule_type === 'ip-allow'));
});

test('request.schema emits unsupported (deep validation belongs in API GW validator)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: {
        request: { schema: { email: { type: 'email', maxLength: 254 } } }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(r.unsupportedDirectives.some(d => d.directive === 'request.schema'));
});

test('owaspApiTop10 mitigates → sqli + xss inspections on POST/PUT/PATCH', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: { mitigates: ['API10:2023'] }
    }),
    makeEndpoint({
      method: 'GET',
      path: '/api/y',
      policy: { mitigates: ['API10:2023'] }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(r.webAclRules.find(x => x.xSecurity.rule_type === 'sqli-body' && x.xSecurity.endpoint_id === 'POST_/api/x'));
  assert.ok(r.webAclRules.find(x => x.xSecurity.rule_type === 'xss-body' && x.xSecurity.endpoint_id === 'POST_/api/x'));
  // GET endpoint must NOT receive body inspection
  assert.ok(!r.webAclRules.find(x => x.xSecurity.rule_type === 'sqli-body' && x.xSecurity.endpoint_id === 'GET_/api/y'));
});

test('botProtection without explicit opt-in → warning only, no rule', () => {
  const policy = { botProtection: true } as unknown as import('@x-security/schema').XSecurityPolicy;
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  assert.ok(!r.webAclRules.find(x => x.xSecurity.rule_type === 'bot-control'));
  assert.ok(r.warnings.some(w => w.field === 'botProtection' && /paid managed rule group/i.test(w.message)));
});

test('botProtection opt-in → Bot Control managed rule group + cost warning', () => {
  const policy = { botProtection: true } as unknown as import('@x-security/schema').XSecurityPolicy;
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]),
    { mode: 'enforce', enableManagedBotControl: true }
  );
  const bc = r.webAclRules.find(x => x.xSecurity.rule_type === 'bot-control');
  assert.ok(bc);
  assert.equal(bc?.Statement.ManagedRuleGroupStatement?.Name, 'AWSManagedRulesBotControlRuleSet');
  assert.deepEqual(bc?.OverrideAction, { None: {} });
  assert.ok(r.warnings.some(w => /pricing|monthly subscription cost/i.test(w.message)));
});

test('botProtection in shadow → OverrideAction.Count, not None', () => {
  const policy = { botProtection: true } as unknown as import('@x-security/schema').XSecurityPolicy;
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]),
    { mode: 'shadow', enableManagedBotControl: true }
  );
  const bc = r.webAclRules.find(x => x.xSecurity.rule_type === 'bot-control');
  assert.deepEqual(bc?.OverrideAction, { Count: {} });
});

test('snapshot: full canonical compile output is structurally stable', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/auth/login',
      policy: {
        authentication: { type: 'none' },
        rateLimit: { requests: 500, window: '5m', identifier: 'ip' },
        request: { contentType: ['application/json'], maxBodySize: '10KB' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'shadow', schemaVersion: '0.2.0' });
  assert.match(r.contentHash, /^[0-9a-f]{64}$/);
  for (const rule of r.webAclRules) {
    assert.match(rule.Name, /^x-security-shadow-[0-9a-f]{12}-[a-z0-9-]+$/);
    assert.equal(typeof rule.Priority, 'number');
    assert.ok(rule.VisibilityConfig.MetricName.length > 0);
  }
});

test('priorities are strictly increasing across rules', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/a',
      policy: {
        authentication: { type: 'api-key' },
        request: { maxBodySize: '1KB', contentType: ['application/json'] },
        rateLimit: { requests: 500, window: '5m', identifier: 'ip' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce', basePriority: 100 });
  const ps = r.webAclRules.map(x => x.Priority);
  assert.ok(ps.length >= 3);
  for (let i = 1; i < ps.length; i++) {
    assert.ok(ps[i]! > ps[i - 1]!, `priorities must be strictly increasing: ${ps.join(',')}`);
  }
  assert.equal(ps[0], 100);
});

test('empty spec yields empty output but stable content hash', () => {
  const r = compile(makeSpec([]), { mode: 'shadow' });
  assert.equal(r.webAclRules.length, 0);
  assert.equal(r.ipSets.length, 0);
  assert.equal(r.usagePlans.length, 0);
  assert.match(r.contentHash, /^[0-9a-f]{64}$/);
});
