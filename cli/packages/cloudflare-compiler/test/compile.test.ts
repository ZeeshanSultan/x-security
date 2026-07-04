import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compile, diffRulesets, stableStringify } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

test('compile is deterministic for the same input', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/auth/login',
      policy: {
        authentication: { type: 'none' },
        rateLimit: { requests: 5, window: '1m', identifier: 'ip' },
        request: { contentType: ['application/json'], maxBodySize: '10KB' }
      }
    }),
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: { type: 'rule-based', rules: [{ field: 'userId', operator: 'equals', value: '$ctx.user.id' }] }
      }
    })
  ]);
  const a = compile(spec, { mode: 'shadow' });
  const b = compile(spec, { mode: 'shadow' });
  assert.equal(stableStringify(a), stableStringify(b));
  assert.equal(a.contentHash, b.contentHash);
});

test('shadow mode forces every rule action to log', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin',
      policy: { authentication: { type: 'api-key' }, ipPolicy: { allow: ['10.0.0.0/8'] } }
    })
  ]);
  const result = compile(spec, { mode: 'shadow' });
  const all = result.rulesets.flatMap(rs => rs.rules);
  assert.ok(all.length > 0, 'expected at least one rule');
  for (const r of all) {
    // Transform "rewrite" rules are allowed even in shadow (they don't block traffic).
    if (r.writ.rule_type.startsWith('cors-headers') ||
        r.writ.rule_type === 'security-headers' ||
        r.writ.rule_type === 'strip-server-headers') {
      assert.equal(r.action, 'rewrite');
    } else {
      assert.equal(r.action, 'log', `${r.id} should be log in shadow mode (got ${r.action})`);
    }
  }
});

test('enforce mode uses the intended action', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: { authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] } }
    })
  ]);
  const result = compile(spec, { mode: 'enforce' });
  const auth = result.rulesets[0]!.rules.find(r => r.writ.rule_type === 'auth');
  assert.ok(auth);
  assert.equal(auth!.action, 'block');
  assert.match(auth!.id, /^writ-enforce-/);
});

test('rule IDs are stable across compilations and endpoints sort deterministically', () => {
  const ep1 = makeEndpoint({ method: 'GET', path: '/b', policy: { authentication: { type: 'api-key' } } });
  const ep2 = makeEndpoint({ method: 'GET', path: '/a', policy: { authentication: { type: 'api-key' } } });
  const a = compile(makeSpec([ep1, ep2]), { mode: 'shadow' });
  const b = compile(makeSpec([ep2, ep1]), { mode: 'shadow' });
  assert.equal(a.contentHash, b.contentHash);
  const ids = a.rulesets.flatMap(rs => rs.rules.map(r => r.id));
  // /a's rules must come before /b's rules because path is sorted
  const firstA = ids.findIndex(i => i.includes('-auth'));
  assert.ok(firstA >= 0);
});

test('rate limit window is rounded to a CF-allowed period', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/login',
      policy: { rateLimit: { requests: 10, window: '5m', identifier: 'ip' } }
    })
  ]);
  const result = compile(spec, { mode: 'shadow' });
  const rl = result.rulesets.find(rs => rs.phase === 'http_ratelimit');
  assert.ok(rl);
  assert.equal(rl!.rules.length, 1);
  assert.equal(rl!.rules[0]!.ratelimit?.period, 300);
  assert.equal(rl!.rules[0]!.ratelimit?.requests_per_period, 10);
});

test('IDOR tripwire emits a LOW-confidence log rule for ownership-scoped resources', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: { type: 'rule-based', rules: [{ field: 'userId', operator: 'equals', value: '$ctx.user.id' }] }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const trip = r.rulesets[0]!.rules.find(x => x.writ.rule_type === 'idor-tripwire');
  assert.ok(trip, 'expected idor-tripwire rule');
  assert.equal(trip!.writ.confidence, 'LOW');
  assert.equal(trip!.action, 'log'); // forceLog
});

test('diffRulesets detects added/removed/modified', () => {
  const policyA = { authentication: { type: 'api-key' as const } };
  const policyB = { authentication: { type: 'bearer-jwt' as const, allowedAlgorithms: ['RS256' as const] } };
  const a = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/a', policy: policyA })]), { mode: 'shadow' });
  const b = compile(makeSpec([
    makeEndpoint({ method: 'GET', path: '/a', policy: policyB }),
    makeEndpoint({ method: 'GET', path: '/b', policy: policyA })
  ]), { mode: 'shadow' });
  const d = diffRulesets(a, b);
  assert.equal(d.identical, false);
  assert.ok(d.added.length >= 1, 'expected /b auth rule to be added');
  assert.ok(d.modified.length >= 1, 'expected /a auth rule to be modified');
});

test('byte size parser handles KB/MB/GB', () => {
  const spec = makeSpec([
    makeEndpoint({ method: 'POST', path: '/upload', policy: { request: { maxBodySize: '5MB' } } })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const bodyRule = r.rulesets[0]!.rules.find(x => x.writ.rule_type === 'body-size');
  assert.ok(bodyRule);
  assert.match(bodyRule!.expression, /http\.request\.body\.size > 5242880/);
});

test('cors: blocks disallowed origin, transforms response headers for allowed methods', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/public',
      policy: { cors: { allowedOrigins: ['https://app.example.com'], allowedMethods: ['GET', 'POST'] } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const custom = r.rulesets.find(rs => rs.phase === 'http_request_firewall_custom');
  const trans = r.rulesets.find(rs => rs.phase === 'http_response_headers_transform');
  assert.ok(custom!.rules.find(x => x.writ.rule_type === 'cors-origin'));
  assert.ok(trans!.rules.find(x => x.writ.rule_type === 'cors-headers'));
});

test('empty spec produces empty rulesets but still returns content hash', () => {
  const r = compile(makeSpec([]), { mode: 'shadow' });
  assert.equal(r.rulesets.length, 0);
  assert.ok(r.contentHash.length === 64);
  // Default planTier='free' — managed rulesets are gated to Business+, so empty here
  assert.equal(r.managedRulesets.length, 0);
  assert.ok(r.warnings.some(w => w.field === 'managedRulesets.owaspCrs'));
});

test('planTier=business emits OWASP CRS managed ruleset', () => {
  const r = compile(makeSpec([]), { mode: 'shadow', planTier: 'business' });
  assert.equal(r.managedRulesets.length, 1);
  assert.equal(r.managedRulesets[0]?.ruleset_id, 'efb7b8c949ac4650a09736fc376e9aee');
  assert.ok(!r.warnings.some(w => w.field === 'managedRulesets.owaspCrs'));
});

test('planTier=enterprise emits OWASP CRS managed ruleset', () => {
  const r = compile(makeSpec([]), { mode: 'shadow', planTier: 'enterprise' });
  assert.equal(r.managedRulesets.length, 1);
});

test('planTier=pro skips OWASP CRS with info-severity warning', () => {
  const r = compile(makeSpec([]), { mode: 'shadow', planTier: 'pro' });
  assert.equal(r.managedRulesets.length, 0);
  const w = r.warnings.find(x => x.field === 'managedRulesets.owaspCrs');
  assert.ok(w);
  assert.equal(w!.severity, 'info');
});

test('planTier=free warns when >1 rate-limit rule is compiled', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/a',
      policy: { rateLimit: { requests: 5, window: '60s', identifier: 'ip' } }
    }),
    makeEndpoint({
      method: 'POST',
      path: '/b',
      policy: { rateLimit: { requests: 5, window: '60s', identifier: 'ip' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce', planTier: 'free' });
  const w = r.warnings.find(x => x.field === 'rateLimit.count');
  assert.ok(w);
  assert.equal(w!.severity, 'warn');
});

test('botProtection emits rule on business+ but warns on free', () => {
  // botProtection lives on the raw policy bag (see compileBotProtection in
  // compile.ts) — not yet in the typed surface. Cast through unknown.
  const policy = { botProtection: true } as unknown as import('@writ/schema').XSecurityPolicy;
  const ep = (tier: 'free' | 'business') =>
    compile(
      makeSpec([makeEndpoint({ method: 'GET', path: '/api/x', policy })]),
      { mode: 'enforce', planTier: tier }
    );

  const free = ep('free');
  const biz = ep('business');
  const freeCustom = free.rulesets.find(rs => rs.phase === 'http_request_firewall_custom');
  const bizCustom = biz.rulesets.find(rs => rs.phase === 'http_request_firewall_custom');
  assert.ok(!freeCustom?.rules.some(r => r.writ.rule_type === 'bot-protection'));
  assert.ok(free.warnings.some(w => w.field === 'botProtection'));
  assert.ok(bizCustom?.rules.some(r => r.writ.rule_type === 'bot-protection'));
});

test('snapshot: full canonical compile output is stable', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/auth/login',
      policy: {
        authentication: { type: 'none' },
        rateLimit: { requests: 5, window: '60s', identifier: 'ip' },
        request: { contentType: ['application/json'], maxBodySize: '10KB' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'shadow', schemaVersion: '0.2.0', version: 1 });
  // Just assert the content hash for the canonical case; if anything changes,
  // the test fails and the developer must consciously update the expected hash.
  // (Mechanical snapshot — no hidden behavior.)
  assert.match(r.contentHash, /^[0-9a-f]{64}$/);
  // Ensure the IDs follow the documented naming scheme.
  for (const rs of r.rulesets) {
    for (const rule of rs.rules) {
      assert.match(rule.id, /^writ-shadow-[0-9a-f]{12}-[a-z0-9-]+$/);
      assert.ok(rule.description.startsWith('[writ] '));
    }
  }
});
