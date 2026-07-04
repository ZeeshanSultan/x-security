import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  capabilities,
  compile,
  CF_SHADOW_MODE_SUPPORT,
  lookupShadowModeSupport
} from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

// ────────────────────────────────────────────────────────────────────────────
// Default mode (rev 3 rollout): mode omitted ⇒ observe.
// ────────────────────────────────────────────────────────────────────────────

test('mode defaults to observe when CompileOptions is omitted', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: { authentication: { type: 'api-key' } }
    })
  ]);
  // No mode passed at all.
  const r = compile(spec);
  const auth = r.rulesets[0]!.rules.find(x => x.writ.rule_type === 'auth')!;
  assert.equal(auth.action, 'log', 'observe-mode should demote auth=block to log');
  assert.equal(auth.mode, 'observe');
  assert.match(auth.id, /^writ-observe-/);
});

test('mode defaults to observe when options is an empty object', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST', path: '/x', policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const r = compile(spec, {});
  const all = r.rulesets.flatMap(rs => rs.rules);
  for (const rule of all) {
    if (rule.action !== 'rewrite') {
      assert.equal(rule.mode, 'observe', `${rule.id} should be observe`);
    }
  }
});

// ────────────────────────────────────────────────────────────────────────────
// WAF Custom Rules: blocking → log in observe, block in enforce.
// ────────────────────────────────────────────────────────────────────────────

test('observe-mode demotes WAF Custom Rule block actions to log', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin',
      policy: {
        authentication: { type: 'api-key' },
        ipPolicy: { allow: ['10.0.0.0/8'] },
        request: { contentType: ['application/json'], maxBodySize: '1MB' }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  const customRs = observe.rulesets.find(rs => rs.phase === 'http_request_firewall_custom')!;
  const blocking = customRs.rules.filter(r => r.writ.rule_type !== 'cors-headers');
  assert.ok(blocking.length >= 3);
  for (const r of blocking) {
    assert.equal(r.action, 'log', `${r.id} should be log in observe`);
    assert.equal(r.mode, 'observe');
  }

  const enforce = compile(spec, { mode: 'enforce' });
  const auth = enforce.rulesets[0]!.rules.find(x => x.writ.rule_type === 'auth')!;
  assert.equal(auth.action, 'block');
  assert.equal(auth.mode, 'enforce');
});

// ────────────────────────────────────────────────────────────────────────────
// Rate Limit Rules: trigger demoted to log + observeModeNote warns counters run.
// ────────────────────────────────────────────────────────────────────────────

test('observe-mode demotes Rate Limit rule trigger to log + emits partial-support note', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/login',
      policy: { rateLimit: { requests: 10, window: '1m', identifier: 'ip' } }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  const rlRs = observe.rulesets.find(rs => rs.phase === 'http_ratelimit')!;
  assert.equal(rlRs.rules[0]!.action, 'log');
  assert.equal(rlRs.rules[0]!.mode, 'observe');
  // Rate limit counters still run — note says so.
  const note = observe.observeModeNotes.find(n => n.field === 'rateLimit');
  assert.ok(note, 'expected rateLimit observeModeNote in observe-mode');
  assert.equal(note!.support, 'partial');
  assert.match(note!.message, /counters/i);

  // Enforce: trigger is block, no observe-mode note for rate limit.
  const enforce = compile(spec, { mode: 'enforce' });
  const rlEnf = enforce.rulesets.find(rs => rs.phase === 'http_ratelimit')!;
  assert.equal(rlEnf.rules[0]!.action, 'block');
  assert.ok(!enforce.observeModeNotes.some(n => n.field === 'rateLimit'));
});

// ────────────────────────────────────────────────────────────────────────────
// Transform Rules (response headers / Set-Cookie rewrite) — always-applied
// even in observe — surface via observeModeNotes.
// ────────────────────────────────────────────────────────────────────────────

test('always-applied transform rules carry an observe-mode "always-applied" note', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/x',
      policy: {
        response: {
          headers: {
            csp: "default-src 'self'",
            hsts: { maxAge: 31536000, includeSubDomains: true }
          },
          cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Lax' } }
        },
        cacheable: { enabled: true, ttl: 60, unkeyedHeadersStrip: ['Cookie', 'Authorization'] }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  const fields = observe.observeModeNotes.map(n => n.field);
  assert.ok(fields.includes('response.headers'), 'expected response.headers always-applied note');
  assert.ok(fields.includes('response.cookies.defaults'), 'expected cookie defaults always-applied note');
  assert.ok(fields.includes('cacheable.unkeyedHeadersStrip'), 'expected cache-strip always-applied note');
  for (const n of observe.observeModeNotes.filter(x =>
    ['response.headers', 'response.cookies.defaults', 'cacheable.unkeyedHeadersStrip'].includes(x.field)
  )) {
    assert.equal(n.support, 'always-applied');
  }

  // Enforce mode: no observe notes (it's not in observe).
  const enforce = compile(spec, { mode: 'enforce' });
  assert.equal(enforce.observeModeNotes.length, 0);
});

test('legacy security headers (no policy.response.headers) carry observe-mode note', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/legacy',
      policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  assert.ok(
    observe.observeModeNotes.some(n => n.field === 'response.securityHeaders' && n.support === 'always-applied'),
    'expected legacy security-headers always-applied note'
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Worker artifacts: SHADOW_MODE env binding gates the 403, switches with mode.
// ────────────────────────────────────────────────────────────────────────────

test('Worker artifacts emit SHADOW_MODE env binding matching the compile mode', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/webhooks/in',
      policy: {
        authentication: { type: 'api-key' },
        request: {
          signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$vault.webhook' }
        }
      }
    })
  ]);
  const observe = compile(spec, { mode: 'observe' });
  const sig = observe.workerArtifacts.find(w => w.kind === 'request-signature');
  assert.ok(sig, 'expected request-signature Worker');
  assert.equal(sig!.mode, 'observe');
  assert.deepEqual(sig!.envBinding, { name: 'SHADOW_MODE', value: 'observe' });
  // Template body carries the gate banner.
  assert.match(sig!.template, /SHADOW_MODE/);
  assert.match(sig!.template, /would-block/);

  const enforce = compile(spec, { mode: 'enforce' });
  const sigE = enforce.workerArtifacts.find(w => w.kind === 'request-signature')!;
  assert.equal(sigE.mode, 'enforce');
  assert.deepEqual(sigE.envBinding, { name: 'SHADOW_MODE', value: 'enforce' });
});

// ────────────────────────────────────────────────────────────────────────────
// Capability matrix exposes shadowModeSupport per field.
// ────────────────────────────────────────────────────────────────────────────

test('capability matrix exposes shadowModeSupport entries', () => {
  // Standalone API: lookup by field path.
  const respHdrs = lookupShadowModeSupport('response.headers');
  assert.ok(respHdrs);
  assert.equal(respHdrs!.support, 'always-applied');

  const auth = lookupShadowModeSupport('authentication');
  assert.ok(auth);
  assert.equal(auth!.support, 'simulatable');

  const rl = lookupShadowModeSupport('rateLimit');
  assert.ok(rl);
  assert.equal(rl!.support, 'partial');

  // Frozen map exposed for dashboards.
  assert.ok(CF_SHADOW_MODE_SUPPORT['authentication']);
  assert.ok(Object.keys(CF_SHADOW_MODE_SUPPORT).length >= 20);

  // Generator-contract capability matrix is unchanged shape.
  assert.ok(capabilities().fields['authentication'] === 'full');
});

// ────────────────────────────────────────────────────────────────────────────
// Provenance notes carry the per-field observeMode classification.
// ────────────────────────────────────────────────────────────────────────────

test('provenance notes include observeMode classification', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/webhook',
      policy: {
        request: {
          signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$vault.s' }
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'observe' });
  const sig = r.provenance.find(p => p.field === 'request.signature');
  assert.ok(sig);
  assert.equal(sig!.observeMode, 'simulatable');
});

// ────────────────────────────────────────────────────────────────────────────
// 'shadow' remains a working alias for 'observe' (back-compat).
// ────────────────────────────────────────────────────────────────────────────

test("legacy 'shadow' mode behaves like observe for action demotion", () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET', path: '/x', policy: { authentication: { type: 'api-key' } }
    })
  ]);
  const sh = compile(spec, { mode: 'shadow' });
  const auth = sh.rulesets[0]!.rules.find(r => r.writ.rule_type === 'auth')!;
  assert.equal(auth.action, 'log');
  assert.equal(auth.mode, 'shadow');
  // Worker env binding still says 'observe' (the runtime keyword is observe/enforce).
  const sigSpec = makeSpec([makeEndpoint({
    method: 'POST', path: '/wh',
    policy: { request: { signature: { algorithm: 'hmac-sha256', headerName: 'x-sig', secretRef: '$vault.s' } } }
  })]);
  const sigOut = compile(sigSpec, { mode: 'shadow' });
  const wa = sigOut.workerArtifacts[0]!;
  assert.equal(wa.envBinding.value, 'observe');
});
