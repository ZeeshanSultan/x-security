// v0.3 schema support — tests for each of the 17 additions documented in
// packages/schema/docs/v0.3-additions.md. Each test compiles a fixture
// policy containing the field and asserts either:
//   - native ruleset emission, OR
//   - a provenance note (compiler MUST NOT silently drop), OR
//   - a Worker artifact (override-only).
//
// Imported types are intentionally minimal — fixtures use the same
// XSecurityPolicy shape exposed by @x-security/schema.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { XSecurityPolicy } from '@x-security/schema';
import { compile, CompileError, capabilities } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

// ---------- 1. RuleRef on authorization.rules[].value ----------

test('v0.3 #1 RuleRef (jwt.*) emits provenance note (Worker required)', () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
    }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/users/{id}', policy })]),
    { mode: 'enforce' }
  );
  const note = r.provenance.find(n => n.field === 'authorization.rules[].value.ref');
  assert.ok(note, 'expected provenance note for RuleRef');
  assert.equal(note!.decision, 'partial');
});

test('v0.3 #1 RuleRef (request.headers.*) lowers to a Wirefilter rule', () => {
  const policy: XSecurityPolicy = {
    authorization: {
      type: 'rule-based',
      rules: [{
        field: 'request.headers.x-tenant-id',
        operator: 'equals',
        value: { ref: 'request.headers.x-actual-tenant' }
      }]
    }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  const custom = r.rulesets.find(rs => rs.phase === 'http_request_firewall_custom')!;
  const ref = custom.rules.find(x => x.xSecurity.rule_type.startsWith('authz-ref-'));
  assert.ok(ref, 'expected wirefilter rule for request.headers ref');
  assert.match(ref!.expression, /http\.request\.headers\["x-tenant-id"\]\[0\] eq http\.request\.headers\["x-actual-tenant"\]\[0\]/);
});

// ---------- 2. Authentication.allowedAlgorithms ----------

test('v0.3 #2 bearer-jwt without allowedAlgorithms is a HARD compile error', () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt' } as XSecurityPolicy['authentication']
  };
  assert.throws(
    () => compile(makeSpec([makeEndpoint({ method: 'GET', path: '/a', policy })]), { mode: 'enforce' }),
    /allowedAlgorithms/i
  );
});

test('v0.3 #2 bearer-jwt with allowedAlgorithms compiles and emits provenance note', () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256', 'ES256'] }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/a', policy })]),
    { mode: 'enforce' }
  );
  const note = r.provenance.find(n => n.field === 'authentication.allowedAlgorithms');
  assert.ok(note);
  assert.equal(note!.decision, 'override-only');
  assert.match(note!.message, /RS256, ES256/);
});

// ---------- 3. Authorization.resourceLookup ----------

test('v0.3 #3 resourceLookup emits Worker artifact + provenance', () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
    authorization: {
      type: 'rule-based',
      resourceLookup: { endpoint: '/users/{id}', identifierFrom: 'request.params.id', expose: ['ownerId'] },
      rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
    }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/users/{id}', policy })]),
    { mode: 'enforce' }
  );
  const worker = r.workerArtifacts.find(w => w.kind === 'resource-lookup');
  assert.ok(worker, 'expected Worker artifact for resourceLookup');
  assert.equal(worker!.field, 'authorization.resourceLookup');
  assert.ok(Array.isArray((worker!.params as { rules: unknown }).rules));
  assert.ok(r.provenance.some(n => n.field === 'authorization.resourceLookup'));
});

// ---------- 4. csrf ----------

test('v0.3 #4 csrf.method=origin-check emits Wirefilter rule', () => {
  const policy: XSecurityPolicy = { csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] } };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'csrf-origin');
  assert.ok(rule);
  assert.match(rule!.expression, /"https:\/\/app\.example\.com"/);
});

test('v0.3 #4 csrf.method=double-submit emits presence rule + provenance for value-equality', () => {
  const policy: XSecurityPolicy = { csrf: { method: 'double-submit', tokenHeader: 'X-CSRF-Token', tokenCookie: 'csrf_token' } };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  assert.ok(r.rulesets.flatMap(rs => rs.rules).some(x => x.xSecurity.rule_type === 'csrf-double-submit-presence'));
  assert.ok(r.provenance.some(n => n.field === 'csrf.method=double-submit'));
});

// ---------- 5. response.cookies.defaults ----------

test('v0.3 #5 response.cookies.defaults emits Set-Cookie Transform Rule', () => {
  const policy: XSecurityPolicy = {
    response: { cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Strict' } } }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/api/x', policy })]), { mode: 'enforce' });
  const resp = r.rulesets.find(rs => rs.phase === 'http_response_headers_transform')!;
  const rule = resp.rules.find(x => x.xSecurity.rule_type === 'response-cookie-defaults');
  assert.ok(rule);
  const params = rule!.action_parameters as { headers: Record<string, { value?: string }> };
  assert.match(params.headers['Set-Cookie']!.value!, /HttpOnly.*Secure.*SameSite=Strict/);
});

test('v0.3 #5 response.cookies.defaults with path/domain emits partial provenance', () => {
  const policy: XSecurityPolicy = {
    response: { cookies: { defaults: { httpOnly: true, path: '/api' } } }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/api/x', policy })]), { mode: 'enforce' });
  assert.ok(r.provenance.some(n => n.field === 'response.cookies.defaults' && n.decision === 'partial'));
});

// ---------- 6. request.denyUnknownFields ----------

test('v0.3 #6 request.denyUnknownFields emits Worker artifact (override-only)', () => {
  const policy: XSecurityPolicy = {
    request: {
      denyUnknownFields: true,
      schema: { id: { type: 'uuid' }, name: { type: 'string', maxLength: 200 } }
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]), { mode: 'enforce' });
  const worker = r.workerArtifacts.find(w => w.kind === 'deny-unknown-fields');
  assert.ok(worker);
  assert.deepEqual((worker!.params as { allowedKeys: string[] }).allowedKeys, ['id', 'name']);
  assert.ok(r.provenance.some(n => n.field === 'request.denyUnknownFields' && n.decision === 'override-only'));
});

// ---------- 7. request.signature ----------

test('v0.3 #7 request.signature emits Worker artifact with hash + binding', () => {
  const policy: XSecurityPolicy = {
    request: {
      signature: {
        algorithm: 'hmac-sha256',
        headerName: 'Stripe-Signature',
        secretRef: '$vault.webhooks/stripe',
        body: 'raw',
        timestampHeader: 'Stripe-Timestamp',
        timestampToleranceSeconds: 300
      }
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/webhook', policy })]), { mode: 'enforce' });
  const worker = r.workerArtifacts.find(w => w.kind === 'request-signature');
  assert.ok(worker);
  const params = worker!.params as Record<string, unknown>;
  assert.equal(params.hash, 'SHA-256');
  assert.equal(params.headerName, 'Stripe-Signature');
  assert.equal(params.timestampToleranceSeconds, 300);
  assert.ok(r.provenance.some(n => n.field === 'request.signature'));
});

// ---------- 8. request.allowedHosts ----------

test('v0.3 #8 request.allowedHosts emits http.host in {...} Wirefilter rule', () => {
  const policy: XSecurityPolicy = { request: { allowedHosts: ['api.example.com', 'api-eu.example.com'] } };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'allowed-hosts');
  assert.ok(rule);
  assert.match(rule!.expression, /not \(http\.host in \{"api\.example\.com" "api-eu\.example\.com"\}\)/);
});

// ---------- 9. request.duplicateParamPolicy ----------

test('v0.3 #9 duplicateParamPolicy=reject emits HPP Wirefilter rule', () => {
  const policy: XSecurityPolicy = { request: { duplicateParamPolicy: 'reject' } };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'dup-param-reject');
  assert.ok(rule);
});

test('v0.3 #9 duplicateParamPolicy=first emits partial provenance note', () => {
  const policy: XSecurityPolicy = { request: { duplicateParamPolicy: 'first' } };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  assert.ok(r.provenance.some(n => n.field === 'request.duplicateParamPolicy=first' && n.decision === 'partial'));
});

// ---------- 10. request.headerInjectionGuard ----------

test('v0.3 #10 headerInjectionGuard emits CR/LF/NUL regex rule', () => {
  const policy: XSecurityPolicy = { request: { headerInjectionGuard: true } };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/x', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'header-injection-guard');
  assert.ok(rule);
  assert.match(rule!.expression, /\[\\\\r\\\\n\\\\x00\]/);
});

// ---------- 11. request.pathCanonicalization ----------

test('v0.3 #11 pathCanonicalization emits double-encoded-traversal guard', () => {
  const policy: XSecurityPolicy = { request: { pathCanonicalization: true } };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/admin', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'path-canonicalization');
  assert.ok(rule);
  assert.match(rule!.expression, /%\(\?:25\)\+/);
});

// ---------- 12. ParamSchema binary (magicByteCheck, extensionAllowlist, denyDoubleExtension) ----------

test('v0.3 #12 ParamSchema.extensionAllowlist emits Wirefilter rule', () => {
  const policy: XSecurityPolicy = {
    request: {
      schema: {
        avatar: { type: 'binary', allowedMimeTypes: ['image/png'], extensionAllowlist: ['.png', '.jpg'] }
      }
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/upload', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type.startsWith('bin-ext-'));
  assert.ok(rule);
});

test('v0.3 #12 ParamSchema.denyDoubleExtension emits Wirefilter rule', () => {
  const policy: XSecurityPolicy = {
    request: { schema: { avatar: { type: 'binary', denyDoubleExtension: true } } }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/upload', policy })]), { mode: 'enforce' });
  assert.ok(r.rulesets.flatMap(rs => rs.rules).some(x => x.xSecurity.rule_type.startsWith('bin-dbl-')));
});

test('v0.3 #12 ParamSchema.magicByteCheck emits Worker artifact', () => {
  const policy: XSecurityPolicy = {
    request: {
      schema: {
        avatar: { type: 'binary', allowedMimeTypes: ['image/png', 'image/jpeg'], magicByteCheck: true }
      }
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/upload', policy })]), { mode: 'enforce' });
  const worker = r.workerArtifacts.find(w => w.kind === 'magic-byte-avatar');
  assert.ok(worker);
  const sigs = (worker!.params as { signatures: { mime: string; hexPrefix: string }[] }).signatures;
  assert.ok(sigs.find(s => s.mime === 'image/png' && s.hexPrefix.startsWith('89504e47')));
});

// ---------- 13. response.headers ----------

test('v0.3 #13 response.headers emits per-field Modify-Response-Header rule', () => {
  const policy: XSecurityPolicy = {
    response: {
      headers: {
        csp: "default-src 'self'",
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        frameOptions: 'DENY',
        contentTypeOptions: 'nosniff',
        referrerPolicy: 'strict-origin-when-cross-origin',
        permissionsPolicy: 'camera=(), microphone=()',
        coop: 'same-origin',
        coep: 'require-corp',
        corp: 'same-origin',
        cacheControl: 'no-store'
      }
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  const resp = r.rulesets.find(rs => rs.phase === 'http_response_headers_transform')!;
  const rule = resp.rules.find(x => x.xSecurity.rule_type === 'response-headers-v3');
  assert.ok(rule, 'expected response-headers-v3 rule');
  const params = rule!.action_parameters as { headers: Record<string, { value?: string }> };
  assert.equal(params.headers['Content-Security-Policy']!.value, "default-src 'self'");
  assert.equal(params.headers['Strict-Transport-Security']!.value, 'max-age=31536000; includeSubDomains; preload');
  assert.equal(params.headers['X-Frame-Options']!.value, 'DENY');
  assert.equal(params.headers['Cross-Origin-Opener-Policy']!.value, 'same-origin');
  assert.equal(params.headers['Cache-Control']!.value, 'no-store');
});

test('v0.3 #13 response.headers absent → legacy default-headers rule still emitted (back-compat)', () => {
  const r = compile(
    makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy: { authentication: { type: 'none' } } })]),
    { mode: 'enforce' }
  );
  const resp = r.rulesets.find(rs => rs.phase === 'http_response_headers_transform')!;
  assert.ok(resp.rules.find(x => x.xSecurity.rule_type === 'security-headers'));
});

test('v0.3 #13 response.headers present → legacy default-headers rule is suppressed', () => {
  const r = compile(
    makeSpec([makeEndpoint({
      method: 'GET',
      path: '/x',
      policy: { response: { headers: { frameOptions: 'DENY' } } }
    })]),
    { mode: 'enforce' }
  );
  const resp = r.rulesets.find(rs => rs.phase === 'http_response_headers_transform')!;
  assert.ok(!resp.rules.some(x => x.xSecurity.rule_type === 'security-headers'),
    'legacy security-headers rule should NOT be emitted when policy.response.headers is set');
  assert.ok(resp.rules.some(x => x.xSecurity.rule_type === 'response-headers-v3'));
});

// ---------- 14. cacheable.unkeyedHeadersStrip ----------

test('v0.3 #14 cacheable.unkeyedHeadersStrip emits req-transform + provenance', () => {
  const policy: XSecurityPolicy = {
    cacheable: { enabled: true, ttl: 60, unkeyedHeadersStrip: ['Cookie', 'Authorization', 'X-Forwarded-Host'] }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/x', policy })]), { mode: 'enforce' });
  const req = r.rulesets.find(rs => rs.phase === 'http_request_late_transform')!;
  const rule = req.rules.find(x => x.xSecurity.rule_type === 'cache-unkey-strip');
  assert.ok(rule);
  const params = rule!.action_parameters as { headers: Record<string, { operation: string }> };
  assert.equal(params.headers['Cookie']!.operation, 'remove');
  const note = r.provenance.find(n => n.field === 'cacheable.unkeyedHeadersStrip');
  assert.ok(note);
  assert.equal(note!.decision, 'partial');
  assert.ok(note!.override, 'expected override payload describing cache-key exclude config');
});

// ---------- 15. graphql ----------

test('v0.3 #15 graphql emits Worker artifact + override-only provenance', () => {
  const policy: XSecurityPolicy = {
    graphql: {
      maxDepth: 10,
      maxComplexity: 1000,
      maxAliases: 15,
      batchLimit: 10,
      disableIntrospection: true,
      allowedOperations: ['query', 'mutation']
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'POST', path: '/graphql', policy })]), { mode: 'enforce' });
  const worker = r.workerArtifacts.find(w => w.kind === 'graphql-limits');
  assert.ok(worker);
  assert.equal((worker!.params as { maxDepth: number }).maxDepth, 10);
  assert.ok(r.provenance.some(n => n.field === 'graphql' && n.decision === 'override-only'));
});

// ---------- 16. websocket ----------

test('v0.3 #16 websocket.allowedOrigins emits handshake Wirefilter rule (full)', () => {
  const policy: XSecurityPolicy = {
    websocket: { allowedOrigins: ['https://app.example.com'] }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/ws', policy })]), { mode: 'enforce' });
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'ws-origin-check');
  assert.ok(rule);
  assert.match(rule!.expression, /upgrade.*websocket/i);
});

test('v0.3 #16 websocket per-message caps emit Durable Object Worker artifact', () => {
  const policy: XSecurityPolicy = {
    websocket: {
      allowedOrigins: ['https://app.example.com'],
      maxMessageSize: '64KB',
      messageRateLimit: { messages: 100, window: '1s' },
      maxConnectionsPerIdentifier: 5,
      idleTimeout: '5m'
    }
  };
  const r = compile(makeSpec([makeEndpoint({ method: 'GET', path: '/ws', policy })]), { mode: 'enforce' });
  const worker = r.workerArtifacts.find(w => w.kind === 'websocket-do-guard');
  assert.ok(worker);
  assert.ok(r.provenance.some(n => n.field === 'websocket' && n.decision === 'partial'));
});

// ---------- 17. botProtection ----------

test('v0.3 #17 botProtection turnstile emits native managed_challenge rule', () => {
  const policy: XSecurityPolicy = {
    botProtection: { provider: 'turnstile', secretRef: '${TURNSTILE_SECRET}', mode: 'enforce' }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  const rule = r.rulesets.flatMap(rs => rs.rules).find(x => x.xSecurity.rule_type === 'bot-turnstile');
  assert.ok(rule);
  assert.equal(rule!.action, 'managed_challenge');
  assert.ok(r.provenance.some(n => n.field === 'botProtection' && n.decision === 'full'));
});

test('v0.3 #17 botProtection recaptcha emits Worker artifact', () => {
  const policy: XSecurityPolicy = {
    botProtection: { provider: 'recaptcha', secretRef: '${RECAPTCHA_SECRET}', mode: 'enforce' }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  const worker = r.workerArtifacts.find(w => w.kind === 'bot-recaptcha');
  assert.ok(worker);
  assert.equal((worker!.params as { verifyUrl: string }).verifyUrl, 'https://www.google.com/recaptcha/api/siteverify');
});

// ---------- TargetOverrides.cloudflare passthrough ----------

test('targetOverrides.cloudflare.<field> is passed through unchanged on a provenance note', () => {
  const policy: XSecurityPolicy = {
    request: { denyUnknownFields: true, schema: { id: {} } },
    targetOverrides: {
      cloudflare: {
        'request.denyUnknownFields': { workerScript: 'custom-validator', workerRoute: '/api/*' }
      }
    }
  };
  const r = compile(
    makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]),
    { mode: 'enforce' }
  );
  const note = r.provenance.find(n => n.field === 'request.denyUnknownFields');
  assert.ok(note);
  assert.deepEqual(note!.override, { workerScript: 'custom-validator', workerRoute: '/api/*' });
});

// ---------- Capability matrix ----------

test('capabilities() exposes a per-field map matching CapabilityMatrix shape', () => {
  const c = capabilities();
  assert.equal(c.fields['response.headers'], 'full');
  assert.equal(c.fields['request.signature'], 'override-only');
  assert.equal(c.fields['graphql'], 'override-only');
  assert.equal(c.fields['websocket.allowedOrigins'], 'full');
  assert.equal(c.fields['botProtection.provider=turnstile'], 'full');
  assert.equal(c.fields['botProtection.provider=recaptcha'], 'override-only');
});

// ---------- Determinism with v0.3 fields ----------

test('compile output stays deterministic with v0.3 provenance + worker artifacts', () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
    request: {
      allowedHosts: ['api.example.com'],
      headerInjectionGuard: true,
      signature: {
        algorithm: 'hmac-sha256', headerName: 'X-Sig', secretRef: '${SECRET}', body: 'raw'
      }
    },
    response: { headers: { hsts: { maxAge: 60 }, frameOptions: 'DENY' } },
    csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] },
    websocket: { allowedOrigins: ['https://app.example.com'] }
  };
  const spec = makeSpec([makeEndpoint({ method: 'POST', path: '/api/x', policy })]);
  const a = compile(spec, { mode: 'enforce' });
  const b = compile(spec, { mode: 'enforce' });
  assert.equal(a.contentHash, b.contentHash);
});

// ---------- Confirm CompileError type ----------

test('CompileError thrown for missing allowedAlgorithms is the exported type', () => {
  try {
    compile(makeSpec([makeEndpoint({
      method: 'GET', path: '/a',
      policy: { authentication: { type: 'bearer-jwt' } as XSecurityPolicy['authentication'] }
    })]), { mode: 'enforce' });
    assert.fail('expected throw');
  } catch (e) {
    assert.ok(e instanceof CompileError);
    assert.equal((e as CompileError).name, 'CompileError');
  }
});
