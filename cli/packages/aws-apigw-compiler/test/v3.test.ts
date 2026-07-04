import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compile } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

// ────────────────────────────────────────────────────────────────────────────
// #2 — authentication.allowedAlgorithms (HARD policy-load error when missing)
// ────────────────────────────────────────────────────────────────────────────

test('bearer-jwt WITHOUT allowedAlgorithms is a hard error and emits no rules', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/me',
      policy: { authentication: { type: 'bearer-jwt' } } // missing allowedAlgorithms
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(
    r.errors.some(e => e.field === 'authentication.allowedAlgorithms'),
    'expected hard error for missing allowedAlgorithms'
  );
  // No rules for this endpoint
  assert.equal(r.webAclRules.filter(x => x.writ.endpoint_id === 'GET_/api/me').length, 0);
});

test('bearer-jwt WITH allowedAlgorithms emits jwt-alg Lambda authorizer (full)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/me',
      policy: {
        authentication: {
          type: 'bearer-jwt',
          jwksUri: 'https://auth.example.com/.well-known/jwks.json',
          allowedAlgorithms: ['RS256', 'ES256']
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const auth = r.lambdaAuthorizers.find(a => a.template.kind === 'jwt-alg-allowlist');
  assert.ok(auth, 'expected jwt-alg-allowlist authorizer');
  assert.deepEqual(auth.template.config['algorithms'], ['RS256', 'ES256']);
  assert.ok(
    r.capabilityMatrix.some(c => c.field === 'authentication.allowedAlgorithms' && c.level === 'full'),
    'expected capability=full for allowedAlgorithms'
  );
});

// ────────────────────────────────────────────────────────────────────────────
// #1 + #3 — RuleRef authorization + resourceLookup
// ────────────────────────────────────────────────────────────────────────────

test('authorization.rules[].value: RuleRef emits jwt-ruleref Lambda authorizer', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: {
          type: 'rule-based',
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const ruleref = r.lambdaAuthorizers.find(a => a.template.kind === 'jwt-ruleref');
  assert.ok(ruleref, 'expected jwt-ruleref authorizer');
  const refs = ruleref.template.config['rules'] as Array<{ valueRef: string }>;
  assert.equal(refs[0]?.valueRef, 'jwt.sub');
});

test('authorization.resourceLookup emits resource-lookup Lambda authorizer (full)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/orders/{id}',
      policy: {
        authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] },
        authorization: {
          type: 'rule-based',
          resourceLookup: {
            endpoint: '/users/{id}',
            identifierFrom: 'request.params.id',
            expose: ['ownerId', 'tenantId']
          },
          rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }]
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lookup = r.lambdaAuthorizers.find(a => a.template.kind === 'resource-lookup');
  assert.ok(lookup);
  assert.equal(lookup.template.config['endpoint'], '/users/{id}');
  assert.deepEqual(lookup.template.config['expose'], ['ownerId', 'tenantId']);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'authorization.resourceLookup' && c.level === 'full'));
});

// ────────────────────────────────────────────────────────────────────────────
// #4 — csrf
// ────────────────────────────────────────────────────────────────────────────

test('csrf origin-check emits WAFv2 origin allowlist Block rule', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: {
        csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rule = r.webAclRules.find(x => x.writ.rule_type === 'csrf-origin');
  assert.ok(rule, 'expected csrf-origin WAFv2 rule');
  assert.ok(rule.Action?.Block !== undefined);
});

test('csrf double-submit emits Lambda authorizer (partial)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: {
        csrf: { method: 'double-submit', tokenHeader: 'X-CSRF-Token', tokenCookie: 'csrf_token' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'csrf-double-submit');
  assert.ok(lam, 'expected csrf-double-submit authorizer');
  assert.equal(lam.template.config['tokenHeader'], 'X-CSRF-Token');
  assert.equal(lam.template.config['tokenCookie'], 'csrf_token');
});

// (#5 response.cookies.defaults lives in v3-response.test.ts.)

// ────────────────────────────────────────────────────────────────────────────
// #6 — request.denyUnknownFields (KEY WIN: JSON Schema model)
// ────────────────────────────────────────────────────────────────────────────

test('request.denyUnknownFields emits API GW request validator + JSON Schema model with additionalProperties:false', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/users',
      policy: {
        request: {
          denyUnknownFields: true,
          schema: {
            id: { type: 'uuid' },
            name: { type: 'string', maxLength: 200 }
          }
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.equal(r.requestValidators.length, 1);
  const v = r.requestValidators[0]!;
  assert.equal(v.ValidateRequestBody, true);
  assert.equal(v.ValidateRequestParameters, true);
  assert.ok(v.Model, 'expected inline model');
  const schema = v.Model!.Schema;
  assert.equal(schema['additionalProperties'], false);
  const props = schema['properties'] as Record<string, Record<string, unknown>>;
  assert.equal(props['id']?.['format'], 'uuid');
  assert.equal(props['name']?.['type'], 'string');
  assert.equal(props['name']?.['maxLength'], 200);
  // No legacy "unsupported request.schema" entry when denyUnknownFields=true.
  assert.equal(r.unsupportedDirectives.filter(d => d.directive === 'request.schema').length, 0);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.denyUnknownFields' && c.level === 'full'));
});

// ────────────────────────────────────────────────────────────────────────────
// #7 — request.signature (HMAC → Lambda authorizer)
// ────────────────────────────────────────────────────────────────────────────

test('request.signature emits HMAC Lambda authorizer (full)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/webhooks/stripe',
      policy: {
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
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'hmac-signature');
  assert.ok(lam);
  assert.equal(lam.template.config['algorithm'], 'hmac-sha256');
  assert.equal(lam.template.config['timestampToleranceSeconds'], 300);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.signature' && c.level === 'full'));
});

// ────────────────────────────────────────────────────────────────────────────
// #8 — request.allowedHosts → WAFv2 host rule
// ────────────────────────────────────────────────────────────────────────────

test('request.allowedHosts emits WAFv2 host-header allowlist Block rule', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/x',
      policy: { request: { allowedHosts: ['api.example.com', 'api-eu.example.com'] } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rule = r.webAclRules.find(x => x.writ.rule_type === 'allowed-hosts');
  assert.ok(rule);
  assert.ok(rule.Action?.Block !== undefined);
  const json = JSON.stringify(rule.Statement);
  assert.match(json, /api\.example\.com/);
  assert.match(json, /api-eu\.example\.com/);
});

// ────────────────────────────────────────────────────────────────────────────
// #9 — request.duplicateParamPolicy
// ────────────────────────────────────────────────────────────────────────────

test('request.duplicateParamPolicy emits duplicate-param-policy authorizer (partial)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/api/x',
      policy: { request: { duplicateParamPolicy: 'reject' } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'duplicate-param-policy');
  assert.ok(lam);
  assert.equal(lam.template.config['policy'], 'reject');
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.duplicateParamPolicy' && c.level === 'partial'));
});

// ────────────────────────────────────────────────────────────────────────────
// #10 — request.headerInjectionGuard
// ────────────────────────────────────────────────────────────────────────────

test('request.headerInjectionGuard emits WAFv2 regex rule + regex pattern set', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/x',
      policy: { request: { headerInjectionGuard: true } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rule = r.webAclRules.find(x => x.writ.rule_type === 'header-injection-guard');
  assert.ok(rule);
  // Statement is wrapped in AndStatement(baseMatch, ...); drill in.
  const json = JSON.stringify(rule.Statement);
  assert.match(json, /RegexPatternSetReferenceStatement/);
  assert.match(json, /"MatchScope":"VALUE"/);
  // Pattern set must contain CR/LF/NUL regex
  const set = r.regexPatternSets.find(s => s.Name.includes('hdr-inject'));
  assert.ok(set);
  assert.ok(set.RegularExpressionList.some(re => re.RegexString.includes('\\r')));
});

// ────────────────────────────────────────────────────────────────────────────
// #11 — request.pathCanonicalization
// ────────────────────────────────────────────────────────────────────────────

test('request.pathCanonicalization (REGIONAL) emits WAFv2 regex + warning', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin/users',
      policy: { request: { pathCanonicalization: true } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const rule = r.webAclRules.find(x => x.writ.rule_type === 'path-canonicalization');
  assert.ok(rule);
  assert.ok(r.warnings.some(w => w.field === 'request.pathCanonicalization'));
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.pathCanonicalization' && c.level === 'partial'));
});

test('request.pathCanonicalization (CLOUDFRONT) marks capability=full, no warning', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'GET',
      path: '/admin',
      policy: { request: { pathCanonicalization: true } }
    })
  ]);
  const r = compile(spec, { mode: 'enforce', scope: 'CLOUDFRONT' });
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.pathCanonicalization' && c.level === 'full'));
});

// ────────────────────────────────────────────────────────────────────────────
// #12 — ParamSchema binary additions
// ────────────────────────────────────────────────────────────────────────────

test('binary ParamSchema with magicByteCheck emits mime-magic-byte Lambda authorizer (partial)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/uploads',
      policy: {
        request: {
          denyUnknownFields: false,
          schema: {
            avatar: {
              type: 'binary',
              allowedMimeTypes: ['image/png', 'image/jpeg'],
              maxSize: '2MB',
              magicByteCheck: true,
              extensionAllowlist: ['.png', '.jpg', '.jpeg'],
              denyDoubleExtension: true
            }
          }
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  const lam = r.lambdaAuthorizers.find(a => a.template.kind === 'mime-magic-byte');
  assert.ok(lam);
  assert.equal(lam.template.config['field'], 'avatar');
  assert.deepEqual(lam.template.config['allowedMimeTypes'], ['image/png', 'image/jpeg']);
  assert.equal(lam.template.config['magicByteCheck'], true);
  assert.equal(lam.template.config['denyDoubleExtension'], true);
  assert.ok(r.capabilityMatrix.some(c => c.field === 'request.schema.<binary>' && c.level === 'partial'));
});

test('binary ParamSchema with maxSize > 10MB warns (API GW payload cap)', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/uploads',
      policy: {
        request: {
          schema: { f: { type: 'binary', maxSize: '20MB', magicByteCheck: true } }
        }
      }
    })
  ]);
  const r = compile(spec, { mode: 'enforce' });
  assert.ok(r.warnings.some(w =>
    w.field.startsWith('request.schema.f.maxSize') && /10MB/i.test(w.message)
  ));
});
