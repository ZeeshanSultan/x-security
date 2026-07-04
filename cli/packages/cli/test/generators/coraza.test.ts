import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { loadSpec, type SpecIR, type EndpointIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

import { corazaGenerator } from '../../src/generators/coraza/index.js';
import {
  buildPolicyRules,
  endpointHash,
  parseByteSize,
  parseDurationSec,
  pathRegex,
  ruleBase,
} from '../../src/generators/coraza/rules.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../../..');
const EXAMPLE_SPEC = resolve(REPO_ROOT, 'fixtures/specs/example.yaml');
const GOLDEN = resolve(REPO_ROOT, 'fixtures/configs/coraza/example.expected.yml');

/** Build a synthetic EndpointIR for unit-level tests. */
function ep(method: EndpointIR['method'], path: string, policy: XSecurityPolicy): EndpointIR {
  return {
    method,
    path,
    operationId: `${method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_')}`,
    policy,
    parameters: [],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    raw: {} as any,
    resolvedVars: new Map(),
  };
}

/** Load and stub env-resolver vars so the spec loads without env. */
async function loadExample(): Promise<SpecIR> {
  process.env['JWKS_ENDPOINT'] = 'https://example.com/.well-known/jwks.json';
  process.env['AUTH_ISSUER'] = 'https://auth.example.com';
  process.env['AUTH_AUDIENCE'] = 'api.example.com';
  return loadSpec(EXAMPLE_SPEC);
}

describe('coraza: helpers', () => {
  it('parseByteSize handles units', () => {
    assert.equal(parseByteSize('1024'), 1024);
    assert.equal(parseByteSize('1KB'), 1024);
    assert.equal(parseByteSize('10KB'), 10 * 1024);
    assert.equal(parseByteSize('1MB'), 1024 * 1024);
    assert.equal(parseByteSize('50MB'), 50 * 1024 * 1024);
    assert.ok(Number.isNaN(parseByteSize(undefined)));
    assert.ok(Number.isNaN(parseByteSize('garbage')));
  });

  it('parseDurationSec handles units', () => {
    assert.equal(parseDurationSec('30s'), 30);
    assert.equal(parseDurationSec('1m'), 60);
    assert.equal(parseDurationSec('5m'), 300);
    assert.equal(parseDurationSec('1h'), 3600);
    assert.equal(parseDurationSec('1d'), 86400);
    assert.equal(parseDurationSec('10'), 10);
  });

  it('pathRegex replaces path params with [^/]+', () => {
    assert.equal(pathRegex('/api/users/{id}'), '^/api/users/[^/]+$');
    assert.equal(pathRegex('/static/path'), '^/static/path$');
    assert.equal(pathRegex('/a/{x}/b/{y}'), '^/a/[^/]+/b/[^/]+$');
  });

  it('endpointHash is deterministic and stable', () => {
    const a = endpointHash('POST', '/api/login');
    const b = endpointHash('POST', '/api/login');
    const c = endpointHash('GET', '/api/login');
    assert.equal(a, b);
    assert.notEqual(a, c);
  });

  it('ruleBase IDs land above 100_000 and below 400_000', () => {
    const base = ruleBase(ep('POST', '/api/auth/login', {}));
    assert.ok(base >= 100000);
    assert.ok(base < 400000);
  });
});

describe('coraza: per-policy rule emission', () => {
  it('emits content-type allowlist when request.contentType set', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { request: { contentType: ['application/json'] } })
    );
    const joined = rules.join('\n');
    assert.match(joined, /Content-Type/);
    assert.match(joined, /@rx \^\(application\/json\)\(;\.\*\)\?\$/);
    assert.match(joined, /status:415/);
  });

  it('emits 413 deny when request.maxBodySize set', () => {
    const rules = buildPolicyRules(ep('POST', '/x', { request: { maxBodySize: '10KB' } }));
    const joined = rules.join('\n');
    assert.match(joined, /status:413/);
    assert.match(joined, /Content-Length.*@gt 10240/);
  });

  it('emits auth check when authentication.type !== none', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { authentication: { type: 'bearer-jwt' } })
    );
    const joined = rules.join('\n');
    assert.match(joined, /status:401/);
    assert.match(joined, /&REQUEST_HEADERS:Authorization "@eq 0"/);
  });

  it('does NOT emit auth check when authentication.type === none', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { authentication: { type: 'none' } })
    );
    const joined = rules.join('\n');
    assert.doesNotMatch(joined, /status:401/);
  });

  it('emits ipMatch for ipPolicy.allow', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { ipPolicy: { allow: ['10.0.0.0/8', '192.168.1.0/24'] } })
    );
    const joined = rules.join('\n');
    assert.match(joined, /!@ipMatch 10\.0\.0\.0\/8,192\.168\.1\.0\/24/);
    assert.match(joined, /status:403/);
  });

  it('emits ipMatch for ipPolicy.deny', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { ipPolicy: { deny: ['1.2.3.4/32'] } })
    );
    assert.match(rules.join('\n'), /@ipMatch 1\.2\.3\.4\/32/);
  });

  it('emits rate-limit three-rule chain (initcol / setvar+expirevar / @gt)', () => {
    // W10-7: Coraza-Go's setvar action enforces TX-only at runtime
    // (verified: ghcr.io/corazawaf/coraza-spoa rejects setvar:ip.X with
    // "expected collection TX"). Cross-request enforcement requires HAProxy
    // stick-tables; we keep the TX-downgrade form and the loud warning.
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'ip' } })
    );
    const joined = rules.join('\n');
    assert.match(joined, /initcol:tx=%\{REMOTE_ADDR\}/);
    assert.match(joined, /setvar:tx\.rl_\w+=\+1/);
    assert.match(joined, /expirevar:tx\.rl_\w+=60/);
    assert.match(joined, /status:429/);
    assert.match(joined, /SecRule TX:rl_\w+ "@gt 5"/);
  });

  it('emits schema validation rules (maxLength, minLength, email)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', {
        request: {
          schema: {
            email: { type: 'email', maxLength: 254 },
            password: { type: 'free-text', minLength: 8, maxLength: 128 },
          },
        },
      })
    );
    const joined = rules.join('\n');
    assert.match(joined, /ARGS:email.*@gt 254/);
    assert.match(joined, /ARGS:password.*@lt 8/);
    assert.match(joined, /ARGS:password.*@gt 128/);
    assert.match(joined, /not a valid email/);
  });

  it('emits ARGS_NAMES allowlist when request.allowedFields is set', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api6/user', {
        request: { allowedFields: ['username', 'password', 'name'] },
      })
    );
    const joined = rules.join('\n');
    assert.match(joined, /SecRule ARGS_NAMES "!@rx \^json\\\.\(username\|password\|name\)\$"/);
    assert.match(joined, /t:none,t:lowercase/);
    assert.match(joined, /status:403/);
    assert.match(joined, /mass-assignment/);
    // Scoped to method + path, not a global rule.
    assert.match(joined, /@streq POST/);
    assert.match(joined, /REQUEST_URI "@rx \^\/api6\/user\$"/);
  });

  it('derives allowlist from request.schema keys when denyUnknownFields=true', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', {
        request: {
          denyUnknownFields: true,
          schema: {
            a: { type: 'free-text' },
            b: { type: 'integer' },
          },
        },
      })
    );
    const joined = rules.join('\n');
    assert.match(joined, /SecRule ARGS_NAMES "!@rx \^json\\\.\(a\|b\)\$"/);
    assert.match(joined, /denyUnknownFields/);
  });

  it('emits no allowlist rule when neither denyUnknownFields nor allowedFields is set', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { request: { schema: { a: { type: 'free-text' } } } })
    );
    const joined = rules.join('\n');
    assert.doesNotMatch(joined, /ARGS_NAMES/);
    assert.doesNotMatch(joined, /mass-assignment/);
  });

  it('body-field allowlist rule is scoped to endpoint method + path (no global SecRule)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api6/user', { request: { allowedFields: ['a', 'b'] } })
    );
    // The allowlist rule must be a chained SecRule beginning with REQUEST_METHOD/REQUEST_URI,
    // never a bare global SecRule on ARGS_NAMES.
    for (const r of rules) {
      if (/ARGS_NAMES/.test(r)) {
        assert.match(r, /^SecRule REQUEST_METHOD "@streq POST"/m);
        assert.match(r, /SecRule REQUEST_URI "@rx \^\/api6\/user\$"/);
        assert.match(r, /chain/);
      }
    }
  });

  it('emits ctl:requestBodyProcessor=JSON when request.contentType includes application/json (wave-8)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api6/user', {
        request: { contentType: ['application/json'], allowedFields: ['username'] },
      })
    );
    const joined = rules.join('\n');
    assert.match(joined, /ctl:requestBodyProcessor=JSON/);
    assert.match(joined, /enable JSON body processor/);
    // Scoped to the endpoint via method + path chain.
    assert.match(joined, /SecRule REQUEST_METHOD "@streq POST"/);
    assert.match(joined, /REQUEST_URI "@rx \^\/api6\/user\$"/);
  });

  it('emits ctl:requestBodyProcessor=JSON for vnd.+json content-type variants (wave-8)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api/jsonapi', {
        request: { contentType: ['application/vnd.api+json'] },
      })
    );
    const joined = rules.join('\n');
    assert.match(joined, /ctl:requestBodyProcessor=JSON/);
  });

  it('does NOT emit ctl:requestBodyProcessor=JSON for non-JSON content-type (wave-8)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api/form', {
        request: { contentType: ['application/x-www-form-urlencoded'] },
      })
    );
    const joined = rules.join('\n');
    assert.doesNotMatch(joined, /ctl:requestBodyProcessor=JSON/);
  });

  it('does NOT emit ctl:requestBodyProcessor=JSON when request.contentType is absent (wave-8)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api/nobody', { authentication: { type: 'bearer-jwt' } })
    );
    const joined = rules.join('\n');
    assert.doesNotMatch(joined, /ctl:requestBodyProcessor=JSON/);
  });

  it('emits B1 identity rules when authorization.roles is single-entry (BFLA pair)', () => {
    // Was previously asserted as a no-op; B1 lifted authorization.roles into
    // identity-aware SecRule emission (BFLA missing-principal + non-role pair).
    const rules = buildPolicyRules(
      ep('GET', '/x', { authorization: { type: 'rbac', roles: ['admin'] } })
    );
    // scope marker + 2 BFLA siblings.
    assert.equal(rules.length, 3);
    assert.match(rules[0]!, /SecAction/);
    const text = rules.join('\n');
    assert.match(text, /writ\/b1\/bfla/);
  });
});

describe('coraza: capabilities()', () => {
  it('declares CORS/mtls/cacheable as unsupported', () => {
    const caps = corazaGenerator.capabilities();
    assert.equal(caps.fields['cors'], 'unsupported');
    assert.equal(caps.fields['mtls'], 'unsupported');
    assert.equal(caps.fields['cacheable'], 'unsupported');
    assert.equal(caps.fields['timeout'], 'unsupported');
  });

  it('declares request.maxBodySize and ipPolicy as full', () => {
    const caps = corazaGenerator.capabilities();
    assert.equal(caps.fields['request.maxBodySize'], 'full');
    assert.equal(caps.fields['ipPolicy.allow'], 'full');
    assert.equal(caps.fields['ipPolicy.deny'], 'full');
  });

  it('declares rateLimit as partial (TX downgrade loses cross-request persistence)', () => {
    // wave-5: profiles.ts legalCollections corrected to {tx} only — Coraza v3
    // setvar only accepts TX. Rate-limit emission still happens, but the
    // counter is per-transaction so cross-request enforcement is not provided
    // by Coraza itself (operator must front it with HAProxy stick-tables).
    // The capability is honestly downgraded to 'partial' to reflect that.
    assert.equal(corazaGenerator.capabilities().fields['rateLimit'], 'partial');
  });
});

describe('coraza: rate-limit identifier modes', () => {
  // wave-5: profiles.ts legalCollections corrected to {tx} only — Coraza v3
  // setvar only accepts TX. All identifier modes (ip / user-id / api-key /
  // header:X) on the default coraza-go profile now downgrade to TX with a
  // loud warning. These assertions previously encoded the latent bug.
  it('identifier=ip keeps TX-downgrade (Coraza-Go setvar TX-only at runtime, W10-7)', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 10, window: '30s', identifier: 'ip' } })
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REMOTE_ADDR\}/);
    assert.match(j, /setvar:tx\.rl_post__x=\+1/);
    assert.match(j, /SecRule TX:rl_post__x "@gt 10"/);
    assert.match(j, /expirevar:tx\.rl_post__x=30/);
  });

  it('identifier=user-id keys tx by Authorization header (downgraded from user)', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { rateLimit: { requests: 30, window: '1m', identifier: 'user-id' } })
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.Authorization\}/);
    assert.match(j, /setvar:tx\.rl_get__x=\+1/);
    assert.match(j, /SecRule TX:rl_get__x "@gt 30"/);
    assert.doesNotMatch(j, /initcol:user=/);
    assert.doesNotMatch(j, /initcol:ip=/);
  });

  it('identifier=api-key keys tx by X-API-Key header (downgraded from user)', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { rateLimit: { requests: 100, window: '1h', identifier: 'api-key' } })
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.X-API-Key\}/);
    assert.match(j, /setvar:tx\.rl_get__x=\+1/);
    assert.match(j, /SecRule TX:rl_get__x "@gt 100"/);
    assert.match(j, /expirevar:tx\.rl_get__x=3600/);
  });

  it('identifier=header:X-Tenant-Id parameterises the header name (tx collection)', () => {
    const rules = buildPolicyRules(
      ep('GET', '/x', { rateLimit: { requests: 50, window: '5m', identifier: 'header:X-Tenant-Id' } })
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.X-Tenant-Id\}/);
    assert.match(j, /SecRule TX:rl_get__x "@gt 50"/);
    assert.match(j, /expirevar:tx\.rl_get__x=300/);
  });

  it('emits a second 1-second burst counter when burst is set', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'ip', burst: 2 } })
    );
    const j = rules.join('\n');
    // primary counter (TX downgrade — Coraza-Go runtime setvar TX-only)
    assert.match(j, /setvar:tx\.rl_post__x=\+1/);
    assert.match(j, /expirevar:tx\.rl_post__x=60/);
    assert.match(j, /SecRule TX:rl_post__x "@gt 5"/);
    // burst counter
    assert.match(j, /setvar:tx\.rl_post__x_burst=\+1/);
    assert.match(j, /expirevar:tx\.rl_post__x_burst=1/);
    assert.match(j, /SecRule TX:rl_post__x_burst "@gt 2"/);
    assert.match(j, /burst exceeded \(2\/1s\)/);
  });

  it('does NOT emit a burst counter when burst is absent', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'ip' } })
    );
    const j = rules.join('\n');
    assert.doesNotMatch(j, /_burst/);
    assert.doesNotMatch(j, /burst exceeded/);
  });

  it('parses window units (10s, 1m, 5m, 1h) into seconds', () => {
    const cases: Array<[string, number]> = [
      ['10s', 10],
      ['1m', 60],
      ['5m', 300],
      ['1h', 3600],
    ];
    for (const [w, sec] of cases) {
      const rules = buildPolicyRules(
        ep('GET', '/x', { rateLimit: { requests: 1, window: w, identifier: 'ip' } })
      );
      const j = rules.join('\n');
      assert.match(j, new RegExp(`expirevar:tx\\.rl_get__x=${sec}\\b`), `window ${w} → ${sec}s`);
    }
  });

  it('allocates distinct IDs for multiple rate-limit entries on one endpoint', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', {
        rateLimit: [
          { requests: 5, window: '1m', identifier: 'ip' },
          { requests: 100, window: '1h', identifier: 'user-id' },
        ],
      })
    );
    const j = rules.join('\n');
    // Collect all ids:NNNN tokens
    const ids = Array.from(j.matchAll(/id:(\d+)/g)).map((m) => Number(m[1]));
    const uniq = new Set(ids);
    assert.equal(ids.length, uniq.size, 'all emitted rule IDs must be unique');
    // Both entries downgrade to TX (Coraza-Go setvar TX-only at runtime).
    assert.match(j, /initcol:tx=%\{REMOTE_ADDR\}/);
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.Authorization\}/);
  });
});

describe('coraza: generate() against example fixture', () => {
  it('produces a coraza.yml artifact + WARNINGS.md (TX downgrade)', async () => {
    // wave-5: the example fixture uses identifier=ip and identifier=user-id,
    // both of which now downgrade to the TX collection (Coraza v3 setvar limit)
    // and emit a WARNINGS.md alongside coraza.yml. Both files are expected output.
    const spec = await loadExample();
    const arts = await corazaGenerator.generate(spec);
    const yml = arts.find((a) => a.path === 'coraza.yml');
    assert.ok(yml, 'must emit coraza.yml');
    assert.equal(yml!.format, 'yaml');
    const warn = arts.find((a) => a.path === 'WARNINGS.md');
    assert.ok(warn, 'must emit WARNINGS.md when downgrades occurred');
  });

  it('includes engine globals and per-endpoint blocks', async () => {
    const spec = await loadExample();
    const [art] = await corazaGenerator.generate(spec);
    const yml = art!.content;
    assert.match(yml, /SecRuleEngine On/);
    assert.match(yml, /SecRequestBodyLimit /);
    assert.match(yml, /POST \/api\/auth\/login/);
    assert.match(yml, /GET \/api\/admin\/users/);
    assert.match(yml, /POST \/api\/files\/upload/);
  });

  it('embeds metadata header', async () => {
    const spec = await loadExample();
    const [art] = await corazaGenerator.generate(spec);
    assert.match(art!.content, /generator: writ-coraza/);
    assert.match(art!.content, /source:/);
  });

  it('uses smallest maxBodySize as global SecRequestBodyLimit (10KB)', async () => {
    const spec = await loadExample();
    const [art] = await corazaGenerator.generate(spec);
    // login=10KB(10240), upload=50MB(52428800) → expect 10240
    assert.match(art!.content, /SecRequestBodyLimit 10240/);
  });

  it('matches golden snapshot', async () => {
    const spec = await loadExample();
    const [art] = await corazaGenerator.generate(spec);
    const expected = await readFile(GOLDEN, 'utf8');
    assert.equal(art!.content, expected);
  });
});

// ---------- C-1: response-body inspection (API3 BOPLA) ----------
import { buildResponseInspectionRules } from '../../src/generators/coraza/rules.ts';
import {
  MODSEC_NGINX_PROFILE,
  CORAZA_SPOA_PROFILE,
} from '../../src/generators/coraza/profiles.ts';
import type { EngineWarning } from '../../src/generators/coraza/profiles.ts';

describe('coraza C-1: response-body inspection', () => {
  it('emits phase-4 SecRule for response.schema.<field>.maxLength', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('POST', '/api/auth/login', {
        response: { schema: { token: { type: 'string', maxLength: 2048 } } },
      }),
      MODSEC_NGINX_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    // phase:4 + deny on the maxLength path
    assert.match(joined, /phase:4/);
    assert.match(joined, /status:500/);
    assert.match(joined, /response\.token exceeds maxLength=2048/);
    // The leak regex inspects RESPONSE_BODY for a long token value
    assert.match(joined, /RESPONSE_BODY "@rx \\"token\\"\\s\*:\\s\*\\"\[\^\\"\]\{2049,\}\\""/);
    // Writ API3/BOPLA tag must be present so verify-readers can grep audit logs.
    assert.match(joined, /writ-api3-bopla/);
    // Cost-of-doing-business warning surfaced.
    assert.ok(warnings.some((w) => w.severity === 'downgrade' && /response inspection/.test(w.reason)));
  });

  it('emits deny-on-unknown rule + structured warning for response.stripUnknownFields', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', {
        response: {
          stripUnknownFields: true,
          schema: { id: { type: 'integer' }, text: { type: 'string' } },
        },
      }),
      MODSEC_NGINX_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    assert.match(joined, /phase:4/);
    assert.match(joined, /undeclared field \(stripUnknownFields\)/);
    // Negative-lookahead over the declared key set:
    assert.match(joined, /\(\?\!\(\?:id\|text\)/);
    // The structured warning explains the deny-vs-strip downgrade.
    assert.ok(
      warnings.some(
        (w) =>
          w.severity === 'downgrade' &&
          /stripUnknownFields/.test(w.reason) &&
          /Lua\/SPOA-side transformer/.test(w.reason)
      ),
      'expected a downgrade warning explaining no native strip support'
    );
  });

  it('skips emission + warns when profile.supportsResponseBodyAccess is false', () => {
    const warnings: EngineWarning[] = [];
    const fakeProfile = {
      ...MODSEC_NGINX_PROFILE,
      supportsResponseBodyAccess: false,
    };
    const rules = buildResponseInspectionRules(
      ep('GET', '/x', { response: { schema: { token: { maxLength: 100 } } } }),
      fakeProfile,
      warnings
    );
    assert.equal(rules.length, 0);
    assert.ok(warnings.some((w) => w.severity === 'skip' && /SecResponseBodyAccess/.test(w.reason)));
  });

  it('coraza-spoa profile still emits the rule + the perf-cost downgrade warning fires', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', { response: { schema: { secret: { maxLength: 256 } } } }),
      CORAZA_SPOA_PROFILE,
      warnings
    );
    assert.ok(rules.length >= 1);
    assert.match(rules.join('\n'), /phase:4/);
    const downgrade = warnings.find((w) => w.severity === 'downgrade');
    assert.ok(downgrade, 'expected perf-cost downgrade warning');
    assert.match(downgrade!.reason, /SPOE round-trip|throughput cost/);
    assert.equal(downgrade!.engine, 'coraza-spoa');
  });

  it('emits SecResponseBodyAccess On in engine globals when at least one endpoint declares response.schema', async () => {
    const spec = await loadExample();
    const [art] = await corazaGenerator.generate(spec);
    // The example spec has response.schema.token.maxLength=2048 on the login
    // endpoint, so engine globals must toggle response body access on.
    assert.match(art!.content, /SecResponseBodyAccess On/);
    assert.match(art!.content, /SecResponseBodyMimeType application\/json/);
  });

  it('capability matrix declares response.schema/stripUnknownFields as partial on engines that support it', () => {
    const caps = corazaGenerator.capabilities();
    assert.equal(caps.fields['response.schema'], 'partial');
    assert.equal(caps.fields['response.stripUnknownFields'], 'partial');
    assert.equal(caps.fields['response'], 'partial');
  });
});

// ---------- W10-1: RE2-safe pattern emission (no negative lookahead) ----------
describe('coraza W10-1: response.schema.<field>.pattern uses RE2-safe capture + inverse-rx', () => {
  it('emits a capture rule that extracts the field value into TX:writ_<field>', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', { response: { schema: { text: { type: 'string', pattern: '^[A-Za-z0-9 ]+$' } } } }),
      CORAZA_SPOA_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    // Rule A: capture into TX
    assert.match(joined, /capture,setvar:tx\.writ_text=%\{TX\.1\}/);
    // The capture rule is a pass+nolog scan that does NOT deny on its own.
    assert.match(joined, /phase:4,pass,nolog/);
    // No negative lookahead — RE2 doesn't support it.
    assert.doesNotMatch(joined, /\(\?!/);
  });

  it('emits a deny rule using !@rx against the captured TX variable (no lookahead)', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', { response: { schema: { text: { pattern: '^[A-Za-z0-9 ]+$' } } } }),
      CORAZA_SPOA_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    // Rule B: deny when the captured value does NOT match the required pattern.
    assert.match(joined, /SecRule TX:writ_text "!@rx \^\[A-Za-z0-9 \]\+\$"/);
    assert.match(joined, /phase:4,deny,status:500/);
    assert.match(joined, /response\.text pattern mismatch \(data exposure\)/);
    assert.match(joined, /writ-api3-bopla/);
  });

  it('emits no SecRule when response.schema has no enforceable constraint (defense-in-depth check)', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', { response: { schema: { id: { type: 'integer' } } } }),
      CORAZA_SPOA_PROFILE,
      warnings
    );
    // type: integer has no maxLength/pattern constraint — nothing to inspect.
    assert.equal(rules.length, 0);
    assert.equal(warnings.length, 0);
  });

  it('stripUnknownFields: emits skip warning on RE2 engines (coraza-go/spoa)', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildResponseInspectionRules(
      ep('GET', '/api3/comment', {
        response: { stripUnknownFields: true, schema: { id: { type: 'integer' }, text: { type: 'string' } } },
      }),
      CORAZA_SPOA_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    // No lookahead anywhere in the emitted output.
    assert.doesNotMatch(joined, /\(\?!/);
    // Skip warning explains the RE2 limitation.
    assert.ok(
      warnings.some((w) => w.severity === 'skip' && /RE2-backed/.test(w.reason)),
      'expected a skip warning when stripUnknownFields hits a RE2-backed engine'
    );
  });
});

// ---------- W10-7: cross-request rate-limit (TX-downgrade + loud warning) ----------
import { CORAZA_GO_PROFILE } from '../../src/generators/coraza/profiles.ts';

describe('coraza W10-7: cross-request rate-limit honest-downgrade behavior', () => {
  it('coraza-go: identifier=ip emits TX-downgrade (runtime setvar TX-only)', () => {
    // Verified empirically: ghcr.io/corazawaf/coraza-spoa rejects setvar:ip.X
    // with "expected collection TX". Cross-request enforcement is NOT possible
    // through Coraza alone — we keep the TX form and warn loudly.
    const warnings: EngineWarning[] = [];
    const rules = buildPolicyRules(
      ep('POST', '/login', { rateLimit: { requests: 5, window: '1m', identifier: 'ip' } }),
      CORAZA_GO_PROFILE,
      warnings as never
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REMOTE_ADDR\}/);
    assert.match(j, /setvar:tx\.rl_post__login=\+1/);
    assert.match(j, /SecRule TX:rl_post__login "@gt 5"/);
    // Loud per-endpoint TX-downgrade warning fires.
    assert.ok(warnings.some((w) => /TX collection/.test(w.reason)));
  });

  it('expirevar TTL matches the configured window', () => {
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 1, window: '5m', identifier: 'ip' } }),
      CORAZA_GO_PROFILE
    );
    assert.match(rules.join('\n'), /expirevar:tx\.rl_post__x=300\b/);
  });

  it('identity-keyed counters (user-id) also downgrade to TX on coraza-go', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'user-id' } }),
      CORAZA_GO_PROFILE,
      warnings as never
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.Authorization\}/);
    assert.ok(warnings.some((w) => /TX collection/.test(w.reason)));
  });

  it('top-level cross-request warning fires once per generator run for coraza-spoa', async () => {
    const spec: SpecIR = {
      info: { title: 't', version: '1' },
      endpoints: [
        ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'ip' } }),
        ep('POST', '/y', { rateLimit: { requests: 10, window: '1m', identifier: 'ip' } }),
      ],
      servers: [],
    };
    const { createCorazaGenerator } = await import('../../src/generators/coraza/index.js');
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(spec) as Array<{ path: string; content: string }>;
    const warn = arts.find((a) => a.path === 'WARNINGS.md');
    assert.ok(warn, 'must emit WARNINGS.md');
    // The loud per-endpoint TX-downgrade warnings include the HAProxy
    // stick-tables recommendation.
    assert.match(warn!.content, /HAProxy stick-tables/);
  });
});

// ---------- W19: injectionGuard-driven enforcement (was W10-8 SQLi heuristic) ----------
import { buildSqliHeuristics } from '../../src/generators/coraza/rules.ts';

describe('coraza W19: per-arg injectionGuard enforcement (query + JSON body)', () => {
  it('emits @detectSQLi for fields declaring injectionGuard:[sql] (not for bare string fields)', () => {
    const rules = buildSqliHeuristics(
      ep('POST', '/api8/user/login', {
        request: {
          contentType: ['application/json'],
          schema: {
            username: { type: 'string', injectionGuard: ['sql'], minLength: 3 },
            password: { type: 'string', injectionGuard: ['sql'] },
          },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    const j = rules.join('\n');
    // Selector targets BOTH query/form (ARGS:<field>) and JSON body (ARGS:json.<field>).
    assert.match(j, /SecRule ARGS:username\|ARGS:json\.username "@detectSQLi"/);
    assert.match(j, /SecRule ARGS:password\|ARGS:json\.password "@detectSQLi"/);
    assert.match(j, /status:403/);
    assert.match(j, /writ-injection-sqli/);
    assert.match(j, /SQL injection detected in username/);
  });

  it('emits @detectXSS for fields declaring injectionGuard:[xss]', () => {
    const rules = buildSqliHeuristics(
      ep('GET', '/render', {
        request: {
          schema: { comment: { type: 'string', injectionGuard: ['xss'] } },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    const j = rules.join('\n');
    assert.match(j, /SecRule ARGS:comment\|ARGS:json\.comment "@detectXSS"/);
    assert.match(j, /writ-injection-xss/);
    assert.match(j, /XSS detected in comment/);
  });

  it('emits a distinct enforcing rule per declared sink', () => {
    const rules = buildSqliHeuristics(
      ep('POST', '/api/search', {
        request: {
          contentType: ['application/json'],
          schema: {
            q: { type: 'string', injectionGuard: ['sql', 'nosql'] },
            cmd: { type: 'string', injectionGuard: ['os-command', 'code-eval'] },
            f: { type: 'string', injectionGuard: ['xpath', 'ldap', 'xss'] },
          },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    const j = rules.join('\n');
    // 7 sinks → 7 rules.
    assert.equal(rules.length, 7);
    assert.match(j, /SecRule ARGS:q\|ARGS:json\.q "@detectSQLi"/);                       // sql
    assert.match(j, /SecRule ARGS:q\|ARGS:json\.q "@rx \(\?i\)\\\$\(\?:where\|gt/);       // nosql operator tokens
    assert.match(j, /SecRule ARGS:cmd\|ARGS:json\.cmd "!@rx \^\[\^;\|&\$/);               // os-command metachar allowlist
    assert.match(j, /SecRule ARGS:f\|ARGS:json\.f "@detectXSS"/);                         // xss
    assert.match(j, /writ-injection-os-command/);
    assert.match(j, /writ-injection-code-eval/);
    assert.match(j, /writ-injection-xpath/);
    assert.match(j, /writ-injection-ldap/);
    assert.match(j, /writ-injection-xss/);
    // Every emitted rule carries the Writ-native injection tag.
    assert.equal((j.match(/tag:'writ-injection'/g) ?? []).length, 7);
  });

  it('does NOT emit for string fields lacking injectionGuard (no blanket FP surface)', () => {
    const rules = buildSqliHeuristics(
      ep('POST', '/api8/user/login', {
        request: {
          contentType: ['application/json'],
          schema: { username: { type: 'string', minLength: 3 }, password: { type: 'string' } },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    assert.equal(rules.length, 0);
  });

  it('emits for query/form args regardless of content-type (not JSON-gated)', () => {
    // No content-type (query-param endpoint, e.g. ?parameters= RCE) → still emits.
    const r1 = buildSqliHeuristics(
      ep('GET', '/admin/stats/disk', {
        request: { schema: { parameters: { type: 'string', injectionGuard: ['os-command'] } } },
      }),
      CORAZA_SPOA_PROFILE
    );
    assert.equal(r1.length, 1);
    assert.match(r1.join('\n'), /SecRule ARGS:parameters\|ARGS:json\.parameters "!@rx/);
    // Non-JSON (form-encoded) content-type → still emits.
    const r2 = buildSqliHeuristics(
      ep('POST', '/x', {
        request: {
          contentType: ['application/x-www-form-urlencoded'],
          schema: { a: { type: 'string', injectionGuard: ['sql'] } },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    assert.equal(r2.length, 1);
    assert.match(r2.join('\n'), /SecRule ARGS:a\|ARGS:json\.a "@detectSQLi"/);
    // No schema → still nothing to guard.
    const r3 = buildSqliHeuristics(
      ep('POST', '/x', { request: { contentType: ['application/json'] } }),
      CORAZA_SPOA_PROFILE
    );
    assert.equal(r3.length, 0);
  });

  it('skips the xss sink (does not placeholder) on a profile lacking @detectXSS', () => {
    const noXssProfile = { ...CORAZA_SPOA_PROFILE, supportsDetectXSS: false };
    const rules = buildSqliHeuristics(
      ep('POST', '/x', {
        request: {
          contentType: ['application/json'],
          schema: { c: { type: 'string', injectionGuard: ['xss', 'sql'] } },
        },
      }),
      noXssProfile
    );
    const j = rules.join('\n');
    // sql still emits; xss is skipped, never placeholdered (Rule D-1).
    assert.equal(rules.length, 1);
    assert.match(j, /@detectSQLi/);
    assert.doesNotMatch(j, /@detectXSS/);
  });
});

describe('coraza W10-9: ssrf-policy-missing warning', () => {
  it('fires when type=url param lacks domainAllowlist + blockPrivateRanges', () => {
    const spec: SpecIR = {
      openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
      servers: [], unprotectedEndpoints: [],
      endpoints: [
        {
          operationId: 'redir', method: 'GET', path: '/redirect',
          parameters: [], resolvedVars: new Map(), raw: {} as any,
          policy: { request: { schema: { url: { type: 'url' } } } } as XSecurityPolicy
        } as EndpointIR
      ]
    };
    corazaGenerator.generate(spec);
    const joined = corazaGenerator.lastWarnings.join('\n');
    assert.match(joined, /\[coraza:ssrf-policy-missing\] GET \/redirect/);
    assert.match(joined, /parameter "url"/);
  });

  it('does not fire when domainAllowlist is set', () => {
    const spec: SpecIR = {
      openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
      servers: [], unprotectedEndpoints: [],
      endpoints: [
        {
          operationId: 'redir', method: 'GET', path: '/redirect',
          parameters: [], resolvedVars: new Map(), raw: {} as any,
          policy: { request: { schema: { url: { type: 'url', domainAllowlist: ['api.example.com'] } } } } as XSecurityPolicy
        } as EndpointIR
      ]
    };
    corazaGenerator.generate(spec);
    assert.equal(
      corazaGenerator.lastWarnings.filter((w) => w.includes('ssrf-policy-missing')).length,
      0
    );
  });
});

describe('coraza W19-A: SSRF url-allowlist SecRule emission', () => {
  it('emits id:980000+ deny + writ-rule-ssrf-403 tag when domainAllowlist set', () => {
    const rules = buildPolicyRules(
      ep('GET', '/vapi/serversurfer', {
        request: { schema: { url: { type: 'url', domainAllowlist: ['roottusk.com'] } } }
      })
    );
    const text = rules.join('\n');
    assert.match(text, /id:98\d{4}/, 'must emit a rule id in the 980000 SSRF range');
    assert.match(text, /tag:'writ-rule-ssrf-403'/);
    // The allowlist regex anchors after scheme and only accepts roottusk.com.
    assert.match(text, /SecRule ARGS:url "!@rx/);
    assert.match(text, /roottusk/);
  });

  it('emits private-range guard with writ-rule-ssrf-private-403 tag when blockPrivateRanges:true', () => {
    const rules = buildPolicyRules(
      ep('POST', '/api/fetch', {
        request: { schema: { url: { type: 'url', blockPrivateRanges: true } } }
      })
    );
    const text = rules.join('\n');
    assert.match(text, /tag:'writ-rule-ssrf-private-403'/);
    // Private-range regex must include canonical RFC1918 + loopback + internal-only.
    // W22-B: single-backslash literal `\.` (not double) — libmodsec3/Coraza
    // pass @rx args verbatim to the regex compiler; doubling backslashes
    // turns `\.` into "literal backslash + dot" and breaks every match.
    assert.match(text, /127\\\./);
    assert.match(text, /169\\\.254/);
    assert.match(text, /internal-only/);
  });

  /**
   * W21-B / W22-B regression: the SSRF private-host regex must compile
   * cleanly inside libmodsec3 / Coraza. Historical bug (W21-B): IPv6 bracket
   * emitted as `\[` collapsed under an assumed parser unescape pass, so we
   * defensively used `[\[]` (single-char class). W22-B re-investigation found
   * the parser does NOT actually unescape @rx args — libmodsec3 / Coraza pass
   * the literal bytes straight to the regex compiler — so the regex shipped
   * with the OLD double-backslash emission (`\\.` → matched a literal
   * backslash) but the IPv6 char class `[\[]` survived because RE2 reads
   * `[\\[]` as "char class containing `\` and `[`" which is still a closed
   * class. Switching to single-backslash emission keeps the regex correct
   * and now matches the IPs we declared.
   */
  it('W21-B/W22-B: private-host SecRule regex is well-formed (parens balance, compiles, matches expected IPs)', () => {
    const rules = buildPolicyRules(
      ep('GET', '/vapi/serversurfer', {
        request: { schema: { url: { type: 'url', blockPrivateRanges: true } } }
      })
    );
    const text = rules.join('\n');
    // Extract the private-range SecRule line.
    const line = text
      .split('\n')
      .find((l) => l.includes('SecRule ARGS:') && l.includes('@rx') && l.includes('fe80'));
    assert.ok(line, 'private-host SecRule line must exist');
    // Pull out just the @rx <regex> argument value (inside the first quoted pair).
    const m = /"@rx\s+([^"]+)"/.exec(line!);
    assert.ok(m, 'must find @rx arg in SecRule line');
    const emittedArg = m![1]!;
    // Paren count must balance on the emitted literal — libmodsec3 / Coraza
    // compile the arg verbatim, no unescape pass.
    const opens = (emittedArg.match(/\(/g) ?? []).length;
    const closes = (emittedArg.match(/\)/g) ?? []).length;
    assert.equal(opens, closes, `paren mismatch in emitted regex: opens=${opens} closes=${closes}`);
    // The regex must compile as a JS RegExp (close-enough proxy for RE2 /
    // PCRE syntax health). Drop the `(?i)` inline flag prefix since JS
    // RegExp doesn't accept it mid-pattern; replicate via the `i` flag.
    const jsPattern = emittedArg.replace(/^\(\?i\)/, '');
    let compiled: RegExp;
    assert.doesNotThrow(
      () => { compiled = new RegExp(jsPattern, 'i'); },
      `emitted regex must compile; got: ${emittedArg}`
    );
    // W22-B: the regex must actually match the canonical private-range probes
    // the corpus uses. Single-backslash emission is what makes this true.
    const c = new RegExp(jsPattern, 'i');
    assert.ok(c.test('http://10.0.0.1/x'), 'must match 10.0.0.1');
    assert.ok(c.test('http://127.0.0.1/x'), 'must match 127.0.0.1');
    assert.ok(c.test('http://169.254.169.254/x'), 'must match link-local 169.254/16');
    assert.ok(c.test('http://internal-only/x'), 'must match the internal-only hostname');
  });

  /**
   * W22-A regression: the SSRF chain rules must inspect REQUEST_FILENAME
   * (path-only), NOT REQUEST_URI. coraza-spoa's REQUEST_URI is set to
   * `parsedURL.String()` — i.e. path + "?" + query — so an anchored
   * `^/vapi/serversurfer$` rx never matches the very `?url=...` request
   * the SSRF rule is meant to inspect. Live-confirmed against
   * chain-coraza-spoa-vapi: with REQUEST_URI the WAF passed every
   * private-host probe (10.0.0.1, internal-only, 169.254.169.254);
   * with REQUEST_FILENAME all three returned 403 from ruleid=980498.
   * (See /tmp/vapi-test/fixes/v22-coraza-args-runtime.md.)
   */
  it('W22-A: SSRF chain anchors on REQUEST_FILENAME (path-only), not REQUEST_URI', () => {
    const rules = buildPolicyRules(
      ep('GET', '/vapi/serversurfer', {
        request: {
          schema: {
            url: {
              type: 'url',
              domainAllowlist: ['roottusk.com'],
              blockPrivateRanges: true,
            },
          },
        },
      })
    );
    const text = rules.join('\n');
    // Locate the SSRF allowlist + private-range blocks (id range 98xxxx).
    const ssrfLines = text
      .split('\n')
      .filter((l) => /^\s*SecRule\s+REQUEST_(FILENAME|URI)\s+"@rx\s+\^\/vapi\/serversurfer/.test(l));
    assert.ok(ssrfLines.length >= 2, 'must emit both allowlist and private-range chain anchor lines');
    for (const line of ssrfLines) {
      assert.match(
        line,
        /SecRule REQUEST_FILENAME/,
        `SSRF chain anchor must use REQUEST_FILENAME, not REQUEST_URI; got: ${line.trim()}`
      );
    }
  });
});

describe('coraza B1: identity-aware authz (BOLA/BFLA) SecRule emission', () => {
  // Mirror the W13-C identity-conf shape that the chain fixture stitches in.
  // Slot allocation is endpoint-hash keyed inside 970000-979999; we assert on
  // the offset pattern (+10/+11/+20/+21) and the chain structure, not the
  // exact base slot.
  it('emits BOLA-read (GET, offset +10) when authorization.rules binds path.id == principal.id', () => {
    const rules = buildPolicyRules(
      ep('GET', '/api1/user/{id}', {
        authorization: {
          type: 'rule-based',
          rules: [
            { field: 'request.params.id', operator: 'equals', value: { ref: 'principal.id' } },
          ],
        },
      })
    );
    const text = rules.join('\n');
    assert.match(text, /id:97\d{4}/, 'must emit a rule id in the 9700xx identity range');
    assert.match(text, /id:97\d{2}10,/, 'BOLA-read offset is +10 within the slot');
    assert.match(text, /Writ B1: BOLA-read denied/);
    assert.match(text, /tag:'writ\/b1\/bola-read'/);
    assert.match(text, /SecRule REQUEST_METHOD "@streq GET"/);
    assert.match(text, /SecRule REQUEST_URI "@rx \^\(\?:\/\[\^\/\]\+\)\?\/api1\/user\/\(\[\^\/\?\]\+\)\(\?:\[\/\?\]\|\$\)"/);
    assert.match(text, /"capture,chain"/);
    assert.match(text, /SecRule TX:1 "!@streq %\{REQUEST_HEADERS\.X-Forwarded-User\}"/);
  });

  it('emits BOLA-update (PUT, offset +11) for the same primitive', () => {
    const rules = buildPolicyRules(
      ep('PUT', '/api1/user/{id}', {
        authorization: {
          type: 'rule-based',
          rules: [
            { field: 'request.params.id', operator: 'equals', value: { ref: 'jwt.sub' } },
          ],
        },
      })
    );
    const text = rules.join('\n');
    assert.match(text, /id:97\d{2}11,/, 'BOLA-update offset is +11 within the slot');
    assert.match(text, /Writ B1: BOLA-update denied/);
    assert.match(text, /tag:'writ\/b1\/bola-update'/);
    assert.match(text, /SecRule REQUEST_METHOD "@streq PUT"/);
  });

  it('emits BFLA pair (offsets +20 / +21) when authorization.roles=[\"admin\"]', () => {
    const rules = buildPolicyRules(
      ep('GET', '/api5/users', {
        authorization: { type: 'rbac', roles: ['admin'] },
      })
    );
    const text = rules.join('\n');
    // Missing-principal sibling.
    assert.match(text, /id:97\d{2}20,/, 'BFLA-missing offset is +20');
    assert.match(text, /Writ B1: BFLA denied \(admin-only route, no authenticated principal\)/);
    assert.match(text, /&REQUEST_HEADERS:X-Forwarded-User "@eq 0"/);
    // Non-admin sibling.
    assert.match(text, /id:97\d{2}21,/, 'BFLA-non-role offset is +21');
    assert.match(text, /Writ B1: BFLA denied \(admin-only route, non-admin principal\)/);
    assert.match(text, /REQUEST_HEADERS:X-Forwarded-User "!@streq admin"/);
    // Path anchor must tolerate optional gateway prefix and trailing /, ?, $.
    assert.match(text, /SecRule REQUEST_URI "@rx \^\(\?:\/\[\^\/\]\+\)\?\/api5\/users\(\?:\[\/\?\]\|\$\)"/);
  });

  it('emits nothing when authorization is absent', () => {
    const rules = buildPolicyRules(ep('GET', '/api/public', {}));
    const text = rules.join('\n');
    assert.doesNotMatch(text, /id:97\d{4}/);
  });

  it('emits nothing for BFLA when roles has != 1 entry (multi-role needs upstream resolution)', () => {
    const rules = buildPolicyRules(
      ep('GET', '/api5/users', {
        authorization: { type: 'rbac', roles: ['admin', 'auditor'] },
      })
    );
    const text = rules.join('\n');
    assert.doesNotMatch(text, /writ\/b1\/bfla/);
  });

  it('emits both BOLA and BFLA when an endpoint declares ownership AND role gate', () => {
    const rules = buildPolicyRules(
      ep('PUT', '/api3/user/{id}/role', {
        authorization: {
          type: 'rbac',
          roles: ['admin'],
          rules: [
            { field: 'request.params.id', operator: 'equals', value: { ref: 'principal.id' } },
          ],
        },
      })
    );
    const text = rules.join('\n');
    // PUT → BOLA-update (+11) AND BFLA pair (+20, +21).
    assert.match(text, /id:97\d{2}11,/);
    assert.match(text, /id:97\d{2}20,/);
    assert.match(text, /id:97\d{2}21,/);
  });

  it('preserves the W13-C identity rule shape (chain count, IDs in 9700xx)', () => {
    // Sanity: the four W13-C rule offsets (+10/+11/+20/+21) all land inside
    // the 9700xx range the attribution table expects (id:970 prefix). The
    // scorer's intent-attribution matches against the leading "id:970",
    // so any base slot in 970000-979999 with offset <= 99 keeps the match.
    const rules = buildPolicyRules(
      ep('GET', '/api1/user/{id}', {
        authorization: {
          type: 'rule-based',
          rules: [
            { field: 'request.params.id', operator: 'equals', value: { ref: 'principal.id' } },
          ],
        },
      })
    );
    const text = rules.join('\n');
    const ids = (text.match(/id:97\d{4}/g) ?? []);
    assert.ok(ids.length >= 1, 'must emit at least one identity rule id');
    for (const id of ids) {
      const n = Number(id.slice(3));
      assert.ok(n >= 970000 && n < 980000, `identity id ${id} must lie in 9700xx range`);
    }
  });
});
