import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileVirtualPatch, VirtualPatchCompileError } from '../src/index.js';

const baseOpts = {
  mode: 'log' as const,
  ruleName: 'writ-cve',
  cveId: 'CVE-2021-44228',
  writRuleId: 'writ-cve-log4shell-abc123',
};

test('compileVirtualPatch: request-uri-denylist emits Custom Rule with uri.path matches', () => {
  const out = compileVirtualPatch(
    {
      shape: 'request-uri-denylist',
      description: 'Block JNDI lookup paths',
      pattern: '\\$\\{jndi:',
    },
    baseOpts,
  );
  assert.equal(out.type, 'customRule');
  assert.equal(out.rule.expression, '(http.request.uri.path matches "\\$\\{jndi:")');
  assert.equal(out.rule.action, 'log');
  assert.equal(out.rule.id, baseOpts.writRuleId);
  assert.ok(out.rule.description.includes('CVE-CVE-2021-44228: virtual patch'));
  assert.equal(out.rule.writ.rule_type, 'cve-uri-denylist');
});

test('compileVirtualPatch: request-header-denylist emits header expression with lowercased name', () => {
  const out = compileVirtualPatch(
    {
      shape: 'request-header-denylist',
      description: 'Block JNDI in user-agent',
      headerName: 'User-Agent',
      pattern: '\\$\\{jndi:',
    },
    baseOpts,
  );
  assert.equal(out.type, 'customRule');
  assert.equal(
    out.rule.expression,
    '(http.request.headers["user-agent"][0] matches "\\$\\{jndi:")',
  );
});

test('compileVirtualPatch: request-body-pattern emits body.raw expression with body-inspection warning', () => {
  const out = compileVirtualPatch(
    {
      shape: 'request-body-pattern',
      description: 'Block Spring4Shell class loader',
      pattern: 'class\\.module\\.classLoader',
    },
    baseOpts,
  );
  assert.equal(out.type, 'customRule');
  assert.equal(
    out.rule.expression,
    '(http.request.body.raw matches "class\\.module\\.classLoader")',
  );
  assert.ok(out.warnings && out.warnings.length > 0);
  assert.match(out.warnings![0]!, /Pro plan/i);
});

test('compileVirtualPatch: tighten-body-size emits body.size gt <bytes>', () => {
  const out = compileVirtualPatch(
    { shape: 'tighten-body-size', description: 'Cap body to 8KB', maxBodySize: '8KB' },
    baseOpts,
  );
  assert.equal(out.type, 'customRule');
  assert.equal(out.rule.expression, '(http.request.body.size gt 8192)');
  assert.equal(out.rule.writ.rule_type, 'cve-body-size');
});

test('compileVirtualPatch: tighten-rate-limit emits rateLimitRule (not customRule)', () => {
  const out = compileVirtualPatch(
    {
      shape: 'tighten-rate-limit',
      description: 'Cap to 30/min per IP',
      rateLimit: { requests: 30, window: '1m' },
    },
    baseOpts,
  );
  assert.equal(out.type, 'rateLimitRule');
  assert.ok(out.rule.ratelimit, 'ratelimit block present');
  assert.equal(out.rule.ratelimit!.requests_per_period, 30);
  assert.equal(out.rule.ratelimit!.period, 60);
  assert.deepEqual(out.rule.ratelimit!.characteristics, ['ip.src']);
});

test('compileVirtualPatch: tighten-rate-limit rounds non-CF windows + warns', () => {
  const out = compileVirtualPatch(
    {
      shape: 'tighten-rate-limit',
      description: 'Cap to 5/45s',
      rateLimit: { requests: 5, window: '45s' },
    },
    baseOpts,
  );
  assert.equal(out.type, 'rateLimitRule');
  assert.equal(out.rule.ratelimit!.period, 60); // 45 → nearest allowed = 60
  assert.ok(out.warnings && out.warnings.some((w) => /rounded/.test(w)));
});

test('compileVirtualPatch: rule tags description with CVE ID and uses writRuleId as ref/id', () => {
  const out = compileVirtualPatch(
    { shape: 'request-uri-denylist', description: 'X', pattern: 'foo' },
    { ...baseOpts, cveId: 'CVE-2024-9999', writRuleId: 'ref-xyz' },
  );
  assert.equal(out.rule.id, 'ref-xyz');
  assert.ok(out.rule.description.includes('CVE-CVE-2024-9999'));
});

test('compileVirtualPatch: mode=block emits action=block', () => {
  const out = compileVirtualPatch(
    { shape: 'request-uri-denylist', description: 'x', pattern: 'foo' },
    { ...baseOpts, mode: 'block' },
  );
  assert.equal(out.rule.action, 'block');
});

test('compileVirtualPatch: rejects .* wildcard patterns', () => {
  assert.throws(
    () =>
      compileVirtualPatch(
        { shape: 'request-uri-denylist', description: 'x', pattern: '.*' },
        baseOpts,
      ),
    VirtualPatchCompileError,
  );
});

test('compileVirtualPatch: rejects invalid header names', () => {
  assert.throws(
    () =>
      compileVirtualPatch(
        {
          shape: 'request-header-denylist',
          description: 'x',
          headerName: 'X-Bad\nInject',
          pattern: 'foo',
        },
        baseOpts,
      ),
    VirtualPatchCompileError,
  );
});

test('compileVirtualPatch: same input → byte-identical output (deterministic)', () => {
  const a = compileVirtualPatch(
    { shape: 'tighten-body-size', description: 'Cap', maxBodySize: '4KB' },
    baseOpts,
  );
  const b = compileVirtualPatch(
    { shape: 'tighten-body-size', description: 'Cap', maxBodySize: '4KB' },
    baseOpts,
  );
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});
