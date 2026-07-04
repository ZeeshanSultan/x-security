import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import yaml from 'js-yaml';
import { loadSpec } from '@writ/core';
import { detectOpenAppSecDrift } from '../../src/drift/openappsec.js';
import { openappsecGenerator } from '../../src/generators/openappsec/index.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('openappsec drift: matching config has zero drift', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(openappsecGenerator.generate(spec));
  const r = await detectOpenAppSecDrift(spec, {
    filePath: 'fake.yml',
    yamlContent: artifacts[0]!.content
  });
  assert.equal(r.target, 'openappsec');
  assert.deepEqual(r.issues, []);
});

test('openappsec drift: rate-limit weakening flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(openappsecGenerator.generate(spec));
  const doc = yaml.load(artifacts[0]!.content) as Record<string, unknown>;
  const practices = (doc.practices as Array<Record<string, unknown>>).map((p) => ({ ...p }));
  const rl = practices.find((p) => p.name === 'writ-rate-limit');
  assert.ok(rl, 'expected rate-limit practice in generator output');
  const rlBlock = rl!['rate-limit'] as { rules: Array<{ uri: string; limit: number; unit: string }> };
  // Weaken the first rule by 100x.
  rlBlock.rules[0]!.limit = rlBlock.rules[0]!.limit * 100;
  const weakened = yaml.dump({ ...doc, practices });
  const r = await detectOpenAppSecDrift(spec, { filePath: 'fake.yml', yamlContent: weakened });
  const finding = r.issues.find((i) => i.field === 'rateLimit.requests');
  assert.ok(finding, `expected rate-limit drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(finding!.severity, 'CRITICAL');
});

// wave-8: openappsec relocated per-endpoint schema rules from a fictional
// top-level `schemaValidation:` key to `writ-extended['schema-validation']`
// in wave-7 (open-appsec proper doesn't consume the old key). Tests updated
// to mutate the new key path.

test('openappsec drift: missing schemaValidation entry flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(openappsecGenerator.generate(spec));
  const doc = yaml.load(artifacts[0]!.content) as Record<string, unknown>;
  const ext = doc['writ-extended'] as { 'schema-validation': Array<unknown> };
  const sv = ext['schema-validation'];
  // Drop the first schema-validation entry.
  const dropped = {
    ...doc,
    'writ-extended': { ...ext, 'schema-validation': sv.slice(1) }
  };
  const r = await detectOpenAppSecDrift(spec, {
    filePath: 'fake.yml',
    yamlContent: yaml.dump(dropped)
  });
  const m = r.issues.find((i) => i.field === 'schemaValidation');
  assert.ok(m, `expected schemaValidation missing drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(m!.severity, 'CRITICAL');
});

test('openappsec drift: overrideMode downgrade flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(openappsecGenerator.generate(spec));
  const doc = yaml.load(artifacts[0]!.content) as Record<string, unknown>;
  const ext = doc['writ-extended'] as { 'schema-validation': Array<Record<string, unknown>> };
  const sv = ext['schema-validation'].map((s) => ({ ...s, overrideMode: 'detect' }));
  const r = await detectOpenAppSecDrift(spec, {
    filePath: 'fake.yml',
    yamlContent: yaml.dump({
      ...doc,
      'writ-extended': { ...ext, 'schema-validation': sv }
    })
  });
  const m = r.issues.find((i) => i.field === 'schemaValidation.overrideMode');
  assert.ok(m);
  assert.equal(m!.severity, 'CRITICAL');
});
