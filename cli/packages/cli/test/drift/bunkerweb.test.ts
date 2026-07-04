import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { loadSpec } from '@writ/core';
import { detectBunkerWebDrift } from '../../src/drift/bunkerweb.js';
import { bunkerwebGenerator } from '../../src/generators/bunkerweb/index.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

// wave-8: bunkerweb output reshaped (wave-6) — assertions updated to new
// configs/modsec/writ.conf layout (commented `# KEY=value` env hints +
// SecRule blocks). The original env-var-YAML check is dead.

test('bunkerweb drift: matching config has zero drift', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  const r = await detectBunkerWebDrift(spec, {
    filePath: 'fake.conf',
    yamlContent: artifacts[0]!.content
  });
  assert.equal(r.target, 'bunkerweb');
  assert.deepEqual(r.issues, []);
});

test('bunkerweb drift: rate-limit rate weakening flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  // The expected has `# LIMIT_REQ_RATE_1=1r/s` → weaken to `100r/s`.
  const weakened = artifacts[0]!.content.replace(
    /# LIMIT_REQ_RATE_1=1r\/s/,
    '# LIMIT_REQ_RATE_1=100r/s'
  );
  assert.notEqual(weakened, artifacts[0]!.content);
  const r = await detectBunkerWebDrift(spec, { filePath: 'fake.conf', yamlContent: weakened });
  const rl = r.issues.find((i) => i.field === 'LIMIT_REQ_RATE_1');
  assert.ok(rl, `expected rate-limit drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(rl!.severity, 'CRITICAL');
});

test('bunkerweb drift: missing auth setting flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  // Remove the USE_MODSECURITY hint line from the deployed config.
  const stripped = artifacts[0]!.content
    .split(/\r?\n/)
    .filter((l) => !/^#\s*USE_MODSECURITY=/.test(l))
    .join('\n');
  const r = await detectBunkerWebDrift(spec, { filePath: 'fake.conf', yamlContent: stripped });
  const m = r.issues.find((i) => i.field === 'USE_MODSECURITY');
  assert.ok(m, `expected USE_MODSECURITY drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(m!.severity, 'CRITICAL');
});

test('bunkerweb drift: missing IP whitelist flagged as HIGH', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  const stripped = artifacts[0]!.content
    .split(/\r?\n/)
    .filter((l) => !/^#\s*WHITELIST_IP=/.test(l))
    .join('\n');
  const r = await detectBunkerWebDrift(spec, { filePath: 'fake.conf', yamlContent: stripped });
  const w = r.issues.find((i) => i.field === 'WHITELIST_IP');
  assert.ok(w, 'expected WHITELIST_IP drift');
  assert.equal(w!.severity, 'HIGH');
});

test('bunkerweb drift: MAX_CLIENT_SIZE widening flagged as HIGH', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  const widened = artifacts[0]!.content.replace(
    /# MAX_CLIENT_SIZE=50m/,
    '# MAX_CLIENT_SIZE=500m'
  );
  const r = await detectBunkerWebDrift(spec, { filePath: 'fake.conf', yamlContent: widened });
  const s = r.issues.find((i) => i.field === 'MAX_CLIENT_SIZE');
  assert.ok(s);
  assert.equal(s!.severity, 'HIGH');
});

test('bunkerweb drift: missing service flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  // Empty deployed config — no SecRules, no env hints → service missing.
  const r = await detectBunkerWebDrift(spec, {
    filePath: 'fake.conf',
    yamlContent: ''
  });
  const s = r.issues.find((i) => i.field === 'service');
  assert.ok(s);
  assert.equal(s!.severity, 'CRITICAL');
});
