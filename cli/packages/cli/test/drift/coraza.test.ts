import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { loadSpec } from '@x-security/core';
import { detectCorazaDrift } from '../../src/drift/coraza.js';
import { corazaGenerator } from '../../src/generators/coraza/index.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('coraza drift: matching config has zero drift', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(corazaGenerator.generate(spec));
  const yamlContent = artifacts[0]!.content;
  const r = await detectCorazaDrift(spec, { filePath: 'fake.yml', yamlContent });
  assert.equal(r.kind, 'drift');
  assert.equal(r.target, 'coraza');
  assert.deepEqual(r.issues, []);
});

test('coraza drift: weakened rate-limit flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(corazaGenerator.generate(spec));
  // W10-7 honest finding: Coraza-Go setvar enforces TX-only at runtime; ALL
  // identifiers downgrade to TX (form: `SecRule TX:rl_login "@gt 5"`).
  const weakened = artifacts[0]!.content.replace(
    /SecRule TX:rl_login "@gt 5"/,
    'SecRule TX:rl_login "@gt 5000"'
  );
  assert.notEqual(weakened, artifacts[0]!.content, 'sanity: replacement happened');
  const r = await detectCorazaDrift(spec, { filePath: 'fake.yml', yamlContent: weakened });
  const rl = r.issues.find((i) => i.field === 'rateLimit.requests' && i.endpoint.includes('login'));
  assert.ok(rl, `expected rate-limit drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(rl!.severity, 'CRITICAL');
});

test('coraza drift: missing auth rule flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(corazaGenerator.generate(spec));
  // Reset the rule id of the auth slot rule so the detector can't find it.
  // The generator emits `id:<base+3>` for SLOT.auth=3. We blanket-replace any
  // line carrying `missing Authorization header` with a stub comment so the
  // matching slot disappears for at least one endpoint.
  const stripped = artifacts[0]!.content
    .split(/\r?\n/)
    .filter((l) => !l.includes('missing Authorization header'))
    .filter((l) => !l.includes('authentication required'))
    .join('\n');
  const r = await detectCorazaDrift(spec, { filePath: 'fake.yml', yamlContent: stripped });
  const auth = r.issues.find((i) => i.field === 'authentication');
  assert.ok(auth, `expected auth missing drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(auth!.severity, 'CRITICAL');
});

test('coraza drift: global SecRequestBodyLimit widening flagged as HIGH', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(corazaGenerator.generate(spec));
  const widened = artifacts[0]!.content.replace(
    /SecRequestBodyLimit 10240/,
    'SecRequestBodyLimit 99999999'
  );
  const r = await detectCorazaDrift(spec, { filePath: 'fake.yml', yamlContent: widened });
  const g = r.issues.find((i) => i.field === 'global.SecRequestBodyLimit');
  assert.ok(g, 'expected global body-limit drift');
  assert.equal(g!.severity, 'HIGH');
});
