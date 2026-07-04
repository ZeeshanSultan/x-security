// Verifies `runTest({ dryRun: true })` produces a compose plan YAML and never
// touches Docker. Runs unconditionally in `pnpm test`.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runTest } from '../../src/commands/test.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('test --dry-run emits compose YAML and exits 0 without Docker', async () => {
  const r = await runTest(SPEC, { target: 'kong', dryRun: true });
  assert.equal(r.exitCode, 0);
  assert.equal(r.report.cases.length, 0);
  assert.match(r.composeYaml, /services:/);
  assert.match(r.composeYaml, /image: kong:3\.4/);
  assert.match(r.composeYaml, /image: mendhak\/http-https-echo:36/);
  assert.match(r.composeYaml, /KONG_DATABASE: "off"/);
  assert.match(r.composeYaml, /KONG_DECLARATIVE_CONFIG: "\/etc\/writ\/kong\.yml"/);
  assert.match(r.composeYaml, /KONG_ADMIN_LISTEN: "off"/);
  assert.match(r.rendered, /dry-run/);
});

test('dry-run plan uses unique container names per invocation (idempotent reruns)', async () => {
  const a = await runTest(SPEC, { target: 'kong', dryRun: true });
  const b = await runTest(SPEC, { target: 'kong', dryRun: true });
  // Container names embed pid + random suffix → never collide.
  const nameA = a.composeYaml.match(/container_name: (writ-kong-gateway-\S+)/)?.[1];
  const nameB = b.composeYaml.match(/container_name: (writ-kong-gateway-\S+)/)?.[1];
  assert.ok(nameA && nameB);
  assert.notEqual(nameA, nameB);
});

test('test --dry-run with unsupported target throws', async () => {
  await assert.rejects(
    () => runTest(SPEC, { target: 'nginx', dryRun: true }),
    /supports kong\|coraza\|bunkerweb\|openappsec/
  );
});
