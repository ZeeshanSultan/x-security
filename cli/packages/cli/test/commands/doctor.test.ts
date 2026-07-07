import test from 'node:test';
import assert from 'node:assert/strict';
import { runDoctor } from '../../src/commands/doctor.js';

test('doctor: default checks include an ok node check and a non-throwing docker check', async () => {
  const r = await runDoctor();
  const node = r.checks.find((c) => c.name === 'node');
  assert.ok(node, 'expected a node check');
  assert.equal(node!.status, 'ok', `node check should be ok on Node >=20: ${node!.detail}`);

  const docker = r.checks.find((c) => c.name === 'docker');
  assert.ok(docker, 'expected a docker check');
  assert.ok(
    docker!.status === 'ok' || docker!.status === 'warn',
    `docker check should never hard-fail, got ${docker!.status}`
  );
});

test('doctor: json format renders parseable JSON with checks + ok', async () => {
  const r = await runDoctor({ format: 'json' });
  const parsed = JSON.parse(r.rendered);
  assert.ok(Array.isArray(parsed.checks), 'expected checks array');
  assert.equal(typeof parsed.ok, 'boolean');
});

test('doctor: unreachable gateway fails fast and sets exit code 1', async () => {
  const start = Date.now();
  const r = await runDoctor({ gateway: 'http://127.0.0.1:1/nope', timeoutMs: 300 });
  const elapsed = Date.now() - start;

  const gateway = r.checks.find((c) => c.name === 'gateway');
  assert.ok(gateway, 'expected a gateway check');
  assert.equal(gateway!.status, 'fail');
  assert.equal(r.exitCode, 1);
  assert.ok(elapsed < 5000, `expected doctor to return quickly, took ${elapsed}ms`);
});

test('doctor: non-HTTP gateway is skipped, not attempted', async () => {
  const r = await runDoctor({ gateway: 'docker:foo' });
  const gateway = r.checks.find((c) => c.name === 'gateway');
  assert.ok(gateway, 'expected a gateway check');
  assert.notEqual(gateway!.status, 'fail');
  assert.match(gateway!.detail, /skipped/i);
});
