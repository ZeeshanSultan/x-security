import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runGenerate } from '../../src/commands/generate.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('generate --target kong --dry-run produces artifacts without writing', async () => {
  const r = await runGenerate(SPEC, { target: 'kong', dryRun: true, strict: false });
  assert.ok(r.artifacts.length > 0, 'expected at least one kong artifact');
  const kongYml = r.artifacts.find((a) => a.path.endsWith('kong.yml') || a.path.endsWith('.yml'));
  assert.ok(kongYml, 'expected a kong.yml-ish artifact');
  assert.ok(kongYml!.content.length > 0);
});

test('generate fails fast on unknown target', async () => {
  await assert.rejects(
    () => runGenerate(SPEC, { target: 'made-up' as 'kong', dryRun: true }),
    /Unknown target/
  );
});

test('generate --target firewall surfaces L3/L4-only WARNING', async () => {
  const r = await runGenerate(SPEC, { target: 'firewall', dryRun: true, strict: false });
  const w = r.warnings.find((s) => s.includes('WARNING:') && s.includes('L3/L4'));
  assert.ok(w, `expected firewall L3/L4 warning, got ${JSON.stringify(r.warnings)}`);
});

test('generate --target kong does NOT emit firewall L3/L4 warning', async () => {
  const r = await runGenerate(SPEC, { target: 'kong', dryRun: true, strict: false });
  const w = r.warnings.find((s) => s.includes('L3/L4'));
  assert.equal(w, undefined, `kong target should not emit firewall warning, got ${JSON.stringify(r.warnings)}`);
});

test('generate --dry-run does NOT touch disk', async () => {
  // Pointing at /nonexistent dir should still succeed in dry-run mode.
  const r = await runGenerate(SPEC, {
    target: 'kong',
    dryRun: true,
    out: '/this/path/should/not/exist',
    strict: false
  });
  assert.ok(r.artifactPaths.every((p) => p.startsWith('/this/path/should/not/exist')));
});
