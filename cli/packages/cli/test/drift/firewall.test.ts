import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { loadSpec } from '@x-security/core';
import { detectFirewallDrift } from '../../src/drift/firewall.js';
import { firewallGenerator } from '../../src/generators/firewall/index.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

async function makeFixtureDir(v4: string, v6: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'writ-firewall-'));
  await writeFile(path.join(dir, 'iptables.rules'), v4, 'utf8');
  await writeFile(path.join(dir, 'ip6tables.rules'), v6, 'utf8');
  return dir;
}

test('firewall drift: matching v4+v6 directory has zero drift', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(firewallGenerator.generate(spec));
  const v4 = artifacts.find((a) => a.path.endsWith('iptables.rules'))!.content;
  const v6 = artifacts.find((a) => a.path.endsWith('ip6tables.rules'))!.content;
  const dir = await makeFixtureDir(v4, v6);
  const r = await detectFirewallDrift(spec, { filePath: dir });
  assert.equal(r.target, 'firewall');
  assert.deepEqual(r.issues, []);
});

test('firewall drift: missing metadata-block rule flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(firewallGenerator.generate(spec));
  const v4 = artifacts.find((a) => a.path.endsWith('iptables.rules'))!.content;
  const v6 = artifacts.find((a) => a.path.endsWith('ip6tables.rules'))!.content;
  // Strip the IMDS block rule for 169.254.169.254.
  const weakenedV4 = v4
    .split(/\r?\n/)
    .filter((l) => !l.includes('169.254.169.254'))
    .join('\n');
  const dir = await makeFixtureDir(weakenedV4, v6);
  const r = await detectFirewallDrift(spec, { filePath: dir });
  const m = r.issues.find(
    (i) => i.severity === 'CRITICAL' && i.field.includes('ssrf-metadata-block')
  );
  assert.ok(m, `expected critical metadata-block drift, got ${JSON.stringify(r.issues)}`);
});

test('firewall drift: missing default-deny terminator flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(firewallGenerator.generate(spec));
  const v4 = artifacts.find((a) => a.path.endsWith('iptables.rules'))!.content;
  const v6 = artifacts.find((a) => a.path.endsWith('ip6tables.rules'))!.content;
  const weakenedV4 = v4
    .split(/\r?\n/)
    .filter((l) => !l.includes('writ/default-deny'))
    .filter((l) => !l.includes('default-deny --'))
    .join('\n');
  const dir = await makeFixtureDir(weakenedV4, v6);
  const r = await detectFirewallDrift(spec, { filePath: dir });
  const d = r.issues.find((i) => i.field.includes('default-deny'));
  assert.ok(d, `expected default-deny drift, got ${JSON.stringify(r.issues)}`);
  assert.equal(d!.severity, 'CRITICAL');
});

test('firewall drift: single-file v4-only input still classifies correctly', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const artifacts = await Promise.resolve(firewallGenerator.generate(spec));
  const v4 = artifacts.find((a) => a.path.endsWith('iptables.rules'))!.content;
  const r = await detectFirewallDrift(spec, {
    filePath: 'fake.rules',
    rulesContent: v4,
    family: 'v4'
  });
  // v4 portion matches; v6 is missing wholesale → expect CRITICAL findings on v6.
  const v6Critical = r.issues.filter(
    (i) => i.field.startsWith('v6.') && i.severity === 'CRITICAL'
  );
  assert.ok(v6Critical.length > 0, 'expected v6 ruleset to be reported as missing');
  // No v4 drift expected.
  const v4Issues = r.issues.filter((i) => i.field.startsWith('v4.'));
  assert.equal(v4Issues.length, 0, `unexpected v4 drift: ${JSON.stringify(v4Issues)}`);
});
