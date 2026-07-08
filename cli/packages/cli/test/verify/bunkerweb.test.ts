// Unit tests for the BunkerWeb verify reader. Parses checked-in fixture
// files captured from a live chain (see __fixtures__/README.md). No live
// containers required — per wave-9 D-1 we do not gate unit tests on docker.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  bunkerwebReader,
  parseBunkerwebGateway,
  scanBunkerwebRules
} from '../../src/verify/readers/bunkerweb.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fix = (p: string): string => path.join(here, '__fixtures__', 'bunkerweb', p);

test('bunkerweb verify: parseBunkerwebGateway accepts single docker target', () => {
  const r = parseBunkerwebGateway('docker:x-security-bunkerweb-1');
  assert.equal(r.bunkerweb, 'x-security-bunkerweb-1');
  assert.equal(r.scheduler, undefined);
});

test('bunkerweb verify: parseBunkerwebGateway accepts scheduler+bunkerweb chain', () => {
  const r = parseBunkerwebGateway('docker:scheduler-1+docker:bunkerweb-1');
  assert.equal(r.scheduler, 'scheduler-1');
  assert.equal(r.bunkerweb, 'bunkerweb-1');
});

test('bunkerweb verify: parseBunkerwebGateway rejects non-docker addrs', () => {
  assert.throws(() => parseBunkerwebGateway('http://localhost'), /docker:/);
});

test('bunkerweb verify: scanBunkerwebRules extracts rule ids from fixture conf', async () => {
  const conf = await readFile(fix('x-security.conf'), 'utf8');
  const rules = scanBunkerwebRules(conf);
  const ids = new Set(rules.map((r) => r.id));
  assert.ok(ids.has('299740'));
  assert.ok(ids.has('299743'));
  assert.ok(ids.has('299744'));
  assert.ok(ids.has('277660'));
  assert.ok(ids.has('277663'));
  // The id inside the "# id:999999 inside a comment" line lives AFTER the
  // "# Settings below" marker — must NOT be counted.
  assert.equal(ids.has('999999'), false);
});

test('bunkerweb verify: scanBunkerwebRules attributes rules to source endpoints', async () => {
  const conf = await readFile(fix('x-security.conf'), 'utf8');
  const rules = scanBunkerwebRules(conf);
  const byId = new Map(rules.map((r) => [r.id, r.endpoint]));
  assert.equal(byId.get('299743'), 'GET /vapi/api1/user/{id}');
  assert.equal(byId.get('277663'), 'GET /vapi/api2/user/details');
});

test('bunkerweb verify: reconcile marks all-loaded when every id is present', async () => {
  const conf = await readFile(fix('x-security.conf'), 'utf8');
  const emitted = scanBunkerwebRules(conf).map((r) => ({
    id: r.id,
    kind: 'coraza-rule' as const,
    endpoint: r.endpoint,
    label: r.label,
    line: r.line
  }));
  // Simulate "every emitted rule was found in nginx -T".
  const loaded = [...new Set(emitted.map((e) => e.id))].map((id) => ({
    id,
    kind: 'coraza-rule' as const
  }));
  const { rows, diagnostics } = bunkerwebReader.reconcile(emitted, loaded);
  const totalLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  const totalEmitted = rows.reduce((s, r) => s + r.emitted, 0);
  assert.equal(totalLoaded, totalEmitted);
  assert.equal(diagnostics.filter((d) => /not present/i.test(d)).length, 0);
});

test('bunkerweb verify: reconcile flags every emitted rule when nginx -T returns nothing', async () => {
  const conf = await readFile(fix('x-security.conf'), 'utf8');
  const emitted = scanBunkerwebRules(conf).map((r) => ({
    id: r.id,
    kind: 'coraza-rule' as const,
    endpoint: r.endpoint,
    label: r.label,
    line: r.line
  }));
  const loaded = [
    {
      id: '__empty-dump__',
      kind: 'coraza-rule' as const,
      rejectionReason: 'nginx -T returned no x-security rule ids'
    }
  ];
  const { rows, diagnostics } = bunkerwebReader.reconcile(emitted, loaded);
  for (const r of rows) {
    assert.equal(r.loaded, 0);
    assert.equal(r.status, 'failed');
  }
  assert.ok(diagnostics.some((d) => /no x-security rule ids/i.test(d)));
});

test('bunkerweb verify: reconcile flags sync-skew when scheduler has more rules than bunkerweb', () => {
  const emitted = [
    { id: '111111', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 1 },
    { id: '222222', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 2 }
  ];
  const loaded = [
    { id: '111111', kind: 'coraza-rule' as const },
    {
      id: 'sync-skew:222222',
      kind: 'coraza-rule' as const,
      rejectionReason: 'rule 222222 present in scheduler config but missing from bunkerweb nginx -T output (sync skew)'
    }
  ];
  const { rows, diagnostics } = bunkerwebReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 1);
  assert.equal(rows[0]!.rejected.length, 1);
  assert.ok(diagnostics.some((d) => /sync skew/i.test(d)));
});
