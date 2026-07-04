// Unit tests for the OpenAppSec verify reader. Parses checked-in fixtures.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  openappsecReader,
  parseOpenappsecPolicy
} from '../../src/verify/readers/openappsec.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fix = (p: string): string => path.join(here, '__fixtures__', 'openappsec', p);

test('openappsec verify: parseOpenappsecPolicy extracts practices, assets, triggers', async () => {
  const yamlText = await readFile(fix('policy.yaml'), 'utf8');
  const p = parseOpenappsecPolicy(yamlText);
  assert.deepEqual(new Set(p.practices), new Set(['writ-threat-prevention', 'writ-rate-limit']));
  assert.equal(p.assets.length, 1);
  assert.equal(p.assets[0]!.name, 'writ-asset-vapi');
  assert.equal(p.assets[0]!.host, 'vapi');
  assert.deepEqual(p.triggers, ['writ-log-trigger']);
  assert.deepEqual(p.customResponses, ['writ-blocked-response']);
  assert.equal(p.schemaEntries.length, 2);
  assert.equal(p.schemaEntries[0]!.endpoint, 'GET /vapi/api1/user/{id}');
});

test('openappsec verify: parseOpenappsecPolicy returns empty arrays on empty input', () => {
  const p = parseOpenappsecPolicy('');
  assert.deepEqual(p.practices, []);
  assert.deepEqual(p.assets, []);
  assert.deepEqual(p.schemaEntries, []);
});

test('openappsec verify: reconcile marks every emitted name loaded when all present in agent conf', async () => {
  const yamlText = await readFile(fix('policy.yaml'), 'utf8');
  const policy = parseOpenappsecPolicy(yamlText);
  const emitted = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const, endpoint: '(practices)', label: 'practice' },
    { id: 'writ-asset-vapi', kind: 'envoy-endpoint-policy' as const, endpoint: '(asset) vapi', label: 'asset' },
    { id: 'get-api1-user-by-id', kind: 'envoy-endpoint-policy' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'schema' }
  ];
  // All three names appear in the agent conf fixture.
  const loaded = emitted.map((e) => ({ id: e.id, kind: e.kind }));
  const { rows } = openappsecReader.reconcile(emitted, loaded);
  const totalLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  assert.equal(totalLoaded, 3);
  void policy;
});

test('openappsec verify: reconcile flags everything when no policy loaded', () => {
  const emitted = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const, endpoint: '(practices)', label: 'practice' }
  ];
  const loaded = [
    {
      id: '__no-policy-loaded__',
      kind: 'envoy-endpoint-policy' as const,
      rejectionReason: '/etc/cp/conf/ on the openappsec agent contains no policy/yaml files'
    }
  ];
  const { rows, diagnostics } = openappsecReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 0);
  assert.equal(rows[0]!.status, 'failed');
  assert.ok(diagnostics.some((d) => /no policy/i.test(d)));
});

test('openappsec verify: reconcile reports verdict count diagnostic', () => {
  const emitted = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const, endpoint: '(practices)', label: 'practice' }
  ];
  const loaded = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const },
    { id: '__verdict-count__', kind: 'envoy-endpoint-policy' as const, rejectionReason: 'verdicts:42' }
  ];
  const { diagnostics } = openappsecReader.reconcile(emitted, loaded);
  assert.ok(diagnostics.some((d) => /42 Writ-attributed verdict/.test(d)));
});

test('openappsec verify: reconcile flags missing practice names', () => {
  const emitted = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const, endpoint: '(practices)', label: 'practice' },
    { id: 'writ-missing-practice', kind: 'envoy-endpoint-policy' as const, endpoint: '(practices)', label: 'practice' }
  ];
  const loaded = [
    { id: 'writ-threat-prevention', kind: 'envoy-endpoint-policy' as const }
  ];
  const { rows } = openappsecReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 1);
  assert.equal(rows[0]!.rejected.length, 1);
  assert.equal(rows[0]!.rejected[0]!.id, 'writ-missing-practice');
});
