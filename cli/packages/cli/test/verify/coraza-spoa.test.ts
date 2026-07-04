// Unit tests for the dedicated Coraza-SPOA verify reader. Parses checked-in
// fixture files captured from a live SPOA chain.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  corazaSpoaReader,
  parseSpoaGateway,
  collectSignals,
  scanEmittedRules,
  extractIncludesAndInline,
  extractRuleIds
} from '../../src/verify/readers/coraza-spoa.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fix = (p: string): string => path.join(here, '__fixtures__', 'coraza-spoa', p);

test('coraza-spoa verify: parseSpoaGateway routes haproxy/spoa containers by substring', () => {
  const r = parseSpoaGateway('docker:my-haproxy-1+docker:my-coraza-spoa-1');
  assert.equal(r.haproxy, 'my-haproxy-1');
  assert.equal(r.spoa, 'my-coraza-spoa-1');
});

test('coraza-spoa verify: parseSpoaGateway handles a single docker target', () => {
  const r = parseSpoaGateway('docker:my-spoa-1');
  assert.ok(r.spoa === 'my-spoa-1' || r.haproxy === 'my-spoa-1');
});

test('coraza-spoa verify: parseSpoaGateway rejects non-docker', () => {
  assert.throws(() => parseSpoaGateway('http://localhost:9000'), /docker:/);
});

test('coraza-spoa verify: collectSignals parses HAProxy ruleid= fields and SPOA startup count', async () => {
  const haproxy = await readFile(fix('haproxy.log'), 'utf8');
  const spoa = await readFile(fix('spoa.log'), 'utf8');
  const sig = collectSignals(haproxy, spoa);
  assert.equal(sig.haproxyRuleIds.has('299743'), true);
  assert.equal(sig.haproxyRuleIds.has('277663'), true);
  assert.equal(sig.haproxyRuleIds.has('299744'), true);
  assert.equal(sig.spoaLoadedCount, 5);
  assert.equal(sig.spoaAbort, undefined);
});

test('coraza-spoa verify: scanEmittedRules extracts ids from directives block', async () => {
  const yml = await readFile(fix('directives.yml'), 'utf8');
  const arts = scanEmittedRules(
    yml.replace(/^directives:\s*\|\s*\n/, '').replace(/^ {2}/gm, '')
  );
  const ids = new Set(arts.map((a) => a.id));
  assert.ok(ids.has('299740'));
  assert.ok(ids.has('299743'));
  assert.ok(ids.has('299744'));
  assert.ok(ids.has('277660'));
  assert.ok(ids.has('277663'));
});

test('coraza-spoa verify: reconcile counts per-id positive hits when summary matches', () => {
  // W12-C: reconcile no longer rounds up against the startup summary when
  // a positive per-id channel is present. The 2 observed ids are confirmed;
  // the 3rd is honestly reported as unconfirmed (Rule D-1).
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 2 },
    { id: '299744', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 3 },
    { id: '277663', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api2/user/details', label: 'SecRule', line: 6 }
  ];
  const loaded = [
    { id: '299743', kind: 'coraza-rule' as const },
    { id: '277663', kind: 'coraza-rule' as const },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:3' }
  ];
  const { rows, diagnostics } = corazaSpoaReader.reconcile(emitted, loaded);
  const totalLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  assert.equal(totalLoaded, 2);
  assert.ok(diagnostics.some((d) => /3 rules loaded/.test(d)));
});

test('coraza-spoa verify: reconcile rejects every rule when SPOA reports zero loaded', () => {
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 1 }
  ];
  const loaded = [
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:0' }
  ];
  const { rows } = corazaSpoaReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 0);
  assert.equal(rows[0]!.status, 'failed');
});

test('coraza-spoa verify: reconcile counts HAProxy-hit rules as loaded even when summary unknown', () => {
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 1 },
    { id: '299744', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 2 }
  ];
  const loaded = [
    { id: '299743', kind: 'coraza-rule' as const },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:unknown' }
  ];
  const { rows, diagnostics } = corazaSpoaReader.reconcile(emitted, loaded);
  // 299743 was observed firing; 299744 unconfirmed.
  assert.equal(rows[0]!.loaded, 1);
  assert.equal(rows[0]!.rejected.length, 1);
  assert.equal(rows[0]!.rejected[0]!.id, '299744');
  assert.ok(diagnostics.some((d) => /not located in container|HAProxy ruleid=/.test(d)));
});

test('coraza-spoa verify: reconcile rejects everything when SPOA logs an abort', () => {
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /x', label: 'SecRule', line: 1 }
  ];
  const loaded = [
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:unknown' },
    { id: '__abort__', kind: 'coraza-rule' as const, rejectionReason: 'coraza: invalid SecRule operator' }
  ];
  const { rows, diagnostics } = corazaSpoaReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 0);
  assert.equal(rows[0]!.status, 'failed');
  assert.ok(diagnostics.some((d) => /invalid SecRule/.test(d)));
});

// ─────────────────────────────────────────────────────────────────────
// W12-C: per-rule positive-confirmation channel from the SPOA config file.
// ─────────────────────────────────────────────────────────────────────

test('coraza-spoa verify (W12-C): extractIncludesAndInline picks up Include lines from directives block', async () => {
  const yamlText = await readFile(fix('coraza-spoa-loaded.yaml'), 'utf8');
  const { inline, includes } = extractIncludesAndInline(yamlText);
  assert.equal(includes.length, 1);
  assert.equal(includes[0], '/shared/writ.conf');
  assert.equal(inline.length, 1);
  assert.ok(inline[0]!.includes('Include /shared/writ.conf'));
});

test('coraza-spoa verify (W12-C): extractRuleIds pulls SecRule + SecAction ids from a flat conf', async () => {
  const conf = await readFile(fix('coraza-spoa-loaded.txt'), 'utf8');
  const ids = extractRuleIds(conf);
  assert.equal(ids.size, 5);
  assert.ok(ids.has('299740'));
  assert.ok(ids.has('299743'));
  assert.ok(ids.has('299744'));
  assert.ok(ids.has('277660'));
  assert.ok(ids.has('277663'));
});

test('coraza-spoa verify (W12-C): reconcile happy path — every emitted id is present in SPOA loaded config', () => {
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 2 },
    { id: '299744', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 3 },
    { id: '277663', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api2/user/details', label: 'SecRule', line: 6 }
  ];
  const loaded = [
    { id: '299743', kind: 'coraza-rule' as const, rejectionReason: 'source:config' },
    { id: '299744', kind: 'coraza-rule' as const, rejectionReason: 'source:config' },
    { id: '277663', kind: 'coraza-rule' as const, rejectionReason: 'source:config' },
    { id: '__config_source__', kind: 'coraza-rule' as const, rejectionReason: 'config:/shared/coraza-spoa.yaml' },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:5' }
  ];
  const { rows, diagnostics } = corazaSpoaReader.reconcile(emitted, loaded);
  const totalLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  const totalEmitted = rows.reduce((s, r) => s + r.emitted, 0);
  assert.equal(totalLoaded, totalEmitted);
  assert.equal(totalLoaded, 3);
  assert.ok(rows.every((r) => r.status === 'ok'));
  assert.ok(diagnostics.some((d) => /3 rule ids resolved from \/shared\/coraza-spoa\.yaml/.test(d)));
});

test('coraza-spoa verify (W12-C): reconcile partial — SPOA config holds api1 ids only, api2 reported missing', () => {
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 2 },
    { id: '299744', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 3 },
    { id: '277663', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api2/user/details', label: 'SecRule', line: 6 }
  ];
  const loaded = [
    { id: '299743', kind: 'coraza-rule' as const, rejectionReason: 'source:config' },
    { id: '299744', kind: 'coraza-rule' as const, rejectionReason: 'source:config' },
    { id: '__config_source__', kind: 'coraza-rule' as const, rejectionReason: 'config:/shared/coraza-spoa.yaml' },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:3' }
  ];
  const { rows } = corazaSpoaReader.reconcile(emitted, loaded);
  const byEndpoint = Object.fromEntries(rows.map((r) => [r.endpoint, r]));
  assert.equal(byEndpoint['GET /vapi/api1/user/{id}']!.loaded, 2);
  assert.equal(byEndpoint['GET /vapi/api1/user/{id}']!.status, 'ok');
  assert.equal(byEndpoint['GET /vapi/api2/user/details']!.loaded, 0);
  assert.equal(byEndpoint['GET /vapi/api2/user/details']!.status, 'failed');
  const rejReason = byEndpoint['GET /vapi/api2/user/details']!.rejected[0]!.reason;
  assert.match(rejReason, /not present in SPOA loaded config/);
});

test('coraza-spoa verify (W12-C): reconcile completely-unmounted — config readable but holds no Writ ids', () => {
  // The "unmounted" scenario: SPOA daemon booted with a config whose
  // directives block contains no SecRules and no Include — the spoa-init
  // sidecar never landed the rule file.
  const emitted = [
    { id: '299743', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api1/user/{id}', label: 'SecRule', line: 2 },
    { id: '277663', kind: 'coraza-rule' as const, endpoint: 'GET /vapi/api2/user/details', label: 'SecRule', line: 6 }
  ];
  const loaded = [
    { id: '__config_source__', kind: 'coraza-rule' as const, rejectionReason: 'config:/shared/coraza-spoa.yaml' },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:0' }
  ];
  const { rows, diagnostics } = corazaSpoaReader.reconcile(emitted, loaded);
  const totalLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  assert.equal(totalLoaded, 0);
  assert.ok(rows.every((r) => r.status === 'failed'));
  assert.ok(diagnostics.some((d) => /0 rules loaded/.test(d)));
});

test('coraza-spoa verify (W12-C): extractIncludesAndInline returns empty when no applications block', () => {
  const r = extractIncludesAndInline('bind: 0.0.0.0:9000\nlog_level: info\n');
  assert.equal(r.inline.length, 0);
  assert.equal(r.includes.length, 0);
});

