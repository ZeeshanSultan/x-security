// Renderer smoke tests — confirm table/json/sarif each produce something
// well-formed for a canned VerifyReport.

import test from 'node:test';
import assert from 'node:assert/strict';
import { renderTable, renderJson, renderSarif } from '../../src/verify/report.js';
import type { VerifyReport } from '../../src/verify/index.js';

const REPORT: VerifyReport = {
  target: 'coraza',
  engine: 'modsec-nginx',
  gateway: 'docker:test-coraza',
  thresholdPct: 90,
  passed: false,
  diagnostics: ['summary: 0 rules loaded'],
  totals: { emitted: 5, loaded: 0, coveragePct: 0 },
  rows: [
    {
      endpoint: 'GET /v1/users',
      emitted: 2,
      loaded: 0,
      status: 'failed',
      rejected: [
        { id: '100001', line: 4, reason: 'collection must be ip/global/resource' },
        { id: '100002', line: 5, reason: 'collection must be ip/global/resource' }
      ]
    },
    {
      endpoint: 'POST /v1/login',
      emitted: 3,
      loaded: 0,
      status: 'failed',
      rejected: [
        { id: '200001', line: 9, reason: 'SecDefaultAction collision' },
        { id: '200002', line: 10, reason: 'SecDefaultAction collision' },
        { id: '200003', line: 11, reason: 'SecDefaultAction collision' }
      ]
    }
  ]
};

test('renderTable surfaces the FAIL verdict and threshold', () => {
  const out = renderTable(REPORT);
  assert.match(out, /FAIL/);
  assert.match(out, /threshold 90%/);
  assert.match(out, /5 emitted/);
  assert.match(out, /collection must be/);
});

test('renderTable groups duplicate rejection reasons by line list', () => {
  const out = renderTable(REPORT);
  // Both rows have identical reasons across all rejected items; expect a
  // single grouped line per row, not three repetitions.
  const occurrences = (out.match(/SecDefaultAction collision/g) ?? []).length;
  assert.equal(occurrences, 1, 'expected the grouped renderer to collapse duplicates');
});

test('renderJson is parseable JSON containing totals and rows', () => {
  const out = renderJson(REPORT);
  const parsed = JSON.parse(out);
  assert.equal(parsed.totals.emitted, 5);
  assert.equal(parsed.passed, false);
  assert.equal(parsed.rows.length, 2);
});

test('renderSarif emits one result per rejected artifact and is parseable', () => {
  const out = renderSarif(REPORT);
  const parsed = JSON.parse(out);
  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs[0].results.length, 5);
  assert.equal(parsed.runs[0].results[0].level, 'error');
});
