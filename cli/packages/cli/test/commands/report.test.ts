import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runReport } from '../../src/commands/report.js';
import { buildAnnotationCoverage } from '../../src/reporters/owasp-analyze.js';
import type { SpecIR } from '@x-security/core';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('report --owasp returns rows for every endpoint', async () => {
  const r = await runReport(SPEC, { mode: 'owasp', format: 'table' });
  assert.equal(r.data.kind, 'owasp');
  if (r.data.kind !== 'owasp') return;
  // example.yaml has 3 annotated endpoints
  assert.equal(r.data.rows.length, 3);
  assert.match(r.rendered, /OWASP API Top 10 Coverage/);
  // The login endpoint should mitigate API4 (rate limit + maxBody + timeout)
  const login = r.data.rows.find((row) => row.endpoint.includes('login'));
  assert.ok(login);
  assert.notEqual(login!.coverage['API4:2023'], 'no');
});

test('report --owasp --format json round-trips', async () => {
  const r = await runReport(SPEC, { mode: 'owasp', format: 'json' });
  const parsed = JSON.parse(r.rendered);
  assert.equal(parsed.kind, 'owasp');
  assert.ok(Array.isArray(parsed.rows));
});

test('report --owasp --format sarif emits valid SARIF skeleton', async () => {
  const r = await runReport(SPEC, { mode: 'owasp', format: 'sarif' });
  const parsed = JSON.parse(r.rendered);
  assert.equal(parsed.version, '2.1.0');
  assert.ok(Array.isArray(parsed.runs));
});

test('report --coverage counts annotated endpoints', async () => {
  const r = await runReport(SPEC, { mode: 'coverage', format: 'json' });
  const parsed = JSON.parse(r.rendered);
  assert.equal(parsed.kind, 'coverage');
  assert.equal(parsed.annotatedEndpoints, 3);
});

test('coverage lists post-v0.2 policy fields (csrf, logging, graphql, tls, ...)', () => {
  const spec: SpecIR = {
    openapi: '3.1.0',
    dialect: '3.1',
    info: { title: 'T', version: '1.0.0' },
    servers: [],
    endpoints: [
      {
        method: 'POST',
        path: '/api/v3-fields',
        operationId: 'v3Fields',
        policy: {
          csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] },
          logging: { events: ['auth-failure'] },
          graphql: { maxDepth: 5 },
          websocket: { allowedOrigins: ['https://app.example.com'] },
          botProtection: { provider: 'turnstile', secretRef: '${TURNSTILE_SECRET}', mode: 'enforce' },
          mitigates: ['API7:2023'],
          outboundCalls: [{ endpoint: 'https://api.partner.example/v1/hook' }],
          tls: { minVersion: 'TLSv1.2' }
        },
        parameters: [],
        raw: {} as SpecIR['endpoints'][number]['raw'],
        resolvedVars: new Map()
      }
    ],
    unprotectedEndpoints: []
  };
  const r = buildAnnotationCoverage(spec);
  assert.equal(r.perEndpoint.length, 1);
  // Regression: these protection fields were silently dropped, under-reporting
  // coverage. mitigates is present on the policy but is metadata, not a
  // protection — it must NOT appear (consistent with the audit controls tally).
  assert.deepEqual(r.perEndpoint[0]!.fields.sort(), [
    'botProtection', 'csrf', 'graphql', 'logging',
    'outboundCalls', 'tls', 'websocket'
  ]);
});

test('report --owasp --format csv has 10 OWASP columns + endpoint', async () => {
  const r = await runReport(SPEC, { mode: 'owasp', format: 'csv' });
  const header = r.rendered.split('\n')[0]!;
  const cols = header.split(',');
  assert.equal(cols.length, 11);
});

test('report --owasp --format html renders table', async () => {
  const r = await runReport(SPEC, { mode: 'owasp', format: 'html' });
  assert.match(r.rendered, /<table>/);
  assert.match(r.rendered, /Example API/);
});
