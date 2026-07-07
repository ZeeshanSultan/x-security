// End-to-end tests for the BYO-agent CLI verbs: routes → verify → compile →
// audit → emit. The zero-hallucination gate (Rule D-3) is the headline
// assertion: a fabricated cite never produces an enforced control, and a cite
// that drifts off its code flips the audit proof to citeBacked:false.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';

import { runRoutes } from '../src/commands/detect/routes.js';
import { runVerify } from '../src/commands/detect/verify.js';
import { runCompile } from '../src/commands/detect/compile.js';
import { runAudit } from '../src/commands/detect/audit.js';
import { runEmit } from '../src/commands/detect/emit.js';
import { persistPolicy } from '../src/commands/detect/store.js';

let dir: string;
const PING_QUOTE = "require('child_process').exec('ping ' + req.body.target);";

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cli-detect-'));
  await fs.mkdir(path.join(dir, 'src'), { recursive: true });
  await fs.writeFile(
    path.join(dir, 'src', 'app.js'),
    [
      "const app = require('express')();",                 // 1
      "app.get('/api/users/:id', (req, res) => {});",       // 2
      "app.post('/api/ping', (req, res) => {",              // 3
      `  ${PING_QUOTE}`,                                     // 4
      '});',                                                // 5
    ].join('\n'),
  );
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('routes emits {method,path,file,line} for every express route', async () => {
  const r = await runRoutes(dir);
  assert.ok(r.routes.length >= 2);
  const ping = r.routes.find((x) => x.path === '/api/ping');
  assert.ok(ping, 'POST /api/ping extracted');
  assert.equal(ping!.method, 'POST');
  assert.equal(ping!.file, 'src/app.js');
  assert.equal(ping!.line, 3);
});

test('verify PASSES a real, byte-matching os-command finding', async () => {
  const r = await runVerify({
    repoDir: dir,
    finding: {
      route: { method: 'POST', path: '/api/ping' },
      controlHint: { kind: 'injectionGuard', sink: 'os-command' },
      cite: { file: 'src/app.js', lineStart: 4, lineEnd: 4, quote: PING_QUOTE },
    },
  });
  assert.equal(r.verdict, 'pass', JSON.stringify(r.reasons));
});

test('verify FAILS a fabricated cite (D-3: never invented)', async () => {
  const r = await runVerify({
    repoDir: dir,
    finding: {
      route: { method: 'POST', path: '/api/ping' },
      controlHint: { kind: 'injectionGuard', sink: 'os-command' },
      cite: { file: 'src/app.js', lineStart: 4, lineEnd: 4, quote: "exec('rm -rf ' + neverWritten)" },
    },
  });
  assert.equal(r.verdict, 'fail');
  assert.ok(r.reasons.some((x) => x.startsWith('V6:')));
});

test('verify snaps a real cite at the wrong line and still passes', async () => {
  const r = await runVerify({
    repoDir: dir,
    finding: {
      route: { method: 'POST', path: '/api/ping' },
      controlHint: { kind: 'injectionGuard', sink: 'os-command' },
      // Cited at line 1 (wrong); real binding is line 4.
      cite: { file: 'src/app.js', lineStart: 1, lineEnd: 1, quote: PING_QUOTE },
    },
  });
  assert.equal(r.verdict, 'pass', JSON.stringify(r.reasons));
  assert.ok(r.snappedCite, 'cite was snapped to its true line');
  assert.equal(r.snappedCite!.lineStart, 4);
});

test('compile produces a cite-backed control and DROPS a fabricated finding', async () => {
  const r = await runCompile({
    repoDir: dir,
    route: { method: 'POST', path: '/api/ping' },
    findings: [
      { controlHint: { kind: 'injectionGuard', sink: 'os-command' }, cite: { file: 'src/app.js', lineStart: 4, lineEnd: 4, quote: PING_QUOTE }, param: 'target' },
      { controlHint: { kind: 'injectionGuard', sink: 'sql' }, cite: { file: 'src/app.js', lineStart: 4, lineEnd: 4, quote: 'SELECT * FROM nowhere' }, param: 'q' },
    ],
  });
  assert.ok(r.policy, 'a control was compiled');
  const schema = r.policy!.request?.schema as Record<string, { injectionGuard?: string[] }> | undefined;
  assert.ok(schema?.['target']?.injectionGuard?.includes('os-command'), 'os-command guard on target');
  assert.equal(schema?.['q'], undefined, 'fabricated sql finding dropped, no control emitted');
  assert.ok(r.dropped.length >= 1, 'the fabricated finding is reported as dropped');
  assert.equal(r.cites.length, 1, 'only the verified cite survives');
});

test('audit proves citeBacked + flips to false when a cite drifts (D-3)', async () => {
  // Persist a known-good policy + cite, then audit.
  const compiled = await runCompile({
    repoDir: dir,
    route: { method: 'POST', path: '/api/ping' },
    findings: [
      { controlHint: { kind: 'injectionGuard', sink: 'os-command' }, cite: { file: 'src/app.js', lineStart: 4, lineEnd: 4, quote: PING_QUOTE }, param: 'target' },
    ],
  });
  await persistPolicy(dir, { method: 'POST', path: '/api/ping' }, compiled.policy!, compiled.cites);

  const ok = await runAudit(dir);
  assert.equal(ok.citeBacked, true);
  assert.equal(ok.coverage, 1);
  assert.equal(ok.uncited.length, 0);

  // Tamper the sidecar so the cite no longer byte-matches → citeBacked false.
  const sidecar = path.join(dir, '.x-security', 'policies', 'POST__api__ping.cites.json');
  const j = JSON.parse(await fs.readFile(sidecar, 'utf8')) as { cites: Array<{ quote: string }> };
  j.cites[0]!.quote = 'this string was never in the source';
  await fs.writeFile(sidecar, JSON.stringify(j));

  const bad = await runAudit(dir);
  assert.equal(bad.citeBacked, false, 'a drifted cite flips the proof');
  assert.ok(bad.uncited.length >= 1);
});

test('audit controls tally counts EVERY emitted control kind, not just auth+schema', async () => {
  // Regression for the VAmPI under-report (2026-07-02): a route emitting
  // authentication + authorization + rateLimit + denyUnknownFields +
  // responseShape + a request.schema param must report controls = 6, not the
  // old 2 (auth + one schema field). The old countControls dropped
  // authorization / rateLimit / denyUnknownFields / responseShape entirely.
  const mixedDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cli-audit-controls-'));
  try {
    const policiesPath = path.join(mixedDir, '.x-security', 'policies');
    await fs.mkdir(policiesPath, { recursive: true });

    const policy = {
      authentication: { type: 'jwt' },
      authorization: {
        type: 'rule-based',
        rules: [{ field: 'request.params.id', operator: 'equals', value: { ref: 'jwt.sub' } }],
      },
      rateLimit: { requests: 10, window: '1m', identifier: 'ip' },
      request: {
        denyUnknownFields: true,
        schema: { id: { type: 'string' } },
      },
      response: { stripUnknownFields: true },
    };
    await fs.writeFile(
      path.join(policiesPath, 'GET__api_books_{id}.yaml'),
      yaml.dump(policy, { sortKeys: true }),
      'utf8',
    );

    const r = await runAudit(mixedDir);
    // 1 authentication + 1 authorization + 1 rateLimit + 1 denyUnknownFields
    // + 1 request.schema param + 1 response.stripUnknownFields = 6.
    assert.equal(r.controls, 6, 'all emitted control kinds are in the denominator');
  } finally {
    await fs.rm(mixedDir, { recursive: true, force: true });
  }
});

test('emit report headlines the audit cite proof', async () => {
  await runEmit(dir, { target: 'report' });
  const md = await fs.readFile(path.join(dir, '.x-security', 'report.md'), 'utf8');
  assert.ok(/Cite-backed/.test(md));
  assert.ok(/cite/i.test(md));
});
