// Unit tests for the extracted V1–V7 verifier core + cite byte-match (V6).
// These guard the detect-core extraction against drift from the llm-agent
// source the closure was copied from.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  snapQuoteToFile,
  evaluateV6ForEmission,
  checkTightness,
  discoverHandlerParams,
  runVerifiers,
  type AgentOutput,
  type PolicyEmission,
} from '../src/index.js';

let dir: string;
const FILE = 'handler.js';

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-verify-'));
  const src = [
    'function addUser(req, res) {',                                  // 1
    "  const user = new User(req.body.name, parseInt(req.body.level));", // 2
    '}',                                                             // 3
    'function ping(req, res) {',                                     // 4
    "  require('child_process').exec('ping ' + req.body.target);",   // 5
    '}',                                                             // 6
  ].join('\n');
  await fs.writeFile(path.join(dir, FILE), src);
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('V6: snapQuoteToFile snaps a real quote cited at the wrong line', async () => {
  const snap = await snapQuoteToFile(
    dir,
    FILE,
    "require('child_process').exec('ping ' + req.body.target);",
    1, // wrong hint line
  );
  assert.ok(snap, 'real quote located despite wrong cited line');
  assert.equal(snap.lineStart, 5);
});

test('V6: snapQuoteToFile returns null for a fabricated quote (D-3)', async () => {
  const snap = await snapQuoteToFile(dir, FILE, "exec('rm -rf ' + neverWritten)", 5);
  assert.equal(snap, null);
});

test('V6: evaluateV6ForEmission keeps a byte-matching cite, drops a fabricated one', async () => {
  const emission: PolicyEmission = {
    endpointId: 'POST /ping',
    policy: null,
    reviewRequired: true,
    assumptions: [
      {
        field: 'request.schema.target.injectionGuard',
        assumption: 'os-command sink',
        confidence: 'high',
        cite: { file: FILE, lineStart: 5, lineEnd: 5, quote: "require('child_process').exec('ping ' + req.body.target);" },
      },
      {
        field: 'request.schema.x.injectionGuard',
        assumption: 'fabricated',
        confidence: 'high',
        cite: { file: FILE, lineStart: 5, lineEnd: 5, quote: 'this text is not in the file' },
      },
    ],
  };
  const r = await evaluateV6ForEmission(emission, dir);
  assert.equal(r.kept.length, 1);
  assert.equal(r.kept[0]!.field, 'request.schema.target.injectionGuard');
  assert.ok(r.droppedReasons.length >= 1);
});

test('V6 cascade: a dropped controlHint-bearing cite revokes its materialized control (D-3, non-schema kinds)', async () => {
  // Regression: before the cascade covered all kinds, an authorization control
  // whose justifying cite failed byte-match survived UNCITED (the cascade only
  // inspected request/response.schema.* params). An orphaned ownership rule
  // enforced with no evidence is exactly what D-3 forbids.
  const emission: PolicyEmission = {
    endpointId: 'PUT /users/:username/password',
    policy: {
      authorization: {
        type: 'rule-based',
        rules: [{ field: 'request.params.username', operator: 'equals', value: { ref: 'jwt.username' } }],
      },
    } as PolicyEmission['policy'],
    reviewRequired: false,
    assumptions: [
      {
        field: 'authorization',
        assumption: 'ownership rule for BOLA',
        confidence: 'high',
        // fabricated quote — does NOT byte-match the file
        cite: { file: FILE, lineStart: 2, lineEnd: 2, quote: 'this ownership check was never written' },
        controlHint: { kind: 'authorization', param: 'username', principalRef: 'jwt.username', operator: 'equals' },
      },
    ],
  };
  const r = await evaluateV6ForEmission(emission, dir);
  assert.equal(r.kept.length, 0, 'fabricated cite is dropped');
  assert.ok(r.cascadeReasons.length > 0, 'the now-uncited authorization control must be revoked, not left enforced');
  assert.match(r.cascadeReasons[0]!, /authorization/);
});

test('V3: checkTightness rejects a bare string, accepts a bounded one', () => {
  assert.ok(checkTightness({ type: 'string' }), 'bare string is theatre');
  assert.equal(checkTightness({ type: 'string', minLength: 1, maxLength: 64 }), null);
  assert.equal(checkTightness({ type: 'free-text', maxLength: 8192 }), null);
  assert.ok(checkTightness({ type: 'integer' }), 'integer needs min+max');
});

test('V2: Flask request.args.get captures the field name, NOT the `get` method or the Authorization header', async () => {
  // Regression: discoverHandlerParams mis-captured `request.args.get('x')` as the
  // method `get`, and `request.headers.get('Authorization')` as a param. Both
  // became "uncovered params" → false demotes (VAmPI 7/9 → 4/9 incident).
  const py = [
    'from flask import request',                            // 1
    '',                                                     // 2
    'def update_password(username):',                       // 3
    "    token = request.headers.get('Authorization')",    // 4
    "    pw = request.args.get('password')",               // 5
    "    fmt = request.form['format']",                    // 6
    '    return pw',                                        // 7
  ].join('\n');
  await fs.writeFile(path.join(dir, 'flask_handler.py'), py);
  const d = await discoverHandlerParams(dir, 'flask_handler.py', {
    handlerSymbol: 'update_password',
    sourceLine: 3,
  });
  const params = [...d.params].sort();
  assert.deepEqual(params, ['format', 'password'], `got ${JSON.stringify(params)}`);
  assert.ok(!d.params.has('get'), 'method name `get` must not be a param');
  assert.ok(!d.params.has('Authorization'), 'Authorization header must not be a param');
  assert.ok(d.scoped, 'handler span should resolve');
});

test('handler-scoping: a sibling Python handler field never leaks', async () => {
  const py = [
    'from flask import request',                       // 1
    '',                                                // 2
    'def handler_a():',                                // 3
    "    a = request.args.get('alpha')",               // 4
    '    return a',                                     // 5
    '',                                                // 6
    'def handler_b():',                                // 7
    "    b = request.args.get('beta')",                // 8
    '    return b',                                     // 9
  ].join('\n');
  await fs.writeFile(path.join(dir, 'siblings.py'), py);
  const a = await discoverHandlerParams(dir, 'siblings.py', { handlerSymbol: 'handler_a', sourceLine: 3 });
  const b = await discoverHandlerParams(dir, 'siblings.py', { handlerSymbol: 'handler_b', sourceLine: 7 });
  assert.deepEqual([...a.params], ['alpha']);
  assert.deepEqual([...b.params], ['beta']);
});

test('runVerifiers: a null-policy emission composes to a clean pass', async () => {
  const output: AgentOutput = {
    routeInventory: [{ method: 'GET', path: '/health', sourceFile: FILE, sourceLine: 1 }],
    profiles: {},
    emissions: [
      { endpointId: 'GET /health', policy: null, reviewRequired: true, assumptions: [] },
    ],
    coverage: { filesRead: [], grepQueriesIssued: [] },
  };
  const r = await runVerifiers({ output, repoDir: dir });
  const composed = r.composedByEndpoint.get('GET /health');
  assert.ok(composed);
  assert.equal(composed!.verdict, 'pass');
});
