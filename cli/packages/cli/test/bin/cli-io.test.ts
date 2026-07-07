import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { Readable } from 'node:stream';
import * as path from 'node:path';
import { resolveSpecArg, makeDiagnostics, _cleanupTempSpecs } from '../../src/bin/cli-io.js';

test('resolveSpecArg: non-dash arg is returned unchanged', async () => {
  const p = await resolveSpecArg('some/path.yaml');
  assert.equal(p, 'some/path.yaml');
});

test('resolveSpecArg: "-" reads stdin and writes it to a temp file', async () => {
  const text = 'openapi: 3.0.0\n';
  const mockStream = Readable.from([text]);
  const p = await resolveSpecArg('-', mockStream);
  // resolveSpecArg trims the piped content, so compare against the trimmed form.
  assert.equal(fs.readFileSync(p, 'utf8'), text.trim());
});

test('resolveSpecArg: "-" temp dir is removed by _cleanupTempSpecs', async () => {
  const mockStream = Readable.from(['openapi: 3.0.0\n']);
  const p = await resolveSpecArg('-', mockStream);
  assert.equal(fs.existsSync(p), true);

  _cleanupTempSpecs();

  assert.equal(fs.existsSync(p), false);
  assert.equal(fs.existsSync(path.dirname(p)), false);
});

test('resolveSpecArg: "-" with empty stdin throws', async () => {
  const emptyStream = Readable.from(['']);
  await assert.rejects(
    () => resolveSpecArg('-', emptyStream),
    /expected a spec document on stdin, got empty input/
  );
});

test('makeDiagnostics: quiet suppresses warn', () => {
  const original = process.stderr.write;
  let written = '';
  process.stderr.write = ((chunk: string) => {
    written += chunk;
    return true;
  }) as typeof process.stderr.write;
  try {
    makeDiagnostics('quiet').warn('warning: nope');
  } finally {
    process.stderr.write = original;
  }
  assert.equal(written, '');
});

test('makeDiagnostics: normal emits warn to stderr', () => {
  const original = process.stderr.write;
  let written = '';
  process.stderr.write = ((chunk: string) => {
    written += chunk;
    return true;
  }) as typeof process.stderr.write;
  try {
    makeDiagnostics('normal').warn('warning: heads up');
  } finally {
    process.stderr.write = original;
  }
  assert.equal(written, 'warning: heads up\n');
});

test('makeDiagnostics: verbose emits info, normal does not', () => {
  const original = process.stderr.write;
  let written = '';
  process.stderr.write = ((chunk: string) => {
    written += chunk;
    return true;
  }) as typeof process.stderr.write;
  try {
    makeDiagnostics('verbose').info('info: details');
    assert.equal(written, 'info: details\n');

    written = '';
    makeDiagnostics('normal').info('info: details');
    assert.equal(written, '');
  } finally {
    process.stderr.write = original;
  }
});
