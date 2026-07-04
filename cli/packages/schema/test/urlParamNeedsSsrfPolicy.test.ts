// W10-9 unit tests for the urlParamNeedsSsrfPolicy Spectral custom function.

import test from 'node:test';
import assert from 'node:assert/strict';
// @ts-expect-error — JS-only custom function, not part of TS rootDir
import urlParamNeedsSsrfPolicy from '../functions/urlParamNeedsSsrfPolicy.js';

test('passes when no schema is declared', () => {
  assert.equal(urlParamNeedsSsrfPolicy({}), undefined);
});

test('passes when url param has domainAllowlist', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: { url: { type: 'url', domainAllowlist: ['api.example.com'] } }
  });
  assert.equal(r, undefined);
});

test('passes when url param has blockPrivateRanges', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: { url: { type: 'url', blockPrivateRanges: true } }
  });
  assert.equal(r, undefined);
});

test('passes when param is not type=url', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: { name: { type: 'free-text', maxLength: 100 } }
  });
  assert.equal(r, undefined);
});

test('fails when url param lacks both domainAllowlist and blockPrivateRanges', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: { url: { type: 'url' } }
  });
  assert.ok(Array.isArray(r), 'expected error array');
  assert.match(r[0].message, /type=url without domainAllowlist or blockPrivateRanges/);
  assert.deepEqual(r[0].path, ['schema', 'url']);
});

test('fails when url param has empty domainAllowlist array', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: { redirect: { type: 'url', domainAllowlist: [] } }
  });
  assert.ok(Array.isArray(r));
  assert.match(r[0].message, /redirect/);
});

test('reports multiple offending params', () => {
  const r = urlParamNeedsSsrfPolicy({
    schema: {
      ok: { type: 'url', blockPrivateRanges: true },
      bad1: { type: 'url' },
      bad2: { type: 'url' }
    }
  });
  assert.ok(Array.isArray(r));
  assert.equal(r.length, 2);
});
