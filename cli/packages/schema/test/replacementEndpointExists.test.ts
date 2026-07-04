// Unit tests for the Spectral custom function. We exercise the function
// directly rather than going through Spectral's loader — Spectral itself is
// a heavyweight dep, and the function is pure modulo `context.document.data`.

import test from 'node:test';
import assert from 'node:assert/strict';
// @ts-expect-error — the custom function is JS-only and not part of TS rootDir
import replacementEndpointExists from '../functions/replacementEndpointExists.js';

function ctx(paths: Record<string, unknown>) {
  return { document: { data: { paths } } };
}

test('passes when replacementEndpoint exactly matches a declared path', () => {
  const r = replacementEndpointExists('/api/v2/users', undefined, ctx({ '/api/v2/users': {}, '/api/v1/users': {} }));
  assert.equal(r, undefined);
});

test('passes when replacementEndpoint structurally matches a path (different param names)', () => {
  // Templated equivalence: /users/{id} ↔ /users/{userId}
  const r = replacementEndpointExists('/users/{userId}', undefined, ctx({ '/users/{id}': {} }));
  assert.equal(r, undefined);
});

test('fails when replacementEndpoint does not match any declared path', () => {
  const r = replacementEndpointExists('/api/v2/users', undefined, ctx({ '/api/v1/users': {} }));
  assert.ok(Array.isArray(r), 'expected error array');
  assert.match(r[0].message, /does not match any path/);
});

test('fails when targetVal is empty or missing', () => {
  const r = replacementEndpointExists('', undefined, ctx({ '/x': {} }));
  assert.ok(Array.isArray(r));
});

test('fails informatively when document has no paths section', () => {
  // @ts-expect-error — deliberately broken context
  const r = replacementEndpointExists('/x', undefined, { document: { data: {} } });
  assert.ok(Array.isArray(r));
  assert.match(r[0].message, /no `paths` section/);
});
