// Drift guard: the SCHEMA_VERSION runtime constant MUST match the version
// embedded in x-security.schema.json's $id. They are read from different
// places by different consumers (TS code reads the constant, Spectral / AJV
// JSON tools read $id), so a drift between the two has historically caused
// silent compat failures.

import test from 'node:test';
import assert from 'node:assert/strict';
import { SCHEMA_VERSION, extractSchemaVersionFromId, xSecuritySchema } from '../src/index.js';

test('SCHEMA_VERSION matches version embedded in $id', () => {
  const id = (xSecuritySchema as { $id: string }).$id;
  const fromId = extractSchemaVersionFromId(id);
  assert.ok(fromId, `Could not parse version from $id: ${id}`);
  assert.equal(SCHEMA_VERSION, fromId, `SCHEMA_VERSION (${SCHEMA_VERSION}) does not match $id version (${fromId} from ${id}). Bump one to match the other.`);
});

test('extractSchemaVersionFromId handles both major.minor and major.minor.patch', () => {
  assert.equal(extractSchemaVersionFromId('https://usewaf.com/schemas/x-security/v0.5.json'), '0.5.0');
  assert.equal(extractSchemaVersionFromId('https://usewaf.com/schemas/x-security/v1.2.3.json'), '1.2.3');
  assert.equal(extractSchemaVersionFromId('not-a-real-id'), null);
});
