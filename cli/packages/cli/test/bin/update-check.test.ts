import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isNewer, resolvePackageMeta, fetchLatestVersion } from '../../src/bin/update-check.ts';

test('isNewer: patch bump is newer', () => {
  assert.equal(isNewer('0.2.0', '0.1.9'), true);
});

test('isNewer: equal versions are not newer', () => {
  assert.equal(isNewer('0.1.0', '0.1.0'), false);
});

test('isNewer: current ahead of latest is not newer', () => {
  assert.equal(isNewer('0.1.0', '0.2.0'), false);
});

test('isNewer: prerelease suffixes do not throw', () => {
  assert.doesNotThrow(() => isNewer('1.0.0-beta.1', '1.0.0'));
  assert.doesNotThrow(() => isNewer('1.0.0', '1.0.0-beta.1'));
});

test('resolvePackageMeta: returns name/version from shipped package.json', () => {
  const meta = resolvePackageMeta();
  assert.equal(typeof meta.name, 'string');
  assert.equal(typeof meta.version, 'string');
  assert.ok(meta.name.length > 0);
  assert.ok(meta.version.length > 0);
});

test('fetchLatestVersion: never throws, even for a nonexistent package or offline', async () => {
  const result = await fetchLatestVersion('this-package-does-not-exist-zzz', 200);
  assert.ok(result === null || typeof result === 'string');
});
