import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  xSecurityDir,
  legacyWritDir,
  resolveArtifactDir,
  resolvePoliciesDir,
  POLICIES_DIR,
} from '../src/commands/detect/store.js';

async function tmpRepo(): Promise<string> {
  return await fs.mkdtemp(path.join(os.tmpdir(), 'xsec-store-'));
}

test('resolveArtifactDir prefers canonical .x-security/', async () => {
  const repo = await tmpRepo();
  await fs.mkdir(xSecurityDir(repo), { recursive: true });
  assert.equal(await resolveArtifactDir(repo), xSecurityDir(repo));
});

test('resolveArtifactDir falls back to legacy .x-security/ when canonical absent', async () => {
  const repo = await tmpRepo();
  await fs.mkdir(legacyWritDir(repo), { recursive: true });
  assert.equal(await resolveArtifactDir(repo), legacyWritDir(repo));
});

test('resolveArtifactDir prefers canonical when BOTH exist (migration in progress)', async () => {
  const repo = await tmpRepo();
  await fs.mkdir(xSecurityDir(repo), { recursive: true });
  await fs.mkdir(legacyWritDir(repo), { recursive: true });
  assert.equal(await resolveArtifactDir(repo), xSecurityDir(repo));
});

test('resolveArtifactDir defaults to canonical when neither exists', async () => {
  const repo = await tmpRepo();
  assert.equal(await resolveArtifactDir(repo), xSecurityDir(repo));
});

test('resolvePoliciesDir reads policies seeded under legacy .x-security/policies/', async () => {
  const repo = await tmpRepo();
  const legacyPolicies = path.join(legacyWritDir(repo), POLICIES_DIR);
  await fs.mkdir(legacyPolicies, { recursive: true });
  await fs.writeFile(path.join(legacyPolicies, 'GET__ping.yaml'), 'authentication: { type: none }\n', 'utf8');
  const resolved = await resolvePoliciesDir(repo);
  assert.equal(resolved, legacyPolicies);
  const files = await fs.readdir(resolved);
  assert.deepEqual(files, ['GET__ping.yaml']);
});
