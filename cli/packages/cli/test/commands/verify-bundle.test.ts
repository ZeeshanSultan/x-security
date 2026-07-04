import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { generateEd25519Keypair, signEd25519 } from '@writ/crypto';
import { runVerifyBundle } from '../../src/commands/verify-bundle.js';

// Build a valid tarball into a fresh tmpdir and return the artifact paths.
// Returns:
//   tarball     — path to the .tar.gz
//   workdir     — the directory that was packed (so tests can mutate + repack)
//   pubKeyPath  — path to the SPKI PEM file
//   privKeyPem  — raw private key PEM (for re-signing in mutation tests)
function buildBundle(): {
  tarball: string;
  workdir: string;
  pubKeyPath: string;
  privKeyPem: string;
} {
  const { privateKeyPem, publicKeyPem } = generateEd25519Keypair();

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'writ-bundle-test-'));
  const workdir = path.join(tmp, 'bundle');
  fs.mkdirSync(workdir, { recursive: true });
  fs.mkdirSync(path.join(workdir, 'config'), { recursive: true });

  const kongYml = '_format_version: "3.0"\nservices: []\n';
  const readme = '# Writ bundle\n';
  fs.writeFileSync(path.join(workdir, 'config', 'kong.yml'), kongYml);
  fs.writeFileSync(path.join(workdir, 'README.md'), readme);

  const manifest = {
    target: 'kong',
    specHash: 'sha256:deadbeef',
    generatorVersion: '0.1.0',
    timestamp: '2026-05-15T00:00:00Z',
    files: {
      'config/kong.yml': 'sha256:' + createHash('sha256').update(kongYml).digest('hex'),
      'README.md': 'sha256:' + createHash('sha256').update(readme).digest('hex')
    }
  };
  // Serialize once and use the EXACT bytes for both packing and signing —
  // the verifier reads the on-disk bytes as the canonical form.
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2), 'utf8');
  fs.writeFileSync(path.join(workdir, 'manifest.json'), manifestBytes);

  const sig = signEd25519(privateKeyPem, manifestBytes);
  fs.writeFileSync(path.join(workdir, 'writ.sig'), sig);

  const pubKeyPath = path.join(tmp, 'pubkey.pem');
  fs.writeFileSync(pubKeyPath, publicKeyPem);

  const tarball = path.join(tmp, 'writ-bundle-kong-deadbeef.tar.gz');
  const result = spawnSync('tar', ['-czf', tarball, '-C', workdir, '.'], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.status !== 0) {
    throw new Error(`tar failed: ${result.stderr.toString()}`);
  }

  return { tarball, workdir, pubKeyPath, privKeyPem: privateKeyPem };
}

function repack(workdir: string, tarball: string): void {
  fs.rmSync(tarball, { force: true });
  const result = spawnSync('tar', ['-czf', tarball, '-C', workdir, '.'], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  if (result.status !== 0) {
    throw new Error(`tar repack failed: ${result.stderr.toString()}`);
  }
}

test('verify-bundle: happy path returns exit 0', async () => {
  const { tarball, pubKeyPath } = buildBundle();
  const r = await runVerifyBundle(tarball, { publicKeyPath: pubKeyPath });
  assert.equal(r.exitCode, 0, `expected exit 0, got ${r.exitCode}: ${r.message}`);
  assert.equal(r.target, 'kong');
  assert.equal(r.filesVerified, 2);
  assert.ok(r.publicKeyFingerprint, 'expected a fingerprint on success');
  assert.equal(r.publicKeyFingerprint!.length, 16);
});

test('verify-bundle: tampered file content -> exit 2', async () => {
  const { tarball, workdir, pubKeyPath } = buildBundle();
  // Flip a byte in config/kong.yml AFTER manifest.json was hashed.
  const kongPath = path.join(workdir, 'config', 'kong.yml');
  const original = fs.readFileSync(kongPath);
  const tampered = Buffer.from(original);
  // Flip the low bit of the first byte — guaranteed to change the hash
  // without making the file unreadable.
  tampered[0] = (tampered[0]! ^ 0x01) & 0xff;
  fs.writeFileSync(kongPath, tampered);
  repack(workdir, tarball);

  const r = await runVerifyBundle(tarball, { publicKeyPath: pubKeyPath });
  assert.equal(r.exitCode, 2, `expected exit 2 (hash mismatch), got ${r.exitCode}: ${r.message}`);
});

test('verify-bundle: tampered manifest with stale signature -> exit 3', async () => {
  const { tarball, workdir, pubKeyPath } = buildBundle();
  // Mutate manifest.json without re-signing. The file hashes inside it
  // still match the payload (we only touch a non-hash field), so file-hash
  // verification passes and the signature check is what catches the tamper.
  const manifestPath = path.join(workdir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.timestamp = '2099-01-01T00:00:00Z';
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  repack(workdir, tarball);

  const r = await runVerifyBundle(tarball, { publicKeyPath: pubKeyPath });
  assert.equal(r.exitCode, 3, `expected exit 3 (sig mismatch), got ${r.exitCode}: ${r.message}`);
});

test('verify-bundle: tampered signature -> exit 3', async () => {
  const { tarball, workdir, pubKeyPath } = buildBundle();
  const sigPath = path.join(workdir, 'writ.sig');
  const sig = fs.readFileSync(sigPath);
  const tampered = Buffer.from(sig);
  tampered[0] = (tampered[0]! ^ 0x01) & 0xff;
  fs.writeFileSync(sigPath, tampered);
  repack(workdir, tarball);

  const r = await runVerifyBundle(tarball, { publicKeyPath: pubKeyPath });
  assert.equal(r.exitCode, 3, `expected exit 3 (sig mismatch), got ${r.exitCode}: ${r.message}`);
});

test('verify-bundle: missing tarball -> exit 1', async () => {
  const r = await runVerifyBundle('/nonexistent/writ-bundle.tar.gz');
  assert.equal(r.exitCode, 1);
});
