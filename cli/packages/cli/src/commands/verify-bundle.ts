// `lazy verify-bundle <tarball> [--public-key <pem-path>]`
//
// Verifies a Writ release bundle:
//
//   writ-bundle-<target>-<specHash>.tar.gz
//     manifest.json   { target, specHash, generatorVersion, timestamp, files: { "<rel>": "sha256:<hex>" } }
//     config/         generator output (one or more files)
//     README.md
//     writ.sig  raw Ed25519 detached signature over the exact UTF-8
//                     bytes of manifest.json as packed in the tarball.
//
// Exit codes:
//   0  — bundle verified
//   1  — usage / IO / tarball-structure error
//   2  — file content hash mismatch (tampered payload)
//   3  — manifest signature invalid (tampered manifest or signature)

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyEd25519 } from '@writ/crypto';
import { BUNDLE_VERIFY_PUBLIC_KEY } from './verify-bundle-pubkey.js';

export interface VerifyBundleOptions {
  publicKeyPath?: string | undefined;
}

export interface VerifyBundleResult {
  exitCode: 0 | 1 | 2 | 3;
  /** Human-readable message; printed to stdout on success, stderr on failure. */
  message: string;
  /** Populated on success: number of file entries the manifest covered. */
  filesVerified?: number;
  /** Populated on success: target name from manifest. */
  target?: string;
  /** Populated on success: first 16 hex chars of sha256(pubkey PEM bytes). */
  publicKeyFingerprint?: string;
}

interface Manifest {
  target: string;
  specHash: string;
  generatorVersion: string;
  timestamp: string;
  files: Record<string, string>;
}

const MANIFEST = 'manifest.json';
const SIG = 'writ.sig';

/**
 * Verify a Writ release bundle. Library-style entrypoint: never throws
 * on verification failure — returns a `VerifyBundleResult` with an exit code
 * the CLI wrapper can pass to `process.exit`.
 */
export async function runVerifyBundle(
  tarballPath: string,
  opts: VerifyBundleOptions = {}
): Promise<VerifyBundleResult> {
  if (!tarballPath) {
    return { exitCode: 1, message: 'verify-bundle: tarball path required' };
  }
  if (!fs.existsSync(tarballPath)) {
    return { exitCode: 1, message: `verify-bundle: tarball not found: ${tarballPath}` };
  }

  // Resolve the public key.
  let pubKeyPem: string;
  if (opts.publicKeyPath) {
    if (!fs.existsSync(opts.publicKeyPath)) {
      return {
        exitCode: 1,
        message: `verify-bundle: public key file not found: ${opts.publicKeyPath}`
      };
    }
    pubKeyPem = fs.readFileSync(opts.publicKeyPath, 'utf8');
  } else {
    pubKeyPem = BUNDLE_VERIFY_PUBLIC_KEY;
  }

  // Extract to a private tmp dir. We use `tar -xzf` rather than adding a
  // dependency; bsdtar (macOS) and GNU tar (Linux) both accept these flags
  // and both auto-detect gzip.
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'writ-verify-'));
  try {
    await extractTarball(tarballPath, tmpdir);

    const manifestPath = path.join(tmpdir, MANIFEST);
    const sigPath = path.join(tmpdir, SIG);

    if (!fs.existsSync(manifestPath)) {
      return { exitCode: 1, message: `verify-bundle: ${MANIFEST} missing from bundle` };
    }
    if (!fs.existsSync(sigPath)) {
      return { exitCode: 1, message: `verify-bundle: ${SIG} missing from bundle` };
    }

    // Read the EXACT bytes of the manifest as packed — canonicalization is
    // "the bytes of manifest.json as written". Re-serializing JSON would lose
    // whitespace/key-order, breaking the signature.
    const manifestBytes = fs.readFileSync(manifestPath);
    const sigBytes = fs.readFileSync(sigPath);

    let manifest: Manifest;
    try {
      manifest = JSON.parse(manifestBytes.toString('utf8')) as Manifest;
    } catch (e) {
      return {
        exitCode: 1,
        message: `verify-bundle: ${MANIFEST} is not valid JSON: ${(e as Error).message}`
      };
    }
    if (!manifest || typeof manifest !== 'object' || !manifest.files) {
      return { exitCode: 1, message: `verify-bundle: ${MANIFEST} missing required field "files"` };
    }

    // 1. Verify per-file content hashes BEFORE signature. A payload swap is
    //    detected here even if the signature happens to match (it won't,
    //    since the manifest covers the hashes — but we surface the more
    //    actionable error first).
    for (const [relPath, expected] of Object.entries(manifest.files)) {
      if (!expected.startsWith('sha256:')) {
        return {
          exitCode: 1,
          message: `verify-bundle: unsupported hash algorithm for ${relPath}: ${expected}`
        };
      }
      const expectedHex = expected.slice('sha256:'.length).toLowerCase();
      const filePath = path.join(tmpdir, relPath);
      if (!fs.existsSync(filePath)) {
        process.stderr.write(`hash mismatch: ${relPath} (missing from bundle)\n`);
        return { exitCode: 2, message: `verify-bundle: file missing: ${relPath}` };
      }
      const actual = createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
      if (actual !== expectedHex) {
        process.stderr.write(`hash mismatch: ${relPath}\n  expected sha256:${expectedHex}\n  actual   sha256:${actual}\n`);
        return { exitCode: 2, message: `verify-bundle: hash mismatch on ${relPath}` };
      }
    }

    // 2. Verify the Ed25519 signature over the manifest bytes.
    let sigValid = false;
    try {
      sigValid = verifyEd25519(pubKeyPem, manifestBytes, sigBytes);
    } catch (e) {
      return {
        exitCode: 3,
        message: `verify-bundle: signature verification error: ${(e as Error).message}`
      };
    }
    if (!sigValid) {
      return { exitCode: 3, message: 'verify-bundle: signature does not match manifest' };
    }

    const fingerprint = createHash('sha256')
      .update(Buffer.from(pubKeyPem, 'utf8'))
      .digest('hex')
      .slice(0, 16);
    const fileCount = Object.keys(manifest.files).length;

    return {
      exitCode: 0,
      message: `OK: ${manifest.target} bundle, ${fileCount} file(s) verified\npubkey fingerprint: ${fingerprint}`,
      filesVerified: fileCount,
      target: manifest.target,
      publicKeyFingerprint: fingerprint
    };
  } finally {
    // Best-effort cleanup. Verification result is independent of cleanup
    // success — a leftover tmpdir is a nuisance, not a correctness bug.
    try {
      fs.rmSync(tmpdir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

function extractTarball(tarballPath: string, destDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('tar', ['-xzf', tarballPath, '-C', destDir], {
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`tar exited with code ${code}: ${stderr.trim()}`));
      }
    });
  });
}
