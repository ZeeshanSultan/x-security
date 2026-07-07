// AES-256-GCM helpers for at-rest encryption of secrets (e.g. Cloudflare API
// tokens, GitHub App installation tokens). Single-blob serialization:
//
//   layout: iv(12) ∥ tag(16) ∥ ciphertext(N)
//
// All callers MUST persist the entire returned Buffer; truncation breaks GCM
// authentication. Decrypt failures throw — never swallow.
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

export function encryptToBytes(plaintext: string, key: Buffer): Buffer {
  if (key.length !== KEY_LEN) {
    throw new Error(`encryptToBytes: key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

export function decryptFromBytes(blob: Buffer, key: Buffer): string {
  if (key.length !== KEY_LEN) {
    throw new Error(`decryptFromBytes: key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (blob.length < IV_LEN + TAG_LEN + 1) {
    throw new Error("decryptFromBytes: blob too short to contain iv+tag+ciphertext");
  }
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = blob.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

/**
 * Load the 32-byte symmetric key from `WRIT_ENCRYPTION_KEY` (base64).
 * Throws if missing or wrong length. Call once at boot and cache.
 */
export function loadEncryptionKey(env: NodeJS.ProcessEnv = process.env): Buffer {
  const raw = env.X_SECURITY_ENCRYPTION_KEY ?? env.WRIT_ENCRYPTION_KEY;
  if (!raw || raw.length === 0) {
    throw new Error(
      "WRIT_ENCRYPTION_KEY not set; required for at-rest secret encryption. " +
        "Generate with: openssl rand -base64 32",
    );
  }
  // PR-M6: Buffer.from(x, "base64") silently truncates at the first invalid
  // char — a typo'd key may decode to fewer than 32 bytes of garbage AND
  // pass any naive length check. Round-trip the decoded buffer back to
  // base64 and require it matches the input (ignoring trailing padding).
  // This catches stray whitespace, hex misencoding, accidental quotes.
  let key: Buffer;
  try {
    key = Buffer.from(raw, "base64");
  } catch {
    throw new Error("WRIT_ENCRYPTION_KEY: invalid base64");
  }
  const reencoded = key.toString("base64");
  if (stripPadding(reencoded) !== stripPadding(raw.trim())) {
    throw new Error(
      "WRIT_ENCRYPTION_KEY: not valid base64 (round-trip mismatch). " +
        "Generate with: openssl rand -base64 32",
    );
  }
  if (key.length !== KEY_LEN) {
    throw new Error(
      `WRIT_ENCRYPTION_KEY: decoded to ${key.length} bytes, expected ${KEY_LEN}`,
    );
  }
  return key;
}

function stripPadding(s: string): string {
  return s.replace(/=+$/, "");
}

// -----------------------------------------------------------------------------
// Ed25519 detached-signature helpers. Used for signing artifacts (e.g. drift
// receipts, audit attestations) where a recipient must verify origin without a
// shared secret. PEM-encoded keys keep the on-disk format human-inspectable and
// compatible with `openssl` tooling.
// -----------------------------------------------------------------------------

/**
 * Sign `bytes` with an Ed25519 private key (PKCS#8 PEM). Returns the raw
 * 64-byte detached signature.
 */
export function signEd25519(privKeyPem: string, bytes: Buffer): Buffer {
  const privateKey = createPrivateKey(privKeyPem);
  // Ed25519 uses null algorithm — the curve dictates the hash (SHA-512 internal).
  return sign(null, bytes, privateKey);
}

/**
 * Verify a detached Ed25519 signature against `bytes` using a public key
 * (SPKI PEM). Returns true on valid signature, false otherwise. Never throws
 * on signature mismatch — only on malformed key material.
 */
export function verifyEd25519(pubKeyPem: string, bytes: Buffer, sig: Buffer): boolean {
  const publicKey = createPublicKey(pubKeyPem);
  return verify(null, bytes, publicKey, sig);
}

/**
 * Generate a fresh Ed25519 keypair, returning PEM-encoded strings suitable for
 * persistence. Private key uses PKCS#8, public key uses SPKI.
 */
export function generateEd25519Keypair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return {
    privateKeyPem: privateKey as string,
    publicKeyPem: publicKey as string,
  };
}
