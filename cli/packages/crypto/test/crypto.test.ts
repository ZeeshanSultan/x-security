import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { encryptToBytes, decryptFromBytes, loadEncryptionKey } from "../src/index.js";

test("encryptToBytes → decryptFromBytes round-trips", () => {
  const key = randomBytes(32);
  const blob = encryptToBytes("hello world", key);
  assert.equal(decryptFromBytes(blob, key), "hello world");
});

test("encryptToBytes produces a fresh IV per call (non-deterministic ciphertext)", () => {
  const key = randomBytes(32);
  const a = encryptToBytes("same plaintext", key);
  const b = encryptToBytes("same plaintext", key);
  assert.notDeepEqual(a, b);
});

test("decryptFromBytes with wrong key throws", () => {
  const key = randomBytes(32);
  const other = randomBytes(32);
  const blob = encryptToBytes("secret", key);
  assert.throws(() => decryptFromBytes(blob, other));
});

test("decryptFromBytes on tampered ciphertext throws", () => {
  const key = randomBytes(32);
  const blob = encryptToBytes("secret payload", key);
  // Flip a bit in the ciphertext region (after iv+tag = 28 bytes).
  blob[blob.length - 1] = blob[blob.length - 1]! ^ 0x01;
  assert.throws(() => decryptFromBytes(blob, key));
});

test("decryptFromBytes on truncated blob throws", () => {
  const key = randomBytes(32);
  assert.throws(() => decryptFromBytes(Buffer.alloc(5), key));
});

test("encryptToBytes rejects wrong-length key", () => {
  assert.throws(() => encryptToBytes("x", Buffer.alloc(16)));
});

test("loadEncryptionKey reads WRIT_ENCRYPTION_KEY", () => {
  const raw = randomBytes(32).toString("base64");
  const key = loadEncryptionKey({ WRIT_ENCRYPTION_KEY: raw } as NodeJS.ProcessEnv);
  assert.equal(key.length, 32);
});

test("loadEncryptionKey throws when missing", () => {
  assert.throws(() => loadEncryptionKey({} as NodeJS.ProcessEnv), /not set/);
});

test("loadEncryptionKey throws when wrong length", () => {
  const raw = Buffer.alloc(16).toString("base64");
  assert.throws(
    () => loadEncryptionKey({ WRIT_ENCRYPTION_KEY: raw } as NodeJS.ProcessEnv),
    /16 bytes/,
  );
});
