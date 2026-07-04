import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { generateEd25519Keypair, signEd25519, verifyEd25519 } from "./index.js";

test("ed25519 round-trip: generated keypair signs and verifies 100 random bytes", () => {
  const { privateKeyPem, publicKeyPem } = generateEd25519Keypair();
  const payload = randomBytes(100);
  const sig = signEd25519(privateKeyPem, payload);
  assert.equal(sig.length, 64, "Ed25519 detached signature is 64 bytes");
  assert.equal(verifyEd25519(publicKeyPem, payload, sig), true);
});

test("ed25519 tampered payload: flipping one byte invalidates the signature", () => {
  const { privateKeyPem, publicKeyPem } = generateEd25519Keypair();
  const payload = randomBytes(100);
  const sig = signEd25519(privateKeyPem, payload);
  const tampered = Buffer.from(payload);
  tampered[0] = tampered[0]! ^ 0x01;
  assert.equal(verifyEd25519(publicKeyPem, tampered, sig), false);
});

test("ed25519 wrong public key: verifying with another key's public part fails", () => {
  const keyA = generateEd25519Keypair();
  const keyB = generateEd25519Keypair();
  const payload = randomBytes(100);
  const sig = signEd25519(keyA.privateKeyPem, payload);
  assert.equal(verifyEd25519(keyB.publicKeyPem, payload, sig), false);
});

test("ed25519 tampered signature: flipping one byte in the sig invalidates verify", () => {
  const { privateKeyPem, publicKeyPem } = generateEd25519Keypair();
  const payload = randomBytes(100);
  const sig = signEd25519(privateKeyPem, payload);
  const tamperedSig = Buffer.from(sig);
  tamperedSig[0] = tamperedSig[0]! ^ 0x01;
  assert.equal(verifyEd25519(publicKeyPem, payload, tamperedSig), false);
});
