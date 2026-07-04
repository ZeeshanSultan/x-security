import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import {
  loadEnv,
  EnvLoadError,
  DEV_SENTINELS,
  DatabaseUrl,
  RedisUrl,
  StrongSecret,
  Base64Key32,
  HexKey32,
  Port,
} from "../src/env.js";

test("loadEnv: happy path", () => {
  const env = loadEnv(z.object({ FOO: z.string(), PORT: Port }), {
    source: { FOO: "bar", PORT: "3000" },
  });
  assert.equal(env.FOO, "bar");
  assert.equal(env.PORT, 3000);
});

test("loadEnv: missing required var throws with path", () => {
  assert.throws(
    () => loadEnv(z.object({ FOO: z.string() }), { source: {} }),
    (err: unknown) => {
      assert.ok(err instanceof EnvLoadError);
      assert.match(err.message, /FOO/);
      return true;
    },
  );
});

test("loadEnv: dev sentinel rejected in production", () => {
  for (const sentinel of DEV_SENTINELS) {
    assert.throws(
      () =>
        loadEnv(z.object({ SECRET: z.string() }), {
          source: { SECRET: sentinel, NODE_ENV: "production" },
        }),
      (err: unknown) => {
        assert.ok(err instanceof EnvLoadError);
        assert.match(err.message, /dev-sentinel/);
        return true;
      },
    );
  }
});

test("loadEnv: dev sentinel allowed outside production", () => {
  const env = loadEnv(z.object({ SECRET: z.string() }), {
    source: { SECRET: "change-me-internal", NODE_ENV: "development" },
  });
  assert.equal(env.SECRET, "change-me-internal");
});

test("loadEnv: aliases resolve canonical from alternate name and warn", () => {
  const warnings: string[] = [];
  const env = loadEnv(z.object({ ENCRYPTION_KEY: z.string() }), {
    source: { OAUTH_ENC_KEY: "secret-value", NODE_ENV: "test" },
    aliases: { ENCRYPTION_KEY: ["OAUTH_ENC_KEY"] },
    warn: (m) => warnings.push(m),
  });
  assert.equal(env.ENCRYPTION_KEY, "secret-value");
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /OAUTH_ENC_KEY.*deprecated/);
});

test("loadEnv: canonical wins over alias when both set", () => {
  const env = loadEnv(z.object({ ENCRYPTION_KEY: z.string() }), {
    source: {
      ENCRYPTION_KEY: "canonical",
      OAUTH_ENC_KEY: "alias",
      NODE_ENV: "test",
    },
    aliases: { ENCRYPTION_KEY: ["OAUTH_ENC_KEY"] },
    warn: () => {},
  });
  assert.equal(env.ENCRYPTION_KEY, "canonical");
});

test("DatabaseUrl + RedisUrl fragments", () => {
  assert.equal(DatabaseUrl.safeParse("postgres://x:y@h/db").success, true);
  assert.equal(DatabaseUrl.safeParse("mysql://x@h/db").success, false);
  assert.equal(RedisUrl.safeParse("redis://h:6379").success, true);
  assert.equal(RedisUrl.safeParse("rediss://h:6380").success, true);
  assert.equal(RedisUrl.safeParse("memcached://h").success, false);
});

test("StrongSecret fragment", () => {
  assert.equal(StrongSecret.safeParse("a".repeat(32)).success, true);
  assert.equal(StrongSecret.safeParse("a".repeat(31)).success, false);
});

test("Base64Key32 + HexKey32 fragments", () => {
  // 32 bytes → 44 chars base64
  assert.equal(Base64Key32.safeParse("A".repeat(43) + "=").success, true);
  assert.equal(Base64Key32.safeParse("A".repeat(43)).success, true);
  assert.equal(Base64Key32.safeParse("A".repeat(40)).success, false);
  assert.equal(HexKey32.safeParse("0".repeat(64)).success, true);
  assert.equal(HexKey32.safeParse("0".repeat(63)).success, false);
  assert.equal(HexKey32.safeParse("X".repeat(64)).success, false);
});

test("Port fragment coerces strings", () => {
  assert.equal(Port.parse("3000"), 3000);
  assert.equal(Port.safeParse("70000").success, false);
  assert.equal(Port.safeParse("0").success, false);
});
