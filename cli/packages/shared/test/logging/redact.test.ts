import { test } from "node:test";
import assert from "node:assert/strict";
import { REDACT_PATHS, redactConfig, scrubString } from "../../src/logging/redact.js";

test("REDACT_PATHS includes the high-risk shapes", () => {
  // Sanity: the paths we explicitly care about must be present.
  const expected = [
    "*.token",
    "*.apiKey",
    "*.headers.authorization",
    "*.config.headers.authorization",
    "*.slackWebhookUrl",
    "*.encrypted_token",
    "*.access_token_enc",
    "headers.authorization",
  ];
  for (const p of expected) {
    assert.ok(REDACT_PATHS.includes(p), `missing redact path: ${p}`);
  }
});

test("redactConfig is a frozen-shaped pino option", () => {
  assert.equal(redactConfig.censor, "[Redacted]");
  assert.equal(redactConfig.remove, false);
  assert.ok(Array.isArray(redactConfig.paths));
});

test("scrubString redacts Slack webhook URLs", () => {
  const s =
    "POST failed for https://hooks.slack.com/services/T01234567/B98765432/abcdefABCDEF1234567890";
  const out = scrubString(s);
  assert.match(out, /\[Redacted Slack webhook\]/);
  assert.doesNotMatch(out, /hooks\.slack\.com/);
});

test("scrubString redacts bearer tokens", () => {
  const out = scrubString("auth failed: Bearer abcdef1234567890ABCDEF");
  assert.match(out, /Bearer \[Redacted\]/);
});

test("scrubString redacts GitHub tokens", () => {
  assert.match(scrubString("ghs_" + "A".repeat(40)), /\[Redacted gh token\]/);
  assert.match(scrubString("ghp_" + "B".repeat(40)), /\[Redacted gh token\]/);
  assert.match(scrubString("github_pat_" + "C".repeat(40)), /\[Redacted gh token\]/);
});

test("scrubString redacts Anthropic + OpenAI keys", () => {
  assert.match(scrubString("sk-ant-api01-" + "x".repeat(80)), /\[Redacted anthropic key\]/);
  // OpenAI sk- pattern (no -ant-) — the openai regex matches sk-<chars>
  assert.match(scrubString("sk-" + "y".repeat(40)), /\[Redacted openai key\]|\[Redacted anthropic key\]/);
});

test("scrubString redacts x-security session keys", () => {
  assert.match(scrubString("sk_session_" + "z".repeat(40)), /\[Redacted session key\]/);
});

test("scrubString preserves non-secret content", () => {
  const s = "Request 1234 to /api/users returned 200 in 45ms";
  assert.equal(scrubString(s), s);
});

test("scrubString handles empty + null-ish", () => {
  assert.equal(scrubString(""), "");
});
