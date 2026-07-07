// Unit tests for the pure `computeDiff` function exposed at
// `@x-security/shared/validation`. Uses node:test (matches the rest of the
// shared package — node --test --import tsx).
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeDiff, regressionCount } from "../src/validation.js";

const baseAttempt = {
  attackClass: "bola",
  payloadName: "p1",
  method: "GET",
  path: "/users/42",
} as const;

test("first run: everything counts as 'unchanged' baseline; no diffs", () => {
  const diff = computeDiff({
    previous: null,
    current: {
      endpoints: [{ method: "GET", path: "/users/42" }],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
  });
  assert.equal(diff.newlyFailing.length, 0);
  assert.equal(diff.newlyPassing.length, 0);
  assert.equal(diff.unchanged, 1);
  assert.equal(diff.newEndpoints.length, 1);
  assert.equal(diff.removedEndpoints.length, 0);
});

test("regression: blocked→expected_block_missed surfaces in newlyFailing", () => {
  const diff = computeDiff({
    previous: {
      endpoints: [{ method: "GET", path: "/users/42" }],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
    current: {
      endpoints: [{ method: "GET", path: "/users/42" }],
      results: [{ ...baseAttempt, verdict: "expected_block_missed" }],
    },
  });
  assert.equal(diff.newlyFailing.length, 1);
  assert.equal(diff.newlyPassing.length, 0);
  assert.equal(diff.unchanged, 0);
  assert.equal(regressionCount(diff), 1);
});

test("improvement: expected_block_missed→blocked surfaces in newlyPassing", () => {
  const diff = computeDiff({
    previous: {
      endpoints: [{ method: "GET", path: "/users/42" }],
      results: [{ ...baseAttempt, verdict: "expected_block_missed" }],
    },
    current: {
      endpoints: [{ method: "GET", path: "/users/42" }],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
  });
  assert.equal(diff.newlyFailing.length, 0);
  assert.equal(diff.newlyPassing.length, 1);
});

test("unchanged verdicts increment the unchanged counter", () => {
  const diff = computeDiff({
    previous: {
      endpoints: [],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
    current: {
      endpoints: [],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
  });
  assert.equal(diff.unchanged, 1);
});

test("endpoints added/removed surface in new/removedEndpoints", () => {
  const diff = computeDiff({
    previous: {
      endpoints: [{ method: "GET", path: "/old" }],
      results: [],
    },
    current: {
      endpoints: [{ method: "POST", path: "/new" }],
      results: [],
    },
  });
  assert.equal(diff.newEndpoints.length, 1);
  assert.equal(diff.newEndpoints[0]?.path, "/new");
  assert.equal(diff.removedEndpoints.length, 1);
  assert.equal(diff.removedEndpoints[0]?.path, "/old");
});

test("allowed→blocked is NOT a regression nor improvement (neutral transition)", () => {
  const diff = computeDiff({
    previous: {
      endpoints: [],
      results: [{ ...baseAttempt, verdict: "allowed" }],
    },
    current: {
      endpoints: [],
      results: [{ ...baseAttempt, verdict: "blocked" }],
    },
  });
  assert.equal(diff.newlyFailing.length, 0);
  assert.equal(diff.newlyPassing.length, 0);
});
