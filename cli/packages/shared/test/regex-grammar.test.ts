// Tests for the strict regex grammar. The threat model is "LLM emits a
// pattern that compiles into a WAF rule"; the tests therefore cover both
// the classic ReDoS shapes we must reject and the legitimate patterns the
// proposer is expected to produce.
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateRegex, MAX_LENGTH, MAX_REPEAT } from "../src/regex-grammar.js";

function ok(p: string): void {
  const r = validateRegex(p);
  assert.equal(r.ok, true, `expected OK for ${JSON.stringify(p)}; got ${JSON.stringify(r)}`);
}
function bad(p: string, expected?: RegExp): void {
  const r = validateRegex(p);
  assert.equal(r.ok, false, `expected FAIL for ${JSON.stringify(p)}`);
  if (!r.ok && expected) assert.match(r.error, expected);
}

test("legitimate patterns pass", () => {
  ok("foo");
  ok("foo/bar");
  ok("^/api/v1/users$");
  ok("[A-Za-z0-9_-]+");
  ok("\\.json$");
  ok("(?:get|post|put)");
  ok("a{3,5}");
});

test("classic ReDoS nested quantifier rejected", () => {
  bad("(?:a+)+", /nested quantifier/);
  bad("(?:a*)*", /nested quantifier/);
  bad("(?:[A-Z]+)+", /nested quantifier/);
});

test("capturing groups rejected", () => {
  bad("(a)", /non-capturing/);
});

test("lookaround rejected", () => {
  bad("(?=foo)", /non-capturing/);
  bad("(?!foo)", /non-capturing/);
  bad("(?<=foo)", /non-capturing/);
});

test("backreferences rejected", () => {
  bad("\\1");
  bad("(?:foo)\\1");
});

test("Unicode property escapes rejected", () => {
  bad("\\p{Letter}");
});

test("shorthand char classes rejected (could pull surprising codepoints)", () => {
  bad("\\w+");
  bad("\\d+");
  bad("\\s+");
});

test("negated char class rejected", () => {
  bad("[^a]", /negated/);
});

test("quantifier bounds enforced", () => {
  ok(`a{${MAX_REPEAT}}`);
  bad(`a{${MAX_REPEAT + 1}}`, /exceeds/);
  bad("a{5,3}", /upper bound/);
  bad("a{}");
});

test("length limit enforced", () => {
  bad("a".repeat(MAX_LENGTH + 1), /exceeds/);
});

test("empty pattern rejected", () => {
  bad("");
});

test("unbalanced parens rejected", () => {
  bad("(?:foo", /unclosed/);
  bad("foo)");
});

test("alternation works but capped", () => {
  ok("a|b|c");
  bad("a|b|c|d|e|f|g|h|i", /too many alternations/);
});

test("possessive / lazy quantifiers rejected", () => {
  bad("a*+", /possessive/);
  bad("a*?", /possessive/);
  bad("a+?", /possessive/);
});

test("dot is allowed as any-char shorthand", () => {
  ok(".+");
});

test("disallowed metachars in char class", () => {
  bad("[a\\w]", /not allowed in char class/);
  bad("[[]");
  bad("[]");
});
