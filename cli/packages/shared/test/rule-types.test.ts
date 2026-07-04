// Type-level contract tests for `DeployRule` (joined read view) vs
// `RuleRow` (raw drizzle row). These tests carry their weight at
// compile time — if someone collapses the two shapes back together, or
// moves `description / endpointPath / method / confidence` onto the raw
// row by mistake, this file stops compiling.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { DeployRule, RuleRow } from "../src/index.js";

// ---------- compile-time helpers (hand-rolled; no expect-type dep) ----------

type Equals<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
  ? true
  : false;
type Has<T, K extends PropertyKey> = K extends keyof T ? true : false;
type Assert<T extends true> = T;

// ---------- DeployRule MUST carry the synthesized projection fields ----------
type _DeployRuleHasDescription = Assert<Has<DeployRule, "description">>;
type _DeployRuleHasEndpointPath = Assert<Has<DeployRule, "endpointPath">>;
type _DeployRuleHasMethod = Assert<Has<DeployRule, "method">>;
type _DeployRuleHasConfidence = Assert<Has<DeployRule, "confidence">>;
type _DeployRuleHasRuleType = Assert<Has<DeployRule, "ruleType">>;
type _DeployRuleHasAction = Assert<Has<DeployRule, "action">>;
type _DeployRuleHasId = Assert<Has<DeployRule, "id">>;

// ---------- RuleRow MUST NOT carry the synthesized fields ----------
type _RuleRowNoDescription = Assert<Equals<Has<RuleRow, "description">, false>>;
type _RuleRowNoEndpointPath = Assert<Equals<Has<RuleRow, "endpointPath">, false>>;
type _RuleRowNoMethod = Assert<Equals<Has<RuleRow, "method">, false>>;
type _RuleRowNoConfidence = Assert<Equals<Has<RuleRow, "confidence">, false>>;

// ---------- RuleRow MUST mirror the raw rules-table columns ----------
type _RuleRowHasId = Assert<Has<RuleRow, "id">>;
type _RuleRowHasPolicyId = Assert<Has<RuleRow, "policyId">>;
type _RuleRowHasScanId = Assert<Has<RuleRow, "scanId">>;
type _RuleRowHasRuleType = Assert<Has<RuleRow, "ruleType">>;
type _RuleRowHasAction = Assert<Has<RuleRow, "action">>;
type _RuleRowHasXSecurityField = Assert<Has<RuleRow, "xSecurityField">>;
type _RuleRowHasOwaspCategory = Assert<Has<RuleRow, "owaspCategory">>;
type _RuleRowHasCloudflareJson = Assert<Has<RuleRow, "cloudflareJson">>;

// ---------- the two shapes must NOT be structurally identical ----------
type _NotEqual = Assert<Equals<Equals<DeployRule, RuleRow>, false>>;

// ---------- runtime smoke: structural samples that satisfy each shape ----------
test("DeployRule joined-view sample has the projected fields", () => {
  const sample: DeployRule = {
    id: "r1",
    description: "Block /admin from non-corp IPs",
    endpointPath: "/admin",
    method: "GET",
    ruleType: "custom",
    action: "block",
    confidence: "HIGH",
  };
  assert.equal(sample.endpointPath, "/admin");
  assert.equal(sample.confidence, "HIGH");
});

test("RuleRow raw-row sample has the drizzle column fields", () => {
  const sample: RuleRow = {
    id: "r1",
    scanId: "s1",
    policyId: "p1",
    ruleType: "custom",
    action: "block",
    xSecurityField: "auth.required",
    owaspCategory: "API2",
    cloudflareId: null,
    cloudflareJson: {},
  };
  assert.equal(sample.policyId, "p1");
  // The runtime object intentionally has no `description` — that's the
  // whole point of separating the two types.
  assert.equal((sample as Record<string, unknown>).description, undefined);
});

// Touch the compile-time assertions at runtime so they're flagged as used
// and not tree-shaken / lint-pruned out of the file.
test("compile-time type assertions are reachable", () => {
  const _t: true = true as Assert<Equals<true, true>>;
  assert.equal(_t, true);
  // also reference the bag of assert aliases above so unused-locals
  // checkers know we mean it.
  type _Touch = [
    _DeployRuleHasDescription,
    _DeployRuleHasEndpointPath,
    _DeployRuleHasMethod,
    _DeployRuleHasConfidence,
    _DeployRuleHasRuleType,
    _DeployRuleHasAction,
    _DeployRuleHasId,
    _RuleRowNoDescription,
    _RuleRowNoEndpointPath,
    _RuleRowNoMethod,
    _RuleRowNoConfidence,
    _RuleRowHasId,
    _RuleRowHasPolicyId,
    _RuleRowHasScanId,
    _RuleRowHasRuleType,
    _RuleRowHasAction,
    _RuleRowHasXSecurityField,
    _RuleRowHasOwaspCategory,
    _RuleRowHasCloudflareJson,
    _NotEqual,
  ];
  const _u: _Touch | undefined = undefined;
  assert.equal(_u, undefined);
});
