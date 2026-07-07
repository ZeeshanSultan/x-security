// @x-security/cloudflare-compiler
// Pure-function policy compiler. Input: parsed/normalized OpenAPI spec
// (SpecIR from @x-security/core). Output: Cloudflare Rulesets API JSON.
// PRD v2 §6 (R2.1–R2.7). Deterministic, all rules default to action: "log"
// when mode === "shadow".

export { compile, stableStringify } from './compile.js';
export { diffRulesets } from './diff.js';
export type { RulesetDiff } from './diff.js';
export {
  endpointHash,
  endpointId,
  pathMatchExpression,
  methodMatchExpression
} from './endpoint.js';
export {
  parseByteSize,
  parseDurationSeconds,
  and,
  or,
  not,
  header,
  hasHeader,
  missingHeader,
  headerEquals,
  headerMatches,
  inCidrAny,
  bodySizeGt,
  contentTypeNotIn
} from './expressions.js';
export { compileVirtualPatch, VirtualPatchCompileError } from './virtual-patch.js';
export type {
  VirtualPatch,
  CompileVirtualPatchOptions,
  CompileVirtualPatchResult,
} from './virtual-patch.js';
export {
  capabilities,
  lookupCapability,
  lookupShadowModeSupport,
  CF_CAPABILITIES,
  CF_SHADOW_MODE_SUPPORT
} from './capabilities.js';
export { CompileError } from './v3-authz.js';
export type {
  CfPlanTier,
  CompileOptions,
  CompileResult,
  CompileWarning,
  CompiledRule,
  CompiledRuleset,
  Confidence,
  DeployMode,
  ManagedRulesetSelection,
  ObserveModeNote,
  ObserveModeSupport,
  ProvenanceNote,
  RateLimitParameters,
  RewriteParameters,
  RuleAction,
  RuleActionParameters,
  RulesetPhase,
  ShadowModeSupportEntry,
  WorkerArtifact,
  CfCapability
} from './types.js';
