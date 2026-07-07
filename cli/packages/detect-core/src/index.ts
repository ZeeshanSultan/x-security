// @x-security/detect-core — the deterministic correctness core.
//
// Everything here is exact, reproducible, and LLM-free: route extraction,
// schema validation, the V1–V7 verifiers, cite byte-match (V6) + tightness
// (V3), the assumption→control compiler, and canonicalization. No provider /
// chat / prompt code lives in this package; the host coding agent does
// detection, this core verifies + compiles + emits.
//
// Extracted from packages/llm-agent/src/agentic/* (the LLM-free closure) so
// the CLI and MCP can share it without dragging in any LLM provider.

// --- Contract schemas + types (non-LLM zod) --------------------------------
export {
  CitationSchema,
  AssumptionSchema,
  ControlHintSchema,
  InjectionSinkSchema,
  PolicyEmissionSchema,
  RouteInventoryEntrySchema,
  ProfileNameSchema,
  ConfidenceSchema,
  VerifierResultSchema,
  VerifierIdSchema,
  VerifierVerdictSchema,
  type Citation,
  type Assumption,
  type ControlHint,
  type ProfileName,
  type ConfidenceLevel,
  type RouteInventoryEntry,
  type PolicyEmission,
  type AgentOutput,
  type VerifierId,
  type VerifierVerdict,
  type VerifierResult,
  type XSecurityPolicy,
} from './agentic/schema.js';

// --- Verifiers (V1–V7) -----------------------------------------------------
export {
  v1SchemaValidity,
  v2Completeness,
  v3Tightness,
  v4RoundTrip,
  v5CrossRouteConsistency,
  v6CitationJustification,
  v7InventoryDiff,
  defaultVerifiers,
  runVerifiers,
  checkTightness,
  type Verifier,
  type VerifierContext,
  type RunVerifiersResult,
} from './agentic/verify.js';

// --- Verifier helpers (cite byte-match, snap, tightness, grep) -------------
export {
  snapQuoteToFile,
  evaluateV6ForEmission,
  readSlice,
  safeResolve,
  normalizeWhitespace,
  discoverHandlerParams,
  deterministicGrep,
  computeV5Demotions,
  applyModifications,
  type GrepHit,
  type V6PerEmission,
} from './agentic/verify-helpers.js';

export {
  isEducationalSourceViewPath,
  detectFilesystemHandlerCandidates,
  type FilesystemHandlerCandidate,
} from './agentic/verify-fs-routing.js';

// --- Emit: compile + hydrate + tighten -------------------------------------
export {
  compileAssumptionsToPolicy,
  applyPerimeterTightnessDefaults,
  hydratePolicy,
  hydratePolicyWithReasons,
} from './agentic/emit.js';

// --- Profile defaults (the base policy a delta hydrates onto) --------------
export { profileDefault, ALL_PROFILES } from './agentic/profiles.js';

// --- Canonicalization ------------------------------------------------------
export {
  canonicalizePolicy,
  canonicalizeAgentOutput,
  serializeStable,
  normalizeRegex,
} from './agentic/canonical.js';

// --- Deterministic route extraction + seed table ---------------------------
export {
  extractRoutes,
  normPath,
  routeKey,
  dedupeRoutes,
  detectFrameworks,
  type ExtractedRoute,
  type ExtractResult,
  type ExtractOptions,
  type RouteSource,
  type SchemaHint,
  type Protocol,
} from './frameworks/index.js';

export { renderSeedTable, filterSeedRoutes } from './agentic/inventory-seed.js';

// --- Deterministic per-route pre-pass (LLM-free; BYO-bundleable) ------------
export {
  buildEvidencePacks,
  renderEvidencePackBlock,
  routeAnalysisIncomplete,
  type EvidencePack,
  type EvidencePackOptions,
  type ObservedInput,
  type ObservedValidator,
  type ObservedOutput,
  type ObjectIdSurface,
} from './agentic/evidence-pack.js';

// --- Candidate-finding taint pass (LLM-free; BYO-bundleable) ----------------
export {
  deriveCandidateFindings,
  deriveMassAssignmentCandidates,
  RESERVED_BODY_FIELDS,
  type CandidateFinding,
  type MassAssignmentCandidate,
  type InjectionSink,
} from './agentic/candidate-findings.js';

// --- Depth-completeness gate (LLM-free; BYO-bundleable) ---------------------
export {
  assessRouteDepth,
  type DepthGap,
  type DepthGapKind,
  type DepthAdvisory,
  type DepthAssessment,
  type DismissalCite,
  type RouteAuthChain,
} from './agentic/depth-gate.js';

export {
  buildAuthContext,
  buildAuthContextMap,
  chainKeyOf,
  detectInlineAuthCalls,
  type AuthContext,
  type AuthContextSnippet,
  type BuildAuthContextOptions,
} from './agentic/auth-context.js';

export {
  reconcileMountPrefix,
  type PrefixRewrite,
  type ReconcileResult,
} from './agentic/prefix-reconcile.js';

// --- V4 round-trip primitives (synthetic request gen + in-process eval) -----
// Exposed so the BYO `verify-route` verb can surface the concrete positive
// sample a too-tight composed policy would false-block — not just V4's reason
// string. Both are pure + LLM-free (they already back the v4RoundTrip verifier).
export {
  generatePositive,
  generateNegative,
  generatePositiveOwnershipAbsent,
  generatePositiveBodyOwnershipAbsent,
  generateAuthzNegative,
  hasAuthzRequestRule,
  isSelfMutationBodyOwnership,
} from './agentic/synthetic-requests.js';

export {
  evaluatePolicy,
  evaluateParam,
  type SyntheticRequest,
  type EvalResult,
} from './agentic/policy-eval.js';

export type {
  AgentTools,
  ListFilesEntry,
  ReadFileResult,
  DefinitionHit,
  ReferenceHit,
} from './agentic/tool-types.js';

// --- Schema validation passthrough -----------------------------------------
export { validateXSecurity } from '@x-security/schema';
