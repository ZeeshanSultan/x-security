// Zod schemas for the agentic policy-generation contract.
// See interfaces.md for the prose contract; this file is the runtime check.
//
// The `policy` field is intentionally typed as a pass-through record + the
// schema-package types: the full XSecurityPolicy validation lives in the
// v0.3 JSON schema (V1 verifier), not here. Re-validating it in zod would
// duplicate the JSON schema and drift.

import { z } from 'zod';
import type {
  XSecurityPolicy,
  RuleRef,
} from '@writ/schema';

export const ProfileNameSchema = z.enum([
  'auth-endpoint',
  'standard-crud',
  'file-upload',
  'webhook-receiver',
  'public-read-only',
  'admin-panel',
  'server-rendered-page',
  'graphql-resolver',
  'grpc-method',
  'internal-rpc',
  'static-asset',
  'unknown',
]);

export const ConfidenceSchema = z.enum(['high', 'medium', 'low']);

export const CitationSchema = z.object({
  file: z.string().min(1),
  lineStart: z.number().int().nonnegative(),
  lineEnd: z.number().int().nonnegative(),
  quote: z.string(),
}).refine((c) => c.lineEnd >= c.lineStart, {
  message: 'lineEnd must be >= lineStart',
});

export const InjectionSinkSchema = z.enum([
  'sql',
  'nosql',
  'os-command',
  'xpath',
  'ldap',
  'code-eval',
  'xss',
  'deserialization',
  'ai-prompt',
]);

// Mirrors the schema-package SemanticType enum (packages/schema $defs.SemanticType).
// Used by the paramConstraint control hint to carry the model-inferred type.
export const SemanticTypeSchema = z.enum([
  'string',
  'integer',
  'float',
  'boolean',
  'email',
  'phone',
  'url',
  'date',
  'datetime',
  'uuid',
  'ip-address',
  'name',
  'free-text',
  'binary',
]);

// Operator enum for authorization rules (mirrors the schema-package
// AuthorizationRule.operator enum). Used by the authorization control hint.
export const AuthzOperatorSchema = z.enum([
  'equals',
  'not-equals',
  'in',
  'not-in',
  'matches',
  'contains',
]);

// Structured detection signal carried on an assumption. The model emits this
// when it identifies a control the route needs — a field flowing to an
// injection sink, a sensitive route with no auth gate, a broken object/function
// level authorization, a mass-assignment surface, an unthrottled credential
// endpoint, an unbounded perimeter param, an SSRF/open-redirect URL, or an
// over-exposing response — INDEPENDENT of whether it managed to express the
// control in the policy delta. The harness compiles it into the enforced
// control deterministically (lever 4). Sourcing every control from structured
// fields (not free-text scraping of `assumption`) is what keeps this
// D-1-compliant: the security-relevant params (param, principalRef, sink,
// identifier) come from the MODEL; the compiler never invents them.
//
// One permissive object carries every kind's fields as optionals; the compiler
// enforces the per-kind required set and DROPS an incomplete descriptor (e.g.
// `authorization` without `principalRef`) rather than fabricating a default
// for a detection-asserting field (D-1).
export const ControlHintSchema = z.object({
  kind: z.enum([
    'injectionGuard',
    'authentication',
    'authorization',
    'denyUnknownFields',
    'rateLimit',
    'paramConstraint',
    'contentType',
    'responseShape',
    'domainAllowlist',
    'ssrfGuard',
  ]),
  // injectionGuard
  sink: InjectionSinkSchema.optional(),
  // authorization (BOLA/BFLA) — param + principalRef REQUIRED to emit
  param: z.string().min(1).optional(),
  principalRef: z.string().min(1).optional(),
  operator: AuthzOperatorSchema.optional(),
  // WHERE the object identifier lives in the request (path/query/body/header).
  // The model cites it; the compiler builds request.<segment>.<param>. Defaults
  // to 'path' (the /resource/:id case). Without it, query/body-keyed ownership
  // was inexpressible (hit by DVAPI, DVRESTaurant, vuln-bank in measurement).
  location: z.enum(['path', 'query', 'body', 'header']).optional(),
  // rateLimit (brute-force) — all optional; safe non-detection config defaults
  identifier: z.string().min(1).optional(),
  requests: z.number().int().positive().optional(),
  window: z.string().min(1).optional(),
  // paramConstraint (perimeter tightness) — tightness fields are structural,
  // not detection claims; supplied by the model, filled by tightness defaults.
  paramType: SemanticTypeSchema.optional(),
  pattern: z.string().min(1).optional(),
  maxLength: z.number().int().nonnegative().optional(),
  minLength: z.number().int().nonnegative().optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  // contentType
  allowed: z.array(z.string().min(1)).optional(),
  // domainAllowlist (SSRF / open-redirect)
  domains: z.array(z.string().min(1)).optional(),
  // ssrfGuard (server-side fetch of a user-supplied URL) — compiles the url
  // param to { type:'url', blockPrivateRanges:true, domainAllowlist?:[...] }.
  // blockPrivateRanges is the enforceable SSRF control (rejects metadata IPs,
  // RFC1918, loopback, link-local, non-http schemes); an empty domainAllowlist
  // is a banned no-op, so the guard does NOT rely on it. Defaults true.
  blockPrivateRanges: z.boolean().optional(),
});

export const AssumptionSchema = z.object({
  field: z.string().min(1),
  assumption: z.string().min(1),
  confidence: ConfidenceSchema,
  cite: CitationSchema,
  controlHint: ControlHintSchema.optional(),
});

// Permissive XSecurityPolicy stand-in — V1 enforces the real schema.
// We accept any object here so the LLM output can carry profile-only
// emissions, partials, etc., without zod fighting JSON-Schema oneOf cases.
export const PolicyPassthroughSchema = z.record(z.unknown());

export const PolicyEmissionSchema = z.object({
  endpointId: z.string().min(1),
  policy: PolicyPassthroughSchema.nullable(),
  reviewRequired: z.boolean(),
  reviewReasons: z.array(z.string()).optional(),
  assumptions: z.array(AssumptionSchema),
});

export const RouteInventoryEntrySchema = z.object({
  method: z.string().min(1),
  path: z.string().min(1),
  sourceFile: z.string().min(1),
  sourceLine: z.number().int().nonnegative(),
  handlerSymbol: z.string().optional(),
  authnMiddlewareChain: z.array(z.string()).optional(),
  modelOrDtoRefs: z.array(z.string()).optional(),
  isPublic: z.boolean().optional(),
});

export const ProfileClassificationSchema = z.object({
  profile: ProfileNameSchema.nullable(),
  // Defaults to false when the model omits it (common when picking a confident
  // profile like `unknown` — the model treats omission as "no, don't need review").
  // The fan-out forces needsHumanReview semantics from profile === null, so the
  // explicit flag is now advisory rather than load-bearing.
  needsHumanReview: z.boolean().default(false),
  reason: z.string().optional(),
});

// Per-scan DETECTION coverage telemetry — the learning loop. Aggregates the
// deterministic fail-loud signals so real customer repos reveal where the engine
// is weak (which frameworks/idioms ground-but-blind, unresolved-handler rate),
// driving the AST-vs-extractor investment from data instead of speculation.
export const DetectionCoverageSchema = z.object({
  routesTotal: z.number(),
  handlerResolved: z.number(), // body resolved cross-file/far
  handlerInline: z.number(), // inline handler at the decl
  handlerUnresolved: z.number(), // fail-loud: handler body not locatable
  reviewRequired: z.number(), // emissions sent to review
  // GROUNDED but BLIND: a risk surface (write / input / id-bearing) whose handler
  // WAS resolved/inline but produced no security control and no review — "we looked
  // and found nothing." The key long-tail signal (silent-miss candidates).
  groundedButBlind: z.number(),
  byLanguage: z.record(z.number()), // route count per source language (ext-derived)
});

export type DetectionCoverage = z.infer<typeof DetectionCoverageSchema>;

export const CoverageSchema = z.object({
  filesRead: z.array(z.string()),
  grepQueriesIssued: z.array(z.string()),
  notes: z.string().optional(),
  detectionCoverage: DetectionCoverageSchema.optional(),
});

export const AgentOutputSchema = z.object({
  routeInventory: z.array(RouteInventoryEntrySchema),
  profiles: z.record(ProfileClassificationSchema),
  emissions: z.array(PolicyEmissionSchema),
  coverage: CoverageSchema,
});

// --- Per-pass payloads -----------------------------------------------------

export const Pass1OutputSchema = z.object({
  routeInventory: z.array(RouteInventoryEntrySchema),
  filesRead: z.array(z.string()),
  grepQueriesIssued: z.array(z.string()),
});

// Defensive preprocessor for `profiles`. Flash Lite occasionally emits
// malformed shapes under prompt-context pressure:
//   - keys that are bare methods ("GET") with no path
//   - values that are bare strings ("standard-crud") instead of objects
//   - both, simultaneously
// Per CLAUDE.md D-1 we MUST NOT fabricate the missing fields — that would
// silently degrade detection. Instead we drop malformed entries; the
// affected routes get no Pass-2 classification and fall through to the
// `unknown` profile in the Pass-3 fan-out, which is the legitimate
// "we don't know" surface. Count is logged for observability.
function preprocessProfiles(v: unknown): unknown {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return v;
  const out: Record<string, unknown> = {};
  let dropped = 0;
  for (const [key, val] of Object.entries(v as Record<string, unknown>)) {
    // Endpoint id must be "METHOD path" — at minimum a space and a leading
    // method-like token. Bare "GET" / "POST" / etc. are model shorthand.
    if (!/^[A-Z]+\s+\S/.test(key)) { dropped++; continue; }
    // Value must be a JSON object (the ProfileClassification shape).
    if (!val || typeof val !== 'object' || Array.isArray(val)) {
      dropped++;
      continue;
    }
    out[key] = val;
  }
  if (dropped > 0) {
    // Stderr — picked up by the worker pino logger as a "warn" line.
    console.warn(
      `[agentic] Pass2 profiles preprocessor dropped ${dropped} malformed entry/entries (bad key or non-object value); affected routes will use the 'unknown' profile fallback in Pass 3`,
    );
  }
  return out;
}

export const Pass2OutputSchema = z.object({
  profiles: z.preprocess(preprocessProfiles, z.record(ProfileClassificationSchema)),
});

// Per-route emit: endpointId is the route the harness already pinned, not a
// detection field — some strong models (sonnet via Bedrock) omit it as
// redundant. Failing the entire emission over an identifier we own loses the
// real detection work. Accept it optional here; runPerRoutePolicyPass injects
// the known route id. (D-1-safe: this is a route identifier, never a finding,
// citation, or control — those stay strictly model-sourced.)
export const Pass3RouteOutputSchema = z.object({
  emission: PolicyEmissionSchema.extend({ endpointId: z.string().min(1).optional() }),
  filesRead: z.array(z.string()),
  grepQueriesIssued: z.array(z.string()),
});

export const Pass3OutputSchema = z.object({
  emissions: z.array(PolicyEmissionSchema),
  filesRead: z.array(z.string()),
  grepQueriesIssued: z.array(z.string()),
});

// --- Budget / cost ---------------------------------------------------------

export const BudgetCapsSchema = z.object({
  totalInputTokens: z.number().int().positive(),
  totalOutputTokens: z.number().int().positive(),
  toolCallsPerRoute: z.number().int().positive(),
  totalToolCalls: z.number().int().positive(),
  wallClockPerRouteMs: z.number().int().positive(),
  wallClockTotalMs: z.number().int().positive(),
  costCapUsd: z.number().positive(),
  /** Per-pass output-token override. Falls back to single-number budget when undefined. */
  maxOutputTokensPerPass: z.object({
    inventory: z.number().int().positive().optional(),
    profile: z.number().int().positive().optional(),
    perRoute: z.number().int().positive().optional(),
  }).optional(),
  /** Per-pass tool-call override. Inventory needs many list_files calls. */
  toolCallsPerPass: z.object({
    inventory: z.number().int().positive().optional(),
  }).optional(),
  /**
   * Inventory pre-seed knobs. The deterministic route extractor grounds the
   * inventory prompt with a candidate table. `seedRowCap` bounds the rows shown
   * in-prompt (the rest are summarized with a `… +K more` marker — never
   * silently dropped) so the seed respects the inventory output budget.
   */
  inventorySeed: z.object({
    seedRowCap: z.number().int().positive().optional(),
  }).optional(),
  /**
   * Chunked-remediation knobs. When V7 flags missed candidate handlers, the
   * inventory pass re-runs once per chunk so Flash Lite can stay focused on
   * a small file list per turn instead of choking on the full addendum.
   */
  remediation: z.object({
    chunkSize: z.number().int().positive().optional(),
    maxChunks: z.number().int().positive().optional(),
    maxOutputTokensPerChunk: z.number().int().positive().optional(),
    toolCallsPerChunk: z.number().int().positive().optional(),
    /**
     * Diminishing-returns break-early threshold. After each chunk, V7 is
     * re-probed; if the missed-list shrinks by fewer than this many entries
     * vs the prior probe, the loop bails out (Flash Lite is no longer
     * making progress on this repo's shape). Default 2.
     */
    diminishingReturnsThreshold: z.number().int().nonnegative().optional(),
    /**
     * Cost-fraction soft cap. When `usage.costUsd / caps.costCapUsd` exceeds
     * this fraction at the top of a remediation iteration, the loop breaks
     * — Pass 2 and Pass 3 still need budget. Default 0.5.
     */
    costFractionCutoff: z.number().positive().max(1).optional(),
  }).optional(),
  /**
   * Chunked profile-classification knobs. Pass 2 in one shot hits the output
   * token cap on 50-100+ route inventories (DVWA scale). Above
   * thresholdRoutes, the harness splits the inventory into chunks, runs each
   * through the existing classification prompt with a per-chunk addendum,
   * and merges results. Below threshold, the original single-pass path runs
   * unchanged.
   */
  profileChunking: z.object({
    thresholdRoutes: z.number().int().positive().optional(),
    chunkSize: z.number().int().positive().optional(),
    maxChunks: z.number().int().positive().optional(),
    maxOutputTokensPerChunk: z.number().int().positive().optional(),
    toolCallsPerChunk: z.number().int().positive().optional(),
  }).optional(),
  /**
   * Auth-context pre-pass knobs. Between Pass 2 and Pass 3 the harness
   * deterministically resolves the auth-check function bodies referenced by
   * each route's authnMiddlewareChain and injects them inline into the per-
   * route prompt. See docs/agentic-partial-fixes-plan.md §4.
   */
  authContext: z.object({
    maxChains: z.number().int().positive().optional(),
    /** Cap on inline-call symbol resolutions (PHP/Rails handler-body auth). */
    maxSymbols: z.number().int().positive().optional(),
    maxSnippetLines: z.number().int().positive().optional(),
    maxTotalBytes: z.number().int().positive().optional(),
  }).optional(),
});

export const BudgetUsageSchema = z.object({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  toolCalls: z.number().int().nonnegative(),
  wallClockMs: z.number().int().nonnegative(),
  costUsd: z.number().nonnegative(),
});

export const VerifierIdSchema = z.enum(['V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7']);

export const VerifierVerdictSchema = z.enum(['pass', 'fail', 'demote-to-review']);

export const VerifierResultSchema = z.object({
  verifier: VerifierIdSchema,
  endpointId: z.string().optional(),
  verdict: VerifierVerdictSchema,
  reasons: z.array(z.string()),
  modifications: PolicyEmissionSchema.partial().optional(),
});

// --- Inferred TS types -----------------------------------------------------

export type ProfileName = z.infer<typeof ProfileNameSchema>;
export type ConfidenceLevel = z.infer<typeof ConfidenceSchema>;
export type Citation = z.infer<typeof CitationSchema>;
export type ControlHint = z.infer<typeof ControlHintSchema>;
export type Assumption = z.infer<typeof AssumptionSchema>;
export type RouteInventoryEntry = z.infer<typeof RouteInventoryEntrySchema>;
export type ProfileClassification = z.infer<typeof ProfileClassificationSchema>;
export type Coverage = z.infer<typeof CoverageSchema>;
export type Pass1Output = z.infer<typeof Pass1OutputSchema>;
export type Pass2Output = z.infer<typeof Pass2OutputSchema>;
export type Pass3RouteOutput = z.infer<typeof Pass3RouteOutputSchema>;
export type Pass3Output = z.infer<typeof Pass3OutputSchema>;
export type BudgetCaps = z.infer<typeof BudgetCapsSchema>;
export type BudgetUsage = z.infer<typeof BudgetUsageSchema>;
export type VerifierId = z.infer<typeof VerifierIdSchema>;
export type VerifierVerdict = z.infer<typeof VerifierVerdictSchema>;

// PolicyEmission carries the real XSecurityPolicy at runtime even though the
// zod schema is permissive (see comment at top).
export interface PolicyEmission {
  endpointId: string;
  policy: XSecurityPolicy | null;
  reviewRequired: boolean;
  reviewReasons?: string[];
  assumptions: Assumption[];
}

export interface AgentOutput {
  routeInventory: RouteInventoryEntry[];
  profiles: Record<string, ProfileClassification>;
  emissions: PolicyEmission[];
  coverage: Coverage;
}

export interface VerifierResult {
  verifier: VerifierId;
  endpointId?: string;
  verdict: VerifierVerdict;
  reasons: string[];
  modifications?: Partial<PolicyEmission>;
}

export interface CostTracking {
  caps: BudgetCaps;
  usage: BudgetUsage;
  perRoute: Record<string, BudgetUsage>;
  exhausted: boolean;
  exhaustionReason?: string;
}

export const DEFAULT_BUDGET_CAPS: BudgetCaps = {
  totalInputTokens: 800_000,
  totalOutputTokens: 100_000,
  toolCallsPerRoute: 25,
  totalToolCalls: 600,
  // 60s/route: 30s timed out per-route before the agent could read the resolved
  // handler file + emit (under-emission root cause; see spec-openapi resolver).
  wallClockPerRouteMs: 60_000,
  wallClockTotalMs: 900_000,
  costCapUsd: 5,
  maxOutputTokensPerPass: {
    inventory: 5000,
    // Profile classification emits one entry per route. After chunked inventory
    // remediation, real repos hit 50-100+ routes (DVWA: ~80). 2000 was sized for
    // ~20-route Express apps and now binds with stop=max_tokens. Bumped to 8000;
    // a chunked profile path (planned A2) will eventually replace this with
    // per-chunk passes that keep individual prompts tight.
    profile: 8000,
    perRoute: 4000,
  },
  toolCallsPerPass: {
    inventory: 60,
  },
  inventorySeed: {
    seedRowCap: 80,
  },
  remediation: {
    chunkSize: 20,
    maxChunks: 10,
    maxOutputTokensPerChunk: 2000,
    toolCallsPerChunk: 30,
    diminishingReturnsThreshold: 2,
    costFractionCutoff: 0.5,
  },
  profileChunking: {
    thresholdRoutes: 25,
    chunkSize: 20,
    maxChunks: 10,
    maxOutputTokensPerChunk: 3000,
    toolCallsPerChunk: 10,
  },
  authContext: {
    maxChains: 8,
    maxSymbols: 12,
    maxSnippetLines: 60,
    maxTotalBytes: 20_000,
  },
};

// Re-export schema-package type for downstream convenience.
export type { XSecurityPolicy, RuleRef };
