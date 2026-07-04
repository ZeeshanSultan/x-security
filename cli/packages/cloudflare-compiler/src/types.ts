/**
 * Cloudflare Rulesets API JSON shapes.
 *
 * These types match the request bodies for the Cloudflare Rulesets API
 * (https://developers.cloudflare.com/api/operations/listAccountRulesets) and
 * the Rate Limiting Rulesets API. We model only the fields we emit; CF will
 * accept unknown fields but we keep the surface tight for determinism.
 */

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

export type RulesetPhase =
  | 'http_request_firewall_custom' // Custom Rules
  | 'http_ratelimit'                // Rate Limit Rules
  | 'http_request_transform'        // Transform: rewrite URL/headers
  | 'http_response_headers_transform'
  | 'http_request_late_transform';

export type RuleAction =
  | 'log'
  | 'block'
  | 'challenge'
  | 'managed_challenge'
  | 'js_challenge'
  | 'skip'
  | 'rewrite'
  | 'set_config';

export interface RateLimitParameters {
  characteristics: string[];
  period: number;
  requests_per_period: number;
  mitigation_timeout?: number;
  counting_expression?: string;
  requests_to_origin?: boolean;
}

export interface RewriteParameters {
  headers?: Record<string, { operation: 'set' | 'add' | 'remove'; value?: string }>;
  uri?: { path?: { value: string }; query?: { value: string } };
}

export interface RuleActionParameters {
  ruleset?: string;                       // for "execute" action — referencing managed rulesets
  products?: string[];                    // for set_config (bot fight mode etc.)
  [key: string]: unknown;
}

export interface CompiledRule {
  /** Stable ID: `writ-<observe|enforce>-<endpoint-hash>-<rule-type>[-<n>]` */
  id: string;
  /** Auditor-facing description tracing back to `x-security` field */
  description: string;
  /** Cloudflare Firewall Rule Language expression */
  expression: string;
  action: RuleAction;
  action_parameters?: RuleActionParameters | RewriteParameters;
  ratelimit?: RateLimitParameters;
  enabled: boolean;
  /** Effective mode for this rule. In observe mode blocking rules emit `log`. */
  mode: DeployMode;
  /** Writ metadata — round-tripped to/from CF via `ref` field on read */
  writ: {
    endpoint_id: string;
    rule_type: string;
    source_field: string;
    confidence: Confidence;
    schema_version: string;
  };
}

export interface CompiledRuleset {
  /** Cloudflare ruleset name, e.g. "writ-shadow-v1" */
  name: string;
  description: string;
  kind: 'zone';
  phase: RulesetPhase;
  rules: CompiledRule[];
}

export interface CompileResult {
  /** Phase → ruleset (one ruleset per phase) */
  rulesets: CompiledRuleset[];
  /** Managed-rules toggles (OWASP CRS etc.) — applied via "execute" rules in custom phase */
  managedRulesets: ManagedRulesetSelection[];
  /** Endpoints with no policy or unsupported fields, surfaced to UI */
  warnings: CompileWarning[];
  /**
   * Per-endpoint provenance notes for fields that the compiler did NOT
   * lower into a native Cloudflare primitive (override-only / unsupported /
   * partially-supported features that require a Worker template). Empty list
   * = every recognized v0.3 field landed in a rule. Surfaced explicitly so
   * a downstream tool / UI can never silently lose a policy directive.
   */
  provenance: ProvenanceNote[];
  /**
   * Worker-template artifacts emitted for fields that Cloudflare WAF /
   * Transform Rules cannot express (request.signature, request.denyUnknownFields,
   * authorization.resourceLookup, ParamSchema.magicByteCheck, etc.).
   * Customer is expected to deploy these alongside the rulesets.
   */
  workerArtifacts: WorkerArtifact[];
  /**
   * Per-(endpoint, field) notes about whether the policy can be faithfully
   * simulated in observe mode. "always-applied" fields (Transform Rules,
   * Set-Cookie rewrite, response-header injection) don't honor mode and ARE
   * still applied during observe; the customer needs to know so they don't
   * assume "observe" means "absolutely nothing changes."
   */
  observeModeNotes: ObserveModeNote[];
  /** Stable hash of the entire compiled output, useful for drift detection */
  contentHash: string;
}

/** Observe-mode behavior classification for a single field. */
export type ObserveModeSupport =
  | 'simulatable'      // Blocking would-be action recorded in logs only.
  | 'always-applied'   // Field is enforced regardless of mode (rewrite/transform).
  | 'partial';         // Some sub-behavior is simulatable, some always-applied.

export interface ObserveModeNote {
  endpoint_id?: string;
  field: string;
  support: ObserveModeSupport;
  message: string;
}

/**
 * A per-policy-field note surfaced when the Cloudflare compiler degrades
 * a field to override-only / unsupported / Worker-only support. Mirrors the
 * v0.3 design doc's "gateway primitive" decisions field-by-field.
 */
export interface ProvenanceNote {
  endpoint_id?: string;
  /** Dotted field path inside x-security, e.g. `request.signature`. */
  field: string;
  /** Per-field decision recorded in the capability matrix. */
  decision: 'full' | 'partial' | 'override-only' | 'unsupported';
  /** What the compiler did (emit Worker stub, accept override, drop). */
  message: string;
  /** If the customer supplied a `targetOverrides.cloudflare.<field>`, pass through unchanged. */
  override?: unknown;
  /**
   * Per-field observe-mode classification. Recorded alongside the lowering
   * decision so dashboards can show "is this field's enforcement
   * fully simulatable while observe-mode is on?" without re-deriving it.
   */
  observeMode?: ObserveModeSupport;
}

export interface WorkerArtifact {
  endpoint_id: string;
  /** Field path that produced this Worker step. */
  field: string;
  /** Short kind identifier, e.g. `request-signature-hmac`, `deny-unknown-fields`. */
  kind: string;
  /** A description for auditors; not executable. */
  description: string;
  /** Static JS Worker snippet template the customer can deploy. */
  template: string;
  /** Parameters captured from the policy that the Worker template references. */
  params: Record<string, unknown>;
  /**
   * Mode the Worker was emitted for. The template reads a `SHADOW_MODE` env
   * binding that the customer flips from `"observe"` → `"enforce"` to switch
   * a Worker from "log would-block" to "actually return 403".
   * Customer redeploy not required to flip; just update the env binding.
   */
  mode: DeployMode;
  /** Env binding value the customer should set (`"observe"` or `"enforce"`). */
  envBinding: { name: 'SHADOW_MODE'; value: 'observe' | 'enforce' };
}

/** Cloudflare-side per-field capability matrix entry. */
export type CfCapability = 'full' | 'partial' | 'override-only' | 'unsupported';

/**
 * Per-field observe-mode classification, surfaced in `capabilities()` so
 * downstream UIs can render "this field is fully simulatable in observe"
 * vs "this field is always applied regardless of mode" without re-deriving.
 */
export interface ShadowModeSupportEntry {
  support: ObserveModeSupport;
  note: string;
}

export interface ManagedRulesetSelection {
  /** Cloudflare managed ruleset ID (e.g. OWASP CRS) */
  ruleset_id: string;
  description: string;
  /** Override list — start with empty (use defaults) */
  overrides?: { rules?: { id: string; action?: RuleAction; enabled?: boolean }[] };
}

export interface CompileWarning {
  endpoint_id?: string;
  field: string;
  message: string;
  severity: 'info' | 'warn';
}

/**
 * Mode passed to the compiler.
 * - 'observe': blocking rules emit `log`/`count`; would-blocks are recorded
 *   but not enforced. **Default for newly generated policies** per the rev 3
 *   rollout plan.
 * - 'shadow': legacy alias for 'observe'. Kept for backward compat with v0.2
 *   callers and CLI flags that already say `--mode shadow`.
 * - 'enforce': blocking rules block. Customer explicitly opts in after an
 *   observation window with zero unexplained would-blocks.
 */
export type DeployMode = 'observe' | 'shadow' | 'enforce';

/**
 * Cloudflare plan tier — determines which features the compiler may emit.
 * - free: Custom + Rate Limit + Transform rules only. No managed rulesets, no Bot Fight Mode.
 * - pro: Adds OWASP ModSecurity Core Rules (legacy managed ruleset).
 * - business: Adds OWASP CRS + Bot Fight Mode + unlimited rate-limit rules.
 * - enterprise: Adds Logpush (instant logs), advanced rate limiting.
 *
 * Default is `free` so that out-of-the-box compile output is safe to deploy
 * to any account; paid features must be opted in explicitly.
 */
export type CfPlanTier = 'free' | 'pro' | 'business' | 'enterprise';

export interface CompileOptions {
  /**
   * Deploy mode. Defaults to `'observe'` per the rev 3 rollout plan —
   * newly generated policies never auto-enforce.
   * In observe mode every blocking rule's action is replaced with `log`.
   */
  mode?: DeployMode;
  /** Ruleset name prefix — default `writ-observe` for observe/shadow, `writ` for enforce. */
  namePrefix?: string;
  /** Ruleset version number (the `v{N}`); defaults to 1. */
  version?: number;
  /** Schema version stamped on each rule. */
  schemaVersion?: string;
  /**
   * Customer's Cloudflare plan tier. Determines which managed rulesets and
   * paid-only features are emitted. Defaults to `free` — emitting only
   * features available on free Cloudflare accounts.
   */
  planTier?: CfPlanTier;
}
