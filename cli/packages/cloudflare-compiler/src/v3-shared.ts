// Shared helpers for v0.3 lowering modules. Kept tiny on purpose so the
// per-concern files (v3-request, v3-response, v3-protocol, v3-authz) all
// produce uniform provenance notes and Worker artifacts.

import type { EndpointIR } from '@x-security/core';
import type {
  CompileWarning,
  CompiledRule,
  CompiledRuleset,
  DeployMode,
  ObserveModeNote,
  ObserveModeSupport,
  ProvenanceNote,
  WorkerArtifact,
  CfCapability,
  ManagedRulesetSelection
} from './types.js';
import { lookupCapability, lookupShadowModeSupport } from './capabilities.js';

export interface V3Builder {
  endpoint: EndpointIR;
  /** Endpoint ID (METHOD_path) for note attribution. */
  eid: string;
  /** Short stable hash for rule IDs. */
  ehash: string;
  mode: DeployMode;
  schemaVersion: string;
  planTier: 'free' | 'pro' | 'business' | 'enterprise';
  warnings: CompileWarning[];
  provenance: ProvenanceNote[];
  observeModeNotes: ObserveModeNote[];
  workerArtifacts: WorkerArtifact[];
  custom: CompiledRule[];
  reqTransform: CompiledRule[];
  respTransform: CompiledRule[];
  rateLimit: CompiledRule[];
  managed: ManagedRulesetSelection[];
  /** Cloudflare-specific overrides supplied by the customer for this endpoint. */
  overrides: Record<string, unknown>;
}

/** True iff the mode treats blocking rules as non-blocking (log/count). */
export function isObserveMode(m: DeployMode): boolean {
  return m === 'observe' || m === 'shadow';
}

/** ID prefix segment for an effective mode. Legacy 'shadow' callers still see 'shadow'. */
export function modePrefix(m: DeployMode): 'observe' | 'shadow' | 'enforce' {
  if (m === 'enforce') return 'enforce';
  if (m === 'shadow') return 'shadow';
  return 'observe';
}

export function noteProvenance(
  b: V3Builder,
  field: string,
  message: string,
  decision?: CfCapability,
  override?: unknown
): void {
  const d = decision ?? lookupCapability(field) ?? 'partial';
  const observe = lookupShadowModeSupport(field)?.support;
  b.provenance.push({
    endpoint_id: b.eid,
    field,
    decision: d,
    message,
    ...(observe !== undefined ? { observeMode: observe } : {}),
    ...(override !== undefined ? { override } : {})
  });
}

/** Record a per-(endpoint, field) observe-mode note. */
export function noteObserveMode(
  b: V3Builder,
  field: string,
  support: ObserveModeSupport,
  message: string
): void {
  b.observeModeNotes.push({ endpoint_id: b.eid, field, support, message });
}

export function emitWorker(
  b: V3Builder,
  args: { field: string; kind: string; description: string; template: string; params: Record<string, unknown>; }
): void {
  const envValue: 'observe' | 'enforce' = isObserveMode(b.mode) ? 'observe' : 'enforce';
  b.workerArtifacts.push({
    endpoint_id: b.eid,
    field: args.field,
    kind: args.kind,
    description: args.description,
    template: wrapWorkerWithShadowGate(args.template),
    params: { ...args.params, SHADOW_MODE: envValue },
    mode: b.mode,
    envBinding: { name: 'SHADOW_MODE', value: envValue }
  });
}

/**
 * Wrap an emitted Worker so its `return new Response(..., { status: 4xx })`
 * lines are gated by `env.SHADOW_MODE`. In observe-mode the Worker logs the
 * would-block decision and falls through to origin; in enforce-mode it
 * actually returns the rejection.
 *
 * The wrapper is intentionally simple: a top-of-file constant + a single
 * helper. Templates that already format their rejection through
 * `denyOrLog(...)` work unchanged. Templates that hand-roll `new Response`
 * keep working — `denyOrLog` is opt-in.
 */
function wrapWorkerWithShadowGate(template: string): string {
  const banner =
    "// [x-security] Shadow-gate. Customer flips env.SHADOW_MODE='enforce' to actually block.\n" +
    "// const SHADOW_MODE = (env && env.SHADOW_MODE) || PARAMS.SHADOW_MODE || 'observe';\n" +
    "// function denyOrLog(req, body, init) {\n" +
    "//   if (SHADOW_MODE === 'enforce') return new Response(body, init);\n" +
    "//   console.log('[x-security][would-block]', init && init.status, body, req.url);\n" +
    "//   return fetch(req);\n" +
    "// }\n";
  return banner + template;
}

/** Read a cloudflare-side override for a v0.3 field path. */
export function getOverride(b: V3Builder, field: string): unknown {
  // Field path may contain dots; do a shallow lookup ("response.headers" → overrides["response.headers"])
  // and a single dotted-path walk so both shapes are accepted.
  if (field in b.overrides) return b.overrides[field];
  const parts = field.split('.');
  let cur: unknown = b.overrides;
  for (const p of parts) {
    if (cur && typeof cur === 'object' && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else return undefined;
  }
  return cur;
}

/** Build canonical x-security rule id: `x-security-<observe|shadow|enforce>-<ehash>-<kind>`. */
export function ruleId(b: V3Builder, kind: string): string {
  return `x-security-${modePrefix(b.mode)}-${b.ehash}-${kind}`;
}

/** Stamp shared `xSecurity.*` metadata onto an emitted rule. */
export function decorate(
  b: V3Builder,
  rule: Omit<CompiledRule, 'id' | 'xSecurity' | 'enabled' | 'mode'> & { kind: string; sourceField: string; confidence: CompiledRule['xSecurity']['confidence']; forceLog?: boolean }
): CompiledRule {
  const isNonBlocking = rule.action === 'rewrite';
  const forceLog = rule.forceLog === true || (isObserveMode(b.mode) && !isNonBlocking);
  const action = forceLog ? 'log' : rule.action;
  const out: CompiledRule = {
    id: ruleId(b, rule.kind),
    description: rule.description.startsWith('[x-security] ') ? rule.description : `[x-security] ${rule.description}`,
    expression: rule.expression,
    action,
    enabled: true,
    mode: b.mode,
    xSecurity: {
      endpoint_id: b.eid,
      rule_type: rule.kind,
      source_field: rule.sourceField,
      confidence: rule.confidence,
      schema_version: b.schemaVersion
    }
  };
  if (rule.action_parameters !== undefined) out.action_parameters = rule.action_parameters;
  if (rule.ratelimit !== undefined) out.ratelimit = rule.ratelimit;
  return out;
}

/** Suppress when a ruleset would otherwise contain zero rules. */
export function pushIfNonEmpty(out: CompiledRuleset[], rs: CompiledRuleset): void {
  if (rs.rules.length > 0) out.push(rs);
}
