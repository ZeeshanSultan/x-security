// Feasibility analysis for `lazy report --owasp --feasible <target[,target...]>`.
//
// Cross-references each endpoint's x-security policy against the capability
// matrices of one or more target generators to decide whether a *declared*
// OWASP mitigation can actually be enforced at runtime by something shipping
// today. Used by owasp-analyze.ts to downgrade Y → Y* or Y → ~ and by human.ts
// to print footnotes.
//
// Cross-target semantics (chains, e.g. kong,coraza):
//   A field is considered feasible across the chain if ANY listed target marks
//   it `full` or `partial`. Cross-target chains are how users compose layers
//   (e.g. Kong for AuthN/rate-limit + Coraza WAF for schema validation), so
//   "covered by someone" is the right rollup.

import type { Generator, CapabilityMatrix } from '@x-security/core';
import type { XSecurityPolicy, SecurityCategoryId } from '@x-security/schema';
import { isKnownTarget, loadGenerator, type TargetName } from '../registry.js';

export type CapStatus = 'full' | 'partial' | 'override-only' | 'unsupported' | 'unknown';

export interface FeasibilityContext {
  /** Targets the user supplied via --feasible (in order). */
  targets: TargetName[];
  /** Merged matrix: best status across the chain per field path. */
  merged: Record<string, CapStatus>;
  /** Per-target matrix, for footnote attribution. */
  perTarget: Record<TargetName, CapabilityMatrix['fields']>;
}

export class UnknownTargetError extends Error {
  constructor(public target: string) {
    super(`Unknown --feasible target: ${target}. Known: kong,coraza,bunkerweb,openappsec,firewall,envoy,aws-apigw,cloudflare.`);
  }
}

export function parseTargetList(raw: string): TargetName[] {
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const out: TargetName[] = [];
  for (const p of parts) {
    if (!isKnownTarget(p)) throw new UnknownTargetError(p);
    out.push(p);
  }
  return out;
}

const RANK: Record<CapStatus, number> = {
  full: 4,
  partial: 3,
  'override-only': 2,
  unsupported: 1,
  unknown: 0
};

function best(a: CapStatus, b: CapStatus): CapStatus {
  return RANK[a] >= RANK[b] ? a : b;
}

/** A generic/parent capability key can't prove a specific subtype, so its
 *  contribution to a subtype probe is capped at `partial` (never `full`). */
function cap(status: CapStatus): CapStatus {
  return status === 'full' ? 'partial' : status;
}

/**
 * Resolve a probe capKey against one target's capability matrix, tolerating
 * the three spelling conventions the generators use:
 *   - canonical subtype:  `authorization.rbac`            (kong)
 *   - explicit subtype:   `authorization.type=rbac`       (bunkerweb)
 *   - generic parent:     `authorization` / `authorization.type` (envoy, coraza)
 * plus child rollups for parent-style probe keys (`request.schema`,
 * `response.headers`, `timeout`, `ipPolicy` …) whose support is expressed
 * only at finer granularity.
 *
 * Exact and explicit-subtype matches are trusted as-is (they name the subtype).
 * A generic-parent match (e.g. `authorization`) is capped at `partial`: it
 * can't prove the specific subtype is enforced. A child rollup (`<capKey>.<sub>`)
 * is trusted as `full` only when EVERY child is `full` — a precise, complete
 * fine-grained matrix is not a coarse signal — and capped at `partial` when the
 * children are mixed.
 */
function resolveStatus(fields: Record<string, CapStatus>, capKey: string): CapStatus {
  const exact = fields[capKey];
  if (exact !== undefined) return exact;

  let out: CapStatus = 'unknown';
  const dot = capKey.indexOf('.');
  // The generic-parent fallback (e.g. `authorization` crediting
  // `authorization.rbac`) is ONLY valid for a single-segment subtype
  // (`group.value`). For deeper reserved paths like `graphql.operations.authz`,
  // folding the coarse parent `graphql` would falsely credit per-resolver
  // GraphQL authz from the block-level cost capability — a fabricated partial on
  // the BOLA/BFLA cell. Deep keys resolve via exact-match + child-rollup only.
  if (dot > 0 && capKey.indexOf('.', dot + 1) === -1) {
    const group = capKey.slice(0, dot);
    const value = capKey.slice(dot + 1);
    const explicit = fields[`${group}.type=${value}`];
    if (explicit !== undefined) out = best(out, explicit);
    for (const generic of [`${group}.type`, group]) {
      const g = fields[generic];
      if (g !== undefined) out = best(out, cap(g));
    }
  }

  // Child rollup: the target expresses the capability only via `<capKey>.<sub>`.
  // All-children-`full` rolls up to `full`; any non-`full` child caps at `partial`.
  const prefix = `${capKey}.`;
  let sawChild = false;
  let allChildrenFull = true;
  let anyChildSupported = false;
  for (const [k, v] of Object.entries(fields)) {
    if (!k.startsWith(prefix)) continue;
    sawChild = true;
    if (v !== 'full') allChildrenFull = false;
    if (v === 'full' || v === 'partial' || v === 'override-only') anyChildSupported = true;
  }
  if (sawChild) {
    const rolled: CapStatus = allChildrenFull ? 'full' : anyChildSupported ? 'partial' : 'unsupported';
    out = best(out, rolled);
  }

  return out;
}

export async function buildFeasibilityContext(targets: TargetName[]): Promise<FeasibilityContext> {
  const perTarget: Partial<Record<TargetName, CapabilityMatrix['fields']>> = {};
  const merged: Record<string, CapStatus> = {};
  for (const t of targets) {
    const gen: Generator | null = await loadGenerator(t);
    if (!gen) throw new Error(`Failed to load generator for target "${t}".`);
    const fields = gen.capabilities().fields;
    perTarget[t] = fields;
    for (const [k, v] of Object.entries(fields)) {
      merged[k] = best(merged[k] ?? 'unknown', v as CapStatus);
    }
  }
  return { targets, merged, perTarget: perTarget as Record<TargetName, CapabilityMatrix['fields']> };
}

// ----------------------------------------------------------------------------
// OWASP → contributing x-security fields (capability-matrix keys).
//
// Each entry lists the fields whose presence-AND-feasibility together qualify
// the endpoint as mitigated for that OWASP id. A field only "contributes" if
// the endpoint actually sets it; we then check feasibility on the contributing
// subset (a field the endpoint doesn't set can't drag the verdict down).
// ----------------------------------------------------------------------------

interface FieldProbe {
  /** Capability matrix key to check against the target. */
  capKey: string;
  /** Returns true iff this policy actually configures this field. */
  present: (p: XSecurityPolicy) => boolean;
}

function nonEmpty(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v as object).length > 0;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.length > 0;
  return true;
}

/** True iff any request.schema field declares a non-empty domainAllowlist
 *  (the SSRF / safe-upstream-fetch allowlist). */
function hasDomainAllowlist(p: XSecurityPolicy): boolean {
  const schema = p.request?.schema;
  if (!schema || typeof schema !== 'object') return false;
  return Object.values(schema).some(
    (f) => Array.isArray((f as { domainAllowlist?: unknown[] })?.domainAllowlist)
      && ((f as { domainAllowlist: unknown[] }).domainAllowlist.length > 0)
  );
}

/** True iff any request.schema field declares a non-empty injectionGuard[]
 *  (the per-arg sink-hardening directive: sql/nosql/os-command/xpath/ldap/
 *  code-eval/xss/deserialization/ai-prompt). Drives the x-security-native
 *  SSEC-INJECTION attribution; 'deserialization' rides this cell (same
 *  injection class), 'ai-prompt' is split out to SSEC-PROMPT below. */
function hasInjectionGuard(p: XSecurityPolicy): boolean {
  const schema = p.request?.schema;
  if (!schema || typeof schema !== 'object') return false;
  return Object.values(schema).some(
    (f) => Array.isArray((f as { injectionGuard?: unknown[] })?.injectionGuard)
      && ((f as { injectionGuard: unknown[] }).injectionGuard.length > 0)
  );
}

/** True iff any request.schema field declares injectionGuard including
 *  'ai-prompt'. LLM prompt injection is a distinct threat class (one synthetic
 *  id per class), so it gets its own SSEC-PROMPT probe rather than folding into
 *  SSEC-INJECTION. Resolves against the same `request.schema.injectionGuard`
 *  capability key (full on coraza/bunkerweb, unsupported on kong/envoy). */
function hasAiPromptGuard(p: XSecurityPolicy): boolean {
  const schema = p.request?.schema;
  if (!schema || typeof schema !== 'object') return false;
  return Object.values(schema).some(
    (f) => Array.isArray((f as { injectionGuard?: unknown[] })?.injectionGuard)
      && (f as { injectionGuard: unknown[] }).injectionGuard.includes('ai-prompt')
  );
}

/** True iff any graphql.operations[] entry declares per-operation authz. This
 *  is the per-resolver BOLA (API1) / BFLA (API5) directive. OVERRIDE-ONLY on
 *  every target — a gateway cannot evaluate per-resolver authz without an
 *  operator-supplied GraphQL-aware processor — so the feasibility verdict can
 *  never resolve to `full` here, only `partial` (Y*) with the operator-handoff
 *  disclaimer below. */
function hasGraphqlOperationAuthz(p: XSecurityPolicy): boolean {
  const ops = p.graphql?.operations;
  if (!Array.isArray(ops)) return false;
  return ops.some((op) => nonEmpty((op as { authz?: unknown })?.authz));
}

/** True iff the policy declares any coarse, block-level GraphQL static limit
 *  (graphql.{maxDepth,maxComplexity,maxAliases,batchLimit,disableIntrospection,
 *  allowedOperations}). Distinct capKey (`graphql.staticLimits`) from the
 *  per-operation authz so the two cells never merge (API4 vs API1/API5). */
function hasGraphqlStaticLimits(p: XSecurityPolicy): boolean {
  const g = p.graphql;
  if (!g || typeof g !== 'object') return false;
  return (
    nonEmpty(g.maxDepth) ||
    nonEmpty(g.maxComplexity) ||
    nonEmpty(g.maxAliases) ||
    nonEmpty(g.batchLimit) ||
    g.disableIntrospection === true ||
    nonEmpty(g.allowedOperations)
  );
}

const OWASP_FIELDS: Record<SecurityCategoryId, FieldProbe[]> = {
  'API1:2023': [
    { capKey: 'authorization.rule-based', present: (p) => p.authorization?.type === 'rule-based' },
    { capKey: 'authorization.abac', present: (p) => p.authorization?.type === 'abac' },
    { capKey: 'authorization.rbac', present: (p) => p.authorization?.type === 'rbac' },
    // v0.8 (BOLA per-resolver): graphql.operations[].authz. OVERRIDE-ONLY on
    // every target — resolves to partial (Y*) at best, never full, because the
    // gateway needs an operator-supplied GraphQL processor to evaluate it.
    { capKey: 'graphql.operations.authz', present: hasGraphqlOperationAuthz }
  ],
  'API2:2023': [
    { capKey: 'authentication.bearer-jwt', present: (p) => p.authentication?.type === 'bearer-jwt' },
    { capKey: 'authentication.oauth2', present: (p) => p.authentication?.type === 'oauth2' },
    { capKey: 'authentication.api-key', present: (p) => p.authentication?.type === 'api-key' },
    { capKey: 'rateLimit', present: (p) => nonEmpty(p.rateLimit) },
    // v0.7: credential-strength + brute-force defenses on auth endpoints.
    { capKey: 'authentication.passwordPolicy', present: (p) => nonEmpty(p.authentication?.passwordPolicy) },
    { capKey: 'authentication.accountLockout', present: (p) => nonEmpty(p.authentication?.accountLockout) }
  ],
  // API3 = Broken Object Property Level Authorization: mass assignment
  // (request.schema / denyUnknownFields) + excessive data exposure
  // (response.schema / stripUnknownFields) + object-property authz. Mirrors
  // owasp-mapping.json; mass-assignment lives here per OWASP 2023, not API6.
  'API3:2023': [
    { capKey: 'request.schema', present: (p) => nonEmpty(p.request?.schema) },
    { capKey: 'request.denyUnknownFields', present: (p) => p.request?.denyUnknownFields === true },
    // PROBE-DRIFT FIX: allowedFields is the shorthand body-key allowlist —
    // kong enforces it `full` (K-3 pre-function) and coraza `partial`. Without
    // this probe an endpoint mass-assignment-hardened via allowedFields got an
    // empty-note `partial`, understating shipped enforcement (VAmPI/vuln-bank/DVWS).
    { capKey: 'request.allowedFields', present: (p) => nonEmpty(p.request?.allowedFields) },
    { capKey: 'response.schema', present: (p) => nonEmpty(p.response?.schema) },
    { capKey: 'response.stripUnknownFields', present: (p) => p.response?.stripUnknownFields === true },
    // v0.7: JSON-hijacking defense — forbid a bare top-level array body.
    { capKey: 'response.forbidArrayRoot', present: (p) => p.response?.forbidArrayRoot === true },
    { capKey: 'authorization.rule-based', present: (p) => p.authorization?.type === 'rule-based' },
    { capKey: 'authorization.rbac', present: (p) => p.authorization?.type === 'rbac' },
    { capKey: 'authorization.abac', present: (p) => p.authorization?.type === 'abac' }
  ],
  'API4:2023': [
    { capKey: 'rateLimit', present: (p) => nonEmpty(p.rateLimit) },
    { capKey: 'timeout', present: (p) => nonEmpty(p.timeout) },
    { capKey: 'request.maxBodySize', present: (p) => nonEmpty(p.request?.maxBodySize) },
    // v0.8 coarse GraphQL cost controls (depth/complexity/aliases/batch/…).
    // capKey `graphql.staticLimits`, kept distinct from graphql.operations.authz
    // so the API4 cell never merges with the per-resolver authz cells. Override-
    // only on every target (a target may reach partial via a crude non-parsing
    // limit); resolves to partial at best here, never full.
    { capKey: 'graphql.staticLimits', present: hasGraphqlStaticLimits }
  ],
  // API5 = BFLA: authorization (any subtype) + ipPolicy. (owasp-mapping.json)
  'API5:2023': [
    { capKey: 'authorization.rule-based', present: (p) => p.authorization?.type === 'rule-based' },
    { capKey: 'authorization.rbac', present: (p) => p.authorization?.type === 'rbac' },
    { capKey: 'authorization.abac', present: (p) => p.authorization?.type === 'abac' },
    { capKey: 'ipPolicy', present: (p) => nonEmpty(p.ipPolicy) },
    // v0.8 (BFLA per-resolver): graphql.operations[].authz. Override-only on
    // every target (operator-supplied GraphQL processor required); partial at
    // best, never full.
    { capKey: 'graphql.operations.authz', present: hasGraphqlOperationAuthz }
  ],
  // API6 = Unrestricted Access to Sensitive Business Flows: rate limiting +
  // authentication + IP restriction (owasp-mapping.json). NOT mass assignment
  // — that is API3 per OWASP 2023.
  'API6:2023': [
    { capKey: 'rateLimit', present: (p) => nonEmpty(p.rateLimit) },
    { capKey: 'authentication.bearer-jwt', present: (p) => p.authentication?.type === 'bearer-jwt' },
    { capKey: 'authentication.oauth2', present: (p) => p.authentication?.type === 'oauth2' },
    { capKey: 'authentication.api-key', present: (p) => p.authentication?.type === 'api-key' },
    { capKey: 'ipPolicy', present: (p) => nonEmpty(p.ipPolicy) },
    // v0.7: replay / double-submit defense keyed on a client idempotency header.
    { capKey: 'request.idempotencyKey', present: (p) => nonEmpty(p.request?.idempotencyKey) },
    // v0.8: live-concurrency serialization key. PARTIAL AT BEST — edge
    // serialization only (coraza/bunkerweb partial, envoy override-only, rest
    // unsupported); does NOT provide in-handler transaction atomicity, so the
    // verdict can never resolve to full here.
    { capKey: 'request.serializeBy', present: (p) => nonEmpty(p.request?.serializeBy) }
  ],
  // API7 = SSRF: server-side fetch allowlist (request.schema.domainAllowlist +
  // blockPrivateRanges), enforced full by envoy/coraza/bunkerweb (W19-A).
  'API7:2023': [
    { capKey: 'request.schema.domainAllowlist', present: hasDomainAllowlist }
  ],
  // API8 = Security Misconfiguration: CORS, content-type enforcement, response
  // header hardening, mTLS. (owasp-mapping.json)
  'API8:2023': [
    { capKey: 'cors', present: (p) => nonEmpty(p.cors) },
    { capKey: 'request.contentType', present: (p) => nonEmpty(p.request?.contentType) },
    { capKey: 'response.contentType', present: (p) => nonEmpty(p.response?.contentType) },
    { capKey: 'response.headers', present: (p) => nonEmpty(p.response?.headers) },
    // PROBE-DRIFT FIX: errorScrubbing strips stack traces / server headers and
    // genericizes 5xx bodies — kong (W26 post-function) and bunkerweb (id:268)
    // enforce it `full` via the response.errorScrubbing.* children, which
    // resolveStatus rolls up. Was unprobed, so error-leak-hardened endpoints
    // got empty-note `partial`s that understated coverage (VAmPI/vuln-bank/DVWS).
    { capKey: 'response.errorScrubbing', present: (p) => nonEmpty(p.response?.errorScrubbing) },
    { capKey: 'mtls', present: (p) => nonEmpty(p.mtls) }
  ],
  'API9:2023': [
    { capKey: 'deprecated', present: (p) => p.deprecated === true },
    { capKey: 'sunsetDate', present: (p) => nonEmpty(p.sunsetDate) },
    { capKey: 'rateLimit', present: (p) => nonEmpty(p.rateLimit) }
  ],
  'API10:2023': [
    // Unsafe upstream consumption (owasp-mapping.json) = mtls +
    // request.schema.domainAllowlist (restrict what the server fetches),
    // plus request signing where present.
    { capKey: 'request.schema.domainAllowlist', present: hasDomainAllowlist },
    { capKey: 'request.signature', present: (p) => nonEmpty(p.request?.signature) },
    { capKey: 'request.allowedHosts', present: (p) => nonEmpty(p.request?.allowedHosts) },
    { capKey: 'mtls', present: (p) => nonEmpty(p.mtls) }
  ],
  // SSEC-INJECTION = x-security-native injection category (W19). Mitigated by
  // per-arg sink hardening: request.schema.<field>.injectionGuard. The probe
  // resolves against the `request.schema.injectionGuard` capability key, which
  // kong + envoy currently advertise `unsupported` (no libinjection/@detectSQLi
  // equivalent — a regex fake would be the Rule D-1 masked-quality trap). When
  // a generator ships real enforcement for this key, the feasibility verdict
  // surfaces it automatically; until then it honestly resolves to none/partial
  // rather than an empty-note placeholder.
  'SSEC-INJECTION': [
    { capKey: 'request.schema.injectionGuard', present: hasInjectionGuard }
  ],
  // SSEC-PROMPT = x-security-native LLM prompt-injection category (v0.7). A
  // distinct threat class from SSEC-INJECTION (one synthetic id per class), so
  // it gets its own probe keyed on injectionGuard.includes('ai-prompt'). It
  // resolves against the SAME `request.schema.injectionGuard` capability key —
  // full on coraza/bunkerweb, unsupported on kong/envoy — so the verdict tracks
  // real enforcement without a separate matrix cell or a masked-quality default.
  'SSEC-PROMPT': [
    { capKey: 'request.schema.injectionGuard', present: hasAiPromptGuard }
  ],
  // SSEC-AUDIT = x-security-native audit-logging category (v0.7). Mitigated by
  // the declarative `logging` policy (events/sink/sinkRef/piiRedaction). The
  // probe resolves against the flat `logging` capability key; until a generator
  // advertises it the verdict honestly resolves to none/partial rather than an
  // empty-note placeholder (Rule D-1).
  'SSEC-AUDIT': [
    { capKey: 'logging', present: (p) => nonEmpty(p.logging) }
  ],
  // SSEC-STORAGE = x-security-native at-rest storage posture (v0.8). ADVISORY
  // ONLY. request.dataAtRest declares the protection the *app* must apply to
  // named body fields; the gateway never sees the DB write, so this compiles to
  // NOTHING enforcing. The capability is hard-pinned override-only/unsupported
  // on every target (never full, never partial in the matrix), so the verdict
  // here resolves to partial (Y*) at best — never full. It is surfaced as an
  // out-of-band finding (a posture declaration, not a control), with the
  // advisory disclaimer attached in the reporter rather than rendered as an
  // enforcement cell.
  'SSEC-STORAGE': [
    { capKey: 'request.dataAtRest', present: (p) => nonEmpty(p.request?.dataAtRest) }
  ]
};

export type FeasibilityVerdict = 'full' | 'partial' | 'none';

// Per-capKey honesty disclaimers. These fields are structurally NOT fully
// gateway-enforceable (override-only or advisory-only by design), so when they
// contribute to a verdict the reader must see *why* the cell is Y* / ~ and not
// Y — the enforcement is an operator/app responsibility, not something the
// emitted config performs. Surfacing this prevents a DVAPI-style "looks
// enforced" illusion (Rule D-1).
const CAPKEY_DISCLAIMERS: Record<string, string> = {
  'graphql.operations.authz':
    'override-only: per-operation GraphQL authz enforcement depends on an operator-supplied GraphQL-aware processor; x-security emits scaffolding only',
  'graphql.staticLimits':
    'override-only: coarse GraphQL cost limits depend on an operator-supplied GraphQL-aware processor; a non-parsing crude limit is partial at best',
  'request.serializeBy':
    'edge serialization only — does NOT provide in-handler transaction atomicity',
  'request.dataAtRest':
    'advisory posture declaration — NOT gateway-enforced; drives an out-of-band SSEC-STORAGE scan finding'
};

export interface FeasibilityResult {
  verdict: FeasibilityVerdict;
  /** Unsupported / partial fields per target — drives footnote text. */
  notes: Array<{ target: TargetName; field: string; status: CapStatus }>;
  /** Honesty disclaimers for contributing override-only / advisory-only fields
   *  (capKey-scoped, target-independent). Surfaced as footnotes so a Y* / ~ on
   *  an unenforceable-by-design field reads as operator/app responsibility. */
  disclaimers: string[];
}

/**
 * Given an endpoint policy that already mitigates `id` per the declarative
 * mapping (verdict='yes'), decide whether the named targets can actually
 * enforce it. Returns:
 *   - 'full'    if every contributing field is `full` for at least one target
 *   - 'partial' if at least one contributing field is `partial` somewhere, or
 *               some targets don't support a field that others do
 *   - 'none'    if every contributing field is `unsupported` across all targets
 */
export function evaluateFeasibility(
  id: SecurityCategoryId,
  policy: XSecurityPolicy,
  ctx: FeasibilityContext
): FeasibilityResult {
  const probes = OWASP_FIELDS[id] ?? [];
  const contributing = probes.filter((pr) => pr.present(policy));
  if (contributing.length === 0) {
    // The declarative mapping said `yes` via a field we don't probe here
    // (e.g. policy.mitigates explicit) — be conservative: mark partial with
    // an attribution note pointing to the unknown surface.
    return { verdict: 'partial', notes: [], disclaimers: [] };
  }

  // Honesty disclaimers for any contributing override-only / advisory-only
  // field, regardless of per-target status — the field is unenforceable by
  // design, so the reader sees the operator/app handoff even when a target
  // advertises a crude partial.
  const disclaimers: string[] = [];
  for (const probe of contributing) {
    const d = CAPKEY_DISCLAIMERS[probe.capKey];
    if (d && !disclaimers.includes(d)) disclaimers.push(d);
  }

  const notes: FeasibilityResult['notes'] = [];
  let everyFieldFull = true;
  let everyFieldUnsupported = true;

  for (const probe of contributing) {
    // The chain enforces a field if ANY target enforces it — take the best
    // status across targets. Adding a target can only raise this, never lower
    // it, so a longer chain is always >= its strongest single member.
    let fieldBest: CapStatus = 'unknown';
    for (const t of ctx.targets) {
      fieldBest = best(fieldBest, resolveStatus(ctx.perTarget[t] ?? {}, probe.capKey));
    }

    if (fieldBest !== 'full') {
      everyFieldFull = false;
      // Attribution footnotes: surface which targets fall short of `full` for
      // this field. Purely informational — they no longer gate the verdict.
      for (const t of ctx.targets) {
        const status = resolveStatus(ctx.perTarget[t] ?? {}, probe.capKey);
        if (status === 'partial' || status === 'override-only' || status === 'unsupported') {
          notes.push({ target: t, field: probe.capKey, status });
        }
      }
    }
    if (fieldBest === 'full' || fieldBest === 'partial' || fieldBest === 'override-only') {
      everyFieldUnsupported = false;
    }
  }

  if (everyFieldUnsupported) return { verdict: 'none', notes, disclaimers };
  // An all-`full` verdict can only happen when no override-only / advisory-only
  // field contributed (those never resolve to `full`), so `disclaimers` is empty
  // here — but pass it through rather than dropping notes, to keep the honesty
  // line attached if a future capKey is both full-capable and disclaimer-worthy.
  if (everyFieldFull) return { verdict: 'full', notes: [], disclaimers };
  return { verdict: 'partial', notes, disclaimers };
}
