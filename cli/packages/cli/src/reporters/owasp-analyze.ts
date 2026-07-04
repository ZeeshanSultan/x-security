// Derives OWASP coverage and annotation-coverage reports from a SpecIR.
// The rules are intentionally simple: each OWASP ID lists the policy field
// paths that mitigate it (from schema/owasp-mapping.json). If the endpoint
// has ALL listed fields set, coverage = 'yes'. If SOME, 'partial'. None, 'no'.

import type { SpecIR, EndpointIR } from '@writ/core';
import { owaspMapping } from '@writ/schema';
import type { SecurityCategoryId, XSecurityPolicy } from '@writ/schema';
import type {
  AnnotationCoverageReport,
  OwaspCoverageReport,
  OwaspCoverageRow
} from './types.js';
import {
  evaluateFeasibility,
  type FeasibilityContext
} from './feasibility.js';

// The 10 OWASP API Top-10 ids plus Writ-native synthetic categories.
// The SSEC ids are appended last so the OWASP matrix order is preserved and the
// synthetic rows sort after the standard cells. Downstream reporters that render
// a fixed 10-column matrix (human.ts) key off their own OWASP-only list and
// surface the synthetic ids in a separate column block — keeping the 10 cells
// uncorrupted while the JSON/SARIF coverage records carry the SSEC rows.
const OWASP_IDS: SecurityCategoryId[] = [
  'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
  'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023', 'API10:2023',
  'SSEC-INJECTION', 'SSEC-PROMPT', 'SSEC-AUDIT', 'SSEC-STORAGE'
];

interface MappingEntry {
  name: string;
  mitigatedBy: string[];
}

const MAPPING = owaspMapping as Record<SecurityCategoryId, MappingEntry>;

/**
 * True iff the policy has a non-empty value at the dotted field path.
 * Supports special path tokens used in owasp-mapping.json:
 *   - "request.schema.domainAllowlist" — any param schema with domainAllowlist
 *   - "coverage-report" / "drift-detection" / "firewall" — meta, treated as
 *      always "partial" (process-level mitigation, not inline policy)
 */
function hasField(policy: XSecurityPolicy, field: string, id: SecurityCategoryId): boolean | 'meta' {
  if (field === 'coverage-report' || field === 'drift-detection' || field === 'firewall') {
    return 'meta';
  }
  if (field === 'request.schema.domainAllowlist') {
    const schema = policy.request?.schema;
    if (!schema) return false;
    return Object.values(schema).some((p) => Array.isArray(p.domainAllowlist) && p.domainAllowlist.length > 0);
  }
  if (field === 'graphql.operations.authz') {
    // Per-operation GraphQL authz: true iff ANY graphql.operations[] entry
    // declares a non-empty authz. A plain dotted traversal would look for
    // `.authz` on the operations ARRAY and miss it (operations is an array of
    // GraphqlOperation). Attributed to API1 (per-resolver BOLA) and API5
    // (per-resolver BFLA); override-only on every target, so feasibility caps
    // the cell at Y* regardless of this coverage hit.
    const ops = policy.graphql?.operations;
    if (!Array.isArray(ops)) return false;
    return ops.some((op) => op.authz !== undefined && op.authz !== null);
  }
  if (field === 'graphql.staticLimits') {
    // Coarse block-level GraphQL cost limits. Capability-key reservation, no
    // single schema field — true iff any of the block-level limits is set.
    const g = policy.graphql;
    if (!g) return false;
    return (
      g.maxDepth !== undefined ||
      g.maxComplexity !== undefined ||
      g.maxAliases !== undefined ||
      g.batchLimit !== undefined ||
      g.disableIntrospection === true ||
      (Array.isArray(g.allowedOperations) && g.allowedOperations.length > 0)
    );
  }
  if (field === 'request.schema.injectionGuard') {
    // Per-arg directive: true iff ANY param schema declares a non-empty
    // injectionGuard[]. A plain dotted traversal would wrongly look for
    // schema.injectionGuard (schema is a Record<field, ParamSchema>).
    //
    // SSEC-INJECTION and SSEC-PROMPT share this mapping field but split the
    // sink space: 'ai-prompt' is a distinct threat class attributed ONLY to
    // SSEC-PROMPT, every other sink to SSEC-INJECTION. Derive each id from the
    // relevant subset so an sql-only guard never lights up SSEC-PROMPT and an
    // ai-prompt-only guard never lights up SSEC-INJECTION.
    const schema = policy.request?.schema;
    if (!schema) return false;
    const matches = (g: string) => g === 'ai-prompt';
    if (id === 'SSEC-PROMPT') {
      return Object.values(schema).some(
        (p) => Array.isArray(p.injectionGuard) && p.injectionGuard.some(matches)
      );
    }
    if (id === 'SSEC-INJECTION') {
      return Object.values(schema).some(
        (p) => Array.isArray(p.injectionGuard) && p.injectionGuard.some((g) => !matches(g))
      );
    }
    return Object.values(schema).some((p) => Array.isArray(p.injectionGuard) && p.injectionGuard.length > 0);
  }
  // dotted path traversal
  const parts = field.split('.');
  let cur: unknown = policy;
  for (const p of parts) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return false;
    cur = (cur as Record<string, unknown>)[p];
  }
  if (cur === undefined || cur === null) return false;
  if (Array.isArray(cur)) return cur.length > 0;
  if (typeof cur === 'object') return Object.keys(cur as Record<string, unknown>).length > 0;
  return true;
}

function coverEndpoint(policy: XSecurityPolicy): Record<SecurityCategoryId, 'yes' | 'no' | 'partial'> {
  const out = {} as Record<SecurityCategoryId, 'yes' | 'no' | 'partial'>;
  // Explicit `mitigates` on the policy short-circuits to 'yes' for those IDs.
  // `mitigates` is OWASP-pure (SSEC-INJECTION is rejected by the schema), so
  // the synthetic id is never short-circuited here — it is always derived from
  // the injectionGuard probe.
  const explicit = new Set<SecurityCategoryId>(policy.mitigates ?? []);
  for (const id of OWASP_IDS) {
    if (explicit.has(id)) {
      out[id] = 'yes';
      continue;
    }
    const entry = MAPPING[id];
    if (!entry) {
      out[id] = 'no';
      continue;
    }
    let hits = 0;
    let metas = 0;
    for (const f of entry.mitigatedBy) {
      const r = hasField(policy, f, id);
      if (r === 'meta') metas++;
      else if (r) hits++;
    }
    const concrete = entry.mitigatedBy.length - metas;
    if (concrete === 0) {
      // Only meta-mitigations exist — mark as partial when at least the
      // endpoint has *some* annotation, else no.
      out[id] = 'partial';
    } else if (hits === concrete) {
      out[id] = 'yes';
    } else if (hits > 0) {
      out[id] = 'partial';
    } else {
      out[id] = 'no';
    }
  }
  return out;
}

function endpointLabel(e: EndpointIR): string {
  return `${e.method} ${e.path}`;
}

export function buildOwaspReport(
  spec: SpecIR,
  feasibility?: FeasibilityContext
): OwaspCoverageReport {
  const rows: OwaspCoverageRow[] = spec.endpoints.map((e) => {
    const coverage = coverEndpoint(e.policy);
    const row: OwaspCoverageRow = {
      endpoint: endpointLabel(e),
      // coverage carries the 10 OWASP cells plus the synthetic SSEC-INJECTION
      // key. The row type tracks only OwaspId; the extra synthetic key rides
      // along in the JSON/SARIF serialization and is ignored by the fixed
      // 10-column human matrix.
      coverage: coverage as OwaspCoverageRow['coverage']
    };
    if (feasibility) {
      const fmap = {} as Record<SecurityCategoryId, 'feasible' | 'partial' | 'none' | 'na'>;
      const notes = {} as Record<SecurityCategoryId, string[]>;
      for (const id of OWASP_IDS) {
        if (coverage[id] !== 'yes') {
          fmap[id] = 'na';
          continue;
        }
        const r = evaluateFeasibility(id, e.policy, feasibility);
        fmap[id] = r.verdict === 'full' ? 'feasible' : r.verdict;
        // De-dupe per-target shortfall notes by `target:field:status`, then
        // append the capKey honesty disclaimers (override-only / advisory-only
        // fields) so a Y* / ~ on an unenforceable-by-design field reads as an
        // operator/app responsibility rather than a gateway control.
        const seen = new Set<string>();
        const lines: string[] = [];
        for (const n of r.notes) {
          const k = `${n.target}:${n.field}:${n.status}`;
          if (seen.has(k)) continue;
          seen.add(k);
          lines.push(`not enforceable by ${n.target}: ${n.field} = ${n.status}`);
        }
        for (const d of r.disclaimers) {
          if (!lines.includes(d)) lines.push(d);
        }
        if (lines.length > 0) notes[id] = lines;
      }
      row.feasibility = fmap as NonNullable<OwaspCoverageRow['feasibility']>;
      row.feasibilityNotes = notes as NonNullable<OwaspCoverageRow['feasibilityNotes']>;
    }
    return row;
  });
  const report: OwaspCoverageReport = {
    kind: 'owasp',
    spec: { title: spec.info.title, version: spec.info.version },
    rows,
    unprotected: spec.unprotectedEndpoints
  };
  if (feasibility) report.feasibleTargets = feasibility.targets;
  return report;
}

function listAnnotatedFields(policy: XSecurityPolicy): string[] {
  const fields: string[] = [];
  // Every security-policy key on XSecurityPolicy, in declaration order.
  // Lifecycle/meta keys (profile, deprecated, sunsetDate, replacementEndpoint,
  // targetOverrides, mitigates) are deliberately excluded — they annotate or
  // route, they are not protections. Keep this consistent with the audit
  // controls tally (packages/cli/src/commands/detect/audit.ts).
  const top: Array<keyof XSecurityPolicy> = [
    'authentication', 'authorization', 'csrf', 'rateLimit', 'timeout',
    'cacheable', 'cors', 'mtls', 'ipPolicy', 'request', 'response',
    'logging', 'graphql', 'websocket', 'botProtection',
    'outboundCalls', 'tls'
  ];
  for (const k of top) {
    const v = policy[k];
    if (v === undefined || v === null) continue;
    if (typeof v === 'boolean') { fields.push(k); continue; }
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    fields.push(k);
  }
  return fields;
}

export function buildAnnotationCoverage(spec: SpecIR): AnnotationCoverageReport {
  const total = spec.endpoints.length + spec.unprotectedEndpoints.length;
  return {
    kind: 'coverage',
    spec: { title: spec.info.title, version: spec.info.version },
    totalEndpoints: total,
    annotatedEndpoints: spec.endpoints.length,
    unprotected: spec.unprotectedEndpoints,
    perEndpoint: spec.endpoints.map((e) => ({
      endpoint: endpointLabel(e),
      fields: listAnnotatedFields(e.policy)
    }))
  };
}
