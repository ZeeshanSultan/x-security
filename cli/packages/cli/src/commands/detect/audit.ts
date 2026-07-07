// `lazy audit <repoDir>`
//
// The self-check / proof step. Reads every policy under .writ/policies/,
// re-validates it against the x-security schema, and byte-matches every cite
// in its sidecar against the repo source. Prints the cite-coverage proof the
// report headlines: "N routes, M controls, 100% cite-backed."
//
// Rule D-3 is the hard gate: citeBacked is false if ANY emitted control lacks a
// byte-matching cite. A schema-invalid policy, a missing sidecar, or a cite
// whose quote no longer matches the file all flip citeBacked to false and list
// the offending endpoint under `uncited`.
//
// Precision proof (P-fix): cite-coverage proves every control reads a real line,
// but NOT that the composed policy admits legitimate traffic. So audit ALSO runs
// V4's positive-sample round-trip over each persisted route policy: a synthetic
// legit request must be ALLOWED. `legitShapesPass: "N/N"` headlines this, and
// `overBlocked` lists any route whose own positive sample is false-blocked. This
// turns "100% cite-backed" into "100% cite-backed AND non-over-blocking".
//
// Contract: stdout
//   {"routes":N,"controls":M,"citeBacked":bool,"uncited":[...],"coverage":...,
//    "legitShapesPass":"N/N","overBlocked":[...]}

import { promises as fs } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import {
  validateXSecurity,
  readSlice,
  snapQuoteToFile,
  normalizeWhitespace,
  generatePositive,
  discoverHandlerParams,
  evaluatePolicy,
  extractRoutes,
  normPath,
  type Citation,
  type ExtractedRoute,
  type RouteInventoryEntry,
  type XSecurityPolicy,
} from '@x-security/detect-core';
import { xSecuritySchema } from '@x-security/schema';
import { resolvePoliciesDir, type PolicyCites } from './store.js';

export interface AuditResult {
  routes: number;
  controls: number;
  citeBacked: boolean;
  uncited: string[];
  coverage: number;
  /** "N/N" — routes whose synthetic POSITIVE (legit) request is allowed by the
   *  persisted policy, over the routes V4 could round-trip. Proves precision. */
  legitShapesPass: string;
  /** Endpoints whose own positive sample is false-blocked by their policy. */
  overBlocked: string[];
}

/** The x-security schema itself is the authority for which keys are controls: the
 * top-level `properties` (minus lifecycle/routing metadata) and every key of the
 * `request` / `response` sub-schemas are enforcement controls. We enumerate them
 * from the exported schema JSON so the audit denominator can never drift from the
 * shape the compiler emits — a new control key added to the schema is counted the
 * moment a policy carries it, with no code change here.
 *
 * The owasp-mapping's `mitigatedBy` list was NOT used as the source: it is a
 * partial view (e.g. `response.stripUnknownFields`, the `responseShape` control,
 * appears nowhere in it), and sourcing the denominator from a partial list is the
 * exact under-reporting class this fix removes.
 *
 * Excluded top-level keys are not controls: `profile` (a preset selector),
 * `deprecated` / `sunsetDate` / `replacementEndpoint` (lifecycle metadata),
 * `targetOverrides` (per-target compile hints), `mitigates` (OWASP annotation). */
const METADATA_TOP_KEYS = new Set([
  'profile',
  'deprecated',
  'sunsetDate',
  'replacementEndpoint',
  'targetOverrides',
  'mitigates',
]);

interface SchemaNode {
  properties?: Record<string, unknown>;
  $ref?: string;
  $defs?: Record<string, SchemaNode>;
}

/** Resolve a `#/$defs/Name` local ref against the schema's $defs. */
function resolveDef(schema: SchemaNode, ref: string): SchemaNode | undefined {
  const name = ref.replace('#/$defs/', '');
  return schema.$defs?.[name];
}

/** Enumerate the control key-paths from the schema. Top-level control blocks
 * count as single controls; `request`/`response` expose their own sub-keys as
 * dot-paths (`request.denyUnknownFields`, `response.stripUnknownFields`, …). */
function controlPathsFromSchema(): string[] {
  const schema = xSecuritySchema as unknown as SchemaNode;
  const top = schema.properties ?? {};
  const paths: string[] = [];

  for (const key of Object.keys(top)) {
    if (METADATA_TOP_KEYS.has(key)) continue;
    if (key === 'request' || key === 'response') {
      // Expand the sub-schema so each request/response control is counted.
      const node = top[key] as SchemaNode;
      const sub = node.$ref ? resolveDef(schema, node.$ref) : node;
      for (const subKey of Object.keys(sub?.properties ?? {})) {
        paths.push(`${key}.${subKey}`);
      }
      continue;
    }
    paths.push(key);
  }
  return paths;
}

const CONTROL_PATHS = controlPathsFromSchema();

/** Resolve a dotted key-path (e.g. `request.denyUnknownFields`) against a policy
 * object, returning the value at that path or undefined if any segment is absent
 * or not an object. Pure structural walk — no defaulting (D-1). */
function resolvePath(policy: Record<string, unknown>, dotted: string): unknown {
  let cur: unknown = policy;
  for (const seg of dotted.split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/** True when a resolved control value is genuinely present AND enforcing, not a
 * disabled/empty placeholder. This is the D-1 line: a key that exists but is
 * switched off (denyUnknownFields:false, authentication.type:'none', an empty
 * schema/allowlist) is NOT a control — counting it would over-report the way the
 * old auth/schema-only tally under-reported. */
function isActiveControl(value: unknown): boolean {
  if (value === undefined || value === null || value === false) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value as object).length > 0;
  return true; // scalar truthy (true, a number, a non-empty string)
}

/** Count the enforced controls in a policy. Every emitted control kind present in
 * the policy set counts toward the denominator the cite set must cover, not just
 * auth + schema fields (the under-reporting bug). Two shapes:
 *
 *  - Map-valued controls (`request.schema`, `response.schema`) count once PER
 *    entry — each param/field constraint is an independently cited control.
 *  - Flag/block controls (authorization, rateLimit, cors, denyUnknownFields,
 *    stripUnknownFields, contentType, timeout, mtls, ipPolicy, logging, …) count
 *    once each when present and active.
 *
 * The path list is derived from the x-security schema, so a new control key added
 * to the schema is counted automatically with no change here. */
function countControls(policy: Record<string, unknown>): number {
  let n = 0;

  // authentication is a control only when it actually authenticates (type !== 'none').
  const auth = policy['authentication'] as { type?: string } | undefined;
  const authActive = !!(auth && auth.type && auth.type !== 'none');

  for (const dotted of CONTROL_PATHS) {
    const value = resolvePath(policy, dotted);

    if (dotted === 'authentication') {
      if (authActive) n += 1;
      continue;
    }

    // Map-valued controls: one control per declared param/field entry.
    if (dotted === 'request.schema' || dotted === 'response.schema') {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        n += Object.keys(value as Record<string, unknown>).length;
      }
      continue;
    }

    if (isActiveControl(value)) n += 1;
  }

  return n;
}

/** Resolve the HTTP route for V4's positive-sample round-trip, grounded against
 * the machine extractor so we carry the REAL handler file + symbol (fix E) — the
 * positive sample then includes the fields the handler actually reads, so an
 * under-enumerated denyUnknownFields policy that false-blocks its own legit input
 * is caught (no false 19/19). Falls back to method+path only when the extractor
 * didn't surface the route (handler-derived params skipped, V4 still round-trips).
 * GraphQL/Lambda/protocol ids (no HTTP request shape) return null → skipped. */
function routeForV4(
  extracted: ExtractedRoute[],
  sidecar: PolicyCites | null,
  endpointId: string,
): RouteInventoryEntry | null {
  let method: string | undefined;
  let routePath: string | undefined;
  if (sidecar?.route && sidecar.route.method && sidecar.route.path) {
    method = sidecar.route.method.toUpperCase();
    routePath = sidecar.route.path;
  } else {
    const m = /^([A-Z]+)\s+(\/.+)$/.exec(endpointId);
    if (!m) return null;
    method = m[1]!;
    routePath = m[2]!;
  }
  const wantPath = normPath(routePath);
  for (const r of extracted) {
    if (!r.sourceFile) continue;
    if (r.method.toUpperCase() !== method) continue;
    if (normPath(r.path) !== wantPath) continue;
    const entry: RouteInventoryEntry = {
      method,
      path: routePath,
      sourceFile: r.sourceFile,
      sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
    };
    if (r.handler) entry.handlerSymbol = r.handler;
    return entry;
  }
  return { method, path: routePath, sourceFile: '<audit>', sourceLine: 0 };
}

/** V4 positive-sample check: a synthetic LEGIT request must be allowed by the
 * policy. The positive carries the handler's named-read fields (fix E) when the
 * route grounded to a real handler file. Returns true (passes / not applicable)
 * or false (false-blocked). */
async function legitShapePasses(
  repoDir: string,
  route: RouteInventoryEntry,
  policy: XSecurityPolicy,
): Promise<boolean> {
  let handlerReadParams: Set<string> | undefined;
  if (route.sourceFile && route.sourceFile !== '<audit>') {
    const d = await discoverHandlerParams(repoDir, route.sourceFile, {
      handlerSymbol: route.handlerSymbol,
      sourceLine: route.sourceLine,
    });
    if (d.scoped && d.params.size > 0) handlerReadParams = d.params;
  }
  let positive;
  try {
    positive = generatePositive(route, policy, handlerReadParams);
  } catch {
    // Generation failed — treat as a precision failure (the policy's allowed
    // space couldn't even be sampled). D-1: surface it, don't paper over.
    return false;
  }
  return evaluatePolicy(positive, policy).decision === 'allow';
}

/** A cite is satisfied when its quote byte-matches the cited range, OR matches
 * elsewhere in the file (line drift — snapQuoteToFile). Empty/absent → false. */
async function citeMatches(repoDir: string, cite: Citation): Promise<boolean> {
  const slice = await readSlice(repoDir, cite.file, cite.lineStart, cite.lineEnd);
  if (slice !== null) {
    const q = normalizeWhitespace(cite.quote);
    if (q.length > 0 && normalizeWhitespace(slice).includes(q)) return true;
  }
  const snap = await snapQuoteToFile(repoDir, cite.file, cite.quote, cite.lineStart);
  return snap !== null;
}

export async function runAudit(repoDir: string): Promise<AuditResult> {
  const dir = await resolvePoliciesDir(repoDir);
  let entries: string[];
  try {
    entries = (await fs.readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    return { routes: 0, controls: 0, citeBacked: true, uncited: [], coverage: 0, legitShapesPass: '0/0', overBlocked: [] };
  }

  // Ground V4's round-trip routes against the machine extractor once, so the
  // positive sample carries each handler's real named-read fields (fix E).
  let extractedRoutes: ExtractedRoute[] = [];
  try {
    extractedRoutes = (await extractRoutes(repoDir)).routes;
  } catch {
    extractedRoutes = [];
  }

  let controls = 0;
  let citeBackedControls = 0;
  const uncited: string[] = [];
  let routes = 0;

  // Precision (V4) accounting: routes V4 could round-trip, and the ones whose
  // own positive sample is false-blocked.
  let legitChecked = 0;
  let legitPassed = 0;
  const overBlocked: string[] = [];

  for (const file of entries.sort()) {
    routes += 1;
    const id = file.replace(/\.ya?ml$/, '');
    const raw = await fs.readFile(path.join(dir, file), 'utf8');
    // A syntactically-malformed policy file is a hard failure, not a silent
    // count-as-zero (D-1). Attribute the parse error to the offending file and
    // throw so the scan surfaces it rather than under-reporting controls.
    let policy: Record<string, unknown> | null;
    try {
      policy = yaml.load(raw) as Record<string, unknown> | null;
    } catch (err) {
      throw new Error(`audit: policy file ${id}.yaml is not valid YAML: ${(err as Error).message}`);
    }

    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
      uncited.push(`${id}: policy file is not a YAML object`);
      continue;
    }
    const v1 = validateXSecurity(policy);
    if (!v1.valid) {
      uncited.push(`${id}: schema-invalid (${v1.errors.length} error(s))`);
    }

    // Load the cite sidecar. No sidecar → every control is uncited (D-3). We
    // read it up front because V4's round-trip route comes from it.
    const sidecarPath = path.join(dir, `${id}.cites.json`);
    let sidecar: PolicyCites | null = null;
    try {
      sidecar = JSON.parse(await fs.readFile(sidecarPath, 'utf8')) as PolicyCites;
    } catch {
      sidecar = null;
    }

    // --- V4 precision: a synthetic legit request must be allowed ------------
    // Run only on schema-valid policies (an invalid policy is already flagged).
    // The round-trip route comes from the sidecar (authoritative); a policy
    // without a sidecar carries no resolvable HTTP route here, so V4 skips it
    // (its missing-sidecar cite failure is already recorded below).
    if (v1.valid) {
      const route = routeForV4(extractedRoutes, sidecar, sidecar?.endpointId ?? '');
      if (route) {
        legitChecked += 1;
        if (await legitShapePasses(repoDir, route, policy as XSecurityPolicy)) legitPassed += 1;
        else overBlocked.push(sidecar?.endpointId ?? id);
      }
    }

    const policyControls = countControls(policy);
    controls += policyControls;
    if (policyControls === 0) continue;

    if (!sidecar) {
      uncited.push(`${id}: missing cite sidecar (${policyControls} control(s) unbacked)`);
      continue;
    }

    // Every cite in the sidecar must byte-match. A control is cite-backed only
    // when at least one matching cite exists; we require the sidecar to carry
    // >= policyControls matching cites.
    let matched = 0;
    for (const cite of sidecar.cites ?? []) {
      if (await citeMatches(repoDir, cite)) matched += 1;
      else uncited.push(`${id}: cite ${cite.file}:${cite.lineStart}-${cite.lineEnd} no longer byte-matches`);
    }
    const backed = Math.min(matched, policyControls);
    citeBackedControls += backed;
    if (backed < policyControls) {
      uncited.push(`${id}: ${policyControls - backed} of ${policyControls} control(s) lack a byte-matching cite`);
    }
  }

  const coverage = controls === 0 ? 0 : Number((citeBackedControls / controls).toFixed(4));
  const citeBacked = controls > 0 && citeBackedControls === controls && uncited.length === 0;
  return {
    routes,
    controls,
    citeBacked,
    uncited,
    coverage,
    legitShapesPass: `${legitPassed}/${legitChecked}`,
    overBlocked,
  };
}
