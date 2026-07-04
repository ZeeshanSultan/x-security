// `lazy reconcile-inventory`  (stdin JSON → stdout JSON)
//
// The inventory GROUNDING gate (P2). A host agent proposes routes; this
// deterministically (1) reconciles their mount prefix against the machine
// extractor's resolved prefix (`reconcileMountPrefix` — fixes the Laravel
// `/api` ⇄ `/vapi` drift) and (2) marks each route grounded or ungrounded.
//
// A route is `grounded:true` iff EITHER:
//   - its (method, path) matches an extractor route-key (the machine extractor
//     surfaced this exact route), OR
//   - its cited sourceFile is a confirmed filesystem-routing handler file AND
//     the cited line exists in that file (PHP/Next/Rails/... fs routers the
//     framework parsers structurally can't enumerate as route-keys).
//
// Otherwise `grounded:false` with a `reason`. The skill quarantines ungrounded
// routes to reviewRequired and may not emit policy for them without a fresh
// handler cite.
//
// D-1: grounding is ALWAYS against the machine extractor + the fs-handler
// detector — NEVER a regex over agent text. The agent's proposed path is only
// ever the LOOKUP KEY; the truth comes from parsed code.
//
// Contract:
//   in  {"repoDir","routes":[{method,path,sourceFile?,sourceLine?},...]}
//   out {"routes":[{method,path,sourceFile?,sourceLine?,grounded,reason?,reconciledPath?}]}

import {
  extractRoutes,
  reconcileMountPrefix,
  routeKey,
  readSlice,
  detectFilesystemHandlerCandidates,
  type RouteInventoryEntry,
} from '@writ/detect-core';

export interface ReconcileRouteInput {
  method: string;
  path: string;
  sourceFile?: string;
  sourceLine?: number;
}

export interface ReconcileInventoryInput {
  repoDir: string;
  routes: ReconcileRouteInput[];
}

export interface ReconcileRouteResult {
  method: string;
  path: string;
  sourceFile?: string;
  sourceLine?: number;
  grounded: boolean;
  reason?: string;
  /** Set when the mount-prefix reconciler rewrote this route's path; carries the
   *  pre-reconcile path so the caller can see the correction. */
  reconciledPath?: string;
}

export interface ReconcileInventoryResult {
  routes: ReconcileRouteResult[];
}

const PLACEHOLDER_SOURCE = '<reconcile>';

/** Map a loose input route to the RouteInventoryEntry the reconciler consumes.
 * sourceFile is required by the schema/type; when the caller omits it we use a
 * placeholder — reconcileMountPrefix only reads method/path and preserves every
 * other field, so the placeholder never leaks into grounding (we ground against
 * the ORIGINAL input's sourceFile). */
function toEntry(r: ReconcileRouteInput): RouteInventoryEntry {
  const e: RouteInventoryEntry = {
    method: r.method.toUpperCase(),
    path: r.path,
    sourceFile: r.sourceFile && r.sourceFile.length > 0 ? r.sourceFile : PLACEHOLDER_SOURCE,
    sourceLine: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
  };
  return e;
}

export async function runReconcileInventory(
  input: ReconcileInventoryInput,
): Promise<ReconcileInventoryResult> {
  const { repoDir, routes } = input;
  const extracted = await extractRoutes(repoDir);

  // (1) Mount-prefix reconciliation against the machine-derived prefix.
  const entries = routes.map(toEntry);
  const reconciled = reconcileMountPrefix(entries, extracted.routes);

  // Grounding denominators, both machine-derived (D-1):
  //   - the extractor's route-key set (exact method+path the parsers surfaced)
  //   - the fs-handler file set (PHP/Next/Rails/... router-by-file)
  const extractorKeys = new Set<string>();
  // Transport bases: when the extractor surfaces per-resolver keys for a single
  // transport endpoint (GraphQL `POST /graphql#mutation.x`, gRPC, JSON-RPC), the
  // bare transport route (`POST /graphql`) — which the GraphQL-one-route rule asks
  // the model to emit — has no exact key. Ground it against the base of those
  // resolver keys (the part before `#`). Still machine-derived from real
  // extractor output (D-1), just the inverse of the one-route collapse.
  const extractorTransportBases = new Set<string>();
  for (const r of extracted.routes) {
    if (!r.sourceFile) continue;
    const key = routeKey(r.method, r.path);
    extractorKeys.add(key);
    const hash = key.indexOf('#');
    if (hash !== -1) extractorTransportBases.add(key.slice(0, hash));
  }
  const fsHandlers = await detectFilesystemHandlerCandidates(repoDir);
  const fsHandlerFiles = new Set(fsHandlers.map((h) => h.file));
  for (const h of fsHandlers) {
    for (const v of h.variants ?? []) fsHandlerFiles.add(v);
  }

  const out: ReconcileRouteResult[] = [];
  for (let i = 0; i < reconciled.inventory.length; i++) {
    const entry = reconciled.inventory[i]!;
    const orig = routes[i]!;
    const rewritten = entry.path !== orig.path;

    const result: ReconcileRouteResult = {
      method: entry.method,
      path: entry.path,
      grounded: false,
    };
    if (orig.sourceFile !== undefined) result.sourceFile = orig.sourceFile;
    if (orig.sourceLine !== undefined) result.sourceLine = orig.sourceLine;
    if (rewritten) result.reconciledPath = orig.path;

    // (a) extractor route-key match — strongest grounding. A fragment-less
    // transport route (POST /graphql) grounds against the resolver-key base set.
    const ek = routeKey(entry.method, entry.path);
    if (extractorKeys.has(ek) || (ek.indexOf('#') === -1 && extractorTransportBases.has(ek))) {
      result.grounded = true;
      out.push(result);
      continue;
    }

    // (b) confirmed fs-handler file at the cited line.
    const file = orig.sourceFile;
    if (file && fsHandlerFiles.has(file)) {
      const line = typeof orig.sourceLine === 'number' && orig.sourceLine > 0 ? orig.sourceLine : 1;
      const slice = await readSlice(repoDir, file, line, line);
      if (slice !== null) {
        result.grounded = true;
        out.push(result);
        continue;
      }
      result.reason = `cited line ${line} not present in fs-handler file ${file}`;
      out.push(result);
      continue;
    }

    // Ungrounded — explain why.
    if (!file) {
      result.reason = 'no extractor route-key match and no sourceFile to confirm against an fs-handler';
    } else if (!fsHandlerFiles.has(file)) {
      result.reason = `no extractor route-key match and ${file} is not a confirmed fs-handler file`;
    } else {
      result.reason = 'ungrounded';
    }
    out.push(result);
  }

  return { routes: out };
}
