// `lazy routes <repoDir> [--seed]`
//
// Deterministic route inventory. Runs the LLM-free extractor over the repo and
// emits the canonical {method, path, file, line} list the host agent grounds
// its own inventory against. `--seed` additionally returns the rendered seed
// table the inventory prompt wraps in <<UNTRUSTED>> fences.
//
// Contract: stdout {"routes":[{method,path,file,line}], "seed"?: string}.

import { extractRoutes, renderSeedTable, type ExtractedRoute } from '@writ/detect-core';

export interface RoutesOptions {
  seed?: boolean;
  seedRowCap?: number;
}

export interface RoutesEntry {
  method: string;
  path: string;
  file: string;
  line: number;
}

export interface RoutesResult {
  routes: RoutesEntry[];
  warnings: string[];
  seed?: string;
}

/** Map an ExtractedRoute to the stable {method,path,file,line} contract. A
 * route the extractor could not cite to a source file is dropped here (Rule
 * D-3: no citation-less surface leaves the core); the extractor already drops
 * citation-less framework routes, so this is the spec-route safety net. */
function toEntry(r: ExtractedRoute): RoutesEntry | null {
  if (!r.sourceFile) return null;
  return {
    method: r.method.toUpperCase(),
    path: r.path,
    file: r.sourceFile,
    line: typeof r.sourceLine === 'number' ? r.sourceLine : 0,
  };
}

export async function runRoutes(repoDir: string, opts: RoutesOptions = {}): Promise<RoutesResult> {
  const extracted = await extractRoutes(repoDir);
  const routes: RoutesEntry[] = [];
  for (const r of extracted.routes) {
    const e = toEntry(r);
    if (e) routes.push(e);
  }
  routes.sort((a, b) => a.method.localeCompare(b.method) || a.path.localeCompare(b.path));

  const result: RoutesResult = { routes, warnings: extracted.warnings };
  if (opts.seed) {
    const seedOpts = typeof opts.seedRowCap === 'number' ? { rowCap: opts.seedRowCap } : {};
    const table = renderSeedTable(extracted.routes, seedOpts);
    if (table !== undefined) result.seed = table;
  }
  return result;
}
