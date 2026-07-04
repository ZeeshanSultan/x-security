// Layer-1 spec-first parser: OpenAPI / Swagger.
//
// Ported faithfully from the Python prototype at
// /tmp/route-extractor-proto/extract.py (`find_spec_files`, `parse_openapi`,
// `_server_base`, `load_struct`). For every spec file found we emit one
// ExtractedRoute per (path × HTTP verb), tagged `source: 'spec'` and (when the
// op declares a body/params contract) `schemaHint: 'declared'` — a spec is the
// canonical place a request schema is *declared*, so the declared hint is honest
// here even when the handler code is opaque.
//
// YAML: parsed via `js-yaml` (the same dep the e2e/security-corpus uses).
// Connexion/VAmPI ship their canonical surface as a `.yaml`/`.yml` OpenAPI spec,
// so skipping YAML was a recall hole (Rule D-2 — context starvation > model
// quality; the fix is upstream, give the parser the spec it can read). An
// unparseable spec is surfaced loudly, never silently dropped (Rule D-1).

import { promises as fs } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

import type { ExtractedRoute } from './types.js';
import { underMount } from './dedupe.js';
import { listFiles } from './walk.js';

const HTTP_VERBS: ReadonlySet<string> = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'options', 'head',
]);

/** Spec discovery uses a narrower skip-set than the framework walk: the
 * prototype's `_walk_specs` deliberately descends into `tests`, `static`,
 * `public`, etc. because specs (and their fixtures) frequently live there. We
 * only prune dependency / build / VCS dirs that never hold a first-party spec. */
const SPEC_SKIP_DIRS: ReadonlySet<string> = new Set([
  '.git', 'node_modules', 'vendor', 'venv', '.venv',
  'site-packages', '__pycache__',
]);

const SPEC_EXTS: ReadonlySet<string> = new Set(['.json', '.yml', '.yaml']);

/** A spec file's basename matches `*openapi*` or `*swagger*` (prototype's
 * `find_spec_files` substring test against the lowercased basename). */
function isSpecBasename(base: string): boolean {
  const b = base.toLowerCase();
  return b.includes('openapi') || b.includes('swagger');
}

/**
 * Extract the path prefix from an OpenAPI 3 `servers[0].url`. Ports the
 * prototype's `_server_base`: strip `scheme://host`, keep the path component,
 * leave template vars (`{x}`) intact, drop a bare `/` or trailing slash.
 */
function serverBase(server: unknown): string {
  if (typeof server !== 'object' || server === null) return '';
  const url = (server as Record<string, unknown>)['url'];
  if (typeof url !== 'string') return '';
  let p: string;
  if (url.includes('://')) {
    const m = /^[a-zA-Z][\w+.-]*:\/\/[^/]+(\/.*)?$/.exec(url);
    p = m && m[1] ? m[1] : '';
  } else {
    p = url;
  }
  return p && p !== '/' ? p.replace(/\/+$/, '') : '';
}

/** OpenAPI 2 `basePath` (trailing slash stripped) or OpenAPI 3
 * `servers[0].url` path component. Mirrors the prototype's base resolution. */
function resolveBase(data: Record<string, unknown>): string {
  const basePath = data['basePath'];
  if (typeof basePath === 'string') {
    return basePath.replace(/\/+$/, '');
  }
  const servers = data['servers'];
  if (Array.isArray(servers) && servers.length > 0) {
    return serverBase(servers[0]);
  }
  return '';
}

/** Honest schema signal for an operation. The prototype distinguishes
 * `declared-spec-body` / `declared-spec-params` / `no-body`; both declared
 * variants map to the contract's `schemaHint: 'declared'`, with the finer
 * prototype label preserved in `notes`. `no-body` leaves the hint omitted
 * (per Rule D-1, we do not default it). */
function classifyOp(op: Record<string, unknown>): { hint?: 'declared'; note: string } {
  const params = op['parameters'];
  const hasBodyParam =
    Array.isArray(params) &&
    params.some(
      (p) => typeof p === 'object' && p !== null && (p as Record<string, unknown>)['in'] === 'body',
    );
  if (op['requestBody'] || hasBodyParam) {
    return { hint: 'declared', note: 'declared-spec-body' };
  }
  if (Array.isArray(params) && params.length > 0) {
    return { hint: 'declared', note: 'declared-spec-params' };
  }
  return { note: 'no-body' };
}

function parseSpecData(
  data: unknown,
  sourceFile: string,
): ExtractedRoute[] {
  if (typeof data !== 'object' || data === null) return [];
  const doc = data as Record<string, unknown>;
  const paths = doc['paths'];
  if (typeof paths !== 'object' || paths === null) return [];

  const base = resolveBase(doc);
  const routes: ExtractedRoute[] = [];

  for (const [rawPath, item] of Object.entries(paths as Record<string, unknown>)) {
    if (typeof item !== 'object' || item === null) continue;
    // Connexion/OpenAPI: a router-controller module can be declared at the
    // path-item level and inherited by every operation. Operation-level wins.
    const itemObj = item as Record<string, unknown>;
    const itemController = itemObj['x-openapi-router-controller'];

    for (const [verb, op] of Object.entries(item as Record<string, unknown>)) {
      if (!HTTP_VERBS.has(verb.toLowerCase())) continue;

      const fullPath = base ? underMount(base, rawPath) : rawPath;
      const route: ExtractedRoute = {
        method: verb.toUpperCase(),
        path: fullPath,
        source: 'spec',
        sourceFile,
      };

      if (typeof op === 'object' && op !== null) {
        const opObj = op as Record<string, unknown>;
        const { hint, note } = classifyOp(opObj);
        route.schemaHint = hint ?? 'declared';
        route.notes = note;
        const opId = opObj['operationId'];
        if (typeof opId === 'string') {
          // Build the fully-qualified handler. Connexion resolves operationId
          // against x-openapi-router-controller (op-level, else path-item-level)
          // when the id isn't already dotted-qualified.
          const controller = opObj['x-openapi-router-controller'] ?? itemController;
          route.handler =
            typeof controller === 'string' && !opId.includes('.')
              ? `${controller}.${opId}`
              : opId;
        }
      } else {
        // Non-object op (e.g. a `$ref` string) — declared by virtue of being in
        // the spec, but no finer signal. Keep the declared hint per the spec
        // contract (`schemaHint: 'declared'`).
        route.schemaHint = 'declared';
      }

      routes.push(route);
    }
  }

  return routes;
}

/**
 * Resolve a dotted handler reference (`api_views.users.delete_user`, or a
 * connexion controller + operationId) to the real source file + def line, so
 * the agent and verifiers read HANDLER CODE instead of the opaque spec. This is
 * the D-2 context-resolution step: without it, spec-sourced routes cite the
 * yml, `handler language not recognized` fires, and every emission demotes to
 * review with no citation (the under-emission root cause). Returns null when no
 * file resolves — pure-spec apps keep their spec `sourceFile`, no regression.
 */
async function resolveHandlerFile(
  repoDir: string,
  handlerFq: string,
): Promise<{ file: string; line: number } | null> {
  const parts = handlerFq.split('.');
  if (parts.length < 2) return null;
  const func = parts[parts.length - 1]!;
  const moduleParts = parts.slice(0, -1);
  // Try `<module>.py` then `<module>/__init__.py` (package handler).
  const candidates = [
    `${moduleParts.join('/')}.py`,
    `${moduleParts.join('/')}/__init__.py`,
  ];
  for (const rel of candidates) {
    const abs = path.join(repoDir, rel);
    let text: string;
    try {
      text = await fs.readFile(abs, 'utf8');
    } catch {
      continue;
    }
    // Find the def line (sync or async). Cite the handler, not the spec (D-3).
    const lines = text.split('\n');
    const re = new RegExp(`^\\s*(async\\s+)?def\\s+${func}\\b`);
    const idx = lines.findIndex((l) => re.test(l));
    return { file: rel, line: idx >= 0 ? idx + 1 : 1 };
  }
  return null;
}

/**
 * Find and parse every OpenAPI / Swagger spec under `repoDir`, returning one
 * ExtractedRoute per (path × HTTP verb).
 *
 * - Spec files: basename contains `openapi` or `swagger` with a `.json`/`.yml`/
 *   `.yaml` extension.
 * - JSON and YAML specs are both parsed (`js-yaml` for YAML). An unparseable
 *   spec is surfaced via `console.warn`; `ExtractedRoute` carries no warning
 *   channel so the orchestrator (Wave 2) owns `ExtractResult.warnings`.
 *
 * `sourceFile` citations are repo-relative.
 */
export async function parseOpenApiSpecs(repoDir: string): Promise<ExtractedRoute[]> {
  const files = await listFiles(repoDir, {
    skipDirs: SPEC_SKIP_DIRS,
    exts: SPEC_EXTS,
  });

  const routes: ExtractedRoute[] = [];

  for (const abs of files) {
    const base = path.basename(abs);
    if (!isSpecBasename(base)) continue;

    const rel = path.relative(repoDir, abs);
    const ext = path.extname(base).toLowerCase();

    let text: string;
    try {
      text = await fs.readFile(abs, 'utf8');
    } catch {
      continue;
    }

    let data: unknown;
    try {
      data = ext === '.json' ? JSON.parse(text) : yaml.load(text);
    } catch {
      console.warn(`[spec-openapi] skipping unparseable spec: ${rel}`);
      continue;
    }

    routes.push(...parseSpecData(data, rel));
  }

  // Context resolution: point spec-sourced routes at their handler code when
  // the operationId resolves to a real file. Keeps the spec ref in `notes`.
  for (const route of routes) {
    if (!route.handler || !route.handler.includes('.')) continue;
    const resolved = await resolveHandlerFile(repoDir, route.handler);
    if (!resolved) continue;
    const specRef = route.sourceFile;
    route.sourceFile = resolved.file;
    route.sourceLine = resolved.line;
    route.notes = route.notes
      ? `${route.notes}; spec:${specRef}`
      : `spec:${specRef}`;
  }

  return routes;
}
