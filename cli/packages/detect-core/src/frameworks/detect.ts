// Framework detection — which framework(s) a repo uses.
//
// Ports the prototype's `detect_framework` (manifest scan) and folds in spec
// presence (OpenAPI/Swagger files), so the orchestrator (Wave 2) can run only
// the relevant parsers. Detection is a UNION of signals — a repo may legitimately
// expose both a Flask app and an OpenAPI spec.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { listFiles } from './walk.js';

/** Manifest files whose contents we lowercase-scan for dependency names, same
 * set as the prototype. */
const MANIFEST_FILENAMES = new Set([
  'package.json', 'requirements.txt', 'composer.json', 'Pipfile', 'pyproject.toml',
]);

/** Dependency-substring → framework label. A substring hit in ANY manifest
 * marks the framework present (mirrors the prototype's `if "x" in pkg`). */
const DEP_SIGNALS: Array<{ needle: string; framework: string }> = [
  { needle: 'express', framework: 'express' },
  { needle: 'fastapi', framework: 'fastapi' },
  { needle: 'flask', framework: 'flask' },
  { needle: 'connexion', framework: 'connexion/openapi' },
  { needle: 'graphene', framework: 'graphene' },
  { needle: 'apollo', framework: 'apollo' },
  { needle: 'laravel', framework: 'laravel' },
];

async function read(file: string): Promise<string> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return '';
  }
}

/** True when the basename looks like an OpenAPI/Swagger spec, matching the
 * prototype's `find_spec_files` predicate. */
function isSpecFile(base: string): boolean {
  const b = base.toLowerCase();
  return (
    (b.includes('openapi') || b.includes('swagger')) &&
    (b.endsWith('.json') || b.endsWith('.yml') || b.endsWith('.yaml'))
  );
}

/**
 * Detect frameworks + spec presence under `repoDir`. Returns a sorted, deduped
 * label list, e.g. `['express', 'flask', 'spec']`.
 *
 * Signals (union):
 *   - Manifest dependency substrings (express/fastapi/flask/connexion/graphene/
 *     apollo/laravel) — and the prototype's `graphql` → apollo alias.
 *   - PHP route files (`*.php` under a `routes/` path) → laravel, matching the
 *     prototype's `has_php_routes` heuristic for manifest-less Laravel apps.
 *   - GraphQL SDL files (`.graphql`/`.gql`) → apollo (SDL is parsed by the
 *     Apollo layer in the prototype).
 *   - An OpenAPI/Swagger spec file present → `spec` (drives the Layer-1 parser).
 */
export async function detectFrameworks(repoDir: string): Promise<string[]> {
  const files = await listFiles(repoDir);

  let manifestBlob = '';
  let hasPhpRoutes = false;
  let hasGraphqlSdl = false;
  let hasSpec = false;

  for (const f of files) {
    const base = path.basename(f);
    if (MANIFEST_FILENAMES.has(base)) {
      manifestBlob += (await read(f)).toLowerCase();
    }
    // `routes` anywhere in the (slash-normalized) path, matching the prototype.
    if (f.toLowerCase().endsWith('.php') && f.replace(/\\/g, '/').includes('routes')) {
      hasPhpRoutes = true;
    }
    const ext = path.extname(base).toLowerCase();
    if (ext === '.graphql' || ext === '.gql') hasGraphqlSdl = true;
    if (isSpecFile(base)) hasSpec = true;
  }

  const fw = new Set<string>();
  for (const { needle, framework } of DEP_SIGNALS) {
    if (manifestBlob.includes(needle)) fw.add(framework);
  }
  // Prototype: `if "apollo" in pkg or "graphql" in pkg` → apollo.
  if (manifestBlob.includes('graphql') || hasGraphqlSdl) fw.add('apollo');
  if (hasPhpRoutes) fw.add('laravel');
  if (hasSpec) fw.add('spec');

  return [...fw].sort();
}
