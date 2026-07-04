// FastAPI route parser (Layer 2 — framework-aware).
//
// Ported from the Python prototype's `parse_fastapi` / `_fastapi_schema`
// (/tmp/route-extractor-proto/extract.py). Captures:
//   - `@router.<verb>('p')` / `@app.<verb>('p')` decorators with their handler
//     function and request path.
//   - `include_router(router, prefix='/v1')` prefix composition: the prefix
//     attached to a router var at its include site is composed onto every
//     decorator path declared on that var (`underMount`, matching the
//     prototype's `_join`).
//   - The handler's request-body schema shape from its signature: a Pydantic
//     model body param → schemaHint `declared` (with the model name preserved in
//     `notes` as `declared-pydantic:<Model>`); otherwise `inferred-untyped`.
//
// Per Rule D-1 we never default the schemaHint with a placeholder: it is always
// derived from the actual signature, and per Rule D-3 every emitted route cites
// its source file + line.

import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ExtractedRoute, SchemaHint } from './types.js';
import { underMount } from './dedupe.js';
import { listFilesByExt } from './walk.js';

const PY_EXTS: ReadonlySet<string> = new Set(['.py']);

const HTTP_VERBS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

/** Signature-annotation type names that are NOT request-body models. Ported
 * verbatim from the prototype's `_fastapi_schema` exclusion set: these are
 * FastAPI dependency/param helpers, not Pydantic bodies. */
const NON_BODY_ANNOTATIONS: ReadonlySet<string> = new Set([
  'Depends', 'Request', 'Response', 'BackgroundTasks', 'UploadFile', 'Form',
  'File', 'Query', 'Path', 'Body', 'Header', 'Cookie', 'Session',
]);

/**
 * Strip Python `#` line comments so commented-out route declarations are not
 * extracted. Ports the prototype's `strip_comments(text, "py")`: full-line
 * comments are dropped entirely (replaced by a blank line to preserve line
 * numbers for citation). Trailing inline `#` comments are left intact — the
 * prototype only drops full-line `#` comments for Python, and stripping inline
 * `#` reliably would require distinguishing `#` inside strings/paths.
 */
function stripPyComments(text: string): string {
  return text
    .split('\n')
    .map((line) => (line.trimStart().startsWith('#') ? '' : line))
    .join('\n');
}

/**
 * Derive the request-body schema shape from a handler's parameter signature.
 * Returns the SchemaHint plus the prototype's richer note string when a Pydantic
 * model is found. Mirrors `_fastapi_schema`: the first non-builtin CamelCase
 * annotation that is not a known FastAPI helper is treated as the body model.
 */
function schemaFromSignature(sig: string): { hint: SchemaHint; note?: string } {
  const re = /:\s*([A-Z][A-Za-z0-9_]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sig)) !== null) {
    const model = m[1]!;
    if (!NON_BODY_ANNOTATIONS.has(model)) {
      return { hint: 'declared', note: `declared-pydantic:${model}` };
    }
  }
  return { hint: 'inferred-untyped' };
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

interface PyFile {
  abs: string;
  rel: string;
  text: string;
}

/**
 * First pass — build a map of router-variable name → mount prefix from every
 * `include_router(<obj>, prefix="/x")` call across the repo. The prototype keys
 * by the last dotted segment of the included object (`routes.users` → `users`),
 * best-effort across files, so a router defined in one module and mounted with a
 * prefix in another still composes.
 */
function collectIncludePrefixes(files: PyFile[]): Map<string, string> {
  const prefixMap = new Map<string, string>();
  const re =
    /include_router\(\s*([\w.]+)\s*(?:,\s*prefix\s*=\s*(["'])(.*?)\2)?/g;
  for (const f of files) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(f.text)) !== null) {
      const segs = m[1]!.split('.');
      const varName = segs[segs.length - 1]!;
      prefixMap.set(varName, m[3] ?? '');
    }
  }
  return prefixMap;
}

/**
 * Parse FastAPI routes under `repoDir`. Returns canonical-but-undeduped routes;
 * the orchestrator (Wave 2) runs `dedupeRoutes` across all parsers.
 *
 * Async because the file walker is async; the contract's nominal
 * `ExtractedRoute[]` return is realized as a resolved Promise.
 */
export async function parseFastapi(repoDir: string): Promise<ExtractedRoute[]> {
  const absPaths = await listFilesByExt(repoDir, PY_EXTS);
  const files: PyFile[] = await Promise.all(
    absPaths.map(async (abs) => ({
      abs,
      rel: path.relative(repoDir, abs),
      text: stripPyComments(await readFile(abs)),
    })),
  );

  const prefixMap = collectIncludePrefixes(files);
  const routes: ExtractedRoute[] = [];

  // `@<var>.<verb>('path' ...) [async] def handler(<sig>)`
  const decoratorRe = new RegExp(
    String.raw`@(\w+)\.(` +
      HTTP_VERBS.join('|') +
      String.raw`)\(\s*(["'])(.*?)\3(.*?)\)\s*` +
      String.raw`(?:async\s+)?def\s+(\w+)\(([^)]*)\)`,
    'gs',
  );

  for (const f of files) {
    if (
      !f.text.includes('@router.') &&
      !f.text.includes('@app.') &&
      !f.text.includes('APIRouter')
    ) {
      continue;
    }

    // The router var declared in this file (`x = APIRouter(...)`) picks up the
    // mount prefix recorded for it at its include site AND any prefix declared on
    // the constructor itself (`APIRouter(prefix="/ajax-api/3.0/jobs")` — mlflow). FastAPI
    // composes both (include-site prefix + constructor prefix); reading only the include
    // site dropped the whole path segment, so the route grounded as a bare `/` (the jobs
    // router never surfaced → its missing-auth sink was invisible, CVE-2026-0545).
    let localPrefix = '';
    const rv = /(\w+)\s*=\s*APIRouter\(([^)]*)\)/.exec(f.text);
    if (rv) {
      const includePrefix = prefixMap.get(rv[1]!) ?? '';
      const ctorPrefix = /prefix\s*=\s*(["'])(.*?)\1/.exec(rv[2] ?? '')?.[2] ?? '';
      localPrefix = ctorPrefix ? underMount(includePrefix, ctorPrefix) : includePrefix;
    }

    let m: RegExpExecArray | null;
    decoratorRe.lastIndex = 0;
    while ((m = decoratorRe.exec(f.text)) !== null) {
      const verb = m[2]!.toUpperCase();
      const declaredPath = m[4]!;
      const sig = m[7]!;
      const handler = m[6]!;
      const full = localPrefix
        ? underMount(localPrefix, declaredPath)
        : declaredPath;
      const { hint, note } = schemaFromSignature(sig);

      const route: ExtractedRoute = {
        method: verb,
        path: full,
        source: 'framework',
        framework: 'fastapi',
        sourceFile: f.rel,
        sourceLine: lineAt(f.text, m.index),
        handler,
        schemaHint: hint,
      };
      if (note !== undefined) route.notes = note;
      routes.push(route);
    }
  }

  return routes;
}

async function readFile(p: string): Promise<string> {
  try {
    return await fs.readFile(p, 'utf8');
  } catch {
    return '';
  }
}
