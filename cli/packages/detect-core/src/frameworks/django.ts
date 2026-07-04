// Django route parser (Layer 2 — framework-aware).
//
// Django wires views in `urls.py` modules: `path("instance/describetable/", instance.describe)`
// / `re_path(r"^x/$", Ctrl.as_view())`. A root urls.py `include()`s app urls.py modules
// under a prefix: `path("api/", include(("sql_api.urls", "sql_api")))`. The full path is
//   [include prefix for this module] + [route path]
// composed with `underMount` (same as FastAPI include_router / NestJS controller prefix).
//
// The handlerSymbol is the view reference as written: a dotted function ref
// (`instance.describe`) or a class-based view (`UserList.as_view()` → `UserList.as_view`).
//
// Django `path()` carries NO HTTP method — a function view handles every verb and branches
// on `request.method` / reads `request.POST`. We emit method `ANY`; the downstream evidence
// layer reads the actual body bag (`request.POST.get`) regardless of verb.
//
// Per Rule D-3 every emitted route cites its urls.py file + line. Per Rule D-1 the
// schemaHint is the honest `inferred-untyped` (Django function views have no typed body
// contract at the route declaration; the body shape is recovered downstream from
// `request.POST.get(...)` reads, not guessed here).

import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ExtractedRoute } from './types.js';
import { underMount } from './dedupe.js';
import { listFilesByExt } from './walk.js';

const PY_EXTS: ReadonlySet<string> = new Set(['.py']);

interface PyFile {
  abs: string;
  rel: string;
  text: string;
}

/** Cheap self-guard: only urls.py-shaped files declare Django routes. `urlpatterns` is a
 *  Django-specific module-level name absent from Flask/FastAPI apps. */
function hasDjangoSurface(text: string): boolean {
  return (text.includes('path(') || text.includes('re_path(')) &&
    (text.includes('urlpatterns') || text.includes('include('));
}

/** Strip Python full-line `#` comments, preserving line count (Rule D-3). */
function stripPyComments(text: string): string {
  return text
    .split('\n')
    .map((line) => (line.trimStart().startsWith('#') ? '' : line))
    .join('\n');
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/** Dotted module name of a urls.py file: `sql/urls.py` → `sql.urls`. */
function moduleNameOf(rel: string): string {
  return rel.replace(/\.py$/i, '').split(path.sep).join('.');
}

/** Strip Django URL-regex syntax from a `re_path`/`path` route so it canonicalizes:
 *  `^register/$` → `register`, `^api/(?P<pk>[0-9]+)/$` → `api/:pk`. `path()` converters
 *  `<int:pk>` are left for normPath. */
function cleanDjangoPath(p: string): string {
  return p
    .replace(/^\^/, '')                                   // leading anchor
    .replace(/[$]$|\\Z$/, '')                             // trailing anchor
    .replace(/\(\?P<([A-Za-z_]\w*)>[^)]*\)/g, ':$1')      // named group → :name
    .replace(/\(\?:[^)]*\)/g, '')                         // non-capturing group → drop
    .replace(/[()]/g, '');                                // stray group parens
}

/** Map included-module → mount prefix from every `path("<prefix>", include(("<module>",…)))`. */
function collectIncludePrefixes(files: PyFile[]): Map<string, string> {
  const prefixMap = new Map<string, string>();
  const re = /\b(?:re_)?path\(\s*r?(["'])([^"']*)\1\s*,\s*include\(\s*(?:\(\s*)?(["'])([^"']+)\3/g;
  for (const f of files) {
    let m: RegExpExecArray | null;
    re.lastIndex = 0;
    while ((m = re.exec(f.text)) !== null) prefixMap.set(m[4]!, cleanDjangoPath(m[2]!));
  }
  return prefixMap;
}

export async function parseDjango(repoDir: string): Promise<ExtractedRoute[]> {
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

  // path("<route>", <view>) — `s` flag so a multi-line path( … ) still matches. The view
  // is the first identifier after the route string: a dotted ref with an optional
  // `.as_view(...)` tail. `include(` is excluded (handled above).
  const routeRe = /\b(?:re_)?path\(\s*r?(["'])([^"']*)\1\s*,\s*([A-Za-z_]\w*(?:\.\w+)*)(\s*\.as_view\s*\([^)]*\))?/gs;

  for (const f of files) {
    if (!hasDjangoSurface(f.text)) continue;
    const mod = moduleNameOf(f.rel);
    let prefix = (prefixMap.get(mod) ?? '').replace(/\/+$/, '');
    if (prefix) prefix = '/' + prefix.replace(/^\/+/, ''); // leading slash so underMount composes

    let m: RegExpExecArray | null;
    routeRe.lastIndex = 0;
    while ((m = routeRe.exec(f.text)) !== null) {
      let view = m[3]!;
      if (view === 'include') continue; // include(...) mount, not a leaf route
      if (m[4]) view = `${view}.as_view`; // class-based / DRF view
      routes.push({
        method: 'ANY', // path() does not constrain the HTTP verb
        path: underMount(prefix, cleanDjangoPath(m[2]!)),
        source: 'framework',
        framework: 'django',
        sourceFile: f.rel,
        sourceLine: lineAt(f.text, m.index),
        handler: view,
        schemaHint: 'inferred-untyped',
      });
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
