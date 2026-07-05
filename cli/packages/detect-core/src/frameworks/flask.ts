// Flask route parser (Wave 1) — ports the prototype's `parse_flask`
// (/tmp/route-extractor-proto/extract.py) to TypeScript.
//
// Handles three Flask route-declaration shapes:
//   1. `@app.route('p', methods=[...])` / `@bp.route(...)` decorators (any
//      `<obj>.route(...)` decorator) — the handler name is the `def` that
//      follows the (possibly stacked) decorators.
//   2. `app.add_url_rule('p', view_func=..., methods=[...])` registrations.
//
// MULTI-METHOD EXPANSION (the codegraph bug this fixes): a decorator with
// `methods=['GET','POST']` yields ONE ExtractedRoute *per verb* — it is NEVER
// collapsed to a single GET. When `methods=` is absent, Flask defaults to GET.
//
// Flask request bodies are untyped (no Pydantic/OpenAPI contract at the route
// declaration), so every route gets `schemaHint: 'inferred-untyped'`. We do not
// emit a schema we can't justify (Rule D-1) — there is no typed-body signal to
// read from a bare `@app.route`.

import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { ExtractedRoute } from './types.js';
import { listFilesByExt } from './walk.js';

const PY_EXTS: ReadonlySet<string> = new Set(['.py']);

// Cheap pre-filter mirroring the prototype's `continue` guard: skip files with
// no Flask route surface at all before running the (more expensive) regexes.
function hasFlaskSurface(text: string): boolean {
  return (
    text.includes('@app.route') ||
    text.includes('@bp.route') ||
    text.includes('.route(') ||
    text.includes('add_url_rule')
  );
}

// `@<obj>.route('p', <tail>)` — group 1 obj, group 2 quote, group 3 path,
// group 4 tail (everything after the closing path quote up to the close paren).
// Ported verbatim from the prototype: r"@(\w+)\.route\(\s*([\"'])(.*?)\2([^\n)]*)\)".
const DECORATOR_RE = /@(\w+)\.route\(\s*(["'])(.*?)\2([^\n)]*)\)/g;

// `@<obj>.route(wrapper('p'), <tail>)` — a path-helper call wrapping a single
// string literal, e.g. redash's `@bp.route(org_scoped_rule("/ldap/login"), methods=[...])`.
// We unwrap to the inner literal: a Flask path helper that takes one rule string
// returns that rule (optionally prefixed in a non-default mode), so the literal is
// the route's served path in the default config. Disjoint from DECORATOR_RE, which
// requires a quote immediately after `route(`. Group 1 obj, 2 wrapper, 3 quote,
// 4 path, 5 tail (after the inner close paren, up to the outer close paren).
const WRAPPER_DECORATOR_RE = /@(\w+)\.route\(\s*(\w+)\(\s*(["'])(.*?)\3\s*\)([^\n)]*)\)/g;

// The `def name(` that follows a route decorator, skipping any stacked
// decorators in between. Ported from: r"(?:\s*@[^\n]*\n)*\s*def\s+(\w+)".
const HANDLER_RE = /(?:\s*@[^\n]*\n)*\s*def\s+(\w+)/;

// `.add_url_rule('p', <tail>)` — group 1 quote, group 2 path, group 3 tail.
// Ported from: r"\.add_url_rule\(\s*([\"'])(.*?)\1(.*?)\)" with DOTALL.
const ADD_URL_RULE_RE = /\.add_url_rule\(\s*(["'])(.*?)\1([\s\S]*?)\)/g;

// `methods=[...]` inside a decorator/add_url_rule tail.
const METHODS_RE = /methods\s*=\s*\[([^\]]*)\]/;
const VERB_RE = /["'](\w+)["']/g;

/**
 * Extract the HTTP verbs declared in a route tail. Ports `_flask_methods`:
 * absent `methods=` → `['GET']`; present → each quoted verb upper-cased, in
 * declaration order. An empty `methods=[]` falls back to `['GET']` (matches the
 * prototype's `or ["GET"]`).
 */
function flaskMethods(tail: string): string[] {
  const mm = METHODS_RE.exec(tail);
  if (!mm || mm[1] === undefined) return ['GET'];
  const inner = mm[1];
  const verbs: string[] = [];
  let v: RegExpExecArray | null;
  VERB_RE.lastIndex = 0;
  while ((v = VERB_RE.exec(inner)) !== null) {
    if (v[1] !== undefined) verbs.push(v[1].toUpperCase());
  }
  return verbs.length > 0 ? verbs : ['GET'];
}

/**
 * Strip Python full-line `#` comments so commented-out route declarations are
 * not extracted. Ports the prototype's `strip_comments(text, "py")` (line
 * comments only; conservative — does not touch `#` inside strings).
 */
function stripPyComments(text: string): string {
  // Blank `#`-comment lines but KEEP the line, so a route's index still maps to
  // its real source line. Filtering the line out shifts every route below it up
  // by the comment count → wrong `sourceLine` → broken citations (Rule D-3) and
  // starved evidence-pack windows. Same fix as express.ts stripComments.
  return text
    .split('\n')
    .map((line) => (line.trimStart().startsWith('#') ? '' : line))
    .join('\n');
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

/**
 * Parse every Flask route under `repoDir`.
 *
 * Async because the shared walker (`listFilesByExt`) is async; the prototype's
 * `parse_flask` is synchronous only because Python's `os.walk` is.
 */
export async function parseFlask(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const files = await listFilesByExt(repoDir, PY_EXTS);

  for (const file of files) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    if (!hasFlaskSurface(raw)) continue;

    const text = stripPyComments(raw);
    const sourceFile = path.relative(repoDir, file);

    // 1. `@<obj>.route('p', methods=[...])` decorators.
    DECORATOR_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DECORATOR_RE.exec(text)) !== null) {
      const routePath = m[3] ?? '';
      const tail = m[4] ?? '';
      const decoratorLine = lineAt(text, m.index);

      const rest = text.slice(DECORATOR_RE.lastIndex);
      const hm = HANDLER_RE.exec(rest);
      const handler = hm ? hm[1] : undefined;

      for (const method of flaskMethods(tail)) {
        routes.push(buildRoute(method, routePath, handler, sourceFile, decoratorLine));
      }
    }

    // 1b. `@<obj>.route(wrapper('p'), methods=[...])` — path-helper-wrapped routes.
    WRAPPER_DECORATOR_RE.lastIndex = 0;
    while ((m = WRAPPER_DECORATOR_RE.exec(text)) !== null) {
      const routePath = m[4] ?? '';
      const tail = m[5] ?? '';
      const decoratorLine = lineAt(text, m.index);

      const rest = text.slice(WRAPPER_DECORATOR_RE.lastIndex);
      const hm = HANDLER_RE.exec(rest);
      const handler = hm ? hm[1] : undefined;

      for (const method of flaskMethods(tail)) {
        routes.push(buildRoute(method, routePath, handler, sourceFile, decoratorLine));
      }
    }

    // 2. `.add_url_rule('p', view_func=..., methods=[...])` registrations.
    ADD_URL_RULE_RE.lastIndex = 0;
    while ((m = ADD_URL_RULE_RE.exec(text)) !== null) {
      const routePath = m[2] ?? '';
      const tail = m[3] ?? '';
      const declLine = lineAt(text, m.index);

      // The view_func arg names the handler; capture it when present rather
      // than dropping the handler (the prototype emitted handler=None here).
      const vf = /view_func\s*=\s*([A-Za-z_]\w*)/.exec(tail);
      const handler = vf ? vf[1] : undefined;

      for (const method of flaskMethods(tail)) {
        routes.push(buildRoute(method, routePath, handler, sourceFile, declLine));
      }
    }
  }

  return routes;
}

function buildRoute(
  method: string,
  routePath: string,
  handler: string | undefined,
  sourceFile: string,
  sourceLine: number,
): ExtractedRoute {
  const route: ExtractedRoute = {
    method,
    path: routePath,
    source: 'framework',
    framework: 'flask',
    schemaHint: 'inferred-untyped',
    sourceFile,
    sourceLine,
  };
  if (handler !== undefined) route.handler = handler;
  return route;
}
