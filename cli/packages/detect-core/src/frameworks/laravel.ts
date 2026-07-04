// Laravel route parser (Wave 1) — ports the prototype's `parse_laravel`
// (/tmp/route-extractor-proto/extract.py) to TypeScript.
//
// Laravel is the 2nd-highest-risk framework in the corpus because its route
// prefix is resolved across two layers and an easy-to-miss prefix yields a
// route surface that doesn't line up with reality. This parser ports all three
// prefix sources faithfully (the vapi 5.6→100 regression was a missing prefix):
//
//   1. INLINE group prefix in a route file:
//        Route::group(['prefix' => 'vapi'], function () { ... })
//        Route::prefix('vapi')->...->group(function () { ... })
//      A route's effective prefix is the join of every inline group span it
//      falls inside (innermost-last), composed via `underMount`.
//   2. FILE→prefix mapping from RouteServiceProvider::boot():
//        Route::prefix('vapi')->...->group(base_path('routes/api.php'))
//      Every route declared in `routes/api.php` then inherits `/vapi`.
//   3. Sanctum's dynamically-registered SPA CSRF-cookie route
//        GET /sanctum/csrf-cookie
//      emitted when laravel/sanctum is a dependency (composer.json) or a route
//      file references the `sanctum` middleware.
//
// HANDLER FIELD: the prototype stores the FIRST per-route `->middleware(...)`
// argument in the `handler` slot (Laravel route closures/controllers aren't
// reliably name-extractable from the declaration; the middleware is the most
// security-relevant token on the route). Ported verbatim for golden parity.
//
// SCHEMA HINT: a route gets `declared` when the route file type-hints a
// FormRequest (a declared, validated request contract); `open-unbounded` when
// the file mass-assigns via `::create(` (the prototype's signal); otherwise
// `inferred-untyped` (raw `$request->input(...)`). We never default a hint we
// can't justify (Rule D-1).

import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { ExtractedRoute, SchemaHint } from './types.js';
import { listFilesByExt, listFiles } from './walk.js';
import { underMount, normPath } from './dedupe.js';

const PHP_EXTS: ReadonlySet<string> = new Set(['.php']);

// Route::<verb>('path', ...) and chained Route::middleware(..)->...-><verb>('path', ...).
// Group 1: bare verb; Group 2: chained verb; Group 3: quote; Group 4: path;
// Group 5: tail (everything after the path up to `;` or newline).
// Ported from the prototype's `_laravel_route_matches` pattern (DOTALL).
// Tail runs to the statement `;` (not the first newline) so a MULTI-LINE route
// def — `Route::get(\n '/p',\n [Ctrl::class,'m']\n)->name(...);` — captures the
// array-callable / `uses` on a later line (the modern Laravel 8+ idiom). The path
// is still captured from m[4]; closures (first `;` inside the body) truncate the
// tail harmlessly (closure handlers aren't symbol-extracted anyway).
const ROUTE_RE =
  /Route::(?:(get|post|put|patch|delete|any|match)\(|(?:\w+\([^;{]*?\)->)+(get|post|put|patch|delete|any|match)\()\s*(["'])([\s\S]*?)\3([\s\S]*?);/g;

// Inline group prefix: Route::group(['prefix' => 'vapi'], fn).
const GROUP_ARRAY_RE =
  /Route::group\(\s*\[[^\]]*['"]prefix['"]\s*=>\s*['"]([^'"]+)['"]/g;

// Inline group prefix: Route::prefix('vapi')->...->group(...).
const GROUP_PREFIX_RE =
  /Route::prefix\(\s*['"]([^'"]+)['"]\s*\)(?:->[^;{]*)?->group\(/g;

// Per-route ->middleware('x') capture (first arg). Ported from
// r"->middleware\(\s*([\"'])(.*?)\1".
const MIDDLEWARE_RE = /->middleware\(\s*(["'])([\s\S]*?)\1/;

// Controller action: `'uses' => 'Ctrl@method'` / `->uses('Ctrl@method')` (group 1),
// or `[Ctrl::class, 'method']` (groups 2 + 3). Closures have no action → no match.
const USES_RE =
  /['"]uses['"]\s*=>\s*['"]([\w\\]+@\w+)['"]|->uses\(\s*['"]([\w\\]+@\w+)['"]|\[\s*([\w\\]+)::class\s*,\s*['"](\w+)['"]\s*\]/;

// RouteServiceProvider file→prefix: Route::prefix('x')->...->group(base_path('routes/<file>')).
const FILE_PREFIX_RE =
  /Route::prefix\(\s*['"]([^'"]+)['"]\s*\)[^;]*?->group\(\s*base_path\(\s*['"]([^'"]+)['"]/g;

interface GroupSpan {
  start: number;
  end: number;
  prefix: string;
}

/**
 * Strip PHP comments so commented-out route declarations are not extracted.
 * Ports the prototype's `strip_comments(text, "php")`: block comments `/* *​/`,
 * full-line `//` and `#`, and trailing `// ...` (rough; ignores `//` inside
 * strings/URLs the same way the prototype does).
 */
function stripPhpComments(text: string): string {
  // Blank comment CONTENT but PRESERVE every line + column so lineAt reports the
  // real source line (Rule D-3: exact citations). Deleting comment lines shifts
  // every route below them — on Firefly III's routes/api.php that desynced
  // citations by ~96 lines. (Same class of bug fixed in express.ts.)
  let t = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  const out: string[] = [];
  for (let line of t.split('\n')) {
    const s = line.trimStart();
    if (s.startsWith('//') || s.startsWith('#')) { out.push(''); continue; }
    line = line.replace(/(^|[^:'"])\/\/.*$/, '$1');
    out.push(line);
  }
  return out.join('\n');
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
 * Index of the matching close of the group body whose opening `group(` paren
 * was already consumed by the caller's regex (so `openIdx` points just past it).
 * Starts at depth 1 to account for that already-open paren, then counts
 * `(`/`{` up and `)`/`}` down until it closes.
 *
 * DELIBERATE FIX over the prototype's `_brace_end`: the prototype started at
 * depth 0, so a closure body `->group(function () { ... })` closed the span at
 * the `)` of `function ()` — truncating it before the routes inside and
 * silently dropping the inline prefix. Seeding depth at 1 makes the closure
 * form (`Route::prefix('x')->group(fn)` / `Route::group([...], fn)`) compose
 * its prefix correctly, which is the 2nd-highest-risk Laravel signal.
 */
function braceEnd(text: string, openIdx: number): number {
  let depth = 1;
  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    if (c === '(' || c === '{') {
      depth += 1;
    } else if (c === ')' || c === '}') {
      depth -= 1;
      if (depth <= 0) return i;
    }
  }
  return text.length;
}

/** Collect inline group-prefix spans (both `Route::group([...])` and
 * `Route::prefix(...)->group(...)` forms) in declaration order. */
function groupSpans(text: string): GroupSpan[] {
  const spans: GroupSpan[] = [];
  let m: RegExpExecArray | null;

  GROUP_ARRAY_RE.lastIndex = 0;
  while ((m = GROUP_ARRAY_RE.exec(text)) !== null) {
    spans.push({ start: m.index, end: braceEnd(text, GROUP_ARRAY_RE.lastIndex), prefix: m[1] ?? '' });
  }
  GROUP_PREFIX_RE.lastIndex = 0;
  while ((m = GROUP_PREFIX_RE.exec(text)) !== null) {
    spans.push({ start: m.index, end: braceEnd(text, GROUP_PREFIX_RE.lastIndex), prefix: m[1] ?? '' });
  }
  return spans;
}

/** Join every inline group prefix the route position falls inside, slash-
 * trimmed and `/`-joined (mirrors the prototype's
 * `"/".join(pf.strip("/") for pf in prefixes)`). */
function inlinePrefix(spans: GroupSpan[], pos: number): string {
  return spans
    .filter((s) => s.start <= pos && pos <= s.end)
    .map((s) => s.prefix.replace(/^\/+|\/+$/g, ''))
    .join('/');
}

/**
 * Build the file-basename → URL-prefix map from every RouteServiceProvider.
 * Ports `_laravel_file_prefixes`. Uses RAW file text (not comment-stripped),
 * matching the prototype's `read(p)` here vs `read_code(p)` for route matching.
 */
async function resolveFilePrefixes(files: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const file of files) {
    if (!path.basename(file).includes('RouteServiceProvider')) continue;
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    let m: RegExpExecArray | null;
    FILE_PREFIX_RE.lastIndex = 0;
    while ((m = FILE_PREFIX_RE.exec(raw)) !== null) {
      const prefix = m[1] ?? '';
      const routeFile = path.basename(m[2] ?? '');
      if (!routeFile) continue;
      out.set(routeFile, '/' + prefix.replace(/^\/+|\/+$/g, ''));
    }
  }
  return out;
}

/** True when laravel/sanctum is declared in any composer.json under the repo.
 * Ports `_laravel_has_sanctum`. */
async function hasSanctumDep(repoDir: string): Promise<boolean> {
  const files = await listFiles(repoDir);
  for (const f of files) {
    if (path.basename(f) !== 'composer.json') continue;
    let raw: string;
    try {
      raw = await fs.readFile(f, 'utf8');
    } catch {
      continue;
    }
    if (raw.toLowerCase().includes('sanctum')) return true;
  }
  return false;
}

/**
 * Determine the schema hint for a route declared in `fileText`.
 *   - `declared` when a FormRequest is type-hinted in the file (a typed,
 *     validated request contract — strongest signal Laravel offers).
 *   - `open-unbounded` when the file mass-assigns via `::create(` (prototype
 *     signal for mass-assignment risk).
 *   - else `inferred-untyped` (raw `$request->input(...)`).
 * FormRequest takes precedence: a declared contract is the truthful hint even
 * if a `::create(` also appears.
 */
function laravelSchema(fileText: string): SchemaHint {
  if (/\bextends\s+FormRequest\b/.test(fileText) || /\bFormRequest\s+\$\w+/.test(fileText)) {
    return 'declared';
  }
  if (/::create\(/.test(fileText)) return 'open-unbounded';
  return 'inferred-untyped';
}

/**
 * Parse every Laravel route under `repoDir`.
 *
 * A route file is any `*.php` whose path contains a `routes` segment (the
 * prototype's `"routes" in p` heuristic). The effective prefix for each route
 * is `underMount(filePrefix, inlinePrefix)` composed with the route's own path.
 */
export async function parseLaravel(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const phpFiles = await listFilesByExt(repoDir, PHP_EXTS);
  const routeFiles = phpFiles.filter((p) => p.replace(/\\/g, '/').includes('routes'));

  const filePrefixes = await resolveFilePrefixes(phpFiles);
  let sanctumSeen = false;

  for (const file of routeFiles) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    const text = stripPhpComments(raw);
    const sourceFile = path.relative(repoDir, file);
    const fpref = filePrefixes.get(path.basename(file)) ?? '';
    const schema = laravelSchema(text);
    const spans = groupSpans(text);

    // A `sanctum` reference anywhere in a route file (e.g. the `auth:sanctum`
    // middleware in a chain head or a group) signals the SPA stack is in use.
    // The prototype only scanned the per-route tail and missed head/group refs;
    // scanning the file is more accurate for the auto-route decision.
    if (text.toLowerCase().includes('sanctum')) sanctumSeen = true;

    ROUTE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = ROUTE_RE.exec(text)) !== null) {
      const rawVerb = (m[1] ?? m[2] ?? '').toUpperCase();
      const routePath = m[4] ?? '';
      const tail = m[5] ?? '';
      const declLine = lineAt(text, m.index);

      const gpref = inlinePrefix(spans, m.index);
      const withGroup = underMount(gpref, routePath);
      // Canonicalize ({id}→:id, collapse slashes, strip trailing) so the parser
      // emits the same path shape the dedupe layer keys on (contract: REST paths
      // are norm_path-canonicalized).
      const full = normPath(underMount(fpref, withGroup));

      const method = rawVerb === 'ANY' || rawVerb === 'MATCH' ? 'ANY' : rawVerb;

      // The controller action: `'uses' => 'UserController@show'`, `->uses('X@y')`,
      // or `[UserController::class, 'show']`. Captured as `Ctrl@method` so the
      // evidence-pack can resolve the controller method body (not the route file).
      // Falls back to the per-route middleware string when no action is present.
      const uses = USES_RE.exec(tail);
      const mw = MIDDLEWARE_RE.exec(tail);
      const handler = uses
        ? (uses[1] ?? uses[2] ?? `${(uses[3] ?? '').split('\\').pop()}@${uses[4]}`)
        : mw
          ? mw[2]
          : undefined;

      const route: ExtractedRoute = {
        method,
        path: full,
        source: 'framework',
        framework: 'laravel',
        schemaHint: schema,
        sourceFile,
        sourceLine: declLine,
      };
      if (handler !== undefined) route.handler = handler;
      routes.push(route);
    }
  }

  // Sanctum auto-registers GET /sanctum/csrf-cookie when the package is present
  // (dependency) or a route file references the sanctum middleware.
  if (sanctumSeen || (await hasSanctumDep(repoDir))) {
    // No request body on the CSRF-cookie endpoint; the SchemaHint enum has no
    // `no-body` member, so we omit the hint rather than mislabel it (Rule D-1).
    routes.push({
      method: 'GET',
      path: '/sanctum/csrf-cookie',
      source: 'framework',
      framework: 'laravel',
      notes: 'sanctum-auto-route',
    });
  }

  return routes;
}
