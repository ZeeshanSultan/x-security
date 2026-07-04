// Express route parser (deterministic, ported from the Python prototype's
// `parse_express` / `_express_*` helpers in /tmp/route-extractor-proto/extract.py).
//
// This is the HIGHEST-RISK parser in the extractor because Express mount
// prefixes are resolved through the transitive require-graph: an
// `app.use('/api', routes(router))` in server.js attaches `/api` to routes
// declared in a *different* file reached only via require() + a delegate call.
// Getting this wrong is what made dvws score 20.5 and dvna miss its `/app`
// mounts; the prototype's `_propagate_prefix` is the fix and is ported here
// faithfully — NO "improvements" to the resolution heuristics.
//
// Two route forms are recognized, matching the prototype:
//   1. chained builder:  router.route('/p').get(fn).post(fn)  → one route/verb
//   2. literal:          router.get('/p', fn) / app.post('/p', fn)
//
// Mount-prefix composition uses `prefix + path` then slash-collapse (the
// prototype's `_express_route`), NOT the `_join`/underMount leading-slash
// normalization used by the spec/Laravel layers — Express prefixes already
// start with `/` and the prototype does not re-anchor them.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { listFilesByExt } from './walk.js';
import type { ExtractedRoute, SchemaHint } from './types.js';

const JS_EXTS: ReadonlySet<string> = new Set(['.js', '.ts', '.jsx', '.tsx']);

/** Objects that expose `.get/.post/...` but are not Express routers; the
 * prototype's literal-route skip list. */
const NON_ROUTER_OBJECTS: ReadonlySet<string> = new Set([
  'res', 'response', 'axios', 'http', 'https', 'fetch', 'supertest',
]);

/** Identifiers that are never a mounted sub-router (so `app.use('/p', cors())`
 * etc. don't create phantom prefixes). Ported from `_express_mount_prefixes`. */
const NON_MOUNT_IDENTIFIERS: ReadonlySet<string> = new Set([
  'express', 'require', 'cors', 'bodyParser', 'path', 'static',
]);

// --------------------------------------------------------------------------- //
// comment stripping (ports the prototype's strip_comments for lang="js")
// --------------------------------------------------------------------------- //
// WHY: commented-out route declarations must not be extracted. Conservative,
// line-oriented; `//` inside strings/URLs is intentionally left rough, matching
// the prototype.
function stripComments(text: string): string {
  // Blank comment CONTENT but preserve every line (and column) so the stripped
  // text stays positionally isomorphic to the source — `lineAt` must report the
  // real source line (Rule D-3: exact citations). Deleting comment lines shifts
  // every route below them up by the comment count; on comment-rich real-world
  // files that desynced citations by ~30 lines (mongo-express dogfood, CVE-2019-10758).
  // Block comments: replace non-newline chars with spaces (keeps line count + columns).
  let t = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  const out: string[] = [];
  for (let line of t.split('\n')) {
    const s = line.replace(/^\s+/, '');
    if (s.startsWith('//')) {
      out.push(''); // hold the line slot — a dropped full-line comment must not shift lines below it
      continue;
    }
    // strip a trailing // comment (rough; ignores // inside strings/urls).
    // Python: re.sub(r"(^|[^:'\"])//.*$", r"\1", line)
    line = line.replace(/(^|[^:'"])\/\/.*$/, '$1');
    out.push(line);
  }
  return out.join('\n');
}

async function readCode(file: string): Promise<string> {
  let raw: string;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch {
    return '';
  }
  return stripComments(raw);
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) n++;
  }
  return n;
}

// --------------------------------------------------------------------------- //
// require resolution + transitive prefix propagation
// --------------------------------------------------------------------------- //

/** Resolve a relative `require('./routes/X')` to an absolute file path. Ports
 * `_resolve_require`: tries the bare path, then .js/.ts, then /index.{js,ts}. */
async function resolveRequire(
  fromFile: string,
  reqPath: string,
): Promise<string | null> {
  const base = path.dirname(path.resolve(fromFile));
  const cand = path.normalize(path.join(base, reqPath));
  for (const suffix of ['', '.js', '.ts', '/index.js', '/index.ts']) {
    const full = cand + suffix;
    try {
      const st = await fs.stat(full);
      if (st.isFile()) return path.resolve(full);
    } catch {
      // not a file; try next suffix
    }
  }
  return null;
}

/** Per-file map: localName → resolved absolute require target. Mirrors the
 * prototype's `requires[ap]`. */
type RequireMap = Map<string, Map<string, string>>;

const RE_REQUIRE_DECL =
  /\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["'](\.[^"']+)["']\)/g;

async function buildRequireMap(
  files: string[],
  codeCache: Map<string, string>,
): Promise<RequireMap> {
  const requires: RequireMap = new Map();
  for (const p of files) {
    const ap = path.resolve(p);
    const t = codeCache.get(ap) ?? '';
    const local = new Map<string, string>();
    for (const m of t.matchAll(RE_REQUIRE_DECL)) {
      const resolved = await resolveRequire(p, m[2]!);
      if (resolved) local.set(m[1]!, resolved);
    }
    requires.set(ap, local);
  }
  return requires;
}

const RE_DEFINES_ROUTES = /\.(get|post|put|patch|delete|route|all)\(/;
const RE_DELEGATE_ARROW = /module\.exports\s*=\s*\(\s*\w+\s*\)\s*=>/;
const RE_DELEGATE_CALL = /\b\w+\s*\(\s*router\s*\)/;

/**
 * Apply `prefix` to `start` and to every route module it reaches through
 * require + delegate-call (hub modules like routes/index.js that invoke
 * sub-modules on a shared router). Ports `_propagate_prefix` faithfully,
 * including the `setdefault` semantics (first/longest assignment wins) and the
 * "invoked AND (defines-routes OR delegates)" follow condition.
 */
async function propagatePrefix(
  start: string,
  prefix: string,
  requires: RequireMap,
  filePrefix: Map<string, string>,
  codeCache: Map<string, string>,
  seen: Set<string>,
): Promise<void> {
  if (seen.has(start)) return;
  seen.add(start);
  if (!filePrefix.has(start)) filePrefix.set(start, prefix);

  const startText = codeCache.get(start) ?? (await readCode(start));
  if (!codeCache.has(start)) codeCache.set(start, startText);

  const localRequires = requires.get(start);
  if (!localRequires) return;
  for (const [name, target] of localRequires) {
    const tText = codeCache.get(target) ?? (await readCode(target));
    if (!codeCache.has(target)) codeCache.set(target, tText);
    const invoked = new RegExp(`\\b${escapeRegExp(name)}\\s*\\(`).test(startText);
    const definesRoutes = RE_DEFINES_ROUTES.test(tText);
    const delegates = RE_DELEGATE_ARROW.test(tText) || RE_DELEGATE_CALL.test(tText);
    if (invoked && (definesRoutes || delegates)) {
      await propagatePrefix(target, prefix, requires, filePrefix, codeCache, seen);
    }
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// DELTA from prototype: the Python `_express_mount_prefixes` captured the mount
// target with a NON-greedy `([^\n]+?)\)`, which truncates `require('./x')()` at
// the require's own inner `)` → target becomes `require('./x'` and BOTH the
// inline-require and identifier branches miss it, so the prefix never
// propagates. The task's documented dvws/dvna fix depends on this exact
// invoked-require form working, so we capture the rest of the line GREEDILY and
// let RE_INLINE_REQUIRE pull the `require('./x')` head off the front. A trailing
// `()` invocation (delegate call) is then preserved inside the target text.
const RE_USE_MOUNT =
  /\b(?:app|router)\.use\(\s*(["'])(\/[^"']*)\1\s*,\s*([^\n]+)\)\s*;?/g;
const RE_INLINE_REQUIRE = /^require\(\s*["'](\.[^"']+)["']\)/;
const RE_LEADING_IDENT = /^([A-Za-z_]\w*)/;

interface MountPrefixes {
  /** sub-router variable name → prefix (for `express.Router()` vars). */
  varPrefix: Map<string, string>;
  /** resolved absolute file path → prefix. */
  filePrefix: Map<string, string>;
}

/**
 * Resolve `app.use('/prefix', X)` mounts to (var→prefix, file→prefix). Ports
 * `_express_mount_prefixes`: handles inline-require, bare-variable, and
 * function-call mount targets, following each through the require-graph via
 * `propagatePrefix`. A target that's neither a known require nor an excluded
 * identifier is treated as a local `express.Router()` variable (`varPrefix`).
 */
async function resolveMountPrefixes(
  files: string[],
  codeCache: Map<string, string>,
): Promise<MountPrefixes> {
  const varPrefix = new Map<string, string>();
  const filePrefix = new Map<string, string>();
  const requires = await buildRequireMap(files, codeCache);

  for (const p of files) {
    const ap = path.resolve(p);
    const t = codeCache.get(ap) ?? '';
    for (const m of t.matchAll(RE_USE_MOUNT)) {
      const prefix = m[2]!.replace(/\/+$/, '');
      const target = m[3]!.trim();

      const rq = RE_INLINE_REQUIRE.exec(target);
      if (rq) {
        const resolved = await resolveRequire(p, rq[1]!);
        if (resolved) {
          await propagatePrefix(
            resolved, prefix, requires, filePrefix, codeCache, new Set(),
          );
        }
        continue;
      }

      const idm = RE_LEADING_IDENT.exec(target);
      if (!idm) continue;
      const name = idm[1]!;
      if (NON_MOUNT_IDENTIFIERS.has(name)) continue;
      const resolved = requires.get(ap)?.get(name);
      if (resolved) {
        await propagatePrefix(
          resolved, prefix, requires, filePrefix, codeCache, new Set(),
        );
      } else {
        varPrefix.set(name, prefix);
      }
    }
  }
  return { varPrefix, filePrefix };
}

// --------------------------------------------------------------------------- //
// per-file route extraction
// --------------------------------------------------------------------------- //

const RE_ROUTER_ASSIGN = /\b(\w+)\s*=\s*express\.Router\(/g;

/** Prefixes that apply to routes declared in this file. Ports
 * `_express_local_prefixes`: a file's `express.Router()` var(s) that are
 * mounted under a known prefix contribute it; otherwise assume root-mounted
 * (empty prefix). */
function localPrefixes(text: string, varPrefix: Map<string, string>): string[] {
  const prefixes = new Set<string>();
  for (const m of text.matchAll(RE_ROUTER_ASSIGN)) {
    const v = m[1]!;
    const pref = varPrefix.get(v);
    if (pref !== undefined) prefixes.add(pref);
  }
  if (prefixes.size === 0) prefixes.add('');
  return [...prefixes];
}

/** Mass-assignment "open schema" signal. Ports `_express_open_schema`. */
const RE_OPEN_NEW = /new\s+\w+\(\s*req\.body\s*\)/;
const RE_OPEN_CREATE = /\.create\(\s*req\.body\s*\)/;
const RE_OPEN_SPREAD = /\{\s*\.\.\.req\.body\s*\}/;
function openSchema(text: string): boolean {
  return (
    RE_OPEN_NEW.test(text) ||
    RE_OPEN_CREATE.test(text) ||
    RE_OPEN_SPREAD.test(text)
  );
}

// Gate the whole-file scan, ports the prototype's cheap pre-check.
const RE_HAS_ROUTE =
  /\b(app|router|\w*[Rr]outer\w*|\w*[Aa]pp\w*|this)\.(get|post|put|patch|delete|route|all)\(/;

// chained builder: `<obj>.route('p')` — the path here may be relative (no
// leading `/`), matching the prototype's `(.*?)` capture.
const RE_CHAINED = /\b(\w+)\.route\(\s*(["'])(.*?)\2\s*\)/g;
// verbs in the chain region following `.route(...)`.
const RE_CHAIN_VERB = /\.\s*(get|post|put|patch|delete|all)\s*\(/g;
// method-first form: `<obj>.route('POST', '/path', ...handlers)` — Parse Server's
// PromiseRouter (`route(method, path, ...handlers)`). An HTTP-verb LITERAL as the
// first arg disambiguates it from express's path-first chained `.route('/p')`.
const RE_METHOD_FIRST =
  /\b(?:this|\w+)\.route\(\s*(["'`])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL)\1\s*,\s*(["'`])(\/.*?)\3/gi;
// literal route: `<obj>.<verb>('p', ...)` — path MUST start with `/`, matching
// the prototype's `(/.*?)`. Backtick template literals are allowed as quote.
const RE_LITERAL =
  /\b(\w+)\.(get|post|put|patch|delete|all)\(\s*(["'`])(\/.*?)\3/g;
// array-path route: `<obj>.<verb>(['/', '/:id'], handler)` — express accepts an
// ARRAY of paths as the first arg. Each string in the array is a route. Without
// this, a router file whose routes ALL use the array form grounds to ZERO routes
// (FlowiseAI leads/tools/variables — three mass-assignment CVEs at once).
const RE_LITERAL_ARRAY =
  /\b(\w+)\.(get|post|put|patch|delete|all)\(\s*(\[[^\]]*\])/g;
const RE_ARRAY_PATH = /(["'`])(\/[^"'`]*)\1/g;

/**
 * Compose a mount prefix with a route path and build the ExtractedRoute. Ports
 * `_express_route`: `prefix + path`, then collapse repeated slashes. Carries
 * the file:line citation + handler reference text the prototype omitted.
 */
function buildRoute(
  verb: string,
  prefix: string,
  routePath: string,
  bodyOpen: boolean,
  sourceFile: string,
  sourceLine: number,
  handler: string | undefined,
): ExtractedRoute {
  let full = prefix ? prefix + routePath : routePath;
  full = full.replace(/\/\/+/g, '/');
  const schemaHint: SchemaHint = bodyOpen ? 'open-unbounded' : 'inferred-untyped';
  const route: ExtractedRoute = {
    method: verb,
    path: full,
    source: 'framework',
    framework: 'express',
    sourceFile,
    sourceLine,
    schemaHint,
  };
  if (handler !== undefined) route.handler = handler;
  return route;
}

/** Best-effort handler reference: the first argument token after the path. The
 * prototype emitted `handler: null`; we surface the binding's handler text when
 * it's a plain identifier or member expression (e.g. `userController.create`),
 * leaving it undefined when it's an inline function/array — we never synthesize
 * one (Rule D-3). The route binding's file:line is the authoritative citation. */
function handlerRef(text: string, afterIdx: number): string | undefined {
  // skip a leading comma + whitespace after the path string
  const rest = text.slice(afterIdx, afterIdx + 200);
  const m = /^\s*,\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)/.exec(rest);
  return m ? m[1]! : undefined;
}

// --------------------------------------------------------------------------- //
// public entry
// --------------------------------------------------------------------------- //

/**
 * Parse every Express route under `repoDir`, with mount prefixes resolved
 * through the transitive require-graph. Returns RAW routes (NOT deduped) so the
 * orchestrator can merge them with spec/protocol layers and dedupe once
 * globally — matching the prototype, whose `parse_express` deduped locally but
 * whose `extract()` deduped the union again. Dedupe is the orchestrator's job
 * (Wave 2); duplicating it here would drop a route a spec layer should win.
 *
 * Paths are NOT normPath-canonicalized here either — `_express_route` only
 * collapses slashes; final `:param`/trailing-slash canonicalization happens in
 * dedupe. Keeping that boundary identical preserves byte-parity with the
 * prototype's intermediate route list.
 */
export async function parseExpress(repoDir: string): Promise<ExtractedRoute[]> {
  const files = await listFilesByExt(repoDir, JS_EXTS);
  const codeCache = new Map<string, string>();
  for (const p of files) {
    codeCache.set(path.resolve(p), await readCode(p));
  }

  const { varPrefix, filePrefix } = await resolveMountPrefixes(files, codeCache);
  const routes: ExtractedRoute[] = [];

  for (const p of files) {
    const ap = path.resolve(p);
    const t = codeCache.get(ap) ?? '';
    if (!RE_HAS_ROUTE.test(t)) continue;

    const rel = path.relative(repoDir, p);
    let prefixes = localPrefixes(t, varPrefix);
    const filePref = filePrefix.get(ap);
    if (filePref !== undefined) prefixes = [filePref];
    const bodyOpen = openSchema(t);

    // chained builder: router.route('p').get(...).post(...)
    for (const m of t.matchAll(RE_CHAINED)) {
      const routePath = m[3]!;
      const chainStart = m.index! + m[0]!.length;
      // scan the chain region: up to 500 chars, bounded by a blank line or `;`
      // (ports `t[end:end+500].split("\n\n")[0].split(";")[0]`).
      let region = t.slice(chainStart, chainStart + 500);
      region = region.split('\n\n')[0]!;
      region = region.split(';')[0]!;
      const verbs = [...region.matchAll(RE_CHAIN_VERB)].map((v) =>
        v[1]!.toUpperCase(),
      );
      const line = lineAt(t, m.index!);
      // Chained handlers live per-verb deep in the chain (`.get(fn).post(fn)`),
      // not as a single post-path arg; the prototype left handler null here and
      // we don't synthesize one. The `.route(...)` line is the citation.
      for (const verb of verbs.length ? verbs : ['GET']) {
        for (const pref of prefixes) {
          routes.push(
            buildRoute(verb, pref, routePath, bodyOpen, rel, line, undefined),
          );
        }
      }
    }

    // method-first: <obj>.route('POST', '/p', ...handlers) (PromiseRouter)
    for (const m of t.matchAll(RE_METHOD_FIRST)) {
      const verb = m[2]!.toUpperCase();
      const routePath = m[4]!;
      const line = lineAt(t, m.index!);
      const afterPath = m.index! + m[0]!.length;
      const handler = handlerRef(t, afterPath);
      for (const pref of prefixes) {
        routes.push(
          buildRoute(verb, pref, routePath, bodyOpen, rel, line, handler),
        );
      }
    }

    // literal: router|app .get/post/...('p', handler)
    for (const m of t.matchAll(RE_LITERAL)) {
      const obj = m[1]!;
      if (NON_ROUTER_OBJECTS.has(obj)) continue;
      const verb = m[2]!.toUpperCase();
      const routePath = m[4]!;
      const line = lineAt(t, m.index!);
      const afterPath = m.index! + m[0]!.length;
      const handler = handlerRef(t, afterPath);
      for (const pref of prefixes) {
        routes.push(
          buildRoute(verb, pref, routePath, bodyOpen, rel, line, handler),
        );
      }
    }

    // array-path literal: router|app .get(['/', '/:id'], handler)
    for (const m of t.matchAll(RE_LITERAL_ARRAY)) {
      const obj = m[1]!;
      if (NON_ROUTER_OBJECTS.has(obj)) continue;
      const verb = m[2]!.toUpperCase();
      const arr = m[3]!;
      const line = lineAt(t, m.index!);
      const afterArr = m.index! + m[0]!.length;
      const handler = handlerRef(t, afterArr);
      RE_ARRAY_PATH.lastIndex = 0;
      let pm: RegExpExecArray | null;
      while ((pm = RE_ARRAY_PATH.exec(arr)) !== null) {
        const routePath = pm[2]!;
        for (const pref of prefixes) {
          routes.push(
            buildRoute(verb, pref, routePath, bodyOpen, rel, line, handler),
          );
        }
      }
    }
  }

  return routes;
}
