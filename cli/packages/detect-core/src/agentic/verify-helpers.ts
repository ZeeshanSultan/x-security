// Helpers for the V1–V7 verifiers in verify.ts. Pure functions + IO helpers
// kept here to keep verify.ts under the 500-line limit. See interfaces.md §5.

import { promises as fs } from 'node:fs';
import path from 'node:path';

import type {
  AuthorizationRule,
  ParamSchema,
  XSecurityPolicy,
} from '@x-security/schema';

import { canonicalizePolicy } from './canonical.js';
import type {
  Assumption,
  PolicyEmission,
  VerifierResult,
} from './schema.js';

// Path / text helpers

/** Extract `{name}` and `:name` path params from a route path. */
export function extractPathParams(routePath: string): string[] {
  const out: string[] = [];
  for (const m of routePath.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
    if (m[1]) out.push(m[1]);
  }
  for (const m of routePath.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

/** Last segment of a dot-path. */
export function tailOf(dotPath: string): string {
  const parts = dotPath.split('.');
  return parts[parts.length - 1] ?? dotPath;
}

/** Collapse runs of whitespace and trim. */
export function normalizeWhitespace(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

/** Resolve a repo-relative path safely. Returns null if it escapes. */
export function safeResolve(repoDir: string, file: string): string | null {
  let abs: string;
  try {
    abs = path.resolve(repoDir, file);
  } catch {
    return null;
  }
  const rel = path.relative(repoDir, abs);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return abs;
}

/** Read [lineStart, lineEnd] (1-based, inclusive) from a file. */
export async function readSlice(
  repoDir: string,
  file: string,
  lineStart: number,
  lineEnd: number,
): Promise<string | null> {
  const abs = safeResolve(repoDir, file);
  if (!abs) return null;
  let src: string;
  try {
    src = await fs.readFile(abs, 'utf8');
  } catch {
    return null;
  }
  const lines = src.split(/\r?\n/);
  const s = Math.max(1, lineStart);
  const e = Math.min(lines.length, lineEnd);
  if (s > lines.length) return null;
  return lines.slice(s - 1, e).join('\n');
}

/** Minimum normalized quote length eligible for whole-file snap. Short, generic
 * quotes ("exit();", "return;") can match many unrelated locations, so they must
 * still byte-match the cited line exactly. Only distinctive quotes get snapped. */
const MIN_SNAP_QUOTE_LEN = 16;

/**
 * cite-from-source: the model frequently cites the RIGHT quote at the WRONG
 * line (e.g. addUser's field cited at updateUser's line) — a real binding the
 * exact-line byte-match then drops, collapsing the policy. This finds the quote
 * anywhere in the cited file and returns the occurrence NEAREST the model's
 * hint line, so the citation is corrected to its true location rather than
 * dropped. Returns null when the quote text is absent from the file entirely
 * (genuine paraphrase/fabrication — D-3: still dropped, never invented).
 */
export async function snapQuoteToFile(
  repoDir: string,
  file: string,
  quote: string,
  hintLine: number,
): Promise<{ lineStart: number; lineEnd: number } | null> {
  const normQuote = normalizeWhitespace(quote);
  if (normQuote.length < MIN_SNAP_QUOTE_LEN) return null;
  const abs = safeResolve(repoDir, file);
  if (!abs) return null;
  let src: string;
  try {
    src = await fs.readFile(abs, 'utf8');
  } catch {
    return null;
  }
  const lines = src.split(/\r?\n/);
  const quoteLineCount = quote.split(/\r?\n/).length;
  // Try window heights at the quote's line count and ±1 (tolerate a trailing
  // blank line or a fold the model's range off-by-one'd).
  // Prefer the quote's exact line count; only fall back to ±1 (trailing blank
  // / off-by-one fold) when the exact height yields no match. Mixing heights
  // would let a taller window match a shorter quote at a misleading start line.
  const heights = [
    quoteLineCount,
    quoteLineCount + 1,
    ...(quoteLineCount > 1 ? [quoteLineCount - 1] : []),
  ];
  for (const h of heights) {
    let best: { lineStart: number; lineEnd: number } | null = null;
    let bestDist = Infinity;
    for (let i = 0; i + h <= lines.length; i++) {
      const window = normalizeWhitespace(lines.slice(i, i + h).join('\n'));
      if (!window.includes(normQuote)) continue;
      const lineStart = i + 1;
      const dist = Math.abs(lineStart - hintLine);
      if (dist < bestDist) {
        bestDist = dist;
        best = { lineStart, lineEnd: i + h };
      }
    }
    if (best) return best; // first height with any match wins
  }
  return null;
}

// V2 helpers — handler param discovery

/** Languages where we know the param-access syntax. */
export const KNOWN_HANDLER_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.go', '.rb', '.php', '.java', '.kt', '.cs', '.rs',
]);

// Request body/query/path param patterns. Each must capture the param NAME the
// route actually accepts — NOT a framework method name (`.get`, `.post`) and
// NOT an HTTP header. A captured false param becomes an "uncovered" demote in
// V2 / a false positive in V4, so accuracy here is load-bearing.
//
// Header access is deliberately EXCLUDED: an `Authorization` header read is auth
// plumbing, not a request body/query field, and naming it as a param caused the
// VAmPI over-demote (uncovered: Authorization). The `(?:args|form|json|values)`
// member-accessors below omit `headers` for the same reason; the standalone
// HEADER_ACCESS_PATTERNS list is kept only to document what we intentionally
// skip — it is never matched into `params`.
const PARAM_PATTERNS: RegExp[] = [
  // Express/Koa: req.params.x / req.query.x / req.body.x  (NOT req.headers.*).
  // The trailing capture is a property access, so `req.body.get(...)` would
  // capture the method name `get`; METHOD_LIKE_NAMES filters those out below.
  /\breq(?:uest)?\.(?:params|query|body)\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /\breq(?:uest)?\.(?:params|query|body)\[['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\]/g,
  // Flask/Werkzeug: request.args.get('x') / request.form['x'] / request.json[...]
  // / request.values.get('x'). The captured group is the STRING ARG (the field
  // name), never the `get` method. `headers` is excluded (header, not a param).
  /\brequest\.(?:args|form|json|values)(?:\.get\(|\[)\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]/g,
  /\bctx\.params\[['"]([A-Za-z_][A-Za-z0-9_-]*)['"]\]/g,
  // Go (gin/echo): c.Param/c.Query/c.PostForm/c.FormValue. GetHeader excluded
  // (header). DefaultQuery added (gin idiom for query with a default).
  /\bc\.(?:Param|Query|DefaultQuery|PostForm|FormValue)\(\s*["']([A-Za-z_][A-Za-z0-9_-]*)["']/g,
  // Spring: @PathVariable / @RequestParam. @RequestHeader excluded (header).
  /@(?:PathVariable|RequestParam)\(\s*(?:value\s*=\s*)?["']([A-Za-z_][A-Za-z0-9_-]*)["']/g,
  /\bparams\[\s*[:'"]([A-Za-z_][A-Za-z0-9_-]*)['"]?\s*\]/g,
  // Laravel: $request->input/query/post. ->header excluded (header).
  /\$request->(?:input|query|post)\(\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]/g,
  // PHP superglobals: $_GET/$_POST/$_REQUEST. $_COOKIE/$_SERVER excluded
  // (cookies / server+header vars, not request body/query fields).
  /\$_(?:GET|POST|REQUEST)\[\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"]/g,
  // ASP.NET: [FromRoute]/[FromQuery]/[FromBody]/[FromForm]. [FromHeader] excluded.
  /\[From(?:Route|Query|Body|Form)\][^\n,)]*?\b([A-Za-z_][A-Za-z0-9_]*)\b\s*[,)]/g,
];

// Method/property names that a property-access pattern can capture by mistake
// (e.g. `req.body.get(...)`, `req.query.has(...)`). These are framework idioms,
// never request field names — drop them.
const METHOD_LIKE_NAMES = new Set([
  'get', 'set', 'has', 'post', 'put', 'patch', 'delete', 'head', 'keys',
  'values', 'entries', 'forEach', 'map', 'filter', 'find', 'toString',
  'hasOwnProperty', 'constructor', 'length',
]);

/**
 * Resolve the [start,end] line span (1-based, inclusive) of the handler within
 * `lines`. Brace-matching for C-family/JS/TS, indentation for Python. Returns
 * null when the symbol can't be located and no sourceLine anchor is usable —
 * the caller then falls back to file scope with a flag.
 */
function resolveHandlerSpan(
  lines: string[],
  ext: string,
  handlerSymbol: string | undefined,
  sourceLine: number | undefined,
): { start: number; end: number } | null {
  const isPython = ext === '.py';
  // The handler symbol may be a member expression (`userController.create`); the
  // function/method is named by its TAIL.
  const tail = handlerSymbol
    ? handlerSymbol.split('.').pop() ?? handlerSymbol
    : undefined;

  let defIdx = -1; // 0-based index into lines of the def line

  if (tail) {
    const esc = tail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // def foo( | function foo( | const foo = | foo: (…) => | foo(…) { (method)
    // | async foo( | foo = async (…) => …
    const defRes: RegExp[] = isPython
      ? [new RegExp(`^\\s*(?:async\\s+)?def\\s+${esc}\\s*\\(`)]
      : [
          new RegExp(`\\bfunction\\s*\\*?\\s+${esc}\\s*\\(`),
          new RegExp(`\\b(?:const|let|var)\\s+${esc}\\s*=`),
          new RegExp(`(?:^|[,{]\\s*)${esc}\\s*:\\s*(?:async\\s*)?(?:function\\b|\\()`),
          new RegExp(`\\b(?:async\\s+)?${esc}\\s*\\([^)]*\\)\\s*(?::[^={]+)?\\{`),
          new RegExp(`\\b${esc}\\s*[:=]\\s*async\\b`),
        ];
    outer: for (let i = 0; i < lines.length; i++) {
      const ln = lines[i] ?? '';
      for (const re of defRes) {
        if (re.test(ln)) { defIdx = i; break outer; }
      }
    }
  }

  // Fall back to the function enclosing/at sourceLine when the symbol didn't
  // resolve. For Python, the def is at or above sourceLine (decorator points at
  // the decorator, the def is the next def line). For JS we accept the binding
  // line itself as the span anchor.
  if (defIdx < 0 && typeof sourceLine === 'number' && sourceLine >= 1) {
    const anchor = Math.min(sourceLine - 1, lines.length - 1);
    if (isPython) {
      for (let i = anchor; i < lines.length; i++) {
        if (/^\s*(?:async\s+)?def\s+/.test(lines[i] ?? '')) { defIdx = i; break; }
      }
    } else {
      defIdx = anchor;
    }
  }

  if (defIdx < 0) return null;

  if (isPython) {
    // Body span: from the def line to the next line at <= the def's indentation
    // that is non-blank (dedent), exclusive.
    const defIndent = (lines[defIdx]?.match(/^\s*/)?.[0].length) ?? 0;
    let end = lines.length;
    for (let i = defIdx + 1; i < lines.length; i++) {
      const ln = lines[i] ?? '';
      if (ln.trim() === '') continue;
      const ind = ln.match(/^\s*/)?.[0].length ?? 0;
      if (ind <= defIndent) { end = i; break; }
    }
    return { start: defIdx + 1, end };
  }

  // JS/TS/C-family: brace-match from the first `{` at or after defIdx.
  let braceLine = -1;
  let braceCol = -1;
  for (let i = defIdx; i < Math.min(lines.length, defIdx + 6); i++) {
    const col = (lines[i] ?? '').indexOf('{');
    if (col >= 0) { braceLine = i; braceCol = col; break; }
  }
  if (braceLine < 0) {
    // Arrow with no block body (`foo = (req,res) => handler(req)`) — single line.
    return { start: defIdx + 1, end: defIdx + 1 };
  }
  let depth = 0;
  for (let i = braceLine; i < lines.length; i++) {
    const ln = lines[i] ?? '';
    const from = i === braceLine ? braceCol : 0;
    for (let c = from; c < ln.length; c++) {
      const ch = ln[c];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) return { start: defIdx + 1, end: i + 1 };
      }
    }
  }
  return { start: defIdx + 1, end: lines.length };
}

/** Where to scope handler-param discovery: the handler symbol + its decl line. */
export interface HandlerScope {
  handlerSymbol?: string | undefined;
  sourceLine?: number | undefined;
}

/**
 * Discover request param names referenced inside a handler. When `scope`
 * resolves the handler's function span, discovery is confined to that span so a
 * sibling handler's fields (e.g. another route's `login` body) don't leak in.
 * Falls back to whole-file scope (scoped=false) only when the span can't be
 * resolved.
 */
export async function discoverHandlerParams(
  repoDir: string,
  sourceFile: string,
  scope?: HandlerScope,
): Promise<{ params: Set<string>; unsupported: boolean; scoped: boolean }> {
  const result = { params: new Set<string>(), unsupported: false, scoped: false };
  const abs = safeResolve(repoDir, sourceFile);
  if (!abs) return result;

  const ext = path.extname(sourceFile).toLowerCase();
  if (!KNOWN_HANDLER_EXTS.has(ext)) {
    result.unsupported = true;
    return result;
  }

  let src: string;
  try {
    src = await fs.readFile(abs, 'utf8');
  } catch {
    return result;
  }

  let scanText = src;
  if (scope && (scope.handlerSymbol || typeof scope.sourceLine === 'number')) {
    const lines = src.split(/\r?\n/);
    const span = resolveHandlerSpan(lines, ext, scope.handlerSymbol, scope.sourceLine);
    if (span) {
      scanText = lines.slice(span.start - 1, span.end).join('\n');
      result.scoped = true;
    }
  }

  for (const re of PARAM_PATTERNS) {
    for (const m of scanText.matchAll(re)) {
      const name = m[1];
      if (!name) continue;
      if (METHOD_LIKE_NAMES.has(name)) continue;
      result.params.add(name);
    }
  }
  return result;
}

/** Walk policy.request.schema / response.schema → entries. */
export function paramSchemaEntries(
  schemas: Record<string, ParamSchema> | undefined,
): Array<[string, ParamSchema]> {
  if (!schemas) return [];
  return Object.entries(schemas);
}

/** Collect rule.field strings. */
export function collectAuthRuleFields(
  rules: AuthorizationRule[] | undefined,
): string[] {
  if (!rules) return [];
  const out: string[] = [];
  for (const r of rules) out.push(r.field);
  return out;
}

// V5 — Stable signature for ParamSchema comparison

export function paramSignature(p: ParamSchema): string {
  const norm: Record<string, unknown> = {};
  const keys = Object.keys(p).sort();
  for (const k of keys) {
    const v = (p as Record<string, unknown>)[k];
    norm[k] = Array.isArray(v) ? [...v].sort() : v;
  }
  return JSON.stringify(norm);
}

// V7 — Inventory grep patterns
export interface InventoryPattern { ext: string[]; re: RegExp; }

export const INVENTORY_PATTERNS: InventoryPattern[] = [
  // Express/Fastify/Hono/Elysia decl-routers; tRPC procedures; Bun/Deno.serve;
  // Nuxt/h3 defineEventHandler.
  { ext: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
    re: /\b(?:app|router|server|fastify|hono|elysia)\s*\.\s*(get|post|put|patch|delete|head|options|all|on)\s*\(\s*['"`]([^'"`)]+)['"`]/gi },
  { ext: ['.ts', '.tsx', '.js'],
    re: /\b(?:procedure|publicProcedure|protectedProcedure|adminProcedure)\s*\.\s*(query|mutation|subscription)\s*\(/g },
  { ext: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'], re: /\b(?:Bun|Deno)\.serve\s*\(/g },
  { ext: ['.js', '.ts', '.mjs'], re: /\bdefineEventHandler\s*\(/g },
  { ext: ['.ts', '.tsx'],
    re: /@(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*['"`]?([^'"`)]*)['"`]?\s*\)/g },
  { ext: ['.py'],
    re: /@(?:app|router|api|blueprint)\s*\.\s*(get|post|put|patch|delete|route)\s*\(\s*['"]([^'"]+)['"]/gi },
  { ext: ['.java', '.kt'],
    re: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
  { ext: ['.go'],
    re: /\b(?:r|e|app|router|mux)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|HandleFunc|Handle)\s*\(\s*"([^"]+)"/g },
  { ext: ['.rs'], re: /#\[(get|post|put|patch|delete|head)\s*\(\s*"([^"]+)"/gi },
  { ext: ['.php'],
    re: /Route::(?:get|post|put|patch|delete|any|match)\s*\(\s*['"]([^'"]+)['"]/gi },
  { ext: ['.rb'], re: /^\s*(?:get|post|put|patch|delete|head)\s+['"]([^'"]+)['"]/gim },
  { ext: ['.cs'], re: /\[Http(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*"([^"]+)"/g },
  { ext: ['.cs'],
    re: /\bapp\.Map(?:Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*"([^"]+)"/g },
  // Phoenix (Elixir) router macros
  { ext: ['.ex', '.exs'],
    re: /^\s*(?:get|post|put|patch|delete|head|options)\s+"([^"]+)"/gim },
  { ext: ['.ex', '.exs'], re: /^\s*(?:scope|resources)\s+"([^"]+)"/gim },
  { ext: ['.graphql', '.gql'], re: /\btype\s+(Query|Mutation|Subscription)\b/g },
  { ext: ['.ts', '.tsx', '.js'], re: /@(Query|Mutation|Subscription|Resolver)\s*\(/g },
  { ext: ['.js', '.ts', '.mjs', '.cjs'],
    re: /\b(?:exports\.handler|exports\.lambdaHandler)\s*=/g },
  { ext: ['.py'], re: /^\s*def\s+(?:lambda_handler|handler)\s*\(/gm },
];

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'target', '.next', 'vendor',
  '__pycache__', '.venv', 'venv', 'out',
]);

/** Recursively list source files under repoDir whose ext is in `exts`. */
async function listSourceFiles(
  repoDir: string,
  exts: Set<string>,
): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string) {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (SKIP_DIRS.has(ent.name)) continue;
      const full = path.join(dir, ent.name);
      try {
        const lst = await fs.lstat(full);
        if (lst.isSymbolicLink()) continue;
        if (lst.isDirectory()) {
          await walk(full);
        } else if (lst.isFile()) {
          if (exts.has(path.extname(ent.name).toLowerCase())) {
            out.push(full);
          }
        }
      } catch {
        // ignore
      }
    }
  }
  await walk(repoDir);
  return out;
}

export {
  detectFilesystemHandlerCandidates,
  type FilesystemHandlerCandidate,
} from './verify-fs-routing.js';

export interface GrepHit {
  file: string;
  line: number;
  path?: string;
}

export async function deterministicGrep(repoDir: string): Promise<GrepHit[]> {
  const allExts = new Set<string>();
  for (const p of INVENTORY_PATTERNS) for (const e of p.ext) allExts.add(e);
  const files = await listSourceFiles(repoDir, allExts);
  const hits: GrepHit[] = [];
  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    let src: string;
    try {
      src = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    const lines = src.split(/\r?\n/);
    for (const pat of INVENTORY_PATTERNS) {
      if (!pat.ext.includes(ext)) continue;
      const re = new RegExp(pat.re.source, pat.re.flags);
      for (let i = 0; i < lines.length; i++) {
        const ln = lines[i];
        if (!ln) continue;
        re.lastIndex = 0;
        const m = re.exec(ln);
        if (m) {
          const rel = path.relative(repoDir, file);
          const hit: GrepHit = { file: rel, line: i + 1 };
          const lastCap = m[m.length - 1];
          if (lastCap) hit.path = lastCap;
          hits.push(hit);
        }
      }
    }
  }
  return hits;
}

// V3 — Tightness rubric (pure function)

/** Returns null if the param schema passes the rubric, else the reason. */
export function checkTightness(p: ParamSchema): string | null {
  const t = p.type;
  switch (t) {
    case 'string': {
      const hasPattern = typeof p.pattern === 'string' && p.pattern.length > 0;
      const hasLenBounds =
        typeof p.minLength === 'number' && typeof p.maxLength === 'number';
      if (!hasPattern && !hasLenBounds) {
        return 'type:string requires pattern OR (minLength + maxLength)';
      }
      return null;
    }
    case 'integer':
    case 'float':
      if (typeof p.min !== 'number' || typeof p.max !== 'number') {
        return `type:${t} requires both min and max`;
      }
      return null;
    case 'url':
      // A url param is tight if it constrains the destination: either a
      // non-empty domainAllowlist OR blockPrivateRanges:true. The latter is the
      // enforceable SSRF guard (rejects metadata IPs, RFC1918, loopback,
      // link-local, non-http schemes) and bites with no operator allowlist — so
      // it satisfies tightness on its own. An empty/absent domainAllowlist with
      // no blockPrivateRanges remains a no-op and is rejected (D-1).
      if (p.blockPrivateRanges === true) return null;
      if (!p.domainAllowlist || p.domainAllowlist.length === 0) {
        return 'type:url requires non-empty domainAllowlist or blockPrivateRanges:true';
      }
      return null;
    case 'email':
      if (typeof p.maxLength !== 'number' || p.maxLength > 254) {
        return 'type:email requires maxLength <= 254';
      }
      return null;
    case 'uuid':
      return null;
    case 'free-text':
      if (typeof p.maxLength !== 'number') {
        return 'type:free-text requires maxLength';
      }
      return null;
    case 'binary':
      if (typeof p.maxSize !== 'string' || p.maxSize.length === 0) {
        return 'type:binary requires maxSize';
      }
      if (!p.allowedMimeTypes || p.allowedMimeTypes.length === 0) {
        return 'type:binary requires non-empty allowedMimeTypes';
      }
      return null;
    case 'date':
    case 'datetime':
    case 'phone':
    case 'name':
    case 'boolean':
    case 'ip-address':
      return null;
    case undefined:
      return 'param schema missing `type` — cannot evaluate tightness';
    default:
      return `unknown semantic type: ${String(t)}`;
  }
}

// V5 — Cross-route consistency core

export function computeV5Demotions(
  emissions: PolicyEmission[],
): Map<string, string[]> {
  interface Hit { endpointId: string; ps: ParamSchema; sig: string }
  const groups = new Map<string, Hit[]>();
  for (const e of emissions) {
    if (!e.policy) continue;
    const cloned = structuredClone(e.policy) as XSecurityPolicy;
    const canon = canonicalizePolicy(cloned);
    const both: Array<[string, ParamSchema]> = [
      ...paramSchemaEntries(canon.request?.schema),
      ...paramSchemaEntries(canon.response?.schema),
    ];
    for (const [name, ps] of both) {
      const key = name.toLowerCase();
      const sig = paramSignature(ps);
      const arr = groups.get(key) ?? [];
      arr.push({ endpointId: e.endpointId, ps, sig });
      groups.set(key, arr);
    }
  }

  const demotedByEndpoint = new Map<string, string[]>();
  for (const [name, hits] of groups) {
    if (hits.length < 2) continue;
    const counts = new Map<string, number>();
    for (const h of hits) counts.set(h.sig, (counts.get(h.sig) ?? 0) + 1);
    let maxSig = '';
    let maxCount = 0;
    let tied = false;
    for (const [sig, c] of counts) {
      if (c > maxCount) { maxCount = c; maxSig = sig; tied = false; }
      else if (c === maxCount) { tied = true; }
    }
    if (tied || maxCount === hits.length) continue;
    const majorityRoutes = hits
      .filter((h) => h.sig === maxSig)
      .map((h) => h.endpointId);
    for (const h of hits) {
      if (h.sig === maxSig) continue;
      const reason = `param ${name} dissents from majority schema (type ${h.ps.type ?? 'unknown'}) seen on routes [${majorityRoutes.join(', ')}]`;
      const arr = demotedByEndpoint.get(h.endpointId) ?? [];
      arr.push(reason);
      demotedByEndpoint.set(h.endpointId, arr);
    }
  }
  return demotedByEndpoint;
}

// V6 — Citation justification core

export interface V6PerEmission {
  kept: Assumption[];
  droppedReasons: string[];
  cascadeReasons: string[];
}

export async function evaluateV6ForEmission(
  e: PolicyEmission,
  repoDir: string,
): Promise<V6PerEmission> {
  const kept: Assumption[] = [];
  const droppedAssumptions: Assumption[] = [];
  const droppedReasons: string[] = [];

  for (const a of e.assumptions) {
    const slice = await readSlice(
      repoDir,
      a.cite.file,
      a.cite.lineStart,
      a.cite.lineEnd,
    );
    if (slice === null) {
      droppedAssumptions.push(a);
      droppedReasons.push(
        `${a.field}: cite ${a.cite.file}:${a.cite.lineStart}-${a.cite.lineEnd} unreadable`,
      );
      continue;
    }
    const normSlice = normalizeWhitespace(slice);
    const normQuote = normalizeWhitespace(a.cite.quote);
    if (normQuote.length === 0) {
      droppedAssumptions.push(a);
      droppedReasons.push(`${a.field}: cite quote empty`);
      continue;
    }
    if (normSlice.includes(normQuote)) {
      kept.push(a);
    } else {
      // cite-from-source: the quote may be real but mis-located (line drift).
      // Snap to its true location nearest the hint before dropping.
      const snap = await snapQuoteToFile(
        repoDir,
        a.cite.file,
        a.cite.quote,
        a.cite.lineStart,
      );
      if (snap) {
        kept.push({
          ...a,
          cite: { ...a.cite, lineStart: snap.lineStart, lineEnd: snap.lineEnd },
        });
      } else {
        droppedAssumptions.push(a);
        droppedReasons.push(
          `${a.field}: cite quote does not byte-match ${a.cite.file}:${a.cite.lineStart}-${a.cite.lineEnd} (and not found elsewhere in file)`,
        );
      }
    }
  }

  const cascadeReasons: string[] = [];
  if (e.policy && droppedAssumptions.length > 0) {
    for (const a of droppedAssumptions) {
      // D-3: any dropped assumption that carried a controlHint BACKED a
      // materialized control (injectionGuard, authentication, authorization,
      // denyUnknownFields, rateLimit, contentType, responseShape, …). With its
      // cite gone, that control is enforced with no evidence — revoke it
      // (demote-to-review), regardless of which policy field it landed on. The
      // old logic only inspected untight request/response.schema.* params, so
      // authorization/rateLimit/etc. — and tight injectionGuard/domainAllowlist
      // — survived UNCITED. An orphaned ownership rule is worse than no rule.
      if (a.controlHint) {
        cascadeReasons.push(
          `V6 cascade: ${a.controlHint.kind} control (${a.field}) is now uncited — its cite no longer byte-matches; revoking`,
        );
        continue;
      }
      // Legacy path: a tight-rule justification with no controlHint on a schema
      // param — demote only when the param is now untight.
      if (
        !a.field.startsWith('request.schema.') &&
        !a.field.startsWith('response.schema.')
      ) continue;
      const parts = a.field.split('.');
      const name = parts[2];
      if (!name) continue;
      const section = parts[0] === 'response'
        ? e.policy.response?.schema
        : e.policy.request?.schema;
      const ps = section?.[name];
      if (!ps) continue;
      const why = checkTightness(ps);
      if (why) {
        cascadeReasons.push(
          `V6 cascade: ${name} now untight without justification (${why})`,
        );
      }
    }
  }

  return { kept, droppedReasons, cascadeReasons };
}

// Orchestrator helper — verdict strictness ordering

export function verdictStrictness(
  v: 'pass' | 'fail' | 'demote-to-review',
): number {
  if (v === 'pass') return 0;
  if (v === 'demote-to-review') return 1;
  return 2;
}

/** Apply one VerifierResult's modifications to a PolicyEmission in place. */
export function applyModifications(
  target: PolicyEmission,
  r: VerifierResult,
): void {
  if (!r.modifications) return;
  const m = r.modifications;
  if (m.assumptions !== undefined) target.assumptions = m.assumptions;
  if (m.reviewRequired !== undefined) target.reviewRequired = m.reviewRequired;
  if (m.reviewReasons !== undefined) {
    const seen = new Set<string>();
    const merged: string[] = [];
    for (const x of m.reviewReasons) {
      if (!seen.has(x)) { seen.add(x); merged.push(x); }
    }
    target.reviewReasons = merged;
  }
  if (m.policy !== undefined) target.policy = m.policy;
}
