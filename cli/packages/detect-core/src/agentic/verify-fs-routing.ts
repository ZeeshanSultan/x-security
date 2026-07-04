// V7 — Filesystem-routing candidate detection.
//
// For languages where the URL is derived from the file path (PHP, Rails,
// Next.js Pages, Next.js App, classic ASP, Sinatra), decl-router grep can't
// find anything. We enumerate the set of files that LOOK like handlers under
// the routing root and treat each as a candidate route. A file only counts as
// "covered" when the agent inventory has it as a sourceFile — otherwise V7
// flags it as a missed candidate handler.

import { promises as fs } from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'target', '.next', 'vendor',
  '__pycache__', '.venv', 'venv', 'out',
]);

// PHP routing root exclusions. Match against any path segment (basename of
// each directory in the relative path) — `vendor` etc. catches both top-level
// and nested vendored deps.
const PHP_FS_SKIP_DIRS = new Set([
  'vendor', 'lib', 'libs', 'includes', 'include', 'config', 'configs',
  'database', 'migrations', 'tests', 'test', 'spec', 'fixtures', 'docs',
  '__tests__',
  // V7-tightening additions: vendored / third-party / DVWA-style include dirs.
  'external', 'third-party', '3rdparty', 'dvwaPage',
]);

const PHP_FS_SKIP_FILENAMES = new Set([
  'bootstrap.php', 'autoload.php', 'config.php', 'phpinfo.php',
]);
const PHP_FS_TEST_FILENAME = /Test\.php$/i;

// Basename-shape exclusions: library/helper/util/common/bootstrap style files
// are rarely top-level routes. Matches anywhere in the basename minus `.php`.
// `recaptchalib.php` → `recaptchalib` → matches `/lib(rary)?\b/i` via `lib`.
const PHP_FS_SKIP_BASENAME_PATTERNS: RegExp[] = [
  /\blib(rary)?\b/i,
  /lib$/i,           // recaptchalib, jslib, mylib — trailing "lib" segment
  /\bhelpers?\b/i,
  /\butils?\b/i,
  /\bcommon\b/i,
  /\bbootstrap\b/i,
];

// Difficulty-level sibling collapse vocab. DVWA puts per-difficulty
// implementations at `<module>/source/{low,medium,high,impossible}.php`;
// the real route is the sibling `index.php`. Generalized across languages.
const VARIANT_PARENT_RE = /^(sources?|levels?|difficulty|difficulties|variants?|examples?)$/i;
const VARIANT_BASENAME_TOKEN_RE =
  /^(low|medium|high|impossible|easy|hard|simple|advanced|safe|unsafe|vulnerable|fixed|insecure|secure|v\d+)$/i;
const VARIANT_INDEX_EXTS = ['.php', '.html', '.htm'];

const NEXT_PAGES_SPECIAL = new Set(['_app', '_document', '_error', '404', '500']);
const RAILS_CONTROLLER_PATH = /\/app\/controllers\/.+_controller\.rb$/;
const SINATRA_BASE_RE = /\bclass\s+\w+\s*<\s*Sinatra::Base\b/;
const ASP_EXTS = new Set(['.asp', '.aspx', '.ashx']);

const ALL_EXTS = new Set<string>([
  '.php', '.rb', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.asp', '.aspx', '.ashx',
]);

// Next App / Astro / SvelteKit / Nuxt route files expose handlers via these
// exact export shapes. Conservative — does not match arbitrary exports.
const ROUTE_EXPORT_RE =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b|\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*=/;

export interface FilesystemHandlerCandidate {
  file: string;
  framework:
    | 'php' | 'next-pages' | 'next-app' | 'rails' | 'sinatra' | 'asp'
    | 'astro' | 'sveltekit' | 'nuxt';
  // Sibling variant paths collapsed into this candidate (e.g. DVWA
  // `source/{low,medium,high}.php`). Absent when nothing was collapsed.
  variants?: string[];
}

async function listSourceFiles(repoDir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string): Promise<void> {
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
          if (ALL_EXTS.has(path.extname(ent.name).toLowerCase())) {
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

/**
 * Strip PHP comments (`/* … *\/`, `// …`, `# …`) and string literals from a
 * source body. The goal is shape analysis only — keep brace/paren structure
 * intact, just neutralize content that could trip handler-signal regexes
 * (e.g. `// echo $_GET['x']`). String literals are collapsed to empty
 * delimiters so brace counting still works.
 */
export function stripPhpCommentsAndStrings(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    const next = i + 1 < n ? src[i + 1]! : '';
    // /* ... */
    if (c === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      out += ' ';
      continue;
    }
    // // ...\n
    if (c === '/' && next === '/') {
      const end = src.indexOf('\n', i + 2);
      i = end === -1 ? n : end; // keep the \n so line counts and brace-depth lines stay aligned
      out += ' ';
      continue;
    }
    // # ...\n  (PHP shell-style comment)
    if (c === '#') {
      const end = src.indexOf('\n', i + 1);
      i = end === -1 ? n : end;
      out += ' ';
      continue;
    }
    // "..." or '...'  — preserve length-ish + newlines, drop content
    if (c === '"' || c === "'") {
      const quote = c;
      out += quote;
      i++;
      while (i < n) {
        const ci = src[i]!;
        if (ci === '\\' && i + 1 < n) { i += 2; continue; }
        if (ci === quote) { out += quote; i++; break; }
        if (ci === '\n') { out += '\n'; }
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// Signals that a chunk of code reads the request or writes a response — the
// shape of a handler body. We test these against TOP-LEVEL (depth 0) code only.
const HANDLER_SIGNAL_RES: RegExp[] = [
  /\becho\b/,
  /\bprint\b/,
  /<\?=/,
  /<html/i,
  /<form/i,
  /<\/html>/i,
  /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/,
  /\bheader\s*\(/,
];

/**
 * Positive predicate: a PHP file is a handler iff there is at least one
 * statement carrying a handler signal that is NOT enclosed by a `function`,
 * `class`, `interface`, or `trait` body. Output signals: echo/print/<?=/
 * header(/raw HTML. Request-read signals: $_GET/$_POST/…
 *
 * Library files (recaptchalib.php, helpers) put all their handler-shape calls
 * inside function bodies; they should be excluded. Class-only files put them
 * inside method bodies; also excluded.
 *
 * Implementation: strip comments+strings, then walk char-by-char tracking a
 * brace stack. A signal counts when there is no `function`/`class` frame on
 * the stack at that point. `if (...) { echo … }` at top-level still counts
 * because the `if` frame is `other` — the disqualifier is enclosure by a
 * function/class, not enclosure by any block.
 */
export function isPhpHandler(src: string): boolean {
  const stripped = stripPhpCommentsAndStrings(src);

  type StackFrame = { kind: 'function' | 'class' | 'other' };
  const stack: StackFrame[] = [];
  // We collect text that lives OUTSIDE any function/class frame and test it
  // for handler signals. `if`/`for`/`while`/`switch` blocks still count as
  // "outside" — they're top-level executable scaffolding.
  let executableTop = '';
  let i = 0;
  const len = stripped.length;

  function inFunctionOrClassScope(): boolean {
    for (const f of stack) {
      if (f.kind === 'function' || f.kind === 'class') return true;
    }
    return false;
  }

  while (i < len) {
    const c = stripped[i]!;

    if (c === '{') {
      // Determine the kind of this brace by looking back at the small window
      // ending at the `{`. PHP signatures for functions/classes always have
      // the keyword on the same statement as the opening brace (no semicolons
      // between).
      const back = stripped.slice(Math.max(0, i - 256), i);
      let kind: StackFrame['kind'] = 'other';
      if (/\bfunction\b[^{};]*$/.test(back)) kind = 'function';
      else if (/\b(class|interface|trait)\b[^{};]*$/.test(back)) kind = 'class';
      stack.push({ kind });
      i++;
      continue;
    }
    if (c === '}') {
      stack.pop();
      i++;
      continue;
    }

    if (!inFunctionOrClassScope()) {
      executableTop += c;
    }
    i++;
  }

  for (const re of HANDLER_SIGNAL_RES) {
    if (re.test(executableTop)) return true;
  }
  return false;
}

// Educational source-view exclusion. DVWA-style training apps ship the raw
// vulnerable implementation at `vulnerabilities/<class>/source/<level>.<ext>`
// for in-page display via `include` — these files are NOT entry points and
// must never reach Pass-3 policy emission (D-1: looks-tight-but-loose).
// Conservative: only the exact level vocabulary the convention uses, only
// directly under a `source/` segment. When in doubt, exclude — false-positive
// endpoints are worse than missed endpoints.
const EDUCATIONAL_SOURCE_VIEW_RE =
  /(^|\/)source\/(low|medium|high|impossible|info)\.(php|js|ts|py)$/i;

/**
 * True when `relPosix` is an educational source-view file (e.g. DVWA's
 * `vulnerabilities/sqli/source/low.php`). Such files are rendered inside
 * other pages via `include` rather than served as endpoints; treating them
 * as endpoints emits meaningless policies (D-1).
 *
 * Mirrors `shouldSkipPhpPath` in style: centralized so the inventory filter
 * and tests can probe the exact rule without re-deriving it.
 */
export function isEducationalSourceViewPath(relPosix: string): boolean {
  return EDUCATIONAL_SOURCE_VIEW_RE.test(relPosix);
}

/**
 * Apply PHP-path-specific exclusions for V7 candidate detection. Centralized
 * so passes/tests can probe the exact rule set without re-deriving it.
 *
 * Returns true when the file should be SKIPPED (i.e. not treated as a
 * candidate handler).
 */
export function shouldSkipPhpPath(relPosix: string): boolean {
  const base = path.basename(relPosix);
  const baseNoExt = base.replace(/\.php$/i, '');
  const segments = relPosix.split('/');

  if (PHP_FS_SKIP_FILENAMES.has(base)) return true;
  if (PHP_FS_TEST_FILENAME.test(base)) return true;
  if (segments.some((s) => PHP_FS_SKIP_DIRS.has(s))) return true;
  if (isEducationalSourceViewPath(relPosix)) return true;
  for (const re of PHP_FS_SKIP_BASENAME_PATTERNS) {
    if (re.test(baseNoExt)) return true;
  }
  return false;
}

function basenameNoExt(base: string): string {
  const dot = base.lastIndexOf('.');
  return dot === -1 ? base : base.slice(0, dot);
}

// A group (same parent dir) collapses iff parent name hits VARIANT_PARENT_RE
// AND ≥2 sibling basenames hit VARIANT_BASENAME_TOKEN_RE. Prefer a sibling
// `index.{php,html,htm}` one level up; else first variant alphabetically.
// Dropped paths are recorded on the kept candidate's `variants` field.
export function collapseSourceVariants<
  T extends { file: string; variants?: string[] },
>(candidates: T[]): T[] {
  if (candidates.length === 0) return candidates;

  const byParent = new Map<string, T[]>();
  for (const c of candidates) {
    const segments = c.file.split('/');
    if (segments.length < 2) continue;
    const parentDir = segments.slice(0, -1).join('/');
    const arr = byParent.get(parentDir) ?? [];
    arr.push(c);
    byParent.set(parentDir, arr);
  }

  const byPath = new Map<string, T>();
  for (const c of candidates) byPath.set(c.file, c);

  const dropped = new Set<string>();
  const variantsByKept = new Map<string, string[]>();

  for (const [parentDir, group] of byParent) {
    const parentSegments = parentDir.split('/');
    const parentBase = parentSegments[parentSegments.length - 1] ?? '';
    if (!VARIANT_PARENT_RE.test(parentBase)) continue;

    const variantMembers = group.filter((c) => {
      const base = c.file.split('/').pop()!;
      return VARIANT_BASENAME_TOKEN_RE.test(basenameNoExt(base));
    });
    if (variantMembers.length < 2) continue;

    variantMembers.sort((a, b) => a.file.localeCompare(b.file));

    const grandparent = parentSegments.slice(0, -1).join('/');
    let indexHit: T | undefined;
    for (const ext of VARIANT_INDEX_EXTS) {
      const candidatePath = grandparent
        ? `${grandparent}/index${ext}`
        : `index${ext}`;
      const hit = byPath.get(candidatePath);
      if (hit) { indexHit = hit; break; }
    }

    const kept = indexHit ?? variantMembers[0]!;
    const droppedHere = variantMembers
      .filter((c) => c.file !== kept.file)
      .map((c) => c.file);

    for (const d of droppedHere) dropped.add(d);
    const existing = variantsByKept.get(kept.file) ?? [];
    variantsByKept.set(kept.file, [...existing, ...droppedHere]);
  }

  const out: T[] = [];
  for (const c of candidates) {
    if (dropped.has(c.file)) continue;
    const droppedFor = variantsByKept.get(c.file);
    if (droppedFor && droppedFor.length > 0) {
      const merged = [...(c.variants ?? []), ...droppedFor].sort();
      out.push({ ...c, variants: merged });
    } else {
      out.push(c);
    }
  }
  return out;
}

export function isNextAppRouterHandler(relPosix: string, content: string): boolean {
  const segs = relPosix.split('/');
  if (segs[0] !== 'app') return false;
  if (segs.some((s) => /^\(.*\)$/.test(s) || s.startsWith('_'))) return false;
  if (!/^route\.(tsx?|jsx?|mjs)$/.test(segs.at(-1) ?? '')) return false;
  return ROUTE_EXPORT_RE.test(content);
}

export function isAstroEndpoint(relPosix: string, content: string): boolean {
  const segs = relPosix.split('/');
  if (segs[0] !== 'src' || segs[1] !== 'pages') return false;
  if (segs.some((s) => s.startsWith('_'))) return false;
  if (!/\.(ts|js|mjs)$/i.test(segs.at(-1) ?? '')) return false;
  return ROUTE_EXPORT_RE.test(content);
}

export function isSvelteKitEndpoint(relPosix: string, content: string): boolean {
  const segs = relPosix.split('/');
  if (segs[0] !== 'src' || segs[1] !== 'routes') return false;
  if (!/^\+server\.(ts|js)$/i.test(segs.at(-1) ?? '')) return false;
  return ROUTE_EXPORT_RE.test(content);
}

export function isNuxtServerHandler(relPosix: string, content: string): boolean {
  const segs = relPosix.split('/');
  if (segs[0] !== 'server') return false;
  if (segs[1] !== 'api' && segs[1] !== 'routes') return false;
  if (!/\.(ts|js|mjs)$/i.test(segs.at(-1) ?? '')) return false;
  return /\bdefineEventHandler\s*\(/.test(content);
}

async function readSrc(abs: string): Promise<string> {
  try { return await fs.readFile(abs, 'utf8'); } catch { return ''; }
}

export async function detectFilesystemHandlerCandidates(
  repoDir: string,
): Promise<FilesystemHandlerCandidate[]> {
  const out: FilesystemHandlerCandidate[] = [];
  const files = await listSourceFiles(repoDir);

  for (const abs of files) {
    const rel = path.relative(repoDir, abs);
    const relPosix = rel.split(path.sep).join('/');
    const ext = path.extname(rel).toLowerCase();
    const base = path.basename(rel);
    const segments = relPosix.split('/');

    if (ext === '.php') {
      if (shouldSkipPhpPath(relPosix)) continue;
      const src = await readSrc(abs);
      if (!src || !isPhpHandler(src)) continue;
      out.push({ file: relPosix, framework: 'php' });
      continue;
    }

    const isJsLike =
      ext === '.ts' || ext === '.tsx' || ext === '.js' ||
      ext === '.jsx' || ext === '.mjs';

    if (isJsLike && segments[0] === 'pages' && segments[1] === 'api') {
      if (segments.some((s) => s.startsWith('_'))) continue;
      out.push({ file: relPosix, framework: 'next-pages' });
      continue;
    }

    if (isJsLike && segments[0] === 'pages') {
      const nameNoExt = base.replace(/\.(tsx?|jsx?|mjs)$/, '');
      if (NEXT_PAGES_SPECIAL.has(nameNoExt)) continue;
      if (segments.some((s) => s.startsWith('_'))) continue;
      out.push({ file: relPosix, framework: 'next-pages' });
      continue;
    }

    if (isJsLike && segments[0] === 'app') {
      const src = await readSrc(abs);
      if (isNextAppRouterHandler(relPosix, src)) {
        out.push({ file: relPosix, framework: 'next-app' });
        continue;
      }
      // Legacy `page.{ts,tsx,js,jsx,mjs}` — App Router pages are URL surfaces
      // even though they don't export HTTP-method handlers.
      const nameNoExt = base.replace(/\.(tsx?|jsx?|mjs)$/, '');
      const groupOrUnderscore = segments.some(
        (s) => /^\(.*\)$/.test(s) || s.startsWith('_'),
      );
      if (nameNoExt === 'page' && !groupOrUnderscore) {
        out.push({ file: relPosix, framework: 'next-app' });
      }
      continue;
    }

    if (isJsLike && segments[0] === 'src' && segments[1] === 'pages') {
      const src = await readSrc(abs);
      if (isAstroEndpoint(relPosix, src)) out.push({ file: relPosix, framework: 'astro' });
      continue;
    }
    if (isJsLike && segments[0] === 'src' && segments[1] === 'routes') {
      const src = await readSrc(abs);
      if (isSvelteKitEndpoint(relPosix, src)) out.push({ file: relPosix, framework: 'sveltekit' });
      continue;
    }
    if (isJsLike && segments[0] === 'server') {
      const src = await readSrc(abs);
      if (isNuxtServerHandler(relPosix, src)) out.push({ file: relPosix, framework: 'nuxt' });
      continue;
    }

    if (ext === '.rb') {
      if (RAILS_CONTROLLER_PATH.test('/' + relPosix)) {
        out.push({ file: relPosix, framework: 'rails' });
        continue;
      }
      const src = await readSrc(abs);
      if (src && SINATRA_BASE_RE.test(src)) {
        out.push({ file: relPosix, framework: 'sinatra' });
        continue;
      }
    }

    if (ASP_EXTS.has(ext)) {
      out.push({ file: relPosix, framework: 'asp' });
      continue;
    }
  }

  const collapsed = collapseSourceVariants(out);
  collapsed.sort((a, b) => a.file.localeCompare(b.file));
  return collapsed;
}

/**
 * Extract repo-relative file paths from V7 reasons of the
 * "missed candidate handler: <path>" shape. Used by the inventory
 * remediation pass to feed those paths into the addendum prompt.
 */
export function extractV7MissedCandidateFiles(reasons: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const r of reasons) {
    const m = r.match(/missed candidate handler:\s+(\S+)/);
    if (m && m[1]) {
      const p = m[1].replace(/\s*\(.*$/, '').trim();
      if (!seen.has(p)) {
        seen.add(p);
        out.push(p);
      }
    }
  }
  return out;
}
