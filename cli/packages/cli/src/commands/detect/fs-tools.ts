// Read-only, sandbox-scoped filesystem AgentTools for the BYO verbs that drive
// detect-core's deterministic pre-pass (evidence-pack / auth-context). These
// builders take an `AgentTools` instance; the only filesystem implementation in
// the monorepo lives in `packages/llm-agent/src/agentic/tools.ts`, which the BYO
// bundle MUST NOT reach (Rule G-2 — the LLM-free guard hard-fails on any
// llm-agent import). So this is the bundle-safe port: identical safety contract
// (path-escape refusal, symlink refusal, byte caps, ripgrep --no-follow + kill
// timer), node builtins + ripgrep only, zero LLM dependencies.
//
// Kept byte-for-byte behaviorally aligned with llm-agent's tools.ts so the two
// paths cannot drift in what they expose to the same detect-core builders.

import { promises as fs } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import type {
  AgentTools,
  ListFilesEntry,
  ReadFileResult,
  DefinitionHit,
  ReferenceHit,
} from '@writ/detect-core';

// The grep-hit shape AgentTools.grep returns. detect-core's tool-types declares
// this locally (and the index re-exports a same-named-but-different GrepHit from
// verify-helpers), so we mirror the tool-types shape here to satisfy the
// AgentTools contract without importing the wrong one.
interface GrepHit {
  file: string;
  line: number;
  match: string;
}

export interface CreateToolsOptions {
  /** Per-call byte cap for read_file. Defaults to 64KB, capped at 256KB. */
  readFileMaxBytes?: number;
  /** Per-call timeout for ripgrep invocations. Default 5000ms. */
  ripgrepTimeoutMs?: number;
  /** Default maxResults for grep. */
  grepDefaultMaxResults?: number;
}

const DEFAULT_READ_BYTES = 64 * 1024;
const MAX_READ_BYTES = 256 * 1024;
const DEFAULT_GREP_MAX = 100;
const DEFAULT_RG_TIMEOUT_MS = 5_000;
// Hard ceiling on a single file's size when satisfying a line-range read.
const ABSOLUTE_MAX_FILE_BYTES = 4 * 1024 * 1024;

export class PathEscapeError extends Error {
  constructor(p: string) {
    super(`path escapes sandbox: ${p}`);
    this.name = 'PathEscapeError';
  }
}

export class SymlinkRefusedError extends Error {
  constructor(p: string) {
    super(`refusing to follow symlink: ${p}`);
    this.name = 'SymlinkRefusedError';
  }
}

// Caller MUST pass a real (lstat-verified non-symlink) `root`.
function resolveInside(root: string, userPath: string): string {
  if (typeof userPath !== 'string') {
    throw new PathEscapeError(String(userPath));
  }
  if (path.isAbsolute(userPath)) throw new PathEscapeError(userPath);
  const joined = path.resolve(root, userPath);
  const rootResolved = path.resolve(root);
  const rel = path.relative(rootResolved, joined);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new PathEscapeError(userPath);
  }
  return joined;
}

// Catch a `subdir -> /etc` symlink even when the user-facing path looks innocent.
async function assertNoSymlinkAncestors(root: string, target: string): Promise<void> {
  const rel = path.relative(root, target);
  if (rel === '') return;
  const parts = rel.split(path.sep);
  let cur = root;
  for (const part of parts) {
    cur = path.join(cur, part);
    let st;
    try {
      st = await fs.lstat(cur);
    } catch {
      return;
    }
    if (st.isSymbolicLink()) {
      throw new SymlinkRefusedError(cur);
    }
  }
}

/** Run ripgrep with --no-follow and a hard kill timer. */
async function runRipgrep(
  args: string[],
  cwd: string,
  timeoutMs: number,
): Promise<{ stdout: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn('rg', args, {
      cwd,
      env: { PATH: process.env['PATH'] ?? '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout.on('data', (b: Buffer) => { stdout += b.toString('utf8'); });
    child.stderr.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });

    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (killed) {
        reject(new Error(`ripgrep timed out after ${timeoutMs}ms`));
        return;
      }
      if (code !== 0 && code !== 1) {
        reject(new Error(`ripgrep exited ${code}: ${stderr.slice(0, 200)}`));
        return;
      }
      resolve({ stdout, code });
    });
  });
}

/** Parse `rg --json` stdout into structured hits. */
function parseRipgrepJson(stdout: string): GrepHit[] {
  const hits: GrepHit[] = [];
  for (const rawLine of stdout.split('\n')) {
    if (rawLine.length === 0) continue;
    let rec: unknown;
    try { rec = JSON.parse(rawLine); } catch { continue; }
    if (
      typeof rec !== 'object' || rec === null ||
      (rec as { type?: string }).type !== 'match'
    ) continue;
    const data = (rec as { data: {
      path?: { text?: string };
      line_number?: number;
      lines?: { text?: string };
    } }).data;
    const file = data.path?.text;
    const line = data.line_number;
    const text = data.lines?.text ?? '';
    if (typeof file !== 'string' || typeof line !== 'number') continue;
    hits.push({ file, line, match: text.replace(/\r?\n$/, '') });
  }
  return hits;
}

interface LangPattern { rgType: string; define: string; }

const LANG_PATTERNS: LangPattern[] = [
  { rgType: 'jstsx:*.{js,jsx,ts,tsx,mjs,cjs}', define:
    '(?:function\\s+__SYM__\\b|class\\s+__SYM__\\b|const\\s+__SYM__\\s*=|let\\s+__SYM__\\s*=|var\\s+__SYM__\\s*=|export\\s+(?:default\\s+)?(?:function|class|const|let|var)\\s+__SYM__\\b)' },
  { rgType: 'py:*.py',
    define: '(?:^\\s*def\\s+__SYM__\\b|^\\s*async\\s+def\\s+__SYM__\\b|^\\s*class\\s+__SYM__\\b)' },
  { rgType: 'php:*.{php,phtml,inc}',
    define: '(?:function\\s+__SYM__\\b|class\\s+__SYM__\\b|interface\\s+__SYM__\\b|trait\\s+__SYM__\\b|const\\s+__SYM__\\s*=|public\\s+(?:static\\s+)?function\\s+__SYM__\\b|private\\s+(?:static\\s+)?function\\s+__SYM__\\b|protected\\s+(?:static\\s+)?function\\s+__SYM__\\b)' },
  { rgType: 'rb:*.{rb,rake}',
    define: '(?:^\\s*def\\s+(?:self\\.)?__SYM__\\b|^\\s*class\\s+__SYM__\\b|^\\s*module\\s+__SYM__\\b)' },
  { rgType: 'go:*.go',
    define: '(?:^func\\s+(?:\\([^)]+\\)\\s+)?__SYM__\\b|^type\\s+__SYM__\\b|^var\\s+__SYM__\\b|^const\\s+__SYM__\\b)' },
  { rgType: 'jvm:*.{java,kt,kts}',
    define: '(?:class\\s+__SYM__\\b|interface\\s+__SYM__\\b|fun\\s+__SYM__\\b|(?:public|private|protected|static|final|\\s)+\\w[\\w<>\\[\\],\\s.]*\\s+__SYM__\\s*\\()' },
  { rgType: 'rs:*.rs',
    define: '(?:(?:pub\\s+)?(?:async\\s+)?fn\\s+__SYM__\\b|(?:pub\\s+)?struct\\s+__SYM__\\b|(?:pub\\s+)?enum\\s+__SYM__\\b|(?:pub\\s+)?trait\\s+__SYM__\\b|(?:pub\\s+)?const\\s+__SYM__\\b|(?:pub\\s+)?static\\s+__SYM__\\b)' },
  { rgType: 'cs:*.cs',
    define: '(?:class\\s+__SYM__\\b|interface\\s+__SYM__\\b|record\\s+__SYM__\\b|struct\\s+__SYM__\\b|enum\\s+__SYM__\\b|(?:public|private|protected|internal|static|async|virtual|override|sealed|\\s)+\\w[\\w<>\\[\\],\\s.?]*\\s+__SYM__\\s*\\()' },
  { rgType: 'ex:*.{ex,exs}',
    define: '(?:^\\s*def(?:p|macro|macrop)?\\s+__SYM__\\b|^\\s*defmodule\\s+__SYM__\\b|^\\s*defprotocol\\s+__SYM__\\b)' },
];

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const SYMBOL_RE = /^[$]?[A-Za-z_][A-Za-z0-9_]*[?!]?$/;

function langByPrefix(prefix: string): LangPattern {
  const found = LANG_PATTERNS.find((l) => l.rgType.startsWith(`${prefix}:`));
  if (!found) throw new Error(`langByPrefix: unknown prefix ${prefix}`);
  return found;
}

function langPatternsForHint(hintFile?: string): LangPattern[] {
  if (!hintFile) return LANG_PATTERNS;
  const ext = path.extname(hintFile).toLowerCase();
  switch (ext) {
    case '.js': case '.jsx': case '.ts': case '.tsx': case '.mjs': case '.cjs':
      return [langByPrefix('jstsx')];
    case '.py':
      return [langByPrefix('py')];
    case '.php': case '.phtml': case '.inc':
      return [langByPrefix('php')];
    case '.rb': case '.rake':
      return [langByPrefix('rb')];
    case '.go':
      return [langByPrefix('go')];
    case '.java': case '.kt': case '.kts':
      return [langByPrefix('jvm')];
    case '.rs':
      return [langByPrefix('rs')];
    case '.cs':
      return [langByPrefix('cs')];
    case '.ex': case '.exs':
      return [langByPrefix('ex')];
    default:
      return LANG_PATTERNS;
  }
}

class FsAgentTools implements AgentTools {
  constructor(
    private readonly root: string,
    private readonly readBytes: number,
    private readonly rgTimeoutMs: number,
    private readonly grepDefaultMax: number,
  ) {}

  async list_files(p: string): Promise<ListFilesEntry[]> {
    const target = p === '' || p === '.' ? this.root : resolveInside(this.root, p);
    await assertNoSymlinkAncestors(this.root, target);
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fs.readdir(target, { withFileTypes: true });
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return [];
      throw err;
    }
    const out: ListFilesEntry[] = [];
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) out.push({ name: e.name, type: 'dir' });
      else if (e.isFile()) out.push({ name: e.name, type: 'file' });
    }
    out.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }

  async read_file(
    p: string,
    lineStart?: number,
    lineEnd?: number,
  ): Promise<ReadFileResult> {
    const target = resolveInside(this.root, p);
    await assertNoSymlinkAncestors(this.root, target);
    const st = await fs.lstat(target);
    if (st.isSymbolicLink()) throw new SymlinkRefusedError(target);
    if (!st.isFile()) {
      throw new Error(`not a regular file: ${p}`);
    }
    if (st.size > ABSOLUTE_MAX_FILE_BYTES) {
      throw new Error(
        `read_file: ${p} is ${st.size} bytes, exceeds hard cap ${ABSOLUTE_MAX_FILE_BYTES}`,
      );
    }

    const relPath = path.relative(this.root, target);
    const wantRange = lineStart !== undefined || lineEnd !== undefined;

    if (!wantRange) {
      const buf = await fs.readFile(target);
      const truncated = buf.byteLength > this.readBytes;
      const slice = truncated ? buf.subarray(0, this.readBytes) : buf;
      const text = slice.toString('utf8');
      const lines = text.split('\n').length;
      return {
        path: relPath,
        lineStart: 1,
        lineEnd: lines,
        content: text,
        truncated,
      };
    }

    const fullText = (await fs.readFile(target)).toString('utf8');
    const allLines = fullText.split('\n');
    const totalLines = allLines.length;

    const reqStart = Math.max(1, lineStart ?? 1);
    if (reqStart > totalLines) {
      return {
        path: relPath,
        lineStart: reqStart,
        lineEnd: reqStart - 1,
        content: '',
        truncated: true,
        outOfRange: true,
        totalLines,
      };
    }

    const reqEnd = Math.min(totalLines, lineEnd ?? totalLines);
    const sliceLines = allLines.slice(reqStart - 1, reqEnd);
    const joined = sliceLines.join('\n');
    const sliceBytes = Buffer.byteLength(joined, 'utf8');

    if (sliceBytes <= this.readBytes) {
      return {
        path: relPath,
        lineStart: reqStart,
        lineEnd: reqEnd,
        content: joined,
        truncated: false,
        totalLines,
      };
    }

    let acc = '';
    let lastLine = reqStart - 1;
    for (let i = 0; i < sliceLines.length; i++) {
      const candidate = i === 0 ? sliceLines[i]! : acc + '\n' + sliceLines[i]!;
      if (Buffer.byteLength(candidate, 'utf8') > this.readBytes) break;
      acc = candidate;
      lastLine = reqStart + i;
    }
    return {
      path: relPath,
      lineStart: reqStart,
      lineEnd: reqEnd,
      content: acc,
      truncated: true,
      clippedAtLine: lastLine,
      totalLines,
    };
  }

  async grep(
    pattern: string,
    options: {
      paths?: string[];
      ignoreCase?: boolean;
      maxResults?: number;
    } = {},
  ): Promise<GrepHit[]> {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      throw new Error('grep: pattern is required');
    }
    const maxResults = options.maxResults ?? this.grepDefaultMax;
    const args = [
      '--json',
      '--no-follow',
      '--max-count', String(maxResults),
      '--max-columns', '1000',
    ];
    if (options.ignoreCase) args.push('-i');
    args.push('-e', pattern);

    if (options.paths && options.paths.length > 0) {
      for (const userPath of options.paths) {
        const abs = resolveInside(this.root, userPath);
        await assertNoSymlinkAncestors(this.root, abs);
        args.push(path.relative(this.root, abs) || '.');
      }
    } else {
      args.push('.');
    }

    const { stdout } = await runRipgrep(args, this.root, this.rgTimeoutMs);
    const hits = parseRipgrepJson(stdout);
    if (hits.length > maxResults) hits.length = maxResults;
    return hits;
  }

  async find_definition(symbol: string, hintFile?: string): Promise<DefinitionHit[]> {
    if (!SYMBOL_RE.test(symbol)) {
      throw new Error(`find_definition: invalid symbol "${symbol}"`);
    }
    const phpVar = symbol.startsWith('$');
    const bare = phpVar ? symbol.slice(1) : symbol;
    const esc = escapeRegex(bare);
    const endsWithNonWord = /[?!]$/.test(bare);
    const langs = phpVar
      ? [langByPrefix('php')]
      : langPatternsForHint(hintFile);
    const out: DefinitionHit[] = [];
    for (const lang of langs) {
      const template = endsWithNonWord
        ? lang.define.replaceAll('__SYM__\\b', '__SYM__')
        : lang.define;
      const pattern = template.replaceAll('__SYM__', esc);
      const args = [
        '--json',
        '--no-follow',
        '--max-columns', '1000',
        '--type-add', lang.rgType,
        '--type', lang.rgType.split(':')[0]!,
        '-e', pattern,
        '.',
      ];
      let stdout: string;
      try {
        ({ stdout } = await runRipgrep(args, this.root, this.rgTimeoutMs));
      } catch (err) {
        if ((err as Error).message.includes('timed out')) throw err;
        continue;
      }
      for (const h of parseRipgrepJson(stdout)) {
        out.push({ file: h.file, line: h.line, preview: h.match });
      }
    }
    return out;
  }

  async find_references(symbol: string, hintFile?: string): Promise<ReferenceHit[]> {
    if (!SYMBOL_RE.test(symbol)) {
      throw new Error(`find_references: invalid symbol "${symbol}"`);
    }
    const phpVar = symbol.startsWith('$');
    const bare = phpVar ? symbol.slice(1) : symbol;
    const endsWithNonWord = /[?!]$/.test(bare);
    const pattern = endsWithNonWord
      ? `\\b${escapeRegex(bare)}`
      : `\\b${escapeRegex(bare)}\\b`;
    const langs = phpVar
      ? [langByPrefix('php')]
      : langPatternsForHint(hintFile);
    const types = langs.map((l) => l.rgType);
    const args: string[] = [
      '--json',
      '--no-follow',
      '--max-columns', '1000',
    ];
    for (const t of types) {
      args.push('--type-add', t);
    }
    for (const t of types) {
      args.push('--type', t.split(':')[0]!);
    }
    args.push('-e', pattern, '.');
    const { stdout } = await runRipgrep(args, this.root, this.rgTimeoutMs);
    return parseRipgrepJson(stdout).map((h) => ({
      file: h.file,
      line: h.line,
      context: h.match,
    }));
  }
}

// The directory itself is lstat-checked once at factory time so the downstream
// ancestor check has a non-symlink anchor to start from.
export async function createTools(
  repoDir: string,
  opts: CreateToolsOptions = {},
): Promise<AgentTools> {
  const rootResolved = path.resolve(repoDir);
  const st = await fs.lstat(rootResolved);
  if (st.isSymbolicLink()) throw new SymlinkRefusedError(rootResolved);
  if (!st.isDirectory()) throw new Error(`createTools: not a directory: ${repoDir}`);

  const readBytes = Math.min(
    MAX_READ_BYTES,
    Math.max(1, opts.readFileMaxBytes ?? DEFAULT_READ_BYTES),
  );
  const rgTimeoutMs = opts.ripgrepTimeoutMs ?? DEFAULT_RG_TIMEOUT_MS;
  const grepMax = opts.grepDefaultMaxResults ?? DEFAULT_GREP_MAX;

  return new FsAgentTools(rootResolved, readBytes, rgTimeoutMs, grepMax);
}
