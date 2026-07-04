// Auth-context pre-pass. Runs between Pass 2 (profile classification) and
// Pass 3 (per-route policy fan-out). Deterministic — no LLM.
//
// Two extraction modes coexist (apps mix them):
//   1. CHAIN-keyed (Express/FastAPI/Spring/Rails-with-callbacks): the LLM
//      already lifted `authnMiddlewareChain` in Pass 1. We resolve the first
//      symbol's body and key it by chainKeyOf(chain).
//   2. SYMBOL-keyed (DVWA-class PHP, classic Rails, classic MVC): no declared
//      middleware decorators. Auth is an inline call inside the handler body
//      (e.g. `dvwaPageStartup()`). We scan each handler file for known auth-
//      call patterns, resolve each unique symbol, and attribute it back per-
//      route via routeSymbols.
//
// D-1: when no useful snippet can be resolved for a chain or a symbol, the
// entry is omitted — never synthesize a placeholder.
//
// Design rationale: see docs/agentic-partial-fixes-plan.md §4 (chain) and the
// inline-call extension (this file).

import type { AgentTools } from './tool-types.js';
import type { RouteInventoryEntry } from './schema.js';
import { stripPhpCommentsAndStrings } from './verify-fs-routing.js';

export interface AuthContextSnippet {
  /** Canonical chain key — present for chain-keyed snippets, absent for
   *  pure inline-call symbol snippets. */
  chainKey?: string;
  /** Declared middleware chain in source order — present for chain-keyed
   *  snippets, absent for inline-call snippets. */
  chain?: string[];
  /** Symbol whose body we resolved. */
  symbol: string;
  /** Repo-relative file. */
  file: string;
  lineStart: number;
  lineEnd: number;
  /** Up to maxSnippetLines lines; may carry a truncation marker. */
  snippet: string;
}

export interface AuthContext {
  /** Chain-keyed map (declared middleware — Express/FastAPI/Spring/Rails). */
  byChain: Map<string, AuthContextSnippet>;
  /** Symbol-keyed map (inline-call apps — PHP/Rails/classic MVC). */
  bySymbol: Map<string, AuthContextSnippet>;
  /** Per-route mapping: endpointId → inline auth symbols detected in its handler. */
  routeSymbols: Map<string, string[]>;
}

export interface BuildAuthContextOptions {
  inventory: RouteInventoryEntry[];
  tools: AgentTools;
  /** Repo dir — accepted for API symmetry; tools are already root-bound. */
  repoDir: string;
  /** Cap the number of unique chains resolved. Default 8. */
  maxChains?: number;
  /** Cap the number of unique inline-call symbols resolved. Default 12. */
  maxSymbols?: number;
  /** Cap each snippet's line count. Default 60. */
  maxSnippetLines?: number;
  /** Aggregate byte cap across all snippets (chain + symbol). Default 20_000. */
  maxTotalBytes?: number;
}

const DEFAULT_MAX_CHAINS = 8;
const DEFAULT_MAX_SYMBOLS = 12;
const DEFAULT_MAX_SNIPPET_LINES = 60;
const DEFAULT_MAX_TOTAL_BYTES = 20_000;

/** Canonical chain-key — sole authoritative form used by all callers. */
export function chainKeyOf(chain: readonly string[] | undefined): string {
  return JSON.stringify(chain ?? []);
}

function endpointIdOf(r: RouteInventoryEntry): string {
  return `${r.method} ${r.path}`;
}

// ---------------------------------------------------------------------------
// Inline-call detection
// ---------------------------------------------------------------------------

/**
 * Regex set matching auth-check call sites in handler bodies. Each entry's
 * first non-undefined capture group is the called symbol that we'll resolve
 * via find_definition. The bare `auth()` form is intentionally NOT included
 * — its false-positive rate (e.g. `auth.user`, `dispatchAuth()`) is too high
 * to justify in the initial version.
 */
const AUTH_CALL_PATTERNS: RegExp[] = [
  // PHP: dvwaPageStartup, fooPageStartup, require_login, check_auth,
  // enforce_auth, authenticate, authenticate_user, is_logged_in, verify_login.
  /\b(\w*[Pp]age[Ss]tartup|require_(?:login|auth|admin|user)|check_(?:auth|login|admin|user|session)|enforce_(?:auth|login)|authenticate(?:_user)?|is_logged_in|verify_login)\s*\(/g,
  // PHP class-style: Auth::check / Auth::user / Auth::guard / ...
  /\b(Auth::(?:check|user|guard|attempt|guest|id))\s*\(/g,
  // Rails: before_action :require_login (capture the action symbol)
  /\bbefore_action\s+:(\w*(?:auth|login|signin|admin)\w*|require_\w+|verify_\w+)\b/g,
  // Rails: authenticate_user!, require_login, require_admin called inline
  /\b(authenticate_(?:user|admin)!|require_(?:login|admin|auth|signin))\b/g,
];

const PER_FILE_SYMBOL_CAP = 10;

/**
 * Strip comments / string literals (PHP-style — works well enough for Ruby
 * too) then match all auth-call patterns. Returns the unique symbols in
 * first-seen order, capped at PER_FILE_SYMBOL_CAP.
 */
export function detectInlineAuthCalls(content: string): string[] {
  const stripped = stripPhpCommentsAndStrings(content);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const re of AUTH_CALL_PATTERNS) {
    // Each regex has the `g` flag; reset lastIndex defensively.
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(stripped)) !== null) {
      // Pick the first non-undefined captured group.
      const sym = m.slice(1).find((g) => typeof g === 'string' && g.length > 0);
      if (!sym) continue;
      if (seen.has(sym)) continue;
      seen.add(sym);
      out.push(sym);
      if (out.length >= PER_FILE_SYMBOL_CAP) return out;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

const VENDOR_PATH_RE = /(^|\/)(node_modules|vendor|third[-_]?party|3rdparty|dist|build|coverage|\.git)\//;
const TEST_PATH_RE = /(^|\/)(tests?|spec|__tests__|fixtures?|__pycache__)\//;
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

async function resolveSymbolDefinition(
  symbol: string,
  tools: AgentTools,
): Promise<{ file: string; line: number } | undefined> {
  // find_definition requires a valid identifier shape.
  if (!IDENT_RE.test(symbol)) return undefined;
  try {
    const hits = await tools.find_definition(symbol);
    if (hits[0]) return { file: hits[0].file, line: hits[0].line };
  } catch {
    // fall through
  }
  return grepDefinitionFallback(symbol, tools);
}

/**
 * Best-effort definition lookup when find_definition (JS/TS/Py/Go/JVM-only)
 * returns no hits. Greps for the common definition syntaxes used by PHP,
 * Ruby, and shell. First non-vendor, non-test hit wins.
 */
async function grepDefinitionFallback(
  symbol: string,
  tools: AgentTools,
): Promise<{ file: string; line: number } | undefined> {
  const escaped = escapeRegexLiteral(symbol);
  const patterns = [
    `function\\s+${escaped}\\s*\\(`,
    `def\\s+${escaped}\\b`,
    `${escaped}\\s*=\\s*function`,
    `${escaped}\\s*\\(\\)\\s*\\{`,
  ];
  for (const pattern of patterns) {
    let hits;
    try {
      hits = await tools.grep(pattern, { maxResults: 20 });
    } catch {
      continue;
    }
    for (const h of hits) {
      if (VENDOR_PATH_RE.test(h.file)) continue;
      if (TEST_PATH_RE.test(h.file)) continue;
      return { file: h.file, line: h.line };
    }
  }
  return undefined;
}

async function readSnippet(
  hit: { file: string; line: number },
  tools: AgentTools,
  maxSnippetLines: number,
): Promise<{ file: string; lineStart: number; lineEnd: number; snippet: string } | null> {
  const startLine = Math.max(1, hit.line);
  const endLine = startLine + maxSnippetLines - 1;
  let read;
  try {
    read = await tools.read_file(hit.file, startLine, endLine);
  } catch {
    return null;
  }
  if (!read.content || read.content.length === 0) return null;
  const lineCount = read.content.split('\n').length;
  let snippet = read.content;
  if (lineCount >= maxSnippetLines) {
    snippet += `\n// ... (function body may continue past line ${read.lineEnd}; truncated)`;
  }
  return {
    file: read.path,
    lineStart: read.lineStart,
    lineEnd: read.lineEnd,
    snippet,
  };
}

async function resolveChainSnippet(
  chain: string[],
  chainKey: string,
  tools: AgentTools,
  maxSnippetLines: number,
): Promise<AuthContextSnippet | null> {
  const symbol = chain[0];
  if (!symbol) return null;
  const hit = await resolveSymbolDefinition(symbol, tools);
  if (!hit) return null;
  const body = await readSnippet(hit, tools, maxSnippetLines);
  if (!body) return null;
  return {
    chainKey,
    chain,
    symbol,
    file: body.file,
    lineStart: body.lineStart,
    lineEnd: body.lineEnd,
    snippet: body.snippet,
  };
}

async function resolveSymbolSnippet(
  symbol: string,
  tools: AgentTools,
  maxSnippetLines: number,
): Promise<AuthContextSnippet | null> {
  const hit = await resolveSymbolDefinition(symbol, tools);
  if (!hit) return null;
  const body = await readSnippet(hit, tools, maxSnippetLines);
  if (!body) return null;
  return {
    symbol,
    file: body.file,
    lineStart: body.lineStart,
    lineEnd: body.lineEnd,
    snippet: body.snippet,
  };
}

// ---------------------------------------------------------------------------
// Public builders
// ---------------------------------------------------------------------------

/**
 * Build the full auth-context (chain-keyed + symbol-keyed + per-route
 * attribution).
 *
 * Algorithm:
 *   1. CHAIN phase: group routes by chainKey (drop empty bucket), sort desc
 *      by frequency, resolve up to maxChains.
 *   2. INLINE phase: per-route, read the handler file, run
 *      detectInlineAuthCalls; populate routeSymbols. Aggregate unique
 *      symbols across all routes, resolve up to maxSymbols.
 *   3. BYTE CAP: aggregate chain+symbol snippets, drop tail (lowest-priority
 *      = lowest chain frequency / latest-added symbol) until under
 *      maxTotalBytes.
 *
 * D-1: unresolved chains and symbols are dropped — no placeholders.
 */
export async function buildAuthContext(
  opts: BuildAuthContextOptions,
): Promise<AuthContext> {
  const maxChains = opts.maxChains ?? DEFAULT_MAX_CHAINS;
  const maxSymbols = opts.maxSymbols ?? DEFAULT_MAX_SYMBOLS;
  const maxSnippetLines = opts.maxSnippetLines ?? DEFAULT_MAX_SNIPPET_LINES;
  const maxTotalBytes = opts.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;

  // --- 1. CHAIN phase ------------------------------------------------------
  const chainBuckets = new Map<string, { chain: string[]; count: number }>();
  for (const route of opts.inventory) {
    const chain = route.authnMiddlewareChain ?? [];
    if (chain.length === 0) continue;
    const key = chainKeyOf(chain);
    const existing = chainBuckets.get(key);
    if (existing) existing.count++;
    else chainBuckets.set(key, { chain: [...chain], count: 1 });
  }
  const sortedChains = [...chainBuckets.entries()].sort(
    (a, b) => b[1].count - a[1].count,
  );
  const chainCandidates: AuthContextSnippet[] = [];
  for (const [key, { chain }] of sortedChains.slice(0, maxChains)) {
    const snip = await resolveChainSnippet(chain, key, opts.tools, maxSnippetLines);
    if (snip) chainCandidates.push(snip);
  }

  // --- 2. INLINE phase -----------------------------------------------------
  const routeSymbols = new Map<string, string[]>();
  const uniqueSymbolsOrdered: string[] = [];
  const uniqueSymbolSet = new Set<string>();
  // Files we've already read this pass — dedupe across routes that share a
  // handler file.
  const fileCache = new Map<string, string[]>();
  for (const route of opts.inventory) {
    let symbols = fileCache.get(route.sourceFile);
    if (symbols === undefined) {
      let content: string;
      try {
        const read = await opts.tools.read_file(route.sourceFile);
        content = read.content;
      } catch {
        content = '';
      }
      symbols = content ? detectInlineAuthCalls(content) : [];
      fileCache.set(route.sourceFile, symbols);
    }
    if (symbols.length > 0) {
      routeSymbols.set(endpointIdOf(route), [...symbols]);
      for (const s of symbols) {
        if (!uniqueSymbolSet.has(s)) {
          uniqueSymbolSet.add(s);
          uniqueSymbolsOrdered.push(s);
        }
      }
    }
  }
  const consideredSymbols = uniqueSymbolsOrdered.slice(0, maxSymbols);
  const symbolCandidates: AuthContextSnippet[] = [];
  for (const sym of consideredSymbols) {
    const snip = await resolveSymbolSnippet(sym, opts.tools, maxSnippetLines);
    if (snip) symbolCandidates.push(snip);
  }

  // --- 3. BYTE CAP ---------------------------------------------------------
  // Apply the byte cap across BOTH maps. Chain candidates have priority order
  // (frequency desc) and symbol candidates follow them in discovery order;
  // we admit in that order until the cap is hit, then drop the tail.
  const byChain = new Map<string, AuthContextSnippet>();
  const bySymbol = new Map<string, AuthContextSnippet>();
  let bytesUsed = 0;
  for (const s of chainCandidates) {
    const size = byteLengthOf(s.snippet);
    if (bytesUsed + size > maxTotalBytes) break;
    bytesUsed += size;
    byChain.set(s.chainKey!, s);
  }
  for (const s of symbolCandidates) {
    const size = byteLengthOf(s.snippet);
    if (bytesUsed + size > maxTotalBytes) break;
    bytesUsed += size;
    bySymbol.set(s.symbol, s);
  }

  // routeSymbols carries ALL detected symbols (including unresolved). The
  // per-route lookup at prompt-build time naturally filters to resolved
  // entries via bySymbol.has().
  return { byChain, bySymbol, routeSymbols };
}

/**
 * @deprecated Prefer `buildAuthContext` which also returns the symbol-keyed
 * map and per-route attribution. This shim projects the chain-keyed slice for
 * backwards compatibility with callers that only need the original behavior.
 */
export async function buildAuthContextMap(
  opts: BuildAuthContextOptions,
): Promise<Map<string, AuthContextSnippet>> {
  const ctx = await buildAuthContext(opts);
  return ctx.byChain;
}

function byteLengthOf(s: string): number {
  return Buffer.byteLength(s, 'utf8');
}

function escapeRegexLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
