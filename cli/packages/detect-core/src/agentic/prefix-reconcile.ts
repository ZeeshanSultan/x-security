// Deterministic, injection-safe MOUNT-PREFIX RECONCILIATION for the inventory pass.
//
// Root cause (Laravel vapi): the deterministic extractor resolves the real mount
// prefix from parsed code (RouteServiceProvider `Route::prefix('vapi')`) and emits
// `/vapi/...`. The LLM, ignoring the untrusted-fenced seed, emits the Laravel-
// default `/api/...`. The route the LLM found is REAL — it read the controller and
// cited file:line — but its BASE PATH is wrong. v7 then can't match it against the
// extractor denominator, so recall collapses.
//
// Fix: after the inventory pass, deterministically rewrite an LLM route's path to
// the extractor's resolved prefix WHEN they match modulo a leading mount prefix and
// the match is UNAMBIGUOUS. The extractor's prefix is machine-derived from parsed
// code, NOT attacker-controlled, so this is a machine-to-machine correction — no
// trust is granted to LLM/raw-seed text (injection-safe per Rule D-1).
//
// Conservative by construction (Rule D-1): we only rewrite on an UNAMBIGUOUS match.
// Zero or multiple extractor candidates for a given tail → leave the LLM's path as-is
// and let v7 flag it. No guessing, no silent best-effort.

import { normPath } from '../frameworks/dedupe.js';
import type { ExtractedRoute } from '../frameworks/index.js';
import type { RouteInventoryEntry } from './schema.js';

export interface PrefixRewrite {
  from: string;
  to: string;
}

export interface ReconcileResult {
  inventory: RouteInventoryEntry[];
  rewrites: PrefixRewrite[];
}

/** Split a canonical path into its non-empty segments (leading/trailing slashes
 * dropped). `/vapi/api1/user/:id` → `['vapi','api1','user',':id']`. */
function segments(p: string): string[] {
  return p.split('/').filter((s) => s.length > 0);
}

/**
 * All "tails" of a segmented path produced by stripping 1..k leading segments,
 * keyed back to a canonical leading-slash path, LONGEST FIRST. For
 * `/api/api1/user/:id` this yields `/api1/user/:id`, `/user/:id`, `/:id`. We do
 * NOT include the full path (k=0) — the full-path case is handled by the
 * exact-match index, and including it here would let a route match itself with a
 * zero-length prefix.
 *
 * Both the LLM's path and the extractor's path may carry a (different) leading
 * mount prefix, so reconciliation matches on a shared SUFFIX: we strip leading
 * segments from BOTH sides and look for a common tail. Longest-first keeps the
 * match maximally specific (strip the fewest segments), which is the conservative
 * choice — we never strip more than we must to find an unambiguous match.
 */
function leadingStrippedTails(canon: string): string[] {
  const segs = segments(canon);
  const tails: string[] = [];
  for (let k = 1; k < segs.length; k++) {
    tails.push('/' + segs.slice(k).join('/'));
  }
  return tails;
}

function isOpaqueOperationPath(p: string): boolean {
  return p.includes('#') || p.startsWith('xmlrpc://');
}

/**
 * Reconcile LLM-inventory route paths to the extractor's machine-derived mount
 * prefix.
 *
 * Algorithm (DETERMINISTIC):
 *   1. Index extracted routes by `(method, normPath(path))` (exact) and build a
 *      per-method tail index mapping each leading-stripped tail → the set of
 *      extracted canonical paths that produce it.
 *   2. For each inventory entry: if its `(method, normPath(path))` already matches
 *      an extracted route → leave as-is (the LLM's base path is already correct).
 *   3. Else, walk the inventory path's OWN leading-stripped tails longest-first.
 *      For the first tail that maps to EXACTLY ONE extracted route → REWRITE the
 *      entry's `path` to that extracted canonical path. Record the rewrite.
 *      Longest-first means we strip the fewest leading segments needed to find a
 *      shared suffix (so `/api/api1/user/:id` vs `/vapi/api1/user/:id` matches on
 *      `/api1/user/:id`, stripping just `/api` ⇄ `/vapi`).
 *   4. If the first non-empty tail bucket is AMBIGUOUS (maps to >1 extracted
 *      route) → stop and DO NOT rewrite. Falling through to shorter, more
 *      aggressively-stripped tails would be guessing. If NO tail matches at all →
 *      leave the path. Either way v7 flags it.
 *
 * Only `path` changes. The LLM's citation (sourceFile:sourceLine), schema refs,
 * auth chain, and every other field are preserved — the route is real; we are
 * only correcting its base path to the machine-derived truth.
 */
export function reconcileMountPrefix(
  inventory: RouteInventoryEntry[],
  extracted: ExtractedRoute[],
): ReconcileResult {
  // Exact (method, canon-path) set — already-correct routes short-circuit here.
  const exact = new Set<string>();
  // method → (tail canon-path → set of full extracted canon-paths).
  const tailIndex = new Map<string, Map<string, Set<string>>>();

  for (const r of extracted) {
    if (isOpaqueOperationPath(r.path)) continue;
    const method = r.method.toUpperCase();
    const canon = normPath(r.path);
    exact.add(`${method} ${canon}`);

    let byTail = tailIndex.get(method);
    if (!byTail) {
      byTail = new Map();
      tailIndex.set(method, byTail);
    }
    for (const tail of leadingStrippedTails(canon)) {
      let set = byTail.get(tail);
      if (!set) {
        set = new Set();
        byTail.set(tail, set);
      }
      set.add(canon);
    }
  }

  const rewrites: PrefixRewrite[] = [];
  const out: RouteInventoryEntry[] = inventory.map((entry) => {
    if (isOpaqueOperationPath(entry.path)) return entry;

    const method = entry.method.toUpperCase();
    const invCanon = normPath(entry.path);

    // (2) Already correct — exact match against the extractor.
    if (exact.has(`${method} ${invCanon}`)) return entry;

    // (3) Walk the inventory path's own tails longest-first; rewrite on the first
    // tail that maps to exactly one extracted route. (4) A multi-candidate tail
    // halts the walk (ambiguous — no guessing).
    const byTail = tailIndex.get(method);
    if (!byTail) return entry;

    // Candidate suffixes, longest-first: the inventory path AS-IS (the LLM emitted
    // the unmounted path with no prefix, e.g. `/api1/user/:id`), then its own
    // leading-stripped tails (the LLM emitted a WRONG prefix, e.g. `/api/...`).
    const invTails = [invCanon, ...leadingStrippedTails(invCanon)];
    for (const tail of invTails) {
      const candidates = byTail.get(tail);
      if (!candidates) continue; // no extracted route shares this suffix; try shorter
      if (candidates.size !== 1) return entry; // ambiguous at this suffix length

      const [to] = [...candidates];
      if (to === undefined || to === invCanon) return entry;
      rewrites.push({ from: entry.path, to });
      return { ...entry, path: to };
    }
    return entry;
  });

  return { inventory: out, rewrites };
}
