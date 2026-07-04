// Recursive source-file walker + skip-set for the route extractor.
//
// SKIP-SET RECONCILIATION DECISION (per Wave-0 plan):
//   The V7 walker `listSourceFiles` / `SKIP_DIRS` in
//   ../agentic/verify-fs-routing.ts is NOT reused here, for two reasons:
//     1. It is module-private (neither the function nor the set is exported),
//        so importing it would require editing that file — out of scope for
//        this wave, and a fork either way.
//     2. It filters to a CODE-only extension set (.php/.rb/.ts/.js/.asp…) with
//        NO Python, and excludes spec files (.yaml/.json) and protocol files
//        (.wsdl/.graphql). The route extractor's Layer-1 (OpenAPI/GraphQL SDL)
//        and protocol layers depend on exactly those file types, so the V7
//        walker would silently drop the inputs this extractor exists to read.
//
//   We therefore port the prototype's broader skip-set
//   (/tmp/route-extractor-proto/extract.py `SKIP_DIRS`) but DELIBERATELY narrow
//   it: the prototype skips `tests`/`test`, `static`, `public`, `assets`,
//   `frontend`, and a one-off `Cert-Generator-master`. A skip-set that drops a
//   real handler directory is a recall regression (Rule D-4), so:
//     - We KEEP the dependency / build / VCS skips (node_modules, vendor, venv,
//       .git, dist, build, __pycache__, site-packages, .idea) — these never
//       contain first-party routes.
//     - We KEEP `migrations` (DB migrations are not routes).
//     - We DROP the one-off `Cert-Generator-master` (corpus-specific noise).
//     - We make `tests`/`test`, `static`/`public`/`assets`, and `frontend`
//       OPTIONAL via the skip-set passed in. The default WalkOptions keeps the
//       prototype behavior (skip them) so golden tests match, but callers that
//       suspect a handler lives under such a dir can widen the walk. This keeps
//       parity-by-default while leaving an explicit escape hatch instead of a
//       silently-too-aggressive prune.
//
//   When Wave 1 finds a corpus repo whose handlers live under a skipped dir,
//   the fix is to narrow DEFAULT_SKIP_DIRS here (with a corpus citation), not to
//   add a per-parser workaround.

import { promises as fs } from 'node:fs';
import path from 'node:path';

/** Directories never walked. Ported from the prototype `SKIP_DIRS`, minus the
 * corpus-specific `Cert-Generator-master`, with the content-bearing dirs
 * (`tests`/`static`/`frontend`…) split into OPTIONAL_SKIP_DIRS below. */
export const DEFAULT_SKIP_DIRS: ReadonlySet<string> = new Set([
  '.git', 'node_modules', 'vendor', 'venv', '.venv', 'dist', 'build',
  '__pycache__', 'site-packages', 'migrations', '.idea',
]);

/** Content-bearing dirs the prototype skipped. Skipped by default (for golden
 * parity) but separable so a caller can opt to walk them when a handler is
 * suspected inside — avoids a silent recall regression. */
export const OPTIONAL_SKIP_DIRS: ReadonlySet<string> = new Set([
  'tests', 'test', 'frontend', 'public', 'assets', 'static',
]);

export interface WalkOptions {
  /** Override the directory skip-set entirely. Defaults to
   * DEFAULT_SKIP_DIRS ∪ OPTIONAL_SKIP_DIRS (full prototype parity). */
  skipDirs?: ReadonlySet<string>;
  /** Restrict results to these lowercased extensions (e.g. `['.py']`). When
   * omitted, every file is yielded (the prototype's `walk` is ext-agnostic;
   * per-extension filtering happens in `files_by_ext`). */
  exts?: ReadonlySet<string>;
}

/** The default skip-set: dependency/build dirs plus the prototype's
 * content-bearing skips, for byte-parity with the prototype walk. */
export const ALL_DEFAULT_SKIP_DIRS: ReadonlySet<string> = new Set([
  ...DEFAULT_SKIP_DIRS,
  ...OPTIONAL_SKIP_DIRS,
]);

/**
 * Recursively list files under `root`, pruning skipped directories. Mirrors the
 * prototype's `os.walk` + `dns[:] = [...]` prune (directories are filtered
 * before descent, so an entire skipped subtree is never read).
 *
 * Symlinks are not followed (cycle / escape safety; the V7 walker does the same
 * via `lstat`). Unreadable dirs/files are skipped silently — a permission error
 * on one entry must not abort the whole walk.
 *
 * Returns absolute paths. Callers that need repo-relative citations compute them
 * against `root`.
 */
export async function listFiles(
  root: string,
  opts: WalkOptions = {},
): Promise<string[]> {
  const skip = opts.skipDirs ?? ALL_DEFAULT_SKIP_DIRS;
  const exts = opts.exts;
  const out: string[] = [];

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      let lst;
      try {
        lst = await fs.lstat(full);
      } catch {
        continue;
      }
      if (lst.isSymbolicLink()) continue;
      if (lst.isDirectory()) {
        if (skip.has(ent.name)) continue;
        await walk(full);
      } else if (lst.isFile()) {
        if (!exts || exts.has(path.extname(ent.name).toLowerCase())) {
          out.push(full);
        }
      }
    }
  }

  await walk(root);
  return out;
}

/** Convenience wrapper for the prototype's `files_by_ext(root, exts)`. */
export function listFilesByExt(
  root: string,
  exts: ReadonlySet<string>,
  opts: Omit<WalkOptions, 'exts'> = {},
): Promise<string[]> {
  return listFiles(root, { ...opts, exts });
}
