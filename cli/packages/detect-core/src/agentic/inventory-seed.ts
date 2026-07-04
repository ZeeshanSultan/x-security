// Render the deterministic route-extractor output as a GROUNDING seed table for
// the inventory prompt.
//
// The extractor PROPOSES; the LLM still confirms each route by reading source
// and emitting its own RouteInventoryEntry with a file:line citation (D-3). The
// seed is NEVER written directly into routeInventory, and `schemaHint` is shown
// as a HINT only — it is rendered as opaque prose and is structurally incapable
// of becoming a request.schema rule (the LLM / V2 / V3 stay authoritative for
// schema). The table is wrapped in <<UNTRUSTED>> fences (prompt-injection
// containment) by the prompt layer, and capped at N rows with an explicit
// `… +K more` marker — never silently truncated (D-1).

import type { ExtractedRoute } from '../frameworks/index.js';
import { isEducationalSourceViewPath } from './verify-fs-routing.js';

/** Default cap on seed rows. Sized so the table stays well under the inventory
 * output budget while still grounding the dominant API surface. The remaining
 * rows are summarized with a `… +K more` marker, not dropped silently. */
export const DEFAULT_SEED_ROW_CAP = 80;

/** Drop extractor routes that point at educational source-view decoys
 * (DVWA-style `…/source/{low,medium,high,…}.<ext>`). Mirrors the inventory
 * filter (`filterEducationalSourceViewRoutes`) so the seed never proposes a
 * non-endpoint the inventory layer would later drop. */
export function filterSeedRoutes(routes: ExtractedRoute[]): ExtractedRoute[] {
  return routes.filter((r) => {
    const src = (r.sourceFile ?? '').split(/[\\/]/).join('/');
    return !(src && isEducationalSourceViewPath(src));
  });
}

function citationOf(r: ExtractedRoute): string {
  if (r.sourceFile && typeof r.sourceLine === 'number') {
    return `${r.sourceFile}:${r.sourceLine}`;
  }
  if (r.sourceFile) return r.sourceFile;
  return '(no citation — confirm by reading source)';
}

/** A single seed row, rendered as a compact pipe-delimited line. `schemaHint`
 * is labelled `hint:` and kept as prose so it cannot be mistaken for a schema
 * rule. */
function renderRow(r: ExtractedRoute): string {
  const parts = [`${r.method} ${r.path}`, citationOf(r)];
  if (r.handler) parts.push(`handler=${r.handler}`);
  if (r.framework) parts.push(`fw=${r.framework}`);
  if (r.protocol) parts.push(`proto=${r.protocol}`);
  if (r.schemaHint) parts.push(`hint:${r.schemaHint}`);
  return `  - ${parts.join(' | ')}`;
}

/**
 * Render the candidate table block. Returns `undefined` when there is nothing
 * to seed (empty after the source-view filter) so the caller can omit the block
 * entirely rather than render an empty section.
 *
 * The returned string is the INNER body only — the prompt layer wraps it in the
 * `<<UNTRUSTED>>` fences and the explanatory header so trust framing lives in
 * one place.
 */
export function renderSeedTable(
  routes: ExtractedRoute[],
  opts: { rowCap?: number } = {},
): string | undefined {
  const filtered = filterSeedRoutes(routes);
  if (filtered.length === 0) return undefined;

  const cap = Math.max(1, opts.rowCap ?? DEFAULT_SEED_ROW_CAP);
  const shown = filtered.slice(0, cap);
  const overflow = filtered.length - shown.length;

  const lines = shown.map(renderRow);
  if (overflow > 0) {
    lines.push(`  … +${overflow} more (deterministic extractor found ${filtered.length} candidate routes; only the first ${cap} are listed here — enumerate the rest from source)`);
  }
  return lines.join('\n');
}
