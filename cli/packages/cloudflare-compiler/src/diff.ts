import type { CompileResult, CompiledRule } from './types.js';
import { stableStringify } from './compile.js';

export interface RulesetDiff {
  added: CompiledRule[];
  removed: CompiledRule[];
  modified: { before: CompiledRule; after: CompiledRule; changedFields: string[] }[];
  /** True iff added/removed/modified all empty. */
  identical: boolean;
}

/**
 * Structured diff between two compiled rulesets. Used for PR comments and
 * for drift detection against deployed state.
 */
export function diffRulesets(before: CompileResult, after: CompileResult): RulesetDiff {
  const a = flatten(before);
  const b = flatten(after);

  const beforeMap = new Map(a.map(r => [r.id, r] as const));
  const afterMap = new Map(b.map(r => [r.id, r] as const));

  const added: CompiledRule[] = [];
  const removed: CompiledRule[] = [];
  const modified: RulesetDiff['modified'] = [];

  for (const [id, ra] of afterMap) {
    const rb = beforeMap.get(id);
    if (!rb) {
      added.push(ra);
      continue;
    }
    const changed = changedFields(rb, ra);
    if (changed.length > 0) modified.push({ before: rb, after: ra, changedFields: changed });
  }
  for (const [id, rb] of beforeMap) {
    if (!afterMap.has(id)) removed.push(rb);
  }

  // Deterministic ordering
  added.sort(byId);
  removed.sort(byId);
  modified.sort((x, y) => byId(x.after, y.after));

  return {
    added,
    removed,
    modified,
    identical: added.length === 0 && removed.length === 0 && modified.length === 0
  };
}

function flatten(r: CompileResult): CompiledRule[] {
  return r.rulesets.flatMap(rs => rs.rules);
}

function byId(a: CompiledRule, b: CompiledRule): number {
  return a.id.localeCompare(b.id);
}

function changedFields(a: CompiledRule, b: CompiledRule): string[] {
  const fields: (keyof CompiledRule)[] = [
    'description', 'expression', 'action', 'enabled',
    'action_parameters', 'ratelimit', 'xSecurity'
  ];
  const out: string[] = [];
  for (const f of fields) {
    if (stableStringify(a[f]) !== stableStringify(b[f])) out.push(String(f));
  }
  return out;
}
