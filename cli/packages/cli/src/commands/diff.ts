// `lazy diff --target <t> <old.yaml> <new.yaml>`
// Generates both configs in-memory and diffs the artifacts as structured
// objects (YAML/JSON parsed where possible, raw string otherwise).

import * as yaml from 'js-yaml';
import { diff as jdiff } from 'jsondiffpatch';
import { loadSpec, buildResolverChain } from '@writ/core';
import { isKnownTarget, loadGenerator, type TargetName } from '../registry.js';

export interface DiffOptions {
  target: string;
  format?: 'human' | 'json';
  vault?: boolean;
  awsSecrets?: boolean;
  vaultKvVersion?: 1 | 2;
}

export interface DiffArtifactDelta {
  path: string;
  status: 'added' | 'removed' | 'modified' | 'unchanged';
  delta: unknown;
}

export interface DiffResult {
  added: string[];
  removed: string[];
  modified: string[];
  unchanged: string[];
  deltas: DiffArtifactDelta[];
  rendered: string;
}

function parseArtifact(content: string, format: string): unknown {
  try {
    if (format === 'yaml') return yaml.load(content) ?? null;
    if (format === 'json') return JSON.parse(content);
  } catch {
    /* fall through to raw string */
  }
  return content;
}

function renderHuman(r: DiffResult): string {
  let out = `Config diff\n\n`;
  if (r.added.length) out += `Added (${r.added.length}):\n${r.added.map((p) => `  + ${p}`).join('\n')}\n\n`;
  if (r.removed.length) out += `Removed (${r.removed.length}):\n${r.removed.map((p) => `  - ${p}`).join('\n')}\n\n`;
  if (r.modified.length) out += `Modified (${r.modified.length}):\n${r.modified.map((p) => `  ~ ${p}`).join('\n')}\n\n`;
  if (!r.added.length && !r.removed.length && !r.modified.length) {
    out += 'No differences.\n';
  }
  return out;
}

export async function runDiff(
  oldSpec: string,
  newSpec: string,
  opts: DiffOptions
): Promise<DiffResult> {
  if (!isKnownTarget(opts.target)) {
    throw new Error(`Unknown target "${opts.target}".`);
  }
  const target: TargetName = opts.target;
  const gen = await loadGenerator(target);
  if (!gen) {
    throw new Error(`Generator for target "${target}" is not available.`);
  }

  const chainOpts: Parameters<typeof buildResolverChain>[0] = {};
  if (opts.vault) chainOpts.enableVault = true;
  if (opts.awsSecrets) chainOpts.enableAws = true;
  if (opts.vaultKvVersion) chainOpts.vaultKvVersion = opts.vaultKvVersion;
  const resolver = buildResolverChain(chainOpts);
  const [oldIr, newIr] = await Promise.all([
    loadSpec(oldSpec, { resolver, strict: false }),
    loadSpec(newSpec, { resolver, strict: false })
  ]);

  const [oldArts, newArts] = await Promise.all([gen.generate(oldIr), gen.generate(newIr)]);

  const oldMap = new Map(oldArts.map((a) => [a.path, a]));
  const newMap = new Map(newArts.map((a) => [a.path, a]));
  const paths = new Set<string>([...oldMap.keys(), ...newMap.keys()]);

  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];
  const unchanged: string[] = [];
  const deltas: DiffArtifactDelta[] = [];

  for (const p of paths) {
    const a = oldMap.get(p);
    const b = newMap.get(p);
    if (!a && b) {
      added.push(p);
      deltas.push({ path: p, status: 'added', delta: parseArtifact(b.content, b.format) });
    } else if (a && !b) {
      removed.push(p);
      deltas.push({ path: p, status: 'removed', delta: parseArtifact(a.content, a.format) });
    } else if (a && b) {
      const av = parseArtifact(a.content, a.format);
      const bv = parseArtifact(b.content, b.format);
      const d = jdiff(av, bv);
      if (d === undefined) {
        unchanged.push(p);
        deltas.push({ path: p, status: 'unchanged', delta: null });
      } else {
        modified.push(p);
        deltas.push({ path: p, status: 'modified', delta: d });
      }
    }
  }

  const result: DiffResult = {
    added,
    removed,
    modified,
    unchanged,
    deltas,
    rendered: ''
  };
  result.rendered = opts.format === 'json' ? JSON.stringify(result, null, 2) + '\n' : renderHuman(result);
  return result;
}
