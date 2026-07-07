// Parse an exported Kong declarative `kong.yml` and diff against a SpecIR.

import { readFile } from 'node:fs/promises';
import * as yaml from 'js-yaml';
import type { SpecIR } from '@x-security/core';
import type { KongPlugin } from '../generators/kong/types.js';
import type { DriftIssue, DriftReport } from '../reporters/types.js';
import { buildExpected, diffExpectedVsActual } from './kong-shared.js';

interface KongFileRoute {
  name?: string;
  paths?: string[];
  methods?: string[];
  plugins?: KongPlugin[];
}

interface KongFileService {
  name?: string;
  routes?: KongFileRoute[];
  plugins?: KongPlugin[];
}

interface KongFileDoc {
  _format_version?: string;
  services?: KongFileService[];
  plugins?: KongPlugin[]; // global
}

/** Build the actual endpoint→plugin map from a parsed kong.yml document. */
export function indexActualFromFile(doc: KongFileDoc, spec: SpecIR): Map<string, Map<string, KongPlugin>> {
  const out = new Map<string, Map<string, KongPlugin>>();
  const globalPlugins = doc.plugins ?? [];

  // Flatten all route entries with their plugin list.
  const allRoutes: Array<{ route: KongFileRoute; servicePlugins: KongPlugin[] }> = [];
  for (const svc of doc.services ?? []) {
    for (const r of svc.routes ?? []) {
      allRoutes.push({ route: r, servicePlugins: svc.plugins ?? [] });
    }
  }

  for (const e of spec.endpoints) {
    const label = `${e.method} ${e.path}`;
    const entry = allRoutes.find(({ route }) => (route.paths ?? []).some((p) => p === e.path));
    const map = new Map<string, KongPlugin>();
    if (entry) {
      const combined: KongPlugin[] = [
        ...globalPlugins,
        ...entry.servicePlugins,
        ...(entry.route.plugins ?? [])
      ];
      for (const p of combined) {
        map.set(p.name, p);
      }
    }
    out.set(label, map);
  }
  return out;
}

export interface FileDriftOptions {
  filePath: string;
  /** Raw YAML content (overrides filePath if provided — for tests). */
  yamlContent?: string;
}

export async function detectFileDrift(spec: SpecIR, opts: FileDriftOptions): Promise<DriftReport> {
  const raw = opts.yamlContent ?? (await readFile(opts.filePath, 'utf8'));
  const doc = (yaml.load(raw) as KongFileDoc | undefined) ?? {};
  const actual = indexActualFromFile(doc, spec);
  const expected = buildExpected(spec);
  const issues: DriftIssue[] = diffExpectedVsActual(expected, actual);
  return {
    kind: 'drift',
    target: 'kong',
    gatewaySource: opts.filePath,
    issues
  };
}
