// `x-security init <spec.yaml> [--defaults] [--target kong]`
// Adds an empty `x-security: {}` block to every operation that lacks one.
// With --defaults, populates a conservative baseline policy.

import { readFile, writeFile } from 'node:fs/promises';
import * as yaml from 'js-yaml';

export interface InitOptions {
  defaults?: boolean;
  target?: string;
  /** Write in place. If false, returns content but doesn't touch disk. */
  write?: boolean;
}

export interface InitResult {
  modifiedEndpoints: string[];
  yaml: string;
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] as const;

interface DefaultPolicy {
  authentication: { type: string };
  rateLimit: { requests: number; window: string; identifier: string };
  timeout: { read: number };
  cacheable: boolean;
}

function defaultPolicy(): DefaultPolicy {
  return {
    authentication: { type: 'bearer-jwt' },
    rateLimit: { requests: 60, window: '1m', identifier: 'user-id' },
    timeout: { read: 10000 },
    cacheable: false
  };
}

export async function runInit(specPath: string, opts: InitOptions): Promise<InitResult> {
  const raw = await readFile(specPath, 'utf8');
  const doc = yaml.load(raw) as Record<string, unknown> | undefined;
  if (!doc || typeof doc !== 'object') {
    throw new Error(`Spec at ${specPath} did not parse to a YAML object.`);
  }
  const paths = (doc as { paths?: Record<string, Record<string, unknown>> }).paths ?? {};
  const modified: string[] = [];
  const stub = opts.defaults ? defaultPolicy() : {};

  for (const [pathKey, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const m of METHODS) {
      const op = (pathItem as Record<string, unknown>)[m];
      if (!op || typeof op !== 'object') continue;
      const opObj = op as Record<string, unknown>;
      if ('x-security' in opObj) continue;
      opObj['x-security'] = stub;
      modified.push(`${m.toUpperCase()} ${pathKey}`);
    }
  }

  const out = yaml.dump(doc, { lineWidth: 120, noRefs: true });
  if (opts.write !== false) {
    await writeFile(specPath, out, 'utf8');
  }
  return { modifiedEndpoints: modified, yaml: out };
}
