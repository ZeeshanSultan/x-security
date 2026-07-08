// Shared stdin/diagnostics helpers for CLI entrypoints. Kept separate from
// x-security.ts so command wiring and I/O plumbing can be edited independently.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const tempSpecDirs = new Set<string>();
let exitHandlerRegistered = false;

export function _cleanupTempSpecs(): void {
  for (const dir of tempSpecDirs) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort: never crash on exit
    }
  }
}

// Command impls read specs by path, so `-` resolution writes stdin to a temp
// file and hands back a path — no downstream code needs to know about pipes.
export async function resolveSpecArg(arg: string, stdin: NodeJS.ReadableStream = process.stdin): Promise<string> {
  if (arg !== '-') return arg;

  const chunks: Buffer[] = [];
  for await (const chunk of stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const content = Buffer.concat(chunks).toString('utf8').trim();
  if (!content) {
    throw new Error('expected a spec document on stdin, got empty input');
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'x-security-stdin-'));
  tempSpecDirs.add(dir);
  if (!exitHandlerRegistered) {
    exitHandlerRegistered = true;
    process.once('exit', _cleanupTempSpecs);
  }
  // .yaml extension regardless of source format: YAML is a JSON superset, so
  // a piped-in JSON spec still parses correctly under this name.
  const specPath = path.join(dir, 'spec.yaml');
  fs.writeFileSync(specPath, content, 'utf8');
  return specPath;
}

export type Verbosity = 'quiet' | 'normal' | 'verbose';

export interface Diagnostics {
  warn(line: string): void;
  info(line: string): void;
}

// Callers format their own lines (including any `warning:` prefix); this only
// decides whether a given verbosity level emits.
export function makeDiagnostics(v: Verbosity): Diagnostics {
  return {
    warn(line: string): void {
      if (v === 'quiet') return;
      process.stderr.write(`${line}\n`);
    },
    info(line: string): void {
      if (v !== 'verbose') return;
      process.stderr.write(`${line}\n`);
    }
  };
}
