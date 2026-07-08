import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request } from 'undici';
import type { Command } from 'commander';

export interface PackageMeta {
  name: string;
  version: string;
}

// Mirrors x-security.ts's resolveVersion: ../package.json in the npm bundle,
// ../../package.json in the dev build.
export function resolvePackageMeta(): PackageMeta {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const rel of ['../package.json', '../../package.json']) {
    try {
      const pkg = JSON.parse(readFileSync(join(here, rel), 'utf8'));
      if (typeof pkg.name === 'string' && typeof pkg.version === 'string') {
        return { name: pkg.name, version: pkg.version };
      }
    } catch {
      // try the next candidate location
    }
  }
  return { name: 'x-security', version: '0.0.0' };
}

// Best-effort only: never throws, so callers (including the passive hook)
// can't be taken down by a registry hiccup.
export async function fetchLatestVersion(name: string, timeoutMs = 2000): Promise<string | null> {
  try {
    const { body } = await request(`https://registry.npmjs.org/${encodeURIComponent(name)}/latest`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    const json = (await body.json()) as { version?: unknown };
    return typeof json.version === 'string' ? json.version : null;
  } catch {
    return null;
  }
}

function toSegments(v: string): [number, number, number] {
  const [major, minor, patch] = v.split('.').map((n) => parseInt(n, 10));
  return [major || 0, minor || 0, patch || 0];
}

export function isNewer(latest: string, current: string): boolean {
  const [aMajor, aMinor, aPatch] = toSegments(latest);
  const [bMajor, bMinor, bPatch] = toSegments(current);
  if (aMajor !== bMajor) return aMajor > bMajor;
  if (aMinor !== bMinor) return aMinor > bMinor;
  return aPatch > bPatch;
}

function truthyEnv(v: string | undefined): boolean {
  return !!v && v !== '0' && v.toLowerCase() !== 'false';
}

export function registerUpdateCheck(program: Command): void {
  program
    .command('update-check')
    .description('Check npm for a newer release (explicit; makes one network call).')
    .option('--timeout <ms>', 'Registry request timeout in ms', (v) => Number(v))
    .action(async (opts: { timeout?: number }) => {
      const { name, version } = resolvePackageMeta();
      const latest = await fetchLatestVersion(name, opts.timeout);
      if (latest === null) {
        process.stderr.write('update-check failed: could not reach npm registry\n');
        process.exit(1);
        return;
      }
      if (isNewer(latest, version)) {
        process.stdout.write(`update available: ${version} → ${latest}  (npm i -g ${name}@latest)\n`);
      } else {
        process.stdout.write(`up to date (v${version})\n`);
      }
    });

  // Passive nudge: opt-in only (positioning constraint — no phone-home by default),
  // and always overridable via the standard NO_UPDATE_NOTIFIER convention or our own flag.
  program.hook('postAction', async () => {
    if (!truthyEnv(process.env.X_SECURITY_UPDATE_CHECK)) return;
    if (truthyEnv(process.env.NO_UPDATE_NOTIFIER) || truthyEnv(process.env.X_SECURITY_NO_UPDATE_CHECK)) return;

    try {
      const { name, version } = resolvePackageMeta();
      const latest = await fetchLatestVersion(name);
      if (latest !== null && isNewer(latest, version)) {
        process.stderr.write(`⇡ x-security ${latest} available (you have ${version}) — run: ${name} update-check\n`);
      }
    } catch {
      // best-effort nudge; never let it disrupt the real command
    }
  });

  // NOTE: stateless by design for now — a cache file (e.g. ~/.cache/x-security/update-check.json)
  // could be added later to avoid a network call on every invocation.
}
