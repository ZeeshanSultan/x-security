/**
 * Loads the deploy-time DNS wrapper scripts from disk and returns them as
 * ConfigArtifact-ready strings.
 *
 * The script bodies live as plain .sh / .service / .timer / .md files in
 * `./scripts/` so they remain editable, lintable (shellcheck), and reviewable
 * outside the TypeScript compile path. tsc doesn't copy non-.ts files, so the
 * package build script copies the `scripts/` directory into `dist/` after
 * compilation; at runtime we resolve relative to `import.meta.url` and try
 * both the dist-adjacent and src-adjacent locations.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Candidate locations for the scripts directory:
 *  - sibling `scripts/` (dist after build copy, or src when running tsx)
 *  - `../scripts/` (defensive — unused today)
 *  - source tree (when running from dist and the build-copy was skipped;
 *    walking up from dist/generators/firewall to src/generators/firewall/scripts)
 */
const CANDIDATES = [
  join(HERE, 'scripts'),
  resolve(HERE, '..', '..', '..', 'src', 'generators', 'firewall', 'scripts'),
];

function scriptsDir(): string {
  for (const c of CANDIDATES) {
    if (existsSync(c)) return c;
  }
  throw new Error(
    `firewall scripts directory not found; checked: ${CANDIDATES.join(', ')}`
  );
}

function read(name: string): string {
  return readFileSync(join(scriptsDir(), name), 'utf8');
}

export interface WrapperScript {
  /** Filename relative to the artifact output dir's `firewall/scripts/` */
  filename: string;
  content: string;
  /** ConfigArtifact format tag */
  format: 'text' | 'conf';
}

/**
 * All wrapper artifacts emitted alongside the .rules files. Order is stable
 * for deterministic test assertions.
 */
export function loadWrapperScripts(): WrapperScript[] {
  return [
    {
      filename: 'x-security-resolve.sh',
      content: read('x-security-resolve.sh'),
      format: 'text',
    },
    {
      filename: 'x-security-refresh.sh',
      content: read('x-security-refresh.sh'),
      format: 'text',
    },
    {
      filename: 'x-security-refresh.service',
      content: read('x-security-refresh.service'),
      format: 'conf',
    },
    {
      filename: 'x-security-refresh.timer',
      content: read('x-security-refresh.timer'),
      format: 'conf',
    },
    {
      filename: 'x-security.logrotate',
      content: read('x-security.logrotate'),
      format: 'conf',
    },
    {
      filename: 'README.md',
      content: read('README.md'),
      format: 'text',
    },
  ];
}
