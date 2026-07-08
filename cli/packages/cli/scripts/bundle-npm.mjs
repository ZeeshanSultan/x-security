// Assembles the self-contained npm publish artifact for the CLI under
// packages/cli/npm-dist/. Mirrors scripts/bundle-runtime.mjs (the plugin
// runtime bundler) but for the FULL CLI surface:
//
//   npm-dist/bin/lazy.mjs   ← esbuild bundle of src/bin/npm-entry.ts
//                             (all @x-security/* workspace deps inlined;
//                              registry deps left external — they ship as
//                              real npm dependencies)
//   npm-dist/bin/scripts/   ← firewall wrapper assets, resolved by the
//                             scripts-loader relative to the bundle location
//   npm-dist/package.json   ← publish manifest derived from ./package.json
//                             (workspace deps stripped, publishConfig public)
//   npm-dist/README.md      ← ./README.md
//   npm-dist/LICENSE        ← repo-root LICENSE
//
// The normal dist build (tsc → dist/bin/lazy.js) is untouched; e2e tests and
// scripts/build-plugins.sh keep consuming it as-is. Publish flow:
//
//   pnpm --filter @x-security/cli build   # workspace deps must be built
//   node scripts/bundle-npm.mjs
//   cd npm-dist && npm publish

import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(HERE, '..');
const REPO = resolve(PKG, '..', '..');
const OUT_DIR = join(PKG, 'npm-dist');

const ENTRY = join(PKG, 'src', 'bin', 'npm-entry.ts');
const FIREWALL_SCRIPTS = join(PKG, 'src', 'generators', 'firewall', 'scripts');

const manifest = JSON.parse(readFileSync(join(PKG, 'package.json'), 'utf8'));

// Workspace deps get inlined into the bundle; registry deps stay external and
// ship as normal npm dependencies (dockerode/ssh2 carry dynamic requires that
// don't survive bundling, and externals keep the artifact small).
const externalDeps = Object.fromEntries(
  Object.entries(manifest.dependencies).filter(([name]) => !name.startsWith('@x-security/')),
);

// Same LLM-free guard as scripts/bundle-runtime.mjs: the published CLI must
// never pull in the LLM layer or a provider SDK (Rule G-2).
const BANNED_IMPORTS = [
  /^@x-security\/llm-agent(\/|$)/,
  /^openai(\/|$)/,
  /^@anthropic-ai\/sdk(\/|$)/,
  /^@google\/.*genai/i,
  /^@google\/generative-ai(\/|$)/,
];
const BANNED_PATH = /[/\\]packages[/\\]llm-agent[/\\]/;

const llmFreeGuard = {
  name: 'llm-free-guard',
  setup(b) {
    b.onResolve({ filter: /.*/ }, (args) => {
      const id = args.path;
      if (BANNED_IMPORTS.some((re) => re.test(id)) || BANNED_PATH.test(id)) {
        return {
          errors: [
            {
              text:
                `LLM-free guard: '${id}' is on the npm bundle path ` +
                `(imported from ${args.importer || '<entry>'}). The published CLI ` +
                `ships no LLM calls and no API keys (Rule G-2).`,
            },
          ],
        };
      }
      return null;
    });
  },
};

async function bundle(cmd) {
  await build({
    bundle: true,
    format: 'esm',
    platform: 'node',
    target: 'node20',
    entryPoints: [ENTRY],
    outfile: join(OUT_DIR, 'bin', `${cmd}.mjs`),
    external: Object.keys(externalDeps),
    plugins: [llmFreeGuard],
    logLevel: 'info',
    // Shebang must be the first line; then the createRequire shim so
    // transitively-bundled CJS workspace-dep code can call require().
    banner: {
      js: [
        '#!/usr/bin/env node',
        "import { createRequire as __lsCreateRequire } from 'node:module';",
        'const require = __lsCreateRequire(import.meta.url);',
      ].join('\n'),
    },
    // registry.ts's `import(\`./generators/${target}/index.js\`)` is dead in
    // this bundle: npm-entry.ts pre-seeds every native generator, and the
    // managed-cloud targets are matrix-only. The empty-glob warning (esbuild
    // can't match the .js suffix against .ts sources) is expected.
    logOverride: { 'empty-glob': 'silent' },
  });
}

function assemble(name, cmd) {
  cpSync(FIREWALL_SCRIPTS, join(OUT_DIR, 'bin', 'scripts'), { recursive: true });

  const out = {
    name,
    version: manifest.version,
    description: manifest.description,
    license: manifest.license,
    ...(manifest.homepage ? { homepage: manifest.homepage } : {}),
    ...(manifest.repository ? { repository: manifest.repository } : {}),
    type: 'module',
    bin: { [cmd]: `./bin/${cmd}.mjs` },
    engines: { node: '>=20' },
    dependencies: externalDeps,
    publishConfig: { access: 'public' },
  };
  writeFileSync(join(OUT_DIR, 'package.json'), `${JSON.stringify(out, null, 2)}\n`);

  copyFileSync(join(PKG, 'README.md'), join(OUT_DIR, 'README.md'));
  copyFileSync(join(REPO, 'LICENSE'), join(OUT_DIR, 'LICENSE'));
}

async function main() {
  // Publish name may be overridden when the preferred scope is unavailable:
  //   node scripts/bundle-npm.mjs --name x-security-cli
  const nameFlag = process.argv.indexOf('--name');
  const name = nameFlag !== -1 ? process.argv[nameFlag + 1] : manifest.name;
  // The published command defaults to the unscoped package name (e.g.
  // @foo/x-security → x-security), but --bin overrides it when the command
  // should differ from the package name (e.g. --bin xsecurity).
  const binFlag = process.argv.indexOf('--bin');
  const cmd = binFlag !== -1 ? process.argv[binFlag + 1] : name.replace(/^@[^/]+\//, '');

  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(join(OUT_DIR, 'bin'), { recursive: true });
  await bundle(cmd);
  assemble(name, cmd);
  process.stdout.write(
    `npm artifact assembled → ${OUT_DIR} (name: ${name}, command: ${cmd})\n` +
      `  bin/${cmd}.mjs  (full CLI, workspace deps inlined, LLM-free)\n` +
      `  bin/scripts/  (firewall wrapper assets)\n` +
      `  package.json  README.md  LICENSE\n`,
  );
}

main().catch((e) => {
  process.stderr.write(`bundle-npm failed: ${e.message || e}\n`);
  process.exit(1);
});
