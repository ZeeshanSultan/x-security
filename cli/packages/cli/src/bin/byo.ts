#!/usr/bin/env node
// BYO-agent CLI entrypoint. A trimmed commander program registering ONLY the
// deterministic correctness verbs a host coding agent shells out to:
//   routes, verify-finding, compile, audit, emit
//
// This is the bundle entry for the LLM-free runtime (dist/runtime/cli.mjs). It
// deliberately does NOT import the full `writ` bin, the test harness
// (dockerode), or the generate/validate/test/diff/migrate/push/verify-bundle
// verbs — so none of those (and none of an LLM provider SDK) enter the bundle.
// The verb logic is shared with the full bin via registerByoCommands().

import { Command } from 'commander';
import { registerByoCommands } from './byo-commands.js';
import { registerGenerator } from '../registry.js';
import { bunkerwebGenerator } from '../generators/bunkerweb/index.js';

// `emit --target waf` loads the bunkerweb generator via the registry's lazy
// template-literal dynamic import, which esbuild cannot statically inline. The
// bundled runtime instead seeds the registry with a static reference, so the
// generator (the only one the BYO surface needs) is bundled in. No other
// generators enter the bundle — keeping it minimal and LLM-free.
registerGenerator('bunkerweb', bunkerwebGenerator);

const program = new Command();

program
  .name('writ')
  .description('Writ BYO-agent runtime: deterministic verify/compile/audit/emit. LLM-free.')
  .version('0.1.0');

registerByoCommands(program);

program.parseAsync(process.argv).catch((e) => {
  process.stderr.write(`fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
