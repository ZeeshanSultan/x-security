// Shared registration of the BYO-agent core verbs: routes, verify-finding,
// compile, audit, emit. Both the full `writ` bin and the trimmed `byo`
// bin call registerByoCommands(program) so the action logic lives in exactly
// one place (no duplication between the two entrypoints).
//
// These verbs are the deterministic correctness surface a host coding agent
// shells out to. They pull in ONLY @writ/* + js-yaml + node builtins —
// no dockerode, no @stoplight/spectral, no LLM provider SDK — which is what
// keeps the BYO bundle self-contained and LLM-free.

import type { Command } from 'commander';
import { runRoutes } from '../commands/detect/routes.js';
import { runVerify, type VerifyInput } from '../commands/detect/verify.js';
import { runCompile, type CompileInput } from '../commands/detect/compile.js';
import { runAudit } from '../commands/detect/audit.js';
import { runEmit, type EmitTarget } from '../commands/detect/emit.js';
import { runContext, parseRouteArg } from '../commands/detect/context.js';
import { runVerifyRoute, type VerifyRouteInput } from '../commands/detect/verify-route.js';
import { runReconcileInventory, type ReconcileInventoryInput } from '../commands/detect/reconcile-inventory.js';
import { readStdinJson } from '../commands/detect/stdin.js';
import { persistPolicy } from '../commands/detect/store.js';

export function registerByoCommands(program: Command): void {
  // ---------------------------------------------------------- routes
  program
    .command('routes <repoDir>')
    .description('Deterministic route inventory. Emits {method,path,file,line} for every extractable route.')
    .option('--seed', 'Also emit the rendered seed table for grounding a host-agent inventory prompt.')
    .option('--seed-row-cap <n>', 'Cap seed-table rows (rest summarized, never dropped).', (v) => Number(v))
    .action(async (repoDir: string, opts: { seed?: boolean; seedRowCap?: number }) => {
      try {
        const routesOpts: Parameters<typeof runRoutes>[1] = {};
        if (opts.seed) routesOpts.seed = true;
        if (opts.seedRowCap !== undefined) routesOpts.seedRowCap = opts.seedRowCap;
        const r = await runRoutes(repoDir, routesOpts);
        process.stdout.write(JSON.stringify(r) + '\n');
      } catch (e) {
        process.stderr.write(`routes failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- verify-finding
  program
    .command('verify-finding')
    .description('Verify ONE finding (V6 cite byte-match + V3 tightness + V1 schema). Reads JSON on stdin.')
    .action(async () => {
      try {
        const input = await readStdinJson<VerifyInput>();
        const r = await runVerify(input);
        process.stdout.write(JSON.stringify(r) + '\n');
        process.exit(r.verdict === 'pass' ? 0 : 2);
      } catch (e) {
        process.stderr.write(`verify failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- context
  program
    .command('context <repoDir>')
    .description('Deterministic per-route context (D-2): evidence pack (handler slice + observed inputs/validators/outputs) + resolved auth context. Grounded against the extractor.')
    .requiredOption('--route <route>', 'Target route as "<METHOD> <path>", e.g. "POST /login".')
    .action(async (repoDir: string, opts: { route: string }) => {
      try {
        const route = parseRouteArg(opts.route);
        const r = await runContext({ repoDir, route });
        process.stdout.write(JSON.stringify(r) + '\n');
      } catch (e) {
        process.stderr.write(`context failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- verify-route
  program
    .command('verify-route')
    .description('Whole-route PRECISION gate: compose all findings into the route policy, run V2+V4+V5. demote if a synthetic legit request is false-blocked. Reads JSON on stdin.')
    .action(async () => {
      try {
        const input = await readStdinJson<VerifyRouteInput>();
        const r = await runVerifyRoute(input);
        process.stdout.write(JSON.stringify(r) + '\n');
        // Non-zero on an over-block demote OR a hard depth gap (under-detected
        // stub). Advisories alone do not fail the gate — they are soft surfaces.
        const depthFails = (r.depth?.gaps.length ?? 0) > 0;
        process.exit(r.verdict === 'pass' && !depthFails ? 0 : 2);
      } catch (e) {
        process.stderr.write(`verify-route failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- reconcile-inventory
  program
    .command('reconcile-inventory')
    .description('Reconcile mount prefixes + GROUND each route against the extractor/fs-handlers (D-1). Marks grounded|ungrounded with a reason. Reads JSON on stdin.')
    .action(async () => {
      try {
        const input = await readStdinJson<ReconcileInventoryInput>();
        const r = await runReconcileInventory(input);
        process.stdout.write(JSON.stringify(r) + '\n');
      } catch (e) {
        process.stderr.write(`reconcile-inventory failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- compile
  program
    .command('compile')
    .description("Compile a route's verified findings into an x-security policy. Reads JSON on stdin.")
    .option('--write <repoDir>', 'Persist the policy + cite sidecar under <repoDir>/.writ/policies/.')
    .action(async (opts: { write?: string }) => {
      try {
        const input = await readStdinJson<CompileInput>();
        const r = await runCompile(input);
        if (opts.write && r.policy) {
          await persistPolicy(opts.write, input.route, r.policy, r.cites);
        }
        process.stdout.write(JSON.stringify({ policy: r.policy, dropped: r.dropped, applied: r.applied }) + '\n');
        process.exit(r.policy ? 0 : 2);
      } catch (e) {
        process.stderr.write(`compile failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- audit
  program
    .command('audit <repoDir>')
    .description('Re-validate every .writ/policies/ control + prove cite-coverage. citeBacked=false if ANY control lacks a byte-matching cite.')
    .action(async (repoDir: string) => {
      try {
        const r = await runAudit(repoDir);
        process.stdout.write(JSON.stringify(r) + '\n');
        process.exit(r.citeBacked ? 0 : 2);
      } catch (e) {
        process.stderr.write(`audit failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });

  // ---------------------------------------------------------- emit
  program
    .command('emit <repoDir>')
    .description('Render compiled policies to an artifact. --target waf|report|ci, written under .writ/.')
    .requiredOption('--target <name>', 'waf|report|ci')
    .action(async (repoDir: string, opts: { target: string }) => {
      try {
        if (!['waf', 'report', 'ci'].includes(opts.target)) {
          process.stderr.write(`Invalid --target "${opts.target}". Allowed: waf, report, ci.\n`);
          process.exit(1);
        }
        const r = await runEmit(repoDir, { target: opts.target as EmitTarget });
        // JSON out — consistent with routes/verify-finding/compile/audit so the
        // MCP bridge parses one object per verb (CONTRACT-3).
        process.stdout.write(`${JSON.stringify({ written: r.written })}\n`);
      } catch (e) {
        process.stderr.write(`emit failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });
}
