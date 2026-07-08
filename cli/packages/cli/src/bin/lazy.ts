#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import { runGenerate } from '../commands/generate.js';
import { runValidate } from '../commands/validate.js';
import { runTest } from '../commands/test.js';
import { runReport } from '../commands/report.js';
import { runDiff } from '../commands/diff.js';
import { runInit } from '../commands/init.js';
import { runMcp } from '../commands/mcp.js';
import { runVerifyBundle, type VerifyBundleOptions } from '../commands/verify-bundle.js';
import { runVerifyCli } from '../commands/verify.js';
import { runMigrate, type FromVersion, type ToVersion } from '../commands/migrate.js';
import { runPush, PushError } from '../commands/detect/push.js';
import { registerExtras } from './register-extras.js';
import { resolveSpecArg, makeDiagnostics, type Verbosity } from './cli-io.js';
import { generateExamples, validateExamples, verifyExamples, reportExamples, diffExamples } from './help-text.js';
import { StrictnessViolation } from '@x-security/core';
import type { ReportFormat } from '../reporters/types.js';

// Derive stderr verbosity from --quiet/--verbose. quiet wins.
function verbosity(): Verbosity {
  const opts = program.opts();
  if (opts.quiet) return 'quiet';
  if (opts.verbose) return 'verbose';
  return 'normal';
}

// Read version from package.json so `--version` can't drift. It's at
// ../package.json in the npm bundle and ../../package.json in the dev build.
function resolveVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const rel of ['../package.json', '../../package.json']) {
    try {
      const v = JSON.parse(readFileSync(join(here, rel), 'utf8')).version;
      if (typeof v === 'string') return v;
    } catch {
      // try the next candidate location
    }
  }
  return '0.0.0';
}

const program = new Command();

// Name the program after the invoked binary so help/usage matches the install:
// `lazy` for the dev bin, the published command name for the npm bundle.
program
  .name(basename(process.argv[1] ?? 'lazy').replace(/\.(mjs|cjs|js)$/, ''))
  .description('Compile, validate, test, and report on x-security policies in OpenAPI specs.')
  .option('--quiet', 'Suppress warnings/advisories on stderr (results still print)')
  .option('--verbose', 'Print extra progress detail to stderr')
  .version(resolveVersion())
  .showHelpAfterError('(add --help for usage)');

program
  .command('generate <spec>')
  .description('Compile an annotated OpenAPI spec into target-specific gateway config. <spec> may be - to read from stdin.')
  .requiredOption('--target <name>', 'Target: kong|coraza|bunkerweb|openappsec|firewall')
  .option('--out <dir>', 'Output directory (default: ./x-security-out/<target>)')
  .option('--dry-run', 'Print planned artifacts without writing to disk')
  .option('--no-strict', 'Allow unresolved variables (default: strict)')
  .option('--vault', 'Resolve $vault.* refs via HashiCorp Vault (uses VAULT_ADDR + VAULT_TOKEN or AppRole)')
  .option('--aws-secrets', 'Resolve $aws.* refs via AWS Secrets Manager (uses default credential chain + AWS_REGION)')
  .option('--vault-kv-version <v>', 'Vault KV engine version: 1 or 2 (default 2)', (v) => (v === '1' ? 1 : 2))
  .option('--no-with-consumers', 'Kong only: emit spec-only output (omit consumers + per-plugin credentials). Consumers are emitted by default so OSS Kong gateways actually authenticate; pass this for the spec-only baseline.')
  .option('--kong-deployment <mode>', 'Kong only: standalone|behind-proxy|with-coraza|with-istio. with-coraza rewrites all service URLs to http://coraza:8080.', 'standalone')
  .option('--kong-edition <edition>', 'Kong only: oss|enterprise. enterprise emits openid-connect (real JWKS+RS256) instead of HS256 jwt_secrets downgrade.', 'oss')
  .option('--kong-dbless', 'Kong only: deployment runs in DB-less mode (KONG_DATABASE=off). Per-identity rate-limits fall back to policy=local with a structured warning instead of policy=cluster.', false)
  .option('--kong-policy <mode>', 'Kong only: rate-limit policy. local|cluster. Default local (safe for OSS DB-less). Pass cluster only when Kong is running in database mode (postgres/cassandra); cluster is a boot error in DB-less Kong.', 'local')
  .option('--coraza-engine <name>', 'Coraza only: modsec-nginx|modsec-apache|coraza-go|coraza-spoa (default modsec-nginx).', 'modsec-nginx')
  .option('--coraza-peers <list>', 'Coraza only (coraza-spoa|coraza-go): HAProxy peer-replication for stick-tables. Format: "name1:host1:port1,name2:host2:port2". When set, emitted haproxy-stick-tables.cfg includes a `peers x-security` section so counters replicate across instances.')
  .option('--strict-fidelity', 'Exit 4 (S3) if any spec field cannot be enforced by the chosen target+engine. Independent of --strict.')
  .addHelpText('after', generateExamples)
  .action(async (spec: string, opts: { target: string; out?: string; dryRun?: boolean; strict?: boolean; vault?: boolean; awsSecrets?: boolean; vaultKvVersion?: 1 | 2; withConsumers?: boolean; kongDeployment?: string; kongEdition?: string; kongDbless?: boolean; kongPolicy?: string; corazaEngine?: string; corazaPeers?: string; strictFidelity?: boolean }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      const fromStdin = spec === '-';
      spec = await resolveSpecArg(spec);
      if (fromStdin) diag.info('reading spec from stdin');
      if (opts.target === 'kong') {
        const dep = opts.kongDeployment;
        if (dep && !['standalone', 'behind-proxy', 'with-coraza', 'with-istio'].includes(dep)) {
          process.stderr.write(`Invalid --kong-deployment "${dep}". Allowed: standalone, behind-proxy, with-coraza, with-istio.\n`);
          process.exit(1);
        }
        const ed = opts.kongEdition;
        if (ed && !['oss', 'enterprise'].includes(ed)) {
          process.stderr.write(`Invalid --kong-edition "${ed}". Allowed: oss, enterprise.\n`);
          process.exit(1);
        }
        const pol = opts.kongPolicy;
        if (pol && !['local', 'cluster'].includes(pol)) {
          process.stderr.write(`Invalid --kong-policy "${pol}". Allowed: local, cluster.\n`);
          process.exit(1);
        }
      }
      const generateOpts: Parameters<typeof runGenerate>[1] = {
        target: opts.target,
        strict: opts.strict ?? true
      };
      if (opts.out !== undefined) generateOpts.out = opts.out;
      if (opts.dryRun !== undefined) generateOpts.dryRun = opts.dryRun;
      if (opts.vault) generateOpts.vault = true;
      if (opts.awsSecrets) generateOpts.awsSecrets = true;
      if (opts.vaultKvVersion) generateOpts.vaultKvVersion = opts.vaultKvVersion;
      if (opts.target === 'kong' && opts.withConsumers !== undefined) {
        generateOpts.withConsumers = opts.withConsumers;
      }
      if (opts.target === 'kong' && opts.kongDeployment !== undefined) {
        generateOpts.kongDeployment = opts.kongDeployment as 'standalone' | 'behind-proxy' | 'with-coraza' | 'with-istio';
      }
      if (opts.target === 'kong' && opts.kongEdition !== undefined) {
        generateOpts.kongEdition = opts.kongEdition as 'oss' | 'enterprise';
      }
      if (opts.target === 'kong' && opts.kongDbless !== undefined) {
        generateOpts.kongDbless = opts.kongDbless;
      }
      if (opts.target === 'kong' && opts.kongPolicy !== undefined) {
        generateOpts.kongPolicy = opts.kongPolicy as 'local' | 'cluster';
      }
      if (opts.target === 'coraza' && opts.corazaEngine !== undefined) {
        generateOpts.corazaEngine = opts.corazaEngine;
      }
      if (opts.target === 'coraza' && opts.corazaPeers !== undefined) {
        generateOpts.corazaPeers = opts.corazaPeers;
      }
      if (opts.strictFidelity) generateOpts.strictFidelity = true;
      const r = await runGenerate(spec, generateOpts);
      for (const w of r.warnings) diag.warn(`warning: ${w}`);
      if (opts.dryRun) {
        diag.info(`generated ${r.artifacts.length} artifact(s) for target ${opts.target} (dry-run)`);
        process.stdout.write(`# Dry-run — ${r.artifacts.length} artifact(s) would be written:\n`);
        for (const a of r.artifacts) {
          process.stdout.write(`\n# ${a.path} (${a.format})\n${a.content}\n`);
        }
      } else {
        diag.info(`generated ${r.artifactPaths.length} artifact(s) for target ${opts.target}`);
        for (const p of r.artifactPaths) process.stdout.write(`${p}\n`);
      }
    } catch (e) {
      if (e instanceof StrictnessViolation) {
        process.stderr.write(`${e.message}\n`);
        process.exit(e.exitCode); // 2=S1 unresolved/placeholder, 3=S2 zero-emission, 4=S3 fidelity
      }
      process.stderr.write(`generate failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program
  .command('validate <spec>')
  .description('Detect drift between the spec and a running/exported gateway config. <spec> may be - to read from stdin.')
  .requiredOption('--target <name>', 'Currently: kong')
  .requiredOption('--gateway <urlOrPath>', 'Kong admin URL (http://...) or path to exported kong.yml')
  .option('--format <fmt>', 'table|json|sarif|csv (default: table)', 'table')
  .option('--timeout <ms>', 'Abort network calls after <ms> milliseconds (gateway admin URL / probes)', (v) => Number(v))
  .option('--vault', 'Resolve $vault.* refs via HashiCorp Vault')
  .option('--aws-secrets', 'Resolve $aws.* refs via AWS Secrets Manager')
  .option('--vault-kv-version <v>', 'Vault KV engine version: 1 or 2 (default 2)', (v) => (v === '1' ? 1 : 2))
  .addHelpText('after', validateExamples)
  .action(async (spec: string, opts: { target: string; gateway: string; format: string; timeout?: number; vault?: boolean; awsSecrets?: boolean; vaultKvVersion?: 1 | 2 }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      const fromStdin = spec === '-';
      spec = await resolveSpecArg(spec);
      if (fromStdin) diag.info('reading spec from stdin');
      const validateOpts: Parameters<typeof runValidate>[1] = {
        target: opts.target,
        gateway: opts.gateway,
        format: opts.format as ReportFormat
      };
      if (opts.timeout !== undefined) validateOpts.timeoutMs = opts.timeout;
      if (opts.vault) validateOpts.vault = true;
      if (opts.awsSecrets) validateOpts.awsSecrets = true;
      if (opts.vaultKvVersion) validateOpts.vaultKvVersion = opts.vaultKvVersion;
      diag.info(`querying gateway ${opts.gateway}${opts.timeout ? ` (timeout ${opts.timeout}ms)` : ''}`);
      const r = await runValidate(spec, validateOpts);
      process.stdout.write(r.rendered);
      process.exit(r.exitCode);
    } catch (e) {
      process.stderr.write(`validate failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program
  .command('test <spec>')
  .description('Closed-loop test: generate config, spin up Docker, send traffic, assert. <spec> may be - to read from stdin.')
  .requiredOption('--target <name>', 'kong|coraza|bunkerweb|openappsec')
  .option('--upstream-port <port>', 'Local port for mock upstream (ignored with --upstream-url)', (v) => Number(v))
  .option('--gateway-port <port>', 'Local port for gateway', (v) => Number(v))
  .option('--upstream-url <url>', 'Test against a real upstream (e.g. http://host.docker.internal:8000) instead of the mock-upstream container')
  .option('--dry-run', 'Print the docker-compose plan without running it')
  .option('--keep', 'Leave containers running on success (debug aid)')
  .option('--format <fmt>', 'table|junit|json (default: table)', 'table')
  .option('--timeout <ms>', 'Abort network calls after <ms> milliseconds (gateway admin URL / probes)', (v) => Number(v))
  .option('--vault', 'Resolve $vault.* refs via HashiCorp Vault')
  .option('--aws-secrets', 'Resolve $aws.* refs via AWS Secrets Manager')
  .option('--vault-kv-version <v>', 'Vault KV engine version: 1 or 2 (default 2)', (v) => (v === '1' ? 1 : 2))
  .addHelpText('after', `
Examples:
  # Mock upstream (default): brings up mendhak/http-https-echo as the backend
  $ lazy test --target kong spec.yaml

  # Real upstream: point the gateway at your local app
  $ lazy test --target kong --upstream-url http://host.docker.internal:8000 spec.yaml

  # Remote staging
  $ lazy test --target kong --upstream-url https://staging.example.com spec.yaml
`)
  .action(async (spec: string, opts: { target: string; upstreamPort?: number; gatewayPort?: number; upstreamUrl?: string; dryRun?: boolean; keep?: boolean; format: string; timeout?: number; vault?: boolean; awsSecrets?: boolean; vaultKvVersion?: 1 | 2 }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      const fromStdin = spec === '-';
      spec = await resolveSpecArg(spec);
      if (fromStdin) diag.info('reading spec from stdin');
      const testOpts: Parameters<typeof runTest>[1] = {
        target: opts.target,
        format: opts.format as 'junit' | 'json' | 'table'
      };
      if (opts.timeout !== undefined) testOpts.timeoutMs = opts.timeout;
      if (opts.upstreamPort !== undefined) testOpts.upstreamPort = opts.upstreamPort;
      if (opts.gatewayPort !== undefined) testOpts.gatewayPort = opts.gatewayPort;
      if (opts.upstreamUrl !== undefined) testOpts.upstreamUrl = opts.upstreamUrl;
      if (opts.dryRun !== undefined) testOpts.dryRun = opts.dryRun;
      if (opts.keep !== undefined) testOpts.keep = opts.keep;
      if (opts.vault) testOpts.vault = true;
      if (opts.awsSecrets) testOpts.awsSecrets = true;
      if (opts.vaultKvVersion) testOpts.vaultKvVersion = opts.vaultKvVersion;
      diag.info(`bringing up ${opts.target} gateway (upstream: ${opts.upstreamUrl ?? 'mock'})`);
      const r = await runTest(spec, testOpts);
      process.stdout.write(r.rendered);
      process.exit(r.exitCode);
    } catch (e) {
      process.stderr.write(`test failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program
  .command('report <spec>')
  .description('OWASP coverage and annotation reports. <spec> may be - to read from stdin.')
  .option('--owasp', 'OWASP API Top 10 coverage report (default if neither flag given)')
  .option('--coverage', 'Annotation coverage report')
  .option('--format <fmt>', 'table|json|sarif|csv|html (default: table)', 'table')
  .option('--feasible <targets>', 'Comma-separated targets (e.g. kong,coraza). Downgrade Y→Y*/~ for declared mitigations no listed target can enforce.')
  .option('--strict-fidelity', 'Exit 4 if --feasible would downgrade any Y to Y*/~. Requires --owasp --feasible.')
  .option('--vault', 'Resolve $vault.* refs via HashiCorp Vault')
  .option('--aws-secrets', 'Resolve $aws.* refs via AWS Secrets Manager')
  .option('--vault-kv-version <v>', 'Vault KV engine version: 1 or 2 (default 2)', (v) => (v === '1' ? 1 : 2))
  .addHelpText('after', reportExamples)
  .action(async (spec: string, opts: { owasp?: boolean; coverage?: boolean; format: string; feasible?: string; strictFidelity?: boolean; vault?: boolean; awsSecrets?: boolean; vaultKvVersion?: 1 | 2 }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      const fromStdin = spec === '-';
      spec = await resolveSpecArg(spec);
      if (fromStdin) diag.info('reading spec from stdin');
      const mode = opts.coverage ? 'coverage' : 'owasp';
      const reportOpts: Parameters<typeof runReport>[1] = {
        mode,
        format: opts.format as ReportFormat
      };
      if (opts.feasible) reportOpts.feasible = opts.feasible;
      if (opts.strictFidelity) reportOpts.strictFidelity = true;
      if (opts.vault) reportOpts.vault = true;
      if (opts.awsSecrets) reportOpts.awsSecrets = true;
      if (opts.vaultKvVersion) reportOpts.vaultKvVersion = opts.vaultKvVersion;
      const r = await runReport(spec, reportOpts);
      process.stdout.write(r.rendered);
    } catch (e) {
      if (e instanceof StrictnessViolation) {
        process.stderr.write(`${e.message}\n`);
        process.exit(e.exitCode);
      }
      process.stderr.write(`report failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program
  .command('verify <spec>')
  .description('Read-only post-deploy check: did the gateway actually load the artifacts we emitted? <spec> may be - to read from stdin.')
  .requiredOption('--target <name>', 'kong|coraza|envoy|bunkerweb|openappsec')
  .requiredOption('--gateway <addr>', 'Kong admin URL, Envoy admin URL, OR (for coraza) path to nginx error log / docker:<container> / coraza-go /debug/rules URL, OR (for bunkerweb) docker:<scheduler>+docker:<bunkerweb>, OR (for openappsec) docker:<agent>')
  .option('--engine <name>', 'Coraza engine: modsec-nginx|coraza-go|coraza-spoa (default modsec-nginx)')
  .option('--format <fmt>', 'table|json|sarif (default table)', 'table')
  .option('--threshold <pct>', 'Minimum load-coverage % to consider PASS (default 90)', (v) => Number(v))
  .option('--timeout <ms>', 'Abort network calls after <ms> milliseconds (gateway admin URL / probes)', (v) => Number(v))
  .addHelpText('after', verifyExamples)
  .action(async (spec: string, opts: { target: string; gateway: string; engine?: string; format: string; threshold?: number; timeout?: number }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      const fromStdin = spec === '-';
      spec = await resolveSpecArg(spec);
      if (fromStdin) diag.info('reading spec from stdin');
      const verifyOpts: Parameters<typeof runVerifyCli>[1] = {
        target: opts.target,
        gateway: opts.gateway,
        format: opts.format
      };
      if (opts.engine !== undefined) verifyOpts.engine = opts.engine;
      if (opts.threshold !== undefined) verifyOpts.threshold = opts.threshold;
      if (opts.timeout !== undefined) verifyOpts.timeoutMs = opts.timeout;
      diag.info(`querying gateway ${opts.gateway} (threshold ${opts.threshold ?? 90}%)`);
      const r = await runVerifyCli(spec, verifyOpts);
      process.stdout.write(r.rendered);
      process.exit(r.exitCode);
    } catch (e) {
      process.stderr.write(`verify failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program
  .command('diff <old> <new>')
  .description('Diff the generated target config for two spec versions. Either <old> or <new> may be - to read from stdin (not both). Exits 1 when configs differ, 0 when identical (git diff --exit-code style).')
  .requiredOption('--target <name>', 'Target generator to use for both specs')
  .option('--format <fmt>', 'human|json (default: human)', 'human')
  .option('--vault', 'Resolve $vault.* refs via HashiCorp Vault')
  .option('--aws-secrets', 'Resolve $aws.* refs via AWS Secrets Manager')
  .option('--vault-kv-version <v>', 'Vault KV engine version: 1 or 2 (default 2)', (v) => (v === '1' ? 1 : 2))
  .addHelpText('after', diffExamples)
  .action(async (oldSpec: string, newSpec: string, opts: { target: string; format: string; vault?: boolean; awsSecrets?: boolean; vaultKvVersion?: 1 | 2 }) => {
    try {
      const diag = makeDiagnostics(verbosity());
      if (oldSpec === '-' && newSpec === '-') {
        process.stderr.write('diff failed: only one of <old>/<new> can be - (a single stdin stream)\n');
        process.exit(1);
      }
      if (oldSpec === '-' || newSpec === '-') diag.info('reading spec from stdin');
      oldSpec = await resolveSpecArg(oldSpec);
      newSpec = await resolveSpecArg(newSpec);
      const diffOpts: Parameters<typeof runDiff>[2] = {
        target: opts.target,
        format: opts.format as 'human' | 'json'
      };
      if (opts.vault) diffOpts.vault = true;
      if (opts.awsSecrets) diffOpts.awsSecrets = true;
      if (opts.vaultKvVersion) diffOpts.vaultKvVersion = opts.vaultKvVersion;
      const r = await runDiff(oldSpec, newSpec, diffOpts);
      process.stdout.write(r.rendered);
      process.exit(r.modified.length + r.added.length + r.removed.length > 0 ? 1 : 0);
    } catch (e) {
      process.stderr.write(`diff failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

// ------------------------------------------------------------ init
program
  .command('init <spec>')
  .description('Add empty x-security blocks to operations missing them.')
  .option('--defaults', 'Populate a conservative baseline policy')
  .option('--target <name>', 'Target hint (informational only)')
  .option('--dry-run', 'Print result without modifying the file')
  .action(async (spec: string, opts: { defaults?: boolean; target?: string; dryRun?: boolean }) => {
    try {
      const initOpts: Parameters<typeof runInit>[1] = {
        write: !opts.dryRun
      };
      if (opts.defaults !== undefined) initOpts.defaults = opts.defaults;
      if (opts.target !== undefined) initOpts.target = opts.target;
      const r = await runInit(spec, initOpts);
      if (opts.dryRun) {
        process.stdout.write(r.yaml);
      } else {
        process.stdout.write(`Updated ${r.modifiedEndpoints.length} endpoint(s):\n`);
        for (const m of r.modifiedEndpoints) process.stdout.write(`  - ${m}\n`);
      }
    } catch (e) {
      process.stderr.write(`init failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

// ------------------------------------------------------------ mcp
program
  .command('mcp')
  .description('Run the x-security Cursor MCP server (stdio JSON-RPC). For use in .cursor/mcp.json.')
  .action(async () => {
    try {
      const r = await runMcp();
      process.exit(r.exitCode);
    } catch (e) {
      process.stderr.write(`mcp failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

// ------------------------------------------------------------ verify-bundle
program
  .command('verify-bundle <tarball>')
  .description('Verify a signed x-security release bundle (sha256 file hashes + Ed25519 manifest signature).')
  .option('--public-key <path>', 'Path to an Ed25519 SPKI PEM public key. Defaults to the embedded release key.')
  .action(async (tarball: string, opts: { publicKey?: string }) => {
    try {
      const verifyOpts: VerifyBundleOptions = {};
      if (opts.publicKey !== undefined) verifyOpts.publicKeyPath = opts.publicKey;
      const r = await runVerifyBundle(tarball, verifyOpts);
      if (r.exitCode === 0) {
        process.stdout.write(`${r.message}\n`);
      } else {
        process.stderr.write(`${r.message}\n`);
      }
      process.exit(r.exitCode);
    } catch (e) {
      process.stderr.write(`verify-bundle failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

// ------------------------------------------------------------ migrate
program
  .command('migrate <spec>')
  .description('Rewrite a spec from one schema version to another. v0.4 → v0.5 is the only supported pair.')
  .requiredOption('--from <ver>', 'Source schema version (currently: 0.4)')
  .requiredOption('--to <ver>', 'Target schema version (currently: 0.5)')
  .option('--in-place', 'Rewrite the input file in place. Exit 1 if no change was needed (idempotent).')
  .option('--out <path>', 'Write migrated spec to <path>. Default: <spec>.v<to>.<ext> next to input.')
  .option('--no-suggestions', 'Silence the stderr suggestion advisories. Auto-migrations still happen.')
  .action(async (spec: string, opts: { from: string; to: string; inPlace?: boolean; out?: string; suggestions?: boolean }) => {
    try {
      const migrateOpts: Parameters<typeof runMigrate>[1] = {
        from: opts.from as FromVersion,
        to: opts.to as ToVersion
      };
      if (opts.inPlace !== undefined) migrateOpts.inPlace = opts.inPlace;
      if (opts.out !== undefined) migrateOpts.out = opts.out;
      if (opts.suggestions === false) migrateOpts.noSuggestions = true;
      const r = await runMigrate(spec, migrateOpts);
      for (const c of r.applied) {
        process.stderr.write(`[migrate] info: ${c.location}: ${c.message}\n`);
      }
      for (const s of r.suggestions) {
        process.stderr.write(`[migrate] suggest: ${s.location}: ${s.message}\n`);
      }
      if (opts.inPlace) {
        if (!r.changed) {
          process.stderr.write(`[migrate] no changes needed (already v${opts.to})\n`);
          process.exit(1);
        }
        process.stdout.write(`${r.writtenTo}\n`);
      } else {
        process.stdout.write(`${r.writtenTo}\n`);
      }
    } catch (e) {
      process.stderr.write(`migrate failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

// BYO correctness verbs + operator extras (doctor, completion, update-check,
// config defaults). The trimmed `byo` bin registers the verbs on its own.
registerExtras(program);

// ------------------------------------------------------------ push
program
  .command('push <repoDir>')
  .description(
    'Upload the verified .x-security/ policies to the x-security SaaS. ' +
      'Aborts if the local audit is not 100% cite-backed. Token from X_SECURITY_API_TOKEN env only.',
  )
  .option('--dry-run', 'Assemble + validate the payload and print a summary WITHOUT sending.')
  .action(async (repoDir: string, opts: { dryRun?: boolean }) => {
    try {
      const pushOpts: Parameters<typeof runPush>[1] = {};
      if (opts.dryRun) pushOpts.dryRun = true;
      const r = await runPush(repoDir, pushOpts);
      if (r.dryRun) {
        const p = r.payload;
        process.stdout.write(
          `dry-run — would POST to ${r.apiUrl}/api/web/v1/policies/import\n` +
            `  repoUrl:    ${p.repoUrl}\n` +
            `  commitSha:  ${p.commitSha}\n` +
            `  audit:      routes=${p.audit.routes} controls=${p.audit.controls} ` +
            `citeBacked=${p.audit.citeBacked} coverage=${p.audit.coverage}\n` +
            `  policies:   ${p.policies.length} (${p.policies.map((x) => x.id).join(', ')})\n` +
            `  report:     ${p.report ? `${p.report.length} bytes` : 'none'}\n`,
        );
        return;
      }
      process.stdout.write(`imported ${r.response!.imported} policies → ${r.response!.reportUrl}\n`);
    } catch (e) {
      if (e instanceof PushError) {
        process.stderr.write(`${e.message}\n`);
        process.exit(1);
      }
      process.stderr.write(`push failed: ${(e as Error).message}\n`);
      process.exit(1);
    }
  });

program.parseAsync(process.argv).catch((e) => {
  process.stderr.write(`fatal: ${(e as Error).message}\n`);
  process.exit(1);
});
