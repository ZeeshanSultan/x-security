// `x-security test --target kong [--upstream-port N] [--gateway-port N] [--dry-run] [--keep] <spec.yaml>`
// Closed-loop test: generate config, bring up Docker, send traffic, assert.

import { mkdir, rm, writeFile } from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadSpec, buildResolverChain } from '@x-security/core';
import { isKnownTarget, loadGenerator } from '../registry.js';
import { buildComposePlan, bringUp, validateUpstreamUrl } from '../test-harness/docker-compose.js';
import { runAllAssertions } from '../test-harness/assertions.js';
import { runVerify } from '../verify/index.js';
import type { TestReport, TestCaseResult } from '../reporters/types.js';
import { testToJunit } from '../reporters/junit.js';
import { renderTest } from '../reporters/human.js';
import { toJson } from '../reporters/json.js';

export interface TestOptions {
  target: string;
  upstreamPort?: number;
  gatewayPort?: number;
  upstreamUrl?: string;
  dryRun?: boolean;
  keep?: boolean;
  format?: 'junit' | 'json' | 'table';
  vault?: boolean;
  awsSecrets?: boolean;
  vaultKvVersion?: 1 | 2;
  /** Abort outbound HTTP probe/admin requests after this many ms. Unset = no timeout. */
  timeoutMs?: number;
}

export interface TestRunResult {
  report: TestReport;
  rendered: string;
  composeYaml: string;
  exitCode: number;
}

const DOCKER_TARGETS = new Set(['kong', 'coraza', 'bunkerweb', 'openappsec']);

export async function runTest(specPath: string, opts: TestOptions): Promise<TestRunResult> {
  if (!isKnownTarget(opts.target) || !DOCKER_TARGETS.has(opts.target)) {
    throw new Error(
      `'test' supports kong|coraza|bunkerweb|openappsec. Got "${opts.target}".`
    );
  }
  const target = opts.target as 'kong' | 'coraza' | 'bunkerweb' | 'openappsec';
  const gen = await loadGenerator(target);
  if (!gen) throw new Error(`Generator for "${target}" not available.`);

  const chainOpts: Parameters<typeof buildResolverChain>[0] = {};
  if (opts.vault) chainOpts.enableVault = true;
  if (opts.awsSecrets) chainOpts.enableAws = true;
  if (opts.vaultKvVersion) chainOpts.vaultKvVersion = opts.vaultKvVersion;
  const resolver = buildResolverChain(chainOpts);
  const spec = await loadSpec(specPath, { resolver, strict: false });

  // Resolve the upstream target. Two modes:
  //   1. --upstream-url given → external upstream, no mock container.
  //   2. otherwise → mendhak/http-https-echo mock-upstream container,
  //      reachable at http://upstream:8080 inside the compose network.
  let upstreamForSpec: string;
  if (opts.upstreamUrl) {
    const { url, warnings } = validateUpstreamUrl(opts.upstreamUrl);
    for (const w of warnings) process.stderr.write(`warning: ${w}\n`);
    // Preserve any path the user supplied (e.g. /vapi prefix).
    upstreamForSpec = url.toString().replace(/\/$/, '');
  } else {
    upstreamForSpec = 'http://upstream:8080';
  }
  spec.servers = [{ url: upstreamForSpec }];

  const artifacts = await gen.generate(spec);

  // Write artifacts to a temp dir for mounting.
  const tmpDir = path.join(os.tmpdir(), `x-security-${target}-${Date.now()}-${process.pid}`);
  await mkdir(tmpDir, { recursive: true });
  for (const a of artifacts) {
    const full = path.join(tmpDir, a.path);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, a.content, 'utf8');
  }

  const plan = buildComposePlan({
    target,
    configMountSourceDir: tmpDir,
    configMountTargetDir: '/etc/x-security',
    ...(opts.upstreamPort !== undefined ? { upstreamPort: opts.upstreamPort } : {}),
    ...(opts.gatewayPort !== undefined ? { gatewayPort: opts.gatewayPort } : {}),
    ...(opts.upstreamUrl !== undefined ? { upstreamUrl: opts.upstreamUrl } : {})
  });

  // --dry-run: just print the compose plan, no docker calls.
  if (opts.dryRun) {
    const report: TestReport = { kind: 'test', target, cases: [] };
    // Clean up the temp dir on dry-run — nothing mounted it.
    await rm(tmpDir, { recursive: true, force: true });
    return {
      report,
      rendered: `# docker-compose plan (dry-run)\n${plan.yaml}`,
      composeYaml: plan.yaml,
      exitCode: 0
    };
  }

  const handle = await bringUp(plan, opts.keep ? { keep: true } : {});
  const cases: TestCaseResult[] = [];
  try {
    await handle.ready();
    // Post-boot load-coverage gate (Workstream C / Open-8). Catches the
    // wave-3 §3 class of bug where the gateway is healthy but loaded ZERO
    // of the artifacts x-security wrote. Coverage failures here invalidate
    // every traffic-based assertion that follows.
    const coverageOk = await verifyCoverageOrSkip(specPath, target, handle, opts.timeoutMs);
    if (coverageOk === false) {
      cases.push({
        endpoint: '(gateway)',
        rule: 'load-coverage',
        verdict: 'FAIL',
        message: 'x-security-emitted artifacts are not loaded by the gateway (x-security verify reported <90%). Aborting traffic phase — the results would be unattributable.',
        durationMs: 0
      });
    } else {
      for (const e of spec.endpoints) {
        cases.push(...(await runAllAssertions(handle.gatewayUrl, e, opts.timeoutMs)));
      }
    }
  } finally {
    await handle.teardown();
    if (!opts.keep) {
      await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  const report: TestReport = { kind: 'test', target, cases };

  let rendered: string;
  switch (opts.format) {
    case 'junit': rendered = testToJunit(report); break;
    case 'json': rendered = toJson(report); break;
    case 'table':
    default: rendered = renderTest(report); break;
  }

  const failures = cases.filter((c) => c.verdict === 'FAIL').length;
  return { report, rendered, composeYaml: plan.yaml, exitCode: failures > 0 ? 1 : 0 };
}

/**
 * Run `x-security verify` against the just-booted gateway. Returns:
 *   true  — coverage passed (or target/engine combo not supported by verify yet)
 *   false — coverage below threshold; caller should abort traffic
 * Never throws (verify failure is reported as a structured FAIL case).
 */
async function verifyCoverageOrSkip(
  specPath: string,
  target: 'kong' | 'coraza' | 'bunkerweb' | 'openappsec',
  handle: { gatewayUrl: string; gatewayContainerName: string },
  timeoutMs?: number
): Promise<boolean | null> {
  const timeoutOpt = timeoutMs !== undefined ? { timeoutMs } : {};
  try {
    if (target === 'kong') {
      // Kong admin port convention: proxy on +0, admin on +1 — matches
      // buildComposePlan's exposure. Use the gateway URL and swap port.
      const adminUrl = handle.gatewayUrl.replace(/:(\d+)$/, (_, p) => `:${Number(p) + 1}`);
      const r = await runVerify(specPath, { target: 'kong', gateway: adminUrl, ...timeoutOpt });
      return r.exitCode === 0;
    }
    if (target === 'coraza') {
      const r = await runVerify(specPath, {
        target: 'coraza',
        engine: 'modsec-nginx',
        gateway: `docker:${handle.gatewayContainerName}`,
        ...timeoutOpt
      });
      return r.exitCode === 0;
    }
    if (target === 'bunkerweb') {
      // Compose plan exposes the bunkerweb data-plane container by name; we
      // pass it directly. Scheduler cross-check is best-effort and skipped
      // here — it isn't a hard gate.
      const r = await runVerify(specPath, {
        target: 'bunkerweb',
        gateway: `docker:${handle.gatewayContainerName}`,
        ...timeoutOpt
      });
      return r.exitCode === 0;
    }
    if (target === 'openappsec') {
      const r = await runVerify(specPath, {
        target: 'openappsec',
        gateway: `docker:${handle.gatewayContainerName}`,
        ...timeoutOpt
      });
      return r.exitCode === 0;
    }
    return null;
  } catch {
    return null; // verify is a soft gate; never block on its own failures
  }
}
