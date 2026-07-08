// `x-security generate --target <t> [--out <dir>] [--dry-run] <spec.yaml>`
// Loads the spec, looks up the registered generator, writes artifacts.

import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import {
  loadSpec,
  buildResolverChain,
  assertNoPlaceholders,
  assertEmission,
  assertFidelity,
  StrictnessViolation,
  UnresolvedVariableError
} from '@x-security/core';
import { isKnownTarget, loadGenerator, type TargetName } from '../registry.js';

export interface GenerateOptions {
  target: string;
  out?: string;
  dryRun?: boolean;
  strict?: boolean;
  vault?: boolean;
  awsSecrets?: boolean;
  vaultKvVersion?: 1 | 2;
  /** Kong-only: emit consumers + per-plugin credentials. Default true. */
  withConsumers?: boolean;
  /** Kong-only: deployment topology. Default 'standalone'. */
  kongDeployment?: 'standalone' | 'behind-proxy' | 'with-coraza' | 'with-istio';
  /** Kong-only: edition. Default 'oss'. */
  kongEdition?: 'oss' | 'enterprise';
  /** Kong-only: deployment runs in DB-less mode (`KONG_DATABASE=off`).
   *  When set, per-identity rate-limit buckets fall back to `policy: local`
   *  with a structured warning instead of `policy: cluster`. Default false. */
  kongDbless?: boolean;
  /** Kong-only (W21-C): explicit rate-limit policy. Default `local`
   *  (safe for OSS DB-less). `cluster` opts in to cross-instance counter
   *  sharing — operator confirms Kong is running in database mode. */
  kongPolicy?: 'local' | 'cluster';
  /** Coraza-only: target engine. Default 'modsec-nginx'. */
  corazaEngine?: string;
  /** Coraza-only (coraza-spoa / coraza-go): HAProxy peer-replication spec.
   *  Format: `name1:host1:port1,name2:host2:port2`. When supplied, emitted
   *  haproxy-stick-tables.cfg includes a `peers x-security` section so the
   *  stick-table counters replicate across instances. */
  corazaPeers?: string;
  /** S3 fidelity gate (opt-in): exit 4 if any spec field is unenforceable
   *  on the chosen target. Independent of --strict (S1/S2). */
  strictFidelity?: boolean;
}

export interface GenerateResult {
  artifactPaths: string[];
  artifacts: Array<{ path: string; content: string; format: string }>;
  /** Generator-emitted warnings (e.g. Kong HS256 downgrade). Caller may
   *  forward these to stderr; they are not errors. */
  warnings: string[];
}

export async function runGenerate(specPath: string, opts: GenerateOptions): Promise<GenerateResult> {
  if (!isKnownTarget(opts.target)) {
    throw new Error(
      `Unknown target "${opts.target}". Known: kong, coraza, bunkerweb, openappsec, firewall.`
    );
  }
  const target: TargetName = opts.target;
  const generator = await loadGenerator(target);
  if (!generator) {
    throw new Error(
      `Generator for target "${target}" is not available in this build.\n` +
        `(Module packages/cli/src/generators/${target}/index.ts is missing or failed to import.)`
    );
  }

  // Per-target options channel.
  if (target === 'kong') {
    const configure = (generator as unknown as {
      configure?: (o: {
        withConsumers?: boolean;
        deployment?: 'standalone' | 'behind-proxy' | 'with-coraza' | 'with-istio';
        edition?: 'oss' | 'enterprise';
        dbless?: boolean;
        policy?: 'local' | 'cluster';
      }) => void;
    }).configure;
    if (typeof configure === 'function') {
      const cfg: Parameters<NonNullable<typeof configure>>[0] = {};
      if (opts.withConsumers !== undefined) cfg.withConsumers = opts.withConsumers;
      if (opts.kongDeployment !== undefined) cfg.deployment = opts.kongDeployment;
      if (opts.kongEdition !== undefined) cfg.edition = opts.kongEdition;
      if (opts.kongDbless !== undefined) cfg.dbless = opts.kongDbless;
      if (opts.kongPolicy !== undefined) cfg.policy = opts.kongPolicy;
      if (Object.keys(cfg).length > 0) configure(cfg);
    }
  }
  if (target === 'coraza' && (opts.corazaEngine || opts.corazaPeers)) {
    const configure = (generator as unknown as {
      configure?: (o: { engine?: string; peers?: string }) => void;
    }).configure;
    if (typeof configure === 'function') {
      const cfg: { engine?: string; peers?: string } = {};
      if (opts.corazaEngine) cfg.engine = opts.corazaEngine;
      if (opts.corazaPeers) cfg.peers = opts.corazaPeers;
      configure(cfg);
    }
  }

  const chainOpts: Parameters<typeof buildResolverChain>[0] = {};
  if (opts.vault) chainOpts.enableVault = true;
  if (opts.awsSecrets) chainOpts.enableAws = true;
  if (opts.vaultKvVersion) chainOpts.vaultKvVersion = opts.vaultKvVersion;
  const resolver = buildResolverChain(chainOpts);
  const strict = opts.strict ?? true;
  // S1 resolution gate. Two flavors:
  //   (a) unresolved variable — loadSpec throws UnresolvedVariableError. We
  //       re-cast as StrictnessViolation so the bin layer's single catch maps
  //       both flavors to exit code 2.
  //   (b) resolved-but-placeholder — assertNoPlaceholders runs after load.
  let spec;
  try {
    spec = await loadSpec(specPath, { resolver, strict });
  } catch (e) {
    if (e instanceof UnresolvedVariableError) {
      throw new StrictnessViolation('S1', e.message, { variables: e.variables, paths: e.paths });
    }
    throw e;
  }
  if (strict) assertNoPlaceholders(spec);
  const artifacts = await generator.generate(spec);
  // S2 emission gate: every endpoint must have produced at least one
  // enforceable artifact. Runs only under --strict so non-strict callers
  // can still inspect partial output.
  if (strict) assertEmission(spec, artifacts);
  // S3 fidelity gate: opt-in via --strict-fidelity. Reads the same
  // capability matrix the --feasible report uses so the two never drift.
  if (opts.strictFidelity) {
    assertFidelity(spec, generator.capabilities(), { targetName: target });
  }

  const outDir = opts.out ?? path.join(process.cwd(), 'x-security-out', target);
  const artifactPaths: string[] = [];

  if (!opts.dryRun) {
    await mkdir(outDir, { recursive: true });
    for (const a of artifacts) {
      const full = path.join(outDir, a.path);
      await mkdir(path.dirname(full), { recursive: true });
      await writeFile(full, a.content, 'utf8');
      artifactPaths.push(full);
    }
  } else {
    for (const a of artifacts) {
      artifactPaths.push(path.join(outDir, a.path));
    }
  }

  const warnings = (generator as unknown as { lastWarnings?: readonly string[] }).lastWarnings ?? [];
  const aggregated = [...warnings];

  // wave-8: firewall is L3/L4 only. If the operator picked it as the sole
  // target, surface a stderr warning so they don't think they shipped
  // application-layer policy. The bin layer forwards `warnings` to stderr
  // as `warning: <msg>`; the body below contains the literal "WARNING:" so
  // grep-based smoke checks anchor on it.
  if (target === 'firewall') {
    aggregated.push(
      'WARNING: --target firewall produces L3/L4 controls only (IP/CIDR allow/deny, ' +
        'mTLS source-IP allowlists, port rate-limits). It does NOT enforce application-' +
        'layer policy (auth, request schema, body allowlists, response shape). Most ' +
        'vAPI-class API security findings will pass through. Pair with a L7 generator ' +
        '(kong, coraza, bunkerweb, envoy) for full coverage.'
    );
  }

  return {
    artifactPaths,
    artifacts: artifacts.map((a) => ({ path: a.path, content: a.content, format: a.format })),
    warnings: aggregated
  };
}
