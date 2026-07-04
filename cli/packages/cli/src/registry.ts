// Generator registry. Lazily imports each generator module. If a generator
// file is missing or fails to import, that target is skipped (other agents
// own those files; we degrade gracefully so the CLI is still usable for
// commands that don't need every target).
//
// Two kinds of target:
//   - native generators (kong/coraza/bunkerweb/openappsec/firewall/envoy):
//     a full Generator under ./generators/<name>/index.js.
//   - managed-cloud compilers (aws-apigw/cloudflare): the capability matrix
//     is the product surface the feasibility/report reporters need; the
//     compilers don't ship a Generator. We adapt their compiler-owned
//     capability matrices (the same matrices their compile() reports) into a
//     report-only Generator whose generate() is a no-op. The matrices stay the
//     single source of truth in the compiler packages (D-1: status mirrors
//     what the compiler emits) — we only adapt their shape here.

import type { Generator, CapabilityMatrix, SpecIR, ConfigArtifact } from '@writ/core';
import { AWS_APIGW_CAPABILITIES } from '@writ/aws-apigw-compiler';
import { CF_CAPABILITIES } from '@writ/cloudflare-compiler';

export type TargetName =
  | 'kong'
  | 'coraza'
  | 'bunkerweb'
  | 'openappsec'
  | 'firewall'
  | 'envoy'
  | 'aws-apigw'
  | 'cloudflare';

export const KNOWN_TARGETS: readonly TargetName[] = [
  'kong',
  'coraza',
  'bunkerweb',
  'openappsec',
  'firewall',
  'envoy',
  'aws-apigw',
  'cloudflare'
] as const;

const NAMED_EXPORT: Record<TargetName, string> = {
  kong: 'kongGenerator',
  coraza: 'corazaGenerator',
  bunkerweb: 'bunkerwebGenerator',
  openappsec: 'openappsecGenerator',
  firewall: 'firewallGenerator',
  envoy: 'envoyGenerator',
  'aws-apigw': 'awsApigwGenerator',
  cloudflare: 'cloudflareGenerator'
};

const cache = new Map<TargetName, Generator | null>();

/** Pre-seed the registry with a generator instead of lazy-importing it. The
 *  BYO runtime bundle uses this to make `bunkerweb` statically reachable for
 *  esbuild — the lazy `import(\`./generators/${target}\`)` is a template-literal
 *  dynamic import esbuild cannot inline, so the bundled CLI registers the one
 *  generator the BYO `emit --target waf` path needs at startup. The full CLI
 *  keeps the lazy path untouched. */
export function registerGenerator(target: TargetName, gen: Generator): void {
  cache.set(target, gen);
}

/** Managed-cloud compilers expose a capability matrix but no Generator. Adapt
 *  the compiler-owned matrix into a report-only Generator. generate() is a
 *  no-op: these targets are feasibility/report surfaces, not config emitters
 *  in the CLI. The matrix is the compiler's; we don't re-author levels here. */
function matrixGenerator(
  name: TargetName,
  fields: Readonly<Record<string, CapabilityMatrix['fields'][string]>>
): Generator {
  return {
    name,
    targets: [name],
    generate(_spec: SpecIR): ConfigArtifact[] {
      return [];
    },
    capabilities(): CapabilityMatrix {
      return { fields: { ...fields } };
    }
  };
}

const CLOUD_GENERATORS: Partial<Record<TargetName, () => Generator>> = {
  'aws-apigw': () => matrixGenerator('aws-apigw', AWS_APIGW_CAPABILITIES),
  cloudflare: () => matrixGenerator('cloudflare', CF_CAPABILITIES)
};

function pickGenerator(mod: Record<string, unknown>, target: TargetName): Generator | null {
  const candidates: unknown[] = [mod.default, mod.generator, mod[NAMED_EXPORT[target]]];
  for (const c of candidates) {
    if (c && typeof c === 'object' && 'generate' in (c as object)) {
      return c as Generator;
    }
  }
  return null;
}

export async function loadGenerator(target: TargetName): Promise<Generator | null> {
  if (cache.has(target)) return cache.get(target) ?? null;

  const cloud = CLOUD_GENERATORS[target];
  if (cloud) {
    const gen = cloud();
    cache.set(target, gen);
    return gen;
  }

  try {
    const mod = (await import(`./generators/${target}/index.js`)) as Record<string, unknown>;
    const gen = pickGenerator(mod, target);
    cache.set(target, gen);
    return gen;
  } catch {
    cache.set(target, null);
    return null;
  }
}

export async function listAvailableTargets(): Promise<TargetName[]> {
  const out: TargetName[] = [];
  for (const t of KNOWN_TARGETS) {
    const g = await loadGenerator(t);
    if (g) out.push(t);
  }
  return out;
}

export function isKnownTarget(t: string): t is TargetName {
  return (KNOWN_TARGETS as readonly string[]).includes(t);
}
