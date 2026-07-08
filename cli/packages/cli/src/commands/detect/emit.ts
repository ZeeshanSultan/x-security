// `lazy emit <repoDir> --target waf|report|ci`
//
// Render the compiled .x-security/policies/ into a downstream artifact:
//   waf    — gateway rules via the existing bunkerweb generator (SpecIR built
//            from the per-route policies), written under .x-security/waf/.
//   report — a human report.md headlining the audit cite-coverage proof.
//   ci     — a CI gate (GitHub Actions + GitLab snippet) that re-runs
//            `lazy audit` and fails the build if citeBacked is false.
//
// Rule D-3: the report and CI gate are built on the audit result; they never
// claim coverage the cite byte-match doesn't support. emit reads only what
// compile wrote — it does not detect or re-score.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import type { SpecIR, EndpointIR } from '@x-security/core';
import type { XSecurityPolicy } from '@x-security/detect-core';
import { loadGenerator } from '../../registry.js';
import { runAudit, type AuditResult } from './audit.js';
import {
  xSecurityDir,
  resolvePoliciesDir,
  WAF_DIR,
  CI_DIR,
  REPORT_FILE,
} from './store.js';
import { renderReport } from './report-md.js';
import { renderCiGate } from './ci-gate.js';

export type EmitTarget = 'waf' | 'report' | 'ci';

export interface EmitOptions {
  target: EmitTarget;
}

export interface EmitResult {
  target: EmitTarget;
  written: string[];
}

interface LoadedPolicy {
  method: string;
  routePath: string;
  policy: XSecurityPolicy;
}

async function loadPolicies(repoDir: string): Promise<LoadedPolicy[]> {
  const dir = await resolvePoliciesDir(repoDir);
  let files: string[];
  try {
    files = (await fs.readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    return [];
  }
  const out: LoadedPolicy[] = [];
  for (const file of files.sort()) {
    const raw = await fs.readFile(path.join(dir, file), 'utf8');
    const policy = yaml.load(raw) as XSecurityPolicy | null;
    if (!policy || typeof policy !== 'object') continue;
    const id = file.replace(/\.ya?ml$/, '');
    const m = /^([A-Z]+)__(.*)$/.exec(id);
    if (!m) continue;
    const method = m[1]!;
    const routePath = '/' + m[2]!.replace(/__/g, '/');
    out.push({ method, routePath, policy });
  }
  return out;
}

/** Synthesize a minimal SpecIR from the per-route policies so the existing
 * gateway generators (which consume SpecIR) can render WAF rules without an
 * annotated OpenAPI spec. */
function toSpecIR(policies: LoadedPolicy[]): SpecIR {
  const endpoints: EndpointIR[] = policies.map((p) => ({
    method: p.method.toUpperCase() as EndpointIR['method'],
    path: p.routePath,
    operationId: `${p.method.toLowerCase()}_${p.routePath.replace(/[^A-Za-z0-9]+/g, '_')}`,
    policy: p.policy,
    parameters: [],
    raw: {} as EndpointIR['raw'],
    resolvedVars: new Map<string, string>(),
  }));
  return {
    openapi: '3.1.0',
    dialect: '3.1',
    info: { title: 'x-security BYO-agent policies', version: '0.0.0' },
    servers: [],
    endpoints,
    unprotectedEndpoints: [],
  };
}

async function emitWaf(repoDir: string, policies: LoadedPolicy[]): Promise<string[]> {
  const gen = await loadGenerator('bunkerweb');
  if (!gen) throw new Error('bunkerweb generator unavailable');
  const artifacts = await gen.generate(toSpecIR(policies));
  const outDir = path.join(xSecurityDir(repoDir), WAF_DIR);
  await fs.mkdir(outDir, { recursive: true });
  const written: string[] = [];
  for (const a of artifacts) {
    const dest = path.join(outDir, a.path);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.writeFile(dest, a.content, 'utf8');
    written.push(dest);
  }
  return written;
}

async function emitReport(repoDir: string, audit: AuditResult, policies: LoadedPolicy[]): Promise<string[]> {
  await fs.mkdir(xSecurityDir(repoDir), { recursive: true });
  const dest = path.join(xSecurityDir(repoDir), REPORT_FILE);
  await fs.writeFile(dest, renderReport(audit, policies.map((p) => ({ method: p.method, path: p.routePath }))), 'utf8');
  return [dest];
}

async function emitCi(repoDir: string): Promise<string[]> {
  const outDir = path.join(xSecurityDir(repoDir), CI_DIR);
  await fs.mkdir(outDir, { recursive: true });
  const gate = renderCiGate();
  const written: string[] = [];
  for (const [name, content] of Object.entries(gate)) {
    const dest = path.join(outDir, name);
    await fs.writeFile(dest, content, 'utf8');
    written.push(dest);
  }
  return written;
}

export async function runEmit(repoDir: string, opts: EmitOptions): Promise<EmitResult> {
  const policies = await loadPolicies(repoDir);
  let written: string[];
  switch (opts.target) {
    case 'waf':
      written = await emitWaf(repoDir, policies);
      break;
    case 'report':
      written = await emitReport(repoDir, await runAudit(repoDir), policies);
      break;
    case 'ci':
      written = await emitCi(repoDir);
      break;
    default:
      throw new Error(`unknown emit target "${opts.target as string}" (expected waf|report|ci)`);
  }
  return { target: opts.target, written };
}
