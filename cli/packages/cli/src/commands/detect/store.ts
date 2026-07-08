// On-disk layout for the .x-security/ artifact store.
//
// A compiled route is two files under .x-security/policies/:
//   <id>.yaml        — the x-security policy (schema-valid on its own)
//   <id>.cites.json  — the detection metadata: the file:line:quote citations
//                      that back each control. Kept OUT of the policy because
//                      the x-security schema rejects unknown top-level props,
//                      and cites are detection provenance, not gateway config.
//
// <id> = "<METHOD>__<path-with-slashes-as-double-underscore>" so the filename
// is filesystem-safe and round-trips to the endpointId.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import type { Citation, XSecurityPolicy } from '@x-security/detect-core';

export const POLICIES_DIR = 'policies';
export const WAF_DIR = 'waf';
export const CI_DIR = 'ci';
export const REPORT_FILE = 'report.md';

export interface PolicyCites {
  endpointId: string;
  route: { method: string; path: string };
  cites: Citation[];
}

/** "GET /api/user/:id" → "GET__api_user_:id". Reversible enough for audit. */
export function endpointToFileId(method: string, routePath: string): string {
  const safePath = routePath
    .replace(/^\//, '')
    .replace(/\//g, '__')
    .replace(/[^A-Za-z0-9_:.\-{}#]/g, '_');
  return `${method.toUpperCase()}__${safePath || 'root'}`;
}

/** Canonical artifact dir (writes go here). */
export function xSecurityDir(repoDir: string): string {
  return path.join(repoDir, '.x-security');
}

/** Legacy artifact dir (pre-rebrand). Reads fall back to it for back-compat. */
export function legacyWritDir(repoDir: string): string {
  return path.join(repoDir, '.x-security');
}

/**
 * Resolve the artifact dir to READ from: prefer the canonical `.x-security/`,
 * fall back to a pre-existing legacy `.x-security/` (emitting a one-line deprecation
 * warning), else default to canonical. Writers always use {@link xSecurityDir}.
 */
export async function resolveArtifactDir(repoDir: string): Promise<string> {
  const canonical = xSecurityDir(repoDir);
  try { await fs.access(canonical); return canonical; } catch { /* fall through */ }
  const legacy = legacyWritDir(repoDir);
  try {
    await fs.access(legacy);
    console.warn('[x-security] reading legacy .x-security/ artifact dir; run a compile to migrate to .x-security/');
    return legacy;
  } catch { /* fall through */ }
  return canonical;
}

/** Policies dir under the canonical artifact dir (write path). */
export function policiesDir(repoDir: string): string {
  return path.join(xSecurityDir(repoDir), POLICIES_DIR);
}

/** Policies dir to READ from, honoring the legacy `.x-security/` fallback. */
export async function resolvePoliciesDir(repoDir: string): Promise<string> {
  return path.join(await resolveArtifactDir(repoDir), POLICIES_DIR);
}

/** Persist a compiled policy + its cite sidecar under .x-security/policies/.
 * Used by `compile --write`. The sidecar carries the detection provenance the
 * audit step byte-matches; it is written ONLY when there are cites to record
 * (an empty sidecar would let audit pass a control with no citation — D-3). */
export async function persistPolicy(
  repoDir: string,
  route: { method: string; path: string },
  policy: XSecurityPolicy,
  cites: Citation[],
): Promise<{ policyPath: string; citesPath: string }> {
  const dir = policiesDir(repoDir);
  await fs.mkdir(dir, { recursive: true });
  const id = endpointToFileId(route.method, route.path);
  const policyPath = path.join(dir, `${id}.yaml`);
  const citesPath = path.join(dir, `${id}.cites.json`);
  await fs.writeFile(policyPath, yaml.dump(policy, { sortKeys: true }), 'utf8');
  const sidecar: PolicyCites = {
    endpointId: `${route.method.toUpperCase()} ${route.path}`,
    route: { method: route.method.toUpperCase(), path: route.path },
    cites,
  };
  await fs.writeFile(citesPath, JSON.stringify(sidecar, null, 2) + '\n', 'utf8');
  return { policyPath, citesPath };
}
