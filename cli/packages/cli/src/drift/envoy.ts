/**
 * Envoy drift detector (file-mode only).
 *
 * Accepts either:
 *   - a single `envoy.yaml` path (with the Lua source inlined via
 *     `envoy.filters.http.lua.inline_code`), OR
 *   - a directory containing `envoy.yaml` + `writ.lua`.
 *
 * Strategy:
 *   1. Regenerate expected `envoy.yaml` + `writ.lua` from the SpecIR via
 *      the Envoy generator.
 *   2. Extract the per-endpoint Lua policy blocks (sentinel markers
 *      `-- writ:<METHOD>:<path>:START` ... `-- writ:END`) from
 *      both the expected and the actual Lua source. The actual Lua is read
 *      from `writ.lua` if present, else from the inlined block inside
 *      `envoy.yaml` under `inline_code: |`.
 *   3. Diff the two block sets:
 *        - Endpoint block missing             → CRITICAL.
 *        - Endpoint block present but key
 *          policy line missing                → severity per the table in
 *          packages/cli/STATUS.md lines 75-86 (auth=CRITICAL, body=HIGH,
 *          content-type=MEDIUM, ...).
 *        - Block body byte-drift (no specific
 *          policy line missing detected)      → MEDIUM.
 *        - Rate-limit descriptor missing in
 *          deployed envoy.yaml                → CRITICAL.
 *        - Unknown writ-tagged block on
 *          deployed config                    → LOW.
 */

import { readFile, stat } from 'node:fs/promises';
import * as path from 'node:path';
import yaml from 'js-yaml';
import type { SpecIR, EndpointIR } from '@writ/core';
import type { DriftIssue, DriftReport, DriftSeverity } from '../reporters/types.js';
import { envoyGenerator } from '../generators/envoy/index.js';
import { endpointLabel } from './kong-shared.js';

export interface EnvoyDriftOptions {
  /** Path to either an envoy.yaml file or a directory containing it + writ.lua. */
  filePath: string;
  /** Raw envoy.yaml override (for tests). */
  yamlContent?: string;
  /** Raw writ.lua override (for tests). Takes precedence over inlined Lua. */
  luaContent?: string;
}

interface EndpointBlock {
  method: string;
  pathTemplate: string;
  lines: string[];
}

const START_RE = /^\s*--\s*writ:([A-Z]+):(.+):START\s*$/;
const END_RE = /^\s*--\s*writ:END\s*$/;

/** Extract every `-- writ:<METHOD>:<path>:START` ... `-- writ:END`
 * block from a Lua source. Markers that lack a matching END are ignored (the
 * detector will report the missing endpoint via the expected-block iteration). */
function extractEndpointBlocks(luaSource: string): Map<string, EndpointBlock> {
  const out = new Map<string, EndpointBlock>();
  const lines = luaSource.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const l = lines[i] ?? '';
    const m = START_RE.exec(l);
    if (!m) {
      i++;
      continue;
    }
    const method = m[1]!;
    const pathTemplate = m[2]!;
    const body: string[] = [];
    let j = i + 1;
    let closed = false;
    while (j < lines.length) {
      const ln = lines[j] ?? '';
      if (END_RE.test(ln)) {
        closed = true;
        break;
      }
      body.push(ln);
      j++;
    }
    if (closed) {
      const key = `${method} ${pathTemplate}`;
      out.set(key, { method, pathTemplate, lines: body });
      i = j + 1;
    } else {
      i++;
    }
  }
  return out;
}

/** Extract the inlined Lua source from a parsed Envoy YAML document, if any. */
function extractInlineLua(rawYaml: string): string | null {
  // We avoid full YAML parsing for the Lua scalar because js-yaml will
  // re-normalize indentation; instead grep for the literal `inline_code: |`
  // marker and slurp the following indented block.
  const lines = rawYaml.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i] ?? '';
    const m = /^(\s*)inline_code:\s*\|\s*$/.exec(l);
    if (!m) continue;
    const baseIndent = m[1]!.length;
    const body: string[] = [];
    let j = i + 1;
    // Capture every following line whose indent strictly exceeds baseIndent,
    // or which is blank. Stop at the first less-indented non-blank line.
    while (j < lines.length) {
      const ln = lines[j] ?? '';
      if (ln.trim() === '') {
        body.push('');
        j++;
        continue;
      }
      const indent = ln.match(/^(\s*)/)?.[1]?.length ?? 0;
      if (indent <= baseIndent) break;
      // Strip the YAML block's indent (baseIndent + 2 from `        ` is the
      // typical emit, but we conservatively strip whatever leading indent
      // belongs to the first non-blank line and consistently apply it).
      body.push(ln.slice(baseIndent + 2));
      j++;
    }
    return body.join('\n');
  }
  return null;
}

/**
 * Extract per-route rate-limit `stat_prefix` values from the deployed YAML.
 * Wave-9 emits per-route token buckets under
 * `routes[].typed_per_filter_config["envoy.filters.http.local_ratelimit"]`,
 * each with a `stat_prefix`. We collect those prefixes as the drift signal
 * (the wave-7 `rate_limit_descriptors` block no longer exists).
 */
function extractRateLimitStatPrefixes(rawYaml: string): Set<string> {
  const out = new Set<string>();
  try {
    const doc = yaml.load(rawYaml) as unknown;
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) { for (const v of node) walk(v); return; }
      if (node && typeof node === 'object') {
        const obj = node as Record<string, unknown>;
        if (typeof obj.stat_prefix === 'string' &&
            obj.stat_prefix !== 'writ_chain_ratelimit' &&
            obj.stat_prefix !== 'writ_hcm') {
          // Only emit prefixes that match the generator's per-route shape.
          if (/_ratelimit$/.test(obj.stat_prefix)) out.add(obj.stat_prefix);
        }
        for (const v of Object.values(obj)) walk(v);
      }
    };
    walk(doc);
  } catch {
    // Malformed YAML — treat as empty set.
  }
  return out;
}

/** Does the deployed YAML contain a jwt_authn rule for this endpoint's path regex? */
function deployedHasJwtRule(rawYaml: string, regex: string): boolean {
  // Cheap substring search — the generator emits a deterministic
  // `regex: "<safe-regex>"` line for every protected endpoint.
  return rawYaml.includes(`regex: ${JSON.stringify(regex)}`);
}

/** Does the deployed YAML contain an RBAC policy named with this fragment? */
function deployedHasRbacPolicy(rawYaml: string, fragment: string): boolean {
  return rawYaml.includes(fragment);
}

/** Has the endpoint declared a rateLimit policy that the generator would emit? */
function endpointHasRateLimit(ep: EndpointIR): boolean {
  const rl = ep.policy.rateLimit;
  if (!rl) return false;
  if (Array.isArray(rl)) return rl.length > 0;
  return true;
}

/**
 * Inspect an endpoint block to determine which policy lines are present.
 * Each indicator is a substring uniquely emitted by the generator for that
 * policy field. Stable strings — when the Lua template changes, update these.
 */
interface BlockSignals {
  hasBodySize: boolean;
  hasContentType: boolean;
  hasHeaderGuard: boolean;
}

function signalsFor(block: EndpointBlock): BlockSignals {
  const joined = block.lines.join('\n');
  return {
    hasBodySize: /:status"\]\s*=\s*"413"/.test(joined),
    hasContentType: /:status"\]\s*=\s*"415"/.test(joined),
    hasHeaderGuard: /headerInjectionGuard/.test(joined)
  };
}

function diffEndpoint(
  ep: EndpointIR,
  expected: EndpointBlock,
  actual: EndpointBlock
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  const label = endpointLabel(ep);
  const expS = signalsFor(expected);
  const actS = signalsFor(actual);

  if (expS.hasBodySize && !actS.hasBodySize) {
    issues.push({
      endpoint: label,
      field: 'request.maxBodySize',
      severity: 'HIGH',
      expected: 'present',
      actual: 'missing',
      message: 'Envoy Lua block missing request.maxBodySize (413) check'
    });
  }
  if (expS.hasContentType && !actS.hasContentType) {
    issues.push({
      endpoint: label,
      field: 'request.contentType',
      severity: 'MEDIUM',
      expected: 'present',
      actual: 'missing',
      message: 'Envoy Lua block missing request.contentType (415) check'
    });
  }
  if (expS.hasHeaderGuard && !actS.hasHeaderGuard) {
    issues.push({
      endpoint: label,
      field: 'request.headerInjectionGuard',
      severity: 'HIGH',
      expected: 'present',
      actual: 'missing',
      message: 'Envoy Lua block missing headerInjectionGuard (400) check'
    });
  }

  // If no specific signal flagged but the block body differs from expected,
  // emit a generic MEDIUM byte-drift finding so operators investigate.
  if (issues.length === 0) {
    const expBody = expected.lines.map((l) => l.trimEnd()).join('\n').trim();
    const actBody = actual.lines.map((l) => l.trimEnd()).join('\n').trim();
    if (expBody !== actBody) {
      issues.push({
        endpoint: label,
        field: 'endpoint.body',
        severity: 'MEDIUM',
        expected: expBody,
        actual: actBody,
        message: 'Envoy Lua block body drift (no policy line missing — review manually)'
      });
    }
  }

  return issues;
}

/**
 * Read source files from disk OR honor inline overrides. Mirrors the
 * firewall detector's `readMaybeDir` shape: `filePath` may be a file or a
 * directory.
 */
async function readSources(opts: EnvoyDriftOptions): Promise<{ envoyYaml: string; lua: string | null }> {
  if (opts.yamlContent !== undefined || opts.luaContent !== undefined) {
    return {
      envoyYaml: opts.yamlContent ?? '',
      lua: opts.luaContent ?? null
    };
  }
  try {
    const s = await stat(opts.filePath);
    if (s.isDirectory()) {
      let envoyYaml = '';
      let lua: string | null = null;
      try {
        envoyYaml = await readFile(path.join(opts.filePath, 'envoy.yaml'), 'utf8');
      } catch {
        envoyYaml = '';
      }
      try {
        lua = await readFile(path.join(opts.filePath, 'writ.lua'), 'utf8');
      } catch {
        lua = null;
      }
      return { envoyYaml, lua };
    }
  } catch {
    // fall through
  }
  const envoyYaml = await readFile(opts.filePath, 'utf8');
  return { envoyYaml, lua: null };
}

export async function detectEnvoyDrift(
  spec: SpecIR,
  opts: EnvoyDriftOptions
): Promise<DriftReport> {
  const { envoyYaml: actualYaml, lua: actualLuaFile } = await readSources(opts);

  // The deployed Lua source is preferentially the standalone `writ.lua`;
  // fall back to the YAML's `inline_code` block. This matches the generator's
  // two-artifact emission shape.
  const actualLua = actualLuaFile ?? extractInlineLua(actualYaml) ?? '';

  const expectedArtifacts = await Promise.resolve(envoyGenerator.generate(spec));
  const expectedYaml = expectedArtifacts.find((a) => a.path === 'envoy.yaml')?.content ?? '';
  const expectedLua = expectedArtifacts.find((a) => a.path === 'writ.lua')?.content ?? '';

  const expectedBlocks = extractEndpointBlocks(expectedLua);
  const actualBlocks = extractEndpointBlocks(actualLua);

  const issues: DriftIssue[] = [];

  // ── Per-endpoint policy blocks ────────────────────────────────────────
  for (const ep of spec.endpoints) {
    const key = `${ep.method} ${ep.path}`;
    const exp = expectedBlocks.get(key);
    if (!exp) continue; // generator emitted no block for this endpoint
    const act = actualBlocks.get(key);
    if (!act) {
      issues.push({
        endpoint: endpointLabel(ep),
        field: 'endpoint',
        severity: 'CRITICAL',
        expected: 'present',
        actual: 'missing',
        message: `Envoy Lua block missing for ${ep.method} ${ep.path}`
      });
      continue;
    }
    issues.push(...diffEndpoint(ep, exp, act));
  }

  // ── Per-route rate-limit buckets (YAML, wave-9 native filter) ─────────
  const expectedPrefixes = extractRateLimitStatPrefixes(expectedYaml);
  const actualPrefixes = extractRateLimitStatPrefixes(actualYaml);
  for (const prefix of expectedPrefixes) {
    if (actualPrefixes.has(prefix)) continue;
    issues.push({
      endpoint: prefix,
      field: 'rateLimit.descriptor',
      severity: 'CRITICAL',
      expected: 'present',
      actual: 'missing',
      message: `Envoy per-route local_ratelimit bucket missing for stat_prefix=${prefix}`
    });
    void endpointHasRateLimit;
  }

  // ── jwt_authn rules (YAML, wave-9 native filter) ──────────────────────
  for (const ep of spec.endpoints) {
    const auth = ep.policy.authentication;
    if (!auth || auth.type !== 'bearer-jwt' || !auth.jwksUri) continue;
    // The generator emits a safe_regex path matcher per protected endpoint.
    // Re-derive it from the spec so we don't have to parse the YAML twice.
    const regex = `^${ep.path.replace(/\{[^}]+\}/g, '[^/]+').replace(/\./g, '\\.')}$`;
    if (!deployedHasJwtRule(actualYaml, regex)) {
      issues.push({
        endpoint: endpointLabel(ep),
        field: 'authentication',
        severity: 'CRITICAL',
        expected: `jwt_authn rule for ${regex}`,
        actual: 'missing',
        message: `Envoy jwt_authn rule missing for ${endpointLabel(ep)} — JWT validation will not run`
      });
    }
  }

  // ── rbac policies (YAML, wave-9 native filter) ────────────────────────
  for (const ep of spec.endpoints) {
    const authz = ep.policy.authorization;
    if (!authz || authz.type !== 'rbac' || !authz.roles?.length) continue;
    for (const role of authz.roles) {
      // The generator emits one policy per (operationId, role). We look for
      // the role fragment in the YAML — cheap and stable.
      const fragment = `"writ-rbac-`;
      const roleFragment = role.replace(/[^a-z0-9]+/gi, '-');
      if (!deployedHasRbacPolicy(actualYaml, fragment) || !actualYaml.includes(`-${roleFragment}":`)) {
        issues.push({
          endpoint: endpointLabel(ep),
          field: 'authorization.role',
          severity: 'CRITICAL',
          expected: `rbac policy for role=${role}`,
          actual: 'missing',
          message: `Envoy rbac policy missing for ${endpointLabel(ep)} role=${role}`
        });
      }
    }
  }

  // ── Unknown writ-tagged blocks in actual ────────────────────────
  for (const [key, block] of actualBlocks.entries()) {
    if (expectedBlocks.has(key)) continue;
    issues.push({
      endpoint: key,
      field: 'unknown-endpoint',
      severity: 'LOW',
      expected: 'absent',
      actual: 'present',
      message: `Unknown Writ-tagged endpoint block in deployed Lua: ${block.method} ${block.pathTemplate}`
    });
  }

  return {
    kind: 'drift',
    target: 'envoy',
    gatewaySource: opts.filePath,
    issues
  };
}
