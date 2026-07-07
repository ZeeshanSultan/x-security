// `lazy push <repoDir>` — Phase 4 SaaS upsell.
//
// Bundles the locally-generated, CLI-verified policies under .writ/ and
// POSTs them to the x-security SaaS import endpoint. This is the ONLY verb that
// leaves the user's machine, so it carries three hard gates:
//
//   D-1 (no shortcuts that mask quality): we re-run the local audit and ABORT
//        if citeBacked is false. Unverified policies never upload. The server
//        gates the same way; we mirror it client-side so the user sees the real
//        reason locally instead of a 400 round-trip — and never leak an
//        incomplete bundle that the server might accept under a looser build.
//
//   G-2 (secrets): the API token is read from WRIT_API_TOKEN ONLY. Never
//        a CLI flag (shell history / process list leak), never logged.
//
//   G-4 (trust boundaries): the API host defaults to a FIXED constant. The
//        WRIT_API_URL override is honored ONLY if its host is on the
//        allowlist. An arbitrary host is REFUSED — otherwise an attacker who
//        controls the env (or a poisoned .env) redirects the Bearer token to
//        their own server. Precedent: packages/cursor-mcp/src/tools/check-endpoint.ts.

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import yaml from 'js-yaml';
import type { Citation, XSecurityPolicy } from '@x-security/detect-core';
import { resolvePoliciesDir, REPORT_FILE, resolveArtifactDir, type PolicyCites } from './store.js';
import { runAudit, type AuditResult } from './audit.js';

const execFileAsync = promisify(execFile);

// The production SaaS (CLAUDE.md G-6). This is the single source of truth for
// where the token may be sent; it is NOT user-overridable except via the
// allowlist below.
export const DEFAULT_API_URL = 'https://usewaf.com';

// Hosts the token is permitted to reach. The production domain, the documented
// product domain, and loopback for local SaaS development. Anything else is a
// hard refusal (G-4).
const HOST_ALLOWLIST_SUFFIXES = ['.chain305.com', '.lazy.chain305.com'];
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

const USER_AGENT = '@x-security/cli push';

// Mirror of the server's PUBLIC_REPO_URL_RE (apps/api/src/server.ts): the
// import endpoint only accepts https://github.com/<owner>/<repo>(.git)?. We
// pre-validate client-side so a non-github / SSH-only origin aborts locally
// with a clear message instead of a 400 round-trip (UX). The server re-checks.
const REPO_URL_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+(\.git)?$/i;

export interface PushAudit {
  routes: number;
  controls: number;
  citeBacked: boolean;
  coverage: number;
}

export interface PushPolicy {
  id: string;
  policy: XSecurityPolicy;
  cites: Citation[];
}

export interface PushPayload {
  repoUrl: string;
  commitSha: string;
  audit: PushAudit;
  policies: PushPolicy[];
  report?: string;
}

export interface PushImportResponse {
  importId: string;
  imported: number;
  reportUrl: string;
}

// Injected HTTP layer so tests run with no real network. Mirrors the Fetcher
// indirection in cursor-mcp's check-endpoint.
export interface PostResult {
  status: number;
  body: unknown;
}
export type Poster = (
  url: string,
  init: { headers: Record<string, string>; body: string },
) => Promise<PostResult>;

export interface PushOptions {
  dryRun?: boolean;
  // Test seams. In production these resolve from the environment / git.
  poster?: Poster;
  env?: NodeJS.ProcessEnv;
}

export interface PushResult {
  dryRun: boolean;
  apiUrl: string;
  payload: PushPayload;
  response?: PushImportResponse;
}

/** Thrown for any user-correctable failure (abort). The bin layer prints
 * `.message` to stderr and exits non-zero. Carries no secret material. */
export class PushError extends Error {}

const defaultPoster: Poster = async (url, init) => {
  const { request } = await import('undici');
  const res = await request(url, { method: 'POST', headers: init.headers, body: init.body });
  const text = await res.body.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // leave as raw text so the server's error is surfaced verbatim (D-1)
  }
  return { status: res.statusCode, body };
};

/** Resolve + validate the API base. Refuses any host not on the allowlist so a
 * poisoned WRIT_API_URL can't redirect the Bearer token (G-4). */
export function resolveApiUrl(env: NodeJS.ProcessEnv): string {
  const override = (env.X_SECURITY_API_URL ?? env.WRIT_API_URL)?.trim();
  if (!override) return DEFAULT_API_URL;

  let parsed: URL;
  try {
    parsed = new URL(override);
  } catch {
    throw new PushError(
      `WRIT_API_URL is not a valid URL: "${override}". ` +
        `Unset it to use the default ${DEFAULT_API_URL}.`,
    );
  }

  if (parsed.protocol !== 'https:' && !LOCAL_HOSTS.has(parsed.hostname)) {
    throw new PushError(
      `WRIT_API_URL must use https (got "${parsed.protocol}//${parsed.hostname}"). ` +
        `Refusing to send the API token over an insecure transport.`,
    );
  }

  const host = parsed.hostname.toLowerCase();
  const allowed =
    LOCAL_HOSTS.has(host) || HOST_ALLOWLIST_SUFFIXES.some((s) => host === s.slice(1) || host.endsWith(s));
  if (!allowed) {
    throw new PushError(
      `Refusing to send the API token to "${host}". ` +
        `WRIT_API_URL must be the x-security SaaS ` +
        `(host ending in ${HOST_ALLOWLIST_SUFFIXES.join(' or ')}, or localhost for dev). ` +
        `This guard prevents token exfiltration to an attacker-controlled host.`,
    );
  }

  // Normalize away any trailing slash; the import path is appended later.
  return override.replace(/\/+$/, '');
}

/** Read the token from env ONLY (G-2). Returns the raw value; the caller never
 * logs it. Absent token is an abort. */
export function resolveToken(env: NodeJS.ProcessEnv): string {
  const token = (env.X_SECURITY_API_TOKEN ?? env.WRIT_API_TOKEN)?.trim();
  if (!token) {
    throw new PushError(
      'WRIT_API_TOKEN is not set. Export your x-security API key ' +
        '(WRIT_API_TOKEN=...) — push reads it from the environment only, ' +
        'never from a flag.',
    );
  }
  return token;
}

async function gitOutput(repoDir: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('git', ['-C', repoDir, ...args]);
    return stdout.trim();
  } catch {
    return null;
  }
}

/** Normalize a git remote (ssh or https) into canonical https form so the
 * server keys the repo the same regardless of clone protocol. */
export function normalizeRemoteUrl(raw: string): string {
  let url = raw.trim();
  // scp-style: git@github.com:org/repo.git  →  https://github.com/org/repo
  const scp = /^[^@/]+@([^:]+):(.+)$/.exec(url);
  if (scp) url = `https://${scp[1]}/${scp[2]}`;
  // ssh://git@host/org/repo  →  https://host/org/repo
  url = url.replace(/^ssh:\/\/(?:[^@/]+@)?/, 'https://');
  url = url.replace(/^git:\/\//, 'https://');
  url = url.replace(/\.git$/, '');
  return url;
}

export async function resolveRepoIdentity(
  repoDir: string,
): Promise<{ repoUrl: string; commitSha: string }> {
  const inside = await gitOutput(repoDir, ['rev-parse', '--is-inside-work-tree']);
  if (inside !== 'true') {
    throw new PushError(
      `${repoDir} is not a git repository. push needs the origin remote and ` +
        `HEAD commit to identify the upload; run it inside a cloned repo.`,
    );
  }
  const remote = await gitOutput(repoDir, ['remote', 'get-url', 'origin']);
  if (!remote) {
    throw new PushError(
      'No "origin" remote found. push identifies the repo by its origin URL; ' +
        'add one with `git remote add origin <url>`.',
    );
  }
  const commitSha = await gitOutput(repoDir, ['rev-parse', 'HEAD']);
  if (!commitSha) {
    throw new PushError('Could not resolve HEAD commit (is there at least one commit?).');
  }
  return { repoUrl: normalizeRemoteUrl(remote), commitSha };
}

/** Load every compiled policy + its cite sidecar from .writ/policies/.
 * Both files must be present and parseable; a policy without its sidecar is a
 * bundle that audit would already have flagged, so we treat it as a hard error
 * rather than uploading an unbacked control (D-1). */
async function loadPolicies(repoDir: string): Promise<PushPolicy[]> {
  const dir = await resolvePoliciesDir(repoDir);
  let files: string[];
  try {
    files = (await fs.readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    throw new PushError(
      `No policies found under ${path.join('.writ', 'policies')}. ` +
        'Run the detection flow (lazy compile) before pushing.',
    );
  }
  if (files.length === 0) {
    throw new PushError('No policies to push — .writ/policies/ is empty.');
  }

  const out: PushPolicy[] = [];
  for (const file of files.sort()) {
    const id = file.replace(/\.ya?ml$/, '');
    const raw = await fs.readFile(path.join(dir, file), 'utf8');
    const policy = yaml.load(raw) as XSecurityPolicy | null;
    if (!policy || typeof policy !== 'object') {
      throw new PushError(`Policy ${file} is not a valid YAML object; refusing to push a malformed bundle.`);
    }
    const citesPath = path.join(dir, `${id}.cites.json`);
    let sidecar: PolicyCites;
    try {
      sidecar = JSON.parse(await fs.readFile(citesPath, 'utf8')) as PolicyCites;
    } catch {
      throw new PushError(
        `Policy ${id} has no cite sidecar (${id}.cites.json). ` +
          'Every uploaded control must carry its citations (D-3); refusing to push.',
      );
    }
    out.push({ id, policy, cites: sidecar.cites ?? [] });
  }
  return out;
}

async function loadReport(repoDir: string): Promise<string | undefined> {
  try {
    return await fs.readFile(path.join(await resolveArtifactDir(repoDir), REPORT_FILE), 'utf8');
  } catch {
    return undefined;
  }
}

function toPushAudit(a: AuditResult): PushAudit {
  return { routes: a.routes, controls: a.controls, citeBacked: a.citeBacked, coverage: a.coverage };
}

/** Assemble + validate the upload bundle. Runs the local audit and ABORTS if
 * citeBacked is false — never uploads unverified policies (D-1). */
export async function buildPayload(repoDir: string): Promise<PushPayload> {
  const audit = await runAudit(repoDir);
  if (!audit.citeBacked) {
    const why =
      audit.controls === 0
        ? 'no enforced controls were found'
        : `${audit.uncited.length} issue(s): ${audit.uncited.slice(0, 5).join('; ')}` +
          (audit.uncited.length > 5 ? ' …' : '');
    throw new PushError(
      `ABORT: local audit reports citeBacked=false (${why}). ` +
        'push never uploads unverified policies. Fix the cited findings ' +
        '(lazy audit ' +
        `${repoDir}) and re-run.`,
    );
  }

  const { repoUrl, commitSha } = await resolveRepoIdentity(repoDir);
  if (!REPO_URL_RE.test(repoUrl)) {
    throw new PushError(
      `ABORT: origin remote "${repoUrl}" is not an accepted import URL. ` +
        'The SaaS only ingests public GitHub repos ' +
        '(https://github.com/<owner>/<repo>). Point origin at the github.com ' +
        'remote and re-run.',
    );
  }
  const policies = await loadPolicies(repoDir);
  const report = await loadReport(repoDir);

  const payload: PushPayload = {
    repoUrl,
    commitSha,
    audit: toPushAudit(audit),
    policies,
  };
  if (report !== undefined) payload.report = report;
  return payload;
}

function parseImportResponse(body: unknown): PushImportResponse {
  if (
    body &&
    typeof body === 'object' &&
    typeof (body as Record<string, unknown>).importId === 'string' &&
    typeof (body as Record<string, unknown>).imported === 'number' &&
    typeof (body as Record<string, unknown>).reportUrl === 'string'
  ) {
    const b = body as Record<string, unknown>;
    return { importId: b.importId as string, imported: b.imported as number, reportUrl: b.reportUrl as string };
  }
  throw new PushError(`Server returned 200 but an unexpected body shape: ${JSON.stringify(body)}`);
}

/** Stringify the server's error body verbatim (D-1: no swallowing). */
function describeBody(body: unknown): string {
  if (body && typeof body === 'object') {
    const msg = (body as Record<string, unknown>).message ?? (body as Record<string, unknown>).error;
    if (typeof msg === 'string') return msg;
    return JSON.stringify(body);
  }
  return typeof body === 'string' ? body : JSON.stringify(body);
}

export async function runPush(repoDir: string, opts: PushOptions = {}): Promise<PushResult> {
  const env = opts.env ?? process.env;
  const dryRun = opts.dryRun === true;

  // Resolve the host first so an arbitrary WRIT_API_URL is refused even on
  // a dry run (the user is asking "where would this go" — answer honestly).
  const apiUrl = resolveApiUrl(env);
  const payload = await buildPayload(repoDir);

  if (dryRun) {
    return { dryRun: true, apiUrl, payload };
  }

  const token = resolveToken(env);
  const poster = opts.poster ?? defaultPoster;
  // Route through the web proxy (apps/web .../api/web/v1/policies/import): the
  // production host is the Next.js app behind Cloudflare, which does NOT expose
  // the api's /v1/* directly. The proxy forwards the bearer + body to the api.
  const url = `${apiUrl}/api/web/v1/policies/import`;

  const res = await poster(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'User-Agent': USER_AGENT,
    },
    body: JSON.stringify(payload),
  });

  if (res.status < 200 || res.status >= 300) {
    throw new PushError(`Server rejected the import (HTTP ${res.status}): ${describeBody(res.body)}`);
  }

  const response = parseImportResponse(res.body);
  return { dryRun: false, apiUrl, payload, response };
}
