// `lazy doctor [--format table|json] [--gateway <url>] [--timeout <ms>]`
//
// Preflight/health-check so a user can diagnose environment problems BEFORE
// a real command (test/validate/verify) fails partway through. Those commands
// depend on Docker and/or a reachable gateway admin URL; doctor checks those
// up front so failures are cheap to diagnose.
//
// Exit codes:
//   0 — all checks ok/warn
//   1 — at least one check failed

import Docker from 'dockerode';
import { request } from 'undici';
import type { Command } from 'commander';

export interface DoctorOptions {
  format?: 'table' | 'json';
  gateway?: string;
  timeoutMs?: number;
}

export interface DoctorCheck {
  name: string;
  status: 'ok' | 'warn' | 'fail';
  detail: string;
}

export interface DoctorResult {
  exitCode: number;
  rendered: string;
  checks: DoctorCheck[];
}

const MIN_NODE_MAJOR = 20;
const DEFAULT_GATEWAY_TIMEOUT_MS = 3000;
const DOCKER_PING_TIMEOUT_MS = 2000;

export async function runDoctor(opts: DoctorOptions = {}): Promise<DoctorResult> {
  const checks: DoctorCheck[] = [checkNode(), await checkDocker()];

  if (opts.gateway) {
    checks.push(await checkGateway(opts.gateway, opts.timeoutMs ?? DEFAULT_GATEWAY_TIMEOUT_MS));
  }

  const exitCode = checks.some((c) => c.status === 'fail') ? 1 : 0;
  const rendered = opts.format === 'json' ? renderJson(checks, exitCode) : renderTable(checks);

  return { exitCode, rendered, checks };
}

function checkNode(): DoctorCheck {
  const version = process.versions.node;
  const major = Number(version.split('.')[0]);
  const ok = major >= MIN_NODE_MAJOR;
  return {
    name: 'node',
    status: ok ? 'ok' : 'fail',
    detail: `v${version} (requires >=${MIN_NODE_MAJOR})`
  };
}

async function checkDocker(): Promise<DoctorCheck> {
  try {
    const docker = new Docker();
    await withTimeout(docker.ping(), DOCKER_PING_TIMEOUT_MS);
    return { name: 'docker', status: 'ok', detail: 'daemon reachable' };
  } catch (e) {
    // Never throw out of the check — Docker is only needed for `test`, so an
    // unreachable daemon is a warning, not a failure.
    return {
      name: 'docker',
      status: 'warn',
      detail: `Docker not reachable — only needed for \`test\` (${(e as Error).message})`
    };
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

async function checkGateway(gateway: string, timeoutMs: number): Promise<DoctorCheck> {
  if (!isHttpUrl(gateway)) {
    return {
      name: 'gateway',
      status: 'ok',
      detail: `skipped: non-HTTP gateway (${gateway})`
    };
  }

  try {
    await request(gateway, { signal: AbortSignal.timeout(timeoutMs) });
    // Any HTTP response — even 4xx — means the gateway is reachable.
    return { name: 'gateway', status: 'ok', detail: `reachable at ${gateway}` };
  } catch (e) {
    return {
      name: 'gateway',
      status: 'fail',
      detail: `unreachable: ${gateway} (${(e as Error).message})`
    };
  }
}

function renderJson(checks: DoctorCheck[], exitCode: number): string {
  return JSON.stringify({ checks, ok: exitCode === 0 }, null, 2) + '\n';
}

function renderTable(checks: DoctorCheck[]): string {
  const nameWidth = Math.max(...checks.map((c) => c.name.length));
  const lines = checks.map(
    (c) => `[${c.status}]${' '.repeat(Math.max(1, 6 - c.status.length))}${c.name.padEnd(nameWidth)}  ${c.detail}`
  );
  return lines.join('\n') + '\n';
}

export function registerDoctor(program: Command): void {
  program
    .command('doctor')
    .description('Preflight: check Node, Docker, and (optionally) a gateway URL are usable.')
    .option('--format <fmt>', 'table|json (default table)', 'table')
    .option('--gateway <url>', 'Also check this gateway admin URL is reachable')
    .option('--timeout <ms>', 'Gateway reachability timeout (default 3000)', (v) => Number(v))
    .action(async (opts: { format: string; gateway?: string; timeout?: number }) => {
      try {
        const doctorOpts: DoctorOptions = { format: opts.format as 'table' | 'json' };
        if (opts.gateway !== undefined) doctorOpts.gateway = opts.gateway;
        if (opts.timeout !== undefined) doctorOpts.timeoutMs = opts.timeout;
        const r = await runDoctor(doctorOpts);
        process.stdout.write(r.rendered);
        process.exit(r.exitCode);
      } catch (e) {
        process.stderr.write(`doctor failed: ${(e as Error).message}\n`);
        process.exit(1);
      }
    });
}
