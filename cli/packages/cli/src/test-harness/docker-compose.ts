// Real Docker container lifecycle for x-security's `x-security test`
// closed-loop validation command.
//
// We drive Docker through the dockerode Node SDK so users don't need
// `docker compose` on PATH. The plan is two services:
//   - upstream: mendhak/http-https-echo:36 echo server
//   - gateway:  target-specific image, configured with the generated config
//
// Kong has a fully wired lifecycle (pull, network, run, wait, teardown).
// Coraza / BunkerWeb / OpenAppSec are stubbed with TODO markers — see
// STATUS.md for the matrix.

import type { Writable } from 'node:stream';
import { request as undiciRequest } from 'undici';

export type DockerTarget = 'kong' | 'coraza' | 'bunkerweb' | 'openappsec';

export interface ComposePlan {
  yaml: string;
  upstreamPort: number;
  gatewayPort: number;
  /** Container names */
  upstreamName: string;
  gatewayName: string;
  network: string;
  target: DockerTarget;
  configMountSourceDir: string;
  configMountTargetDir: string;
  /** When set, the upstream is external; no mock-upstream container is launched. */
  externalUpstreamUrl?: string;
}

export interface BuildPlanOptions {
  target: DockerTarget;
  /** Generated config — written into a temp dir and mounted into the gateway. */
  configMountSourceDir: string;
  configMountTargetDir: string;
  /** Local port to expose the gateway on. */
  gatewayPort?: number;
  /** Local port for the mock upstream. Ignored when `upstreamUrl` is set. */
  upstreamPort?: number;
  /**
   * Point the gateway at a real upstream URL instead of the mock-upstream
   * container. When set, no upstream container is launched and the gateway
   * has no `depends_on` upstream service.
   *
   * Examples:
   *   http://host.docker.internal:8000   — local app on the host
   *   http://10.0.0.5:8080               — LAN
   *   https://staging.example.com        — remote
   */
  upstreamUrl?: string;
}

/**
 * Validate a user-supplied upstream URL. Throws on invalid input. Returns the
 * parsed URL and a list of human-readable warnings (e.g. `localhost` inside a
 * container is almost certainly a mistake — recommend `host.docker.internal`).
 */
export function validateUpstreamUrl(raw: string): { url: URL; warnings: string[] } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`--upstream-url is not a valid URL: ${raw}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`--upstream-url must be http:// or https:// (got ${url.protocol})`);
  }
  if (!url.hostname) {
    throw new Error(`--upstream-url is missing a hostname: ${raw}`);
  }
  const warnings: string[] = [];
  if (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '0.0.0.0') {
    warnings.push(
      `--upstream-url uses "${url.hostname}", which resolves to the gateway container itself, not your host. ` +
        `If your app is running on the host, use "host.docker.internal" instead.`
    );
  }
  return { url, warnings };
}

// mendhak/http-https-echo:36 echoes the request back as JSON. Tiny image,
// no custom build required.
const UPSTREAM_IMAGE = 'mendhak/http-https-echo:36';
const UPSTREAM_INTERNAL_PORT = 8080;

const GATEWAY_IMAGE: Record<DockerTarget, string> = {
  kong: 'kong:3.4',
  coraza: 'owasp/coraza-spoa:latest',
  bunkerweb: 'bunkerity/bunkerweb:latest',
  openappsec: 'ghcr.io/openappsec/agent:latest'
};

function randomSuffix(): string {
  return `${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
}

export function buildComposePlan(opts: BuildPlanOptions): ComposePlan {
  const upstreamPort = opts.upstreamPort ?? 18080;
  const gatewayPort = opts.gatewayPort ?? 18000;
  const suffix = randomSuffix();
  const network = `x-security-${opts.target}-net-${suffix}`;
  const upstreamName = `x-security-${opts.target}-upstream-${suffix}`;
  const gatewayName = `x-security-${opts.target}-gateway-${suffix}`;
  const image = GATEWAY_IMAGE[opts.target];

  // Kong-specific env defaults — declarative DBless mode pointing at the mount.
  let gatewayEnv = '';
  if (opts.target === 'kong') {
    gatewayEnv = `      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: "${opts.configMountTargetDir}/kong.yml"
      KONG_PROXY_LISTEN: "0.0.0.0:8000"
      KONG_ADMIN_LISTEN: "off"
      KONG_LOG_LEVEL: "warn"`;
  }

  const externalUpstream = opts.upstreamUrl;
  // When pointing at an external upstream, omit the mock-upstream service and
  // drop `depends_on`. Add `extra_hosts` so `host.docker.internal` resolves on
  // Linux (Docker Desktop on macOS/Windows already maps it).
  const needsHostGateway = externalUpstream
    ? new URL(externalUpstream).hostname === 'host.docker.internal'
    : false;

  const upstreamBlock = externalUpstream
    ? ''
    : `  upstream:
    image: ${UPSTREAM_IMAGE}
    container_name: ${upstreamName}
    networks: [${network}]
    ports:
      - "${upstreamPort}:${UPSTREAM_INTERNAL_PORT}"
`;
  const dependsOn = externalUpstream ? '' : `    depends_on: [upstream]\n`;
  const extraHosts = needsHostGateway
    ? `    extra_hosts:\n      - "host.docker.internal:host-gateway"\n`
    : '';

  const yamlStr = `services:
${upstreamBlock}  gateway:
    image: ${image}
    container_name: ${gatewayName}
${dependsOn}    networks: [${network}]
    environment:
${gatewayEnv}
${extraHosts}    volumes:
      - "${opts.configMountSourceDir}:${opts.configMountTargetDir}:ro"
    ports:
      - "${gatewayPort}:8000"
networks:
  ${network}:
    driver: bridge
`;

  const plan: ComposePlan = {
    yaml: yamlStr,
    upstreamPort,
    gatewayPort,
    upstreamName,
    gatewayName,
    network,
    target: opts.target,
    configMountSourceDir: opts.configMountSourceDir,
    configMountTargetDir: opts.configMountTargetDir
  };
  if (externalUpstream) plan.externalUpstreamUrl = externalUpstream;
  return plan;
}

export interface DockerHarnessHandle {
  teardown(): Promise<void>;
  gatewayUrl: string;
  /** Container name of the gateway. Exposed so the post-boot verify hook
   *  in `commands/test.ts` can read its config/logs via `docker:<name>`. */
  gatewayContainerName: string;
  /** Resolves once the gateway answers HTTP. */
  ready(): Promise<void>;
}

export interface BringUpOptions {
  /** Don't teardown on success (debug aid). */
  keep?: boolean;
  /** ms to wait for gateway readiness; default 30_000. */
  readyTimeoutMs?: number;
  logger?: Writable;
}

interface DockerodeShape {
  ping(): Promise<unknown>;
  getImage(name: string): { inspect(): Promise<unknown> };
  pull(image: string, cb: (err: Error | null, stream: NodeJS.ReadableStream | null) => void): void;
  modem: { followProgress(stream: NodeJS.ReadableStream, cb: (err: Error | null) => void): void };
  createNetwork(opts: { Name: string; Driver: string }): Promise<{ id: string; remove(): Promise<void> }>;
  createContainer(opts: Record<string, unknown>): Promise<DockerodeContainer>;
  getContainer(id: string): DockerodeContainer;
}

interface DockerodeContainer {
  id: string;
  start(): Promise<void>;
  stop(opts?: { t: number }): Promise<void>;
  remove(opts?: { force: boolean; v?: boolean }): Promise<void>;
  inspect(): Promise<{ State: { Running: boolean }; NetworkSettings: { Ports?: Record<string, Array<{ HostPort: string }> | null> } }>;
}

async function ensureImage(docker: DockerodeShape, image: string, log: (m: string) => void): Promise<void> {
  try {
    await docker.getImage(image).inspect();
    log(`[docker] image present: ${image}`);
    return;
  } catch {
    log(`[docker] pulling image: ${image}`);
  }
  await new Promise<void>((resolve, reject) => {
    docker.pull(image, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error(`pull failed: ${image}`));
      docker.modem.followProgress(stream, (finishErr) => {
        if (finishErr) reject(finishErr);
        else resolve();
      });
    });
  });
}

async function removeIfExists(docker: DockerodeShape, name: string, log: (m: string) => void): Promise<void> {
  try {
    const c = docker.getContainer(name);
    await c.remove({ force: true, v: true });
    log(`[docker] removed stale container: ${name}`);
  } catch {
    // not found — fine
  }
}

async function waitForHttp(url: string, timeoutMs: number, log: (m: string) => void): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await undiciRequest(url, { method: 'GET', headersTimeout: 2000, bodyTimeout: 2000 });
      // drain
      await res.body.arrayBuffer();
      // Kong returns 404 with no route on the root path — that's "ready".
      if (res.statusCode >= 200 && res.statusCode < 600) {
        log(`[docker] gateway ready (status ${res.statusCode})`);
        return;
      }
    } catch (e) {
      lastErr = e;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`gateway not ready within ${timeoutMs}ms${lastErr ? `: ${(lastErr as Error).message}` : ''}`);
}

/**
 * Bring up the planned stack via dockerode. Returns a handle with
 * `gatewayUrl`, `ready()`, and `teardown()`. Idempotent: stale containers
 * with the same name are removed before re-creating.
 *
 * Currently only the `kong` target has a fully wired lifecycle. Other
 * targets throw with a clear "stub" message.
 */
export async function bringUp(plan: ComposePlan, opts: BringUpOptions = {}): Promise<DockerHarnessHandle> {
  const log = (m: string) => {
    if (opts.logger) opts.logger.write(m + '\n');
  };

  if (plan.target !== 'kong') {
    // TODO: implement Coraza / BunkerWeb / OpenAppSec lifecycles.
    throw new Error(
      `Docker lifecycle for target "${plan.target}" is stubbed. Only "kong" is implemented. ` +
        `Use --dry-run to print the compose plan.`
    );
  }

  const DockerMod = await import('dockerode');
  const Docker = (DockerMod as unknown as { default: new () => DockerodeShape }).default;
  const docker = new Docker();

  await docker.ping().catch(() => {
    throw new Error('Docker daemon not reachable (set DOCKER_HOST or start Docker Desktop).');
  });

  const useExternal = Boolean(plan.externalUpstreamUrl);

  // Clean up any leftover containers from a prior failed run.
  if (!useExternal) await removeIfExists(docker, plan.upstreamName, log);
  await removeIfExists(docker, plan.gatewayName, log);

  // Pull images.
  if (!useExternal) await ensureImage(docker, UPSTREAM_IMAGE, log);
  await ensureImage(docker, GATEWAY_IMAGE[plan.target], log);

  // Create network.
  log(`[docker] creating network ${plan.network}`);
  const network = await docker.createNetwork({ Name: plan.network, Driver: 'bridge' });

  let upstream: DockerodeContainer | null = null;
  let gateway: DockerodeContainer | null = null;

  const cleanup = async (): Promise<void> => {
    for (const c of [gateway, upstream]) {
      if (!c) continue;
      try {
        await c.stop({ t: 2 });
      } catch {
        /* ignore */
      }
      try {
        await c.remove({ force: true, v: true });
      } catch {
        /* ignore */
      }
    }
    try {
      await network.remove();
    } catch {
      /* ignore */
    }
  };

  try {
    if (!useExternal) {
      log(`[docker] starting upstream ${plan.upstreamName}`);
      upstream = await docker.createContainer({
        Image: UPSTREAM_IMAGE,
        name: plan.upstreamName,
        HostConfig: {
          NetworkMode: plan.network,
          AutoRemove: false,
          PortBindings: {
            [`${UPSTREAM_INTERNAL_PORT}/tcp`]: [{ HostPort: String(plan.upstreamPort) }]
          }
        },
        NetworkingConfig: {
          EndpointsConfig: {
            [plan.network]: { Aliases: ['upstream'] }
          }
        },
        ExposedPorts: { [`${UPSTREAM_INTERNAL_PORT}/tcp`]: {} }
      });
      await upstream.start();
    } else {
      log(`[docker] using external upstream: ${plan.externalUpstreamUrl}`);
    }

    const needsHostGateway =
      useExternal && new URL(plan.externalUpstreamUrl!).hostname === 'host.docker.internal';

    log(`[docker] starting gateway ${plan.gatewayName}`);
    gateway = await docker.createContainer({
      Image: GATEWAY_IMAGE[plan.target],
      name: plan.gatewayName,
      Env: [
        'KONG_DATABASE=off',
        `KONG_DECLARATIVE_CONFIG=${plan.configMountTargetDir}/kong.yml`,
        'KONG_PROXY_LISTEN=0.0.0.0:8000',
        'KONG_ADMIN_LISTEN=off',
        'KONG_LOG_LEVEL=warn'
      ],
      HostConfig: {
        NetworkMode: plan.network,
        AutoRemove: false,
        Binds: [`${plan.configMountSourceDir}:${plan.configMountTargetDir}:ro`],
        PortBindings: {
          '8000/tcp': [{ HostPort: String(plan.gatewayPort) }]
        },
        ...(needsHostGateway ? { ExtraHosts: ['host.docker.internal:host-gateway'] } : {})
      },
      NetworkingConfig: {
        EndpointsConfig: {
          [plan.network]: { Aliases: ['gateway'] }
        }
      },
      ExposedPorts: { '8000/tcp': {} }
    });
    await gateway.start();
  } catch (e) {
    await cleanup();
    throw e;
  }

  const gatewayUrl = `http://127.0.0.1:${plan.gatewayPort}`;
  return {
    gatewayUrl,
    gatewayContainerName: plan.gatewayName,
    ready: () => waitForHttp(gatewayUrl + '/', opts.readyTimeoutMs ?? 30_000, log),
    teardown: async () => {
      if (opts.keep) {
        log('[docker] --keep: leaving containers running');
        log(`  upstream: ${plan.upstreamName}`);
        log(`  gateway:  ${plan.gatewayName} -> ${gatewayUrl}`);
        return;
      }
      log(`[docker] teardown ${plan.gatewayName} + ${plan.upstreamName}`);
      await cleanup();
    }
  };
}
