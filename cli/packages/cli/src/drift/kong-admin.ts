// Kong Admin API client (HTTP) + drift comparison against SpecIR.
//
// We fetch /routes and /plugins, then group plugins by route paths. The
// matching strategy is "first route whose paths contain the spec path",
// which matches the generator's strategy of one route per endpoint.

import { request } from 'undici';
import type { SpecIR } from '@writ/core';
import type { KongPlugin } from '../generators/kong/types.js';
import type { DriftIssue, DriftReport } from '../reporters/types.js';
import { buildExpected, diffExpectedVsActual } from './kong-shared.js';

interface KongAdminRoute {
  id: string;
  name?: string;
  paths?: string[];
  methods?: string[];
}

interface KongAdminPlugin {
  id: string;
  name: string;
  config?: Record<string, unknown>;
  route?: { id: string } | null;
  service?: { id: string } | null;
  enabled?: boolean;
}

interface ListResponse<T> {
  data: T[];
  next?: string | null;
}

async function fetchAll<T>(baseUrl: string, resource: string): Promise<T[]> {
  const out: T[] = [];
  let url: string | null = `${baseUrl.replace(/\/$/, '')}/${resource}`;
  while (url) {
    const res = await request(url, { method: 'GET' });
    if (res.statusCode >= 400) {
      throw new Error(`Kong admin GET ${url} → ${res.statusCode}`);
    }
    const body = (await res.body.json()) as ListResponse<T>;
    out.push(...(body.data ?? []));
    url = body.next ? `${baseUrl.replace(/\/$/, '')}${body.next}` : null;
  }
  return out;
}

export interface KongAdminClient {
  routes(): Promise<KongAdminRoute[]>;
  plugins(): Promise<KongAdminPlugin[]>;
}

export function createHttpClient(baseUrl: string): KongAdminClient {
  return {
    routes: () => fetchAll<KongAdminRoute>(baseUrl, 'routes'),
    plugins: () => fetchAll<KongAdminPlugin>(baseUrl, 'plugins')
  };
}

/** Build actual endpoint→plugin map from Kong admin API responses. */
export function indexActualFromAdmin(
  routes: KongAdminRoute[],
  plugins: KongAdminPlugin[],
  spec: SpecIR
): Map<string, Map<string, KongPlugin>> {
  const byRouteId = new Map<string, KongAdminPlugin[]>();
  for (const p of plugins) {
    const rid = p.route?.id;
    if (!rid) continue;
    const list = byRouteId.get(rid) ?? [];
    list.push(p);
    byRouteId.set(rid, list);
  }

  const out = new Map<string, Map<string, KongPlugin>>();
  for (const e of spec.endpoints) {
    const route = routes.find((r) => (r.paths ?? []).some((p) => p === e.path));
    const label = `${e.method} ${e.path}`;
    const pMap = new Map<string, KongPlugin>();
    if (route) {
      for (const p of byRouteId.get(route.id) ?? []) {
        pMap.set(p.name, { name: p.name, config: p.config ?? {} });
      }
    }
    out.set(label, pMap);
  }
  return out;
}

export interface AdminDriftOptions {
  gatewayUrl: string;
  client?: KongAdminClient; // injectable for tests
}

export async function detectAdminDrift(spec: SpecIR, opts: AdminDriftOptions): Promise<DriftReport> {
  const client = opts.client ?? createHttpClient(opts.gatewayUrl);
  const [routes, plugins] = await Promise.all([client.routes(), client.plugins()]);
  const actual = indexActualFromAdmin(routes, plugins, spec);
  const expected = buildExpected(spec);
  const issues: DriftIssue[] = diffExpectedVsActual(expected, actual);
  return {
    kind: 'drift',
    target: 'kong',
    gatewaySource: opts.gatewayUrl,
    issues
  };
}
