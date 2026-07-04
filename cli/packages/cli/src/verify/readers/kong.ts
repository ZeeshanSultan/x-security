// Kong reader.
//
// Read-only HTTP GETs against the Kong admin API. We don't trust the
// declarative kong.yml mounted to disk — Kong may have failed to ingest
// rows (typo, duplicate id, plugin schema rejection) and silently kept
// running with the rest. Asking /services + /routes + /plugins back is
// the only honest source of truth.
//
// Matching key:
//   Service   → name
//   Route     → name
//   Plugin    → (route_name, plugin_name) tuple. The generator assigns at
//               most one plugin of a given name per route, so this is
//               unambiguous for our coverage check.
//
// We don't try to confirm Kong /jwt-secrets / /hmacauth-credentials /
// /acls inhabited consumers correctly here — that's a wave-2 concern
// covered by `lazy validate`. Verify focuses on the load-coverage
// signal that REPORT-v3 §3 was missing.

import { request } from 'undici';
import type { SpecIR } from '@writ/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

interface KongAdminPlugin {
  id?: string;
  name: string;
  route?: { id?: string } | null;
  service?: { id?: string } | null;
  tags?: string[];
}

interface KongAdminRoute {
  id?: string;
  name?: string;
  service?: { id?: string };
}

interface KongAdminService {
  id?: string;
  name?: string;
}

async function getJson<T>(base: string, p: string): Promise<T> {
  const url = base.replace(/\/$/, '') + p;
  try {
    const res = await request(url, { method: 'GET' });
    if (res.statusCode >= 400) {
      throw new Error(`${url} → HTTP ${res.statusCode}`);
    }
    const body = (await res.body.json()) as T;
    return body;
  } catch (e) {
    const msg = (e as Error).message;
    if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(msg)) {
      throw new Error(`gateway-unreachable: ${msg}`);
    }
    throw e;
  }
}

interface KongPage<T> { data: T[]; next?: string | null; }

async function listAll<T>(base: string, p: string): Promise<T[]> {
  // Kong's admin paginator returns `next` as an absolute or path-relative URL.
  let url: string | null = p;
  const out: T[] = [];
  while (url) {
    const page: KongPage<T> = await getJson<KongPage<T>>(base, url);
    out.push(...page.data);
    if (page.next) {
      const u = new URL(page.next, base + '/');
      url = u.pathname + (u.search ?? '');
    } else {
      url = null;
    }
  }
  return out;
}

interface KongDeclarative {
  services?: Array<{
    name?: string;
    routes?: Array<{
      name?: string;
      plugins?: Array<{ name: string; id?: string; tags?: string[] }>;
    }>;
    plugins?: Array<{ name: string }>;
  }>;
}

function scanEmittedFromDeclarative(decl: KongDeclarative): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  for (const svc of decl.services ?? []) {
    if (svc.name) out.push({ id: svc.name, kind: 'kong-service', endpoint: svc.name, label: `service ${svc.name}` });
    for (const route of svc.routes ?? []) {
      const routeKey = route.name ?? '(unnamed)';
      out.push({ id: routeKey, kind: 'kong-route', endpoint: routeKey, label: `route ${routeKey}` });
      for (const plugin of route.plugins ?? []) {
        out.push({
          id: `${routeKey}|${plugin.name}`,
          kind: 'kong-plugin',
          endpoint: routeKey,
          label: `plugin ${plugin.name}`
        });
      }
    }
    for (const plugin of svc.plugins ?? []) {
      out.push({
        id: `${svc.name ?? ''}|${plugin.name}`,
        kind: 'kong-plugin',
        endpoint: svc.name ?? '(service-level)',
        label: `plugin ${plugin.name} (service-level)`
      });
    }
  }
  return out;
}

export const kongReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('kong');
    if (!gen) throw new Error('kong generator not available');
    const arts = await gen.generate(spec);
    const kongYml = arts.find((a) => a.path === 'kong.yml' || a.path.endsWith('/kong.yml'));
    if (!kongYml) throw new Error('kong generator did not emit kong.yml');
    // Light YAML parse — we only need the structure, not the values.
    const { load } = await import('js-yaml');
    const decl = load(kongYml.content) as KongDeclarative;
    return scanEmittedFromDeclarative(decl);
  },

  async readLoadedArtifacts(gateway: string): Promise<LoadedArtifact[]> {
    const [services, routes, plugins] = await Promise.all([
      listAll<KongAdminService>(gateway, '/services'),
      listAll<KongAdminRoute>(gateway, '/routes'),
      listAll<KongAdminPlugin>(gateway, '/plugins')
    ]);

    const routeIdToName = new Map<string, string>();
    for (const r of routes) if (r.id && r.name) routeIdToName.set(r.id, r.name);

    const out: LoadedArtifact[] = [];
    for (const s of services) {
      if (s.name) out.push({ id: s.name, kind: 'kong-service' });
    }
    for (const r of routes) {
      if (r.name) out.push({ id: r.name, kind: 'kong-route' });
    }
    for (const p of plugins) {
      const routeName = p.route?.id ? routeIdToName.get(p.route.id) : undefined;
      out.push({
        id: routeName ? `${routeName}|${p.name}` : `(global)|${p.name}`,
        kind: 'kong-plugin'
      });
    }
    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];
    const loadedSet = new Set(loaded.map((l) => `${l.kind}:${l.id}`));

    const byEndpoint = new Map<string, EmittedArtifact[]>();
    for (const a of emitted) {
      const list = byEndpoint.get(a.endpoint) ?? [];
      list.push(a);
      byEndpoint.set(a.endpoint, list);
    }

    const rows: VerifyRow[] = [];
    for (const [endpoint, arts] of byEndpoint) {
      const rejected: VerifyRow['rejected'] = [];
      let loadedCount = 0;
      for (const art of arts) {
        if (loadedSet.has(`${art.kind}:${art.id}`)) {
          loadedCount++;
        } else {
          rejected.push({ id: art.id, reason: `${art.label}: emitted but not present in admin API` });
        }
      }
      const status: VerifyRow['status'] = rejected.length === 0
        ? 'ok'
        : loadedCount === 0
          ? 'failed'
          : 'partial';
      rows.push({ endpoint, emitted: arts.length, loaded: loadedCount, rejected, status });
    }
    rows.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
    return { rows, diagnostics };
  }
};
