// Envoy verify reader (wave-9 native-filter rev).
//
// Wave-7 emitted a Lua-everything snippet; the reader only had to grep for
// `envoy.filters.http.lua` and the x-security sentinel markers. Wave-9 emits a
// full bootstrap with native filters (jwt_authn, rbac, local_ratelimit, cors,
// lua, router) and per-route typed_per_filter_config overrides. This reader
// reconciles each native artefact independently so coverage attribution
// matches the verb in the report: "jwt rule for GET /api1/user/1 is present"
// vs "rate-limit bucket for POST /login is present", etc.
//
// Emitted artefact kinds (id is the human-readable handle):
//   envoy-http-filter             chain-level filter name (e.g. envoy.filters.http.jwt_authn)
//   envoy-jwt-rule                "<METHOD> <path>" — endpoint requiring jwt_authn
//   envoy-rbac-policy             RBAC policy name (e.g. x-security-rbac-listusers-admin)
//   envoy-ratelimit-route         per-route stat_prefix (e.g. x_security_login_ratelimit)
//   envoy-cors-route              "<METHOD> <path>" — endpoint with native CorsPolicy override
//   envoy-endpoint-policy         "<METHOD>:<path>" — residual Lua sentinel
//
// Loaded set is harvested from Envoy admin API:
//   GET /listeners?format=json
//   GET /clusters?format=json
//   GET /config_dump?include_eds=false
//   GET /stats?format=json (optional — confirms rate-limit buckets actually exist)

import { request } from 'undici';
import * as yaml from 'js-yaml';
import type { SpecIR } from '@x-security/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

interface EnvoyConfigDump {
  configs?: Array<Record<string, unknown>>;
}

async function getJson<T>(base: string, p: string, timeoutMs?: number): Promise<T> {
  const url = base.replace(/\/$/, '') + p;
  try {
    const res = await request(url, {
      method: 'GET',
      ...(timeoutMs !== undefined ? { signal: AbortSignal.timeout(timeoutMs) } : {})
    });
    if (res.statusCode >= 400) {
      throw new Error(`${url} → HTTP ${res.statusCode}`);
    }
    return (await res.body.json()) as T;
  } catch (e) {
    const name = (e as Error).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new Error(`${url} timed out after ${timeoutMs}ms`);
    }
    const msg = (e as Error).message;
    if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(msg)) {
      throw new Error(`gateway-unreachable: ${msg}`);
    }
    throw e;
  }
}

// ── recursive walkers (exported for tests) ───────────────────────────────

export function* walkStrings(node: unknown): Generator<string> {
  if (typeof node === 'string') {
    yield node;
    return;
  }
  if (Array.isArray(node)) {
    for (const v of node) yield* walkStrings(v);
    return;
  }
  if (node && typeof node === 'object') {
    for (const v of Object.values(node)) yield* walkStrings(v);
  }
}

export function collectFilterNames(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const v of node) collectFilterNames(v, into);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (typeof obj.name === 'string' && obj.name.startsWith('envoy.filters.http.')) {
      into.add(obj.name);
    }
    for (const v of Object.values(obj)) collectFilterNames(v, into);
  }
}

/** Collect every `stat_prefix:` string anywhere in the config — used to find
 *  per-route rate-limit buckets without having to traverse the
 *  typed_per_filter_config tree by exact path. */
export function collectStatPrefixes(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const v of node) collectStatPrefixes(v, into);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (typeof obj.stat_prefix === 'string') into.add(obj.stat_prefix);
    for (const v of Object.values(obj)) collectStatPrefixes(v, into);
  }
}

/** Collect every RBAC policy name (the keys of `policies:`). */
export function collectRbacPolicyNames(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const v of node) collectRbacPolicyNames(v, into);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    // RBAC config shape: rules.policies = { "<name>": {...} }
    if (obj.policies && typeof obj.policies === 'object' && !Array.isArray(obj.policies)) {
      // Only treat as a policies map if the parent typed_config looks like RBAC
      // — best signal is the presence of `action: ALLOW|DENY` alongside.
      if (typeof (obj as { action?: unknown }).action === 'string') {
        for (const k of Object.keys(obj.policies)) into.add(k);
      }
    }
    for (const v of Object.values(obj)) collectRbacPolicyNames(v, into);
  }
}

/** Collect every jwt_authn rule's regex path — these are the endpoints
 *  requiring JWT. */
export function collectJwtRuleRegexes(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const v of node) collectJwtRuleRegexes(v, into);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    // jwt_authn shape: rules: [{ match: { safe_regex: { regex: "..."} }, requires: ... }]
    if (Array.isArray(obj.rules) && obj.providers) {
      for (const rule of obj.rules) {
        if (rule && typeof rule === 'object') {
          const r = rule as Record<string, unknown>;
          const match = r.match as Record<string, unknown> | undefined;
          const sr = match?.safe_regex as Record<string, unknown> | undefined;
          if (sr && typeof sr.regex === 'string') into.add(sr.regex);
          // Fallback: prefix-style match
          if (match && typeof (match as Record<string, unknown>).prefix === 'string') {
            into.add((match as Record<string, unknown>).prefix as string);
          }
        }
      }
    }
    for (const v of Object.values(obj)) collectJwtRuleRegexes(v, into);
  }
}

// Markers the residual Lua emits.
const SENTINEL_RE = /--\s*xSecurity:([A-Z]+):([^\s:]+):START/g;

export function extractSentinels(text: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  SENTINEL_RE.lastIndex = 0;
  while ((m = SENTINEL_RE.exec(text)) !== null) {
    out.add(`${m[1]}:${m[2]}`);
  }
  return [...out];
}

// ── emit side: parse the full bootstrap ──────────────────────────────────

export interface EmittedEnvoyYaml {
  filters: string[];               // chain-level filter names in declared order
  jwtRules: string[];              // safe_regex strings from jwt_authn rules
  rbacPolicies: string[];          // policies keys under filters.http.rbac
  ratelimitStatPrefixes: string[]; // per-route stat_prefix values
  corsRoutes: string[];            // route entries with CorsPolicy override
  endpointPolicies: string[];      // `<METHOD>:<path>` from Lua sentinels
}

/**
 * Parse the generator-emitted bootstrap.  We use js-yaml here (the snippet
 * shape changed enough that line-grep is no longer sufficient — route
 * configs span multiple keys with the same name).  The inline Lua is
 * captured back into a string and grep'd for sentinels separately.
 */
export function parseEmittedSnippet(yamlText: string): EmittedEnvoyYaml {
  const doc = yaml.load(yamlText) as Record<string, unknown>;

  const filterNames = new Set<string>();
  collectFilterNames(doc, filterNames);
  // Preserve emission order by walking the listener's http_filters list explicitly.
  const orderedFilters: string[] = [];
  const filtersList = pickHttpFiltersList(doc);
  if (filtersList) {
    for (const f of filtersList) {
      if (f && typeof f === 'object' && typeof (f as Record<string, unknown>).name === 'string') {
        orderedFilters.push((f as Record<string, unknown>).name as string);
      }
    }
  }

  const jwtRules = new Set<string>();
  collectJwtRuleRegexes(doc, jwtRules);

  const rbacPolicies = new Set<string>();
  collectRbacPolicyNames(doc, rbacPolicies);

  const ratelimitStatPrefixes = new Set<string>();
  collectStatPrefixes(doc, ratelimitStatPrefixes);
  // Filter out the chain-level shell prefix; it doesn't represent per-route enforcement.
  ratelimitStatPrefixes.delete('x_security_chain_ratelimit');
  ratelimitStatPrefixes.delete('x_security_hcm');

  // CORS routes — walk routes and check typed_per_filter_config.
  const corsRoutes: string[] = [];
  const routes = pickRoutes(doc);
  if (routes) {
    for (const r of routes) {
      if (!r || typeof r !== 'object') continue;
      const rr = r as Record<string, unknown>;
      const tpfc = rr.typed_per_filter_config as Record<string, unknown> | undefined;
      if (!tpfc?.['envoy.filters.http.cors']) continue;
      const label = routeLabel(rr);
      if (label) corsRoutes.push(label);
    }
  }

  const endpointPolicies = extractSentinels(yamlText);

  return {
    filters: orderedFilters.length ? orderedFilters : [...filterNames],
    jwtRules: [...jwtRules],
    rbacPolicies: [...rbacPolicies],
    ratelimitStatPrefixes: [...ratelimitStatPrefixes],
    corsRoutes,
    endpointPolicies
  };
}

function pickHttpFiltersList(doc: Record<string, unknown>): unknown[] | null {
  try {
    const listener = (doc.static_resources as Record<string, unknown>)?.listeners as unknown[];
    const fc = (listener?.[0] as Record<string, unknown>)?.filter_chains as unknown[];
    const filters = (fc?.[0] as Record<string, unknown>)?.filters as unknown[];
    const hcm = filters?.[0] as Record<string, unknown> | undefined;
    const tc = hcm?.typed_config as Record<string, unknown> | undefined;
    return (tc?.http_filters as unknown[]) ?? null;
  } catch {
    return null;
  }
}

function pickRoutes(doc: Record<string, unknown>): unknown[] | null {
  const filters = pickHttpFiltersList(doc);
  if (!filters) return null;
  // Walk back to HCM config to grab route_config
  try {
    const listener = (doc.static_resources as Record<string, unknown>)?.listeners as unknown[];
    const fc = (listener?.[0] as Record<string, unknown>)?.filter_chains as unknown[];
    const fl = (fc?.[0] as Record<string, unknown>)?.filters as unknown[];
    const hcm = fl?.[0] as Record<string, unknown> | undefined;
    const tc = hcm?.typed_config as Record<string, unknown> | undefined;
    const rc = tc?.route_config as Record<string, unknown> | undefined;
    const vh = rc?.virtual_hosts as unknown[] | undefined;
    const routes = (vh?.[0] as Record<string, unknown>)?.routes as unknown[];
    return routes ?? null;
  } catch {
    return null;
  }
}

function routeLabel(route: Record<string, unknown>): string | null {
  const match = route.match as Record<string, unknown> | undefined;
  if (!match) return null;
  const sr = match.safe_regex as Record<string, unknown> | undefined;
  const path = (sr?.regex as string) ?? (match.prefix as string) ?? null;
  const headers = match.headers as unknown[] | undefined;
  let method = '';
  if (headers) {
    for (const h of headers) {
      const hr = h as Record<string, unknown>;
      if (hr?.name === ':method') {
        const sm = hr.string_match as Record<string, unknown> | undefined;
        if (sm && typeof sm.exact === 'string') method = sm.exact;
      }
    }
  }
  return path ? `${method} ${path}`.trim() : null;
}

function emittedToArtifacts(parsed: EmittedEnvoyYaml): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  const seen = new Set<string>();
  const push = (a: EmittedArtifact) => {
    const k = `${a.kind}:${a.id}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(a);
  };

  for (const name of parsed.filters) {
    push({
      id: name,
      kind: 'envoy-http-filter',
      endpoint: '(http-filters)',
      label: `filter ${name}`
    });
  }
  for (const regex of parsed.jwtRules) {
    push({
      id: regex,
      kind: 'envoy-jwt-rule',
      endpoint: `(jwt) ${regex}`,
      label: `jwt_authn rule ${regex}`
    });
  }
  for (const pol of parsed.rbacPolicies) {
    push({
      id: pol,
      kind: 'envoy-rbac-policy',
      endpoint: `(rbac) ${pol}`,
      label: `rbac policy ${pol}`
    });
  }
  for (const sp of parsed.ratelimitStatPrefixes) {
    push({
      id: sp,
      kind: 'envoy-ratelimit-route',
      endpoint: `(ratelimit) ${sp}`,
      label: `local_ratelimit ${sp}`
    });
  }
  for (const route of parsed.corsRoutes) {
    push({
      id: route,
      kind: 'envoy-cors-route',
      endpoint: route,
      label: `CorsPolicy on ${route}`
    });
  }
  for (const key of parsed.endpointPolicies) {
    const [method, path] = key.split(':', 2);
    const endpoint = method && path ? `${method} ${path}` : key;
    push({
      id: key,
      kind: 'envoy-endpoint-policy',
      endpoint,
      label: `lua policy block ${key}`
    });
  }
  return out;
}

export const envoyReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('envoy');
    if (!gen) throw new Error('envoy generator not available');
    const arts = await gen.generate(spec);
    const envoyYaml = arts.find((a) => a.path === 'envoy.yaml' || a.path.endsWith('/envoy.yaml'));
    if (!envoyYaml) throw new Error('envoy generator did not emit envoy.yaml');
    const parsed = parseEmittedSnippet(envoyYaml.content);
    return emittedToArtifacts(parsed);
  },

  async readLoadedArtifacts(gateway: string, timeoutMs?: number): Promise<LoadedArtifact[]> {
    const [listeners, clusters, configDump] = await Promise.all([
      getJson<unknown>(gateway, '/listeners?format=json', timeoutMs).catch(() => ({})),
      getJson<unknown>(gateway, '/clusters?format=json', timeoutMs).catch(() => ({})),
      getJson<EnvoyConfigDump>(gateway, '/config_dump?include_eds=false', timeoutMs)
    ]);

    const out: LoadedArtifact[] = [];

    const filterNames = new Set<string>();
    collectFilterNames(configDump, filterNames);
    for (const name of filterNames) out.push({ id: name, kind: 'envoy-http-filter' });

    const jwtRules = new Set<string>();
    collectJwtRuleRegexes(configDump, jwtRules);
    for (const r of jwtRules) out.push({ id: r, kind: 'envoy-jwt-rule' });

    const rbacPolicies = new Set<string>();
    collectRbacPolicyNames(configDump, rbacPolicies);
    for (const p of rbacPolicies) out.push({ id: p, kind: 'envoy-rbac-policy' });

    const statPrefixes = new Set<string>();
    collectStatPrefixes(configDump, statPrefixes);
    statPrefixes.delete('x_security_chain_ratelimit');
    statPrefixes.delete('x_security_hcm');
    for (const s of statPrefixes) out.push({ id: s, kind: 'envoy-ratelimit-route' });

    // CORS routes — best signal from config_dump is the presence of CorsPolicy
    // typed_per_filter_config under a route. We walk the routes and report.
    const corsRouteLabels = new Set<string>();
    walkCorsRoutes(configDump, corsRouteLabels);
    for (const c of corsRouteLabels) out.push({ id: c, kind: 'envoy-cors-route' });

    const sentinels = new Set<string>();
    for (const s of walkStrings(configDump)) for (const k of extractSentinels(s)) sentinels.add(k);
    for (const key of sentinels) out.push({ id: key, kind: 'envoy-endpoint-policy' });

    void listeners; void clusters;
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
          rejected.push({ id: art.id, reason: `${art.label}: emitted but not present in /config_dump` });
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

    if (loaded.length === 0) {
      diagnostics.push(
        'envoy /config_dump returned no x-security artifacts — the bootstrap may not have loaded'
      );
    } else {
      const haveJwt = loaded.some((l) => l.kind === 'envoy-http-filter' && l.id === 'envoy.filters.http.jwt_authn');
      const wantJwt = emitted.some((l) => l.kind === 'envoy-http-filter' && l.id === 'envoy.filters.http.jwt_authn');
      if (wantJwt && !haveJwt) {
        diagnostics.push('jwt_authn emitted but not present in /config_dump — native JWT validation will not run');
      }
    }

    return { rows, diagnostics };
  }
};

/** Walk routes in a parsed config_dump and collect CORS-overriding route labels. */
function walkCorsRoutes(node: unknown, into: Set<string>): void {
  if (Array.isArray(node)) {
    for (const v of node) walkCorsRoutes(v, into);
    return;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    if (obj.match && obj.typed_per_filter_config) {
      const tpfc = obj.typed_per_filter_config as Record<string, unknown>;
      if (tpfc['envoy.filters.http.cors']) {
        const label = routeLabel(obj);
        if (label) into.add(label);
      }
    }
    for (const v of Object.values(obj)) walkCorsRoutes(v, into);
  }
}
