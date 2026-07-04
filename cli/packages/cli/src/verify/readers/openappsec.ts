// OpenAppSec reader.
//
// open-appsec ("nano-agent") loads policy from /etc/cp/conf/ and writes
// per-request decisions to /var/log/nano_agent/decision.log as JSON-lines.
// We don't have a structured admin API, so verification proceeds in two
// stages:
//
//   1. Confirm the policy file the generator emitted reached /etc/cp/conf/.
//      We `docker exec ls /etc/cp/conf/` and look for *.policy / *.yaml
//      entries whose contents reference one of our Writ asset names.
//      As a coarse loaded-or-not signal, the presence of the file plus a
//      cat of its head bearing the Writ generator marker is enough.
//   2. Per-asset attribution: scan the emitted policy for the list of
//      `specific-rules[].name`, `practices[].name`, `assets[]`. Each one
//      becomes an EmittedArtifact whose endpoint is its declared host/asset.
//      A loaded entry exists iff the asset/practice name appears in the
//      docker-side policy text (i.e. the agent loaded it).
//
// Verdict attribution (post-traffic) is documented but not required for
// pre-traffic coverage gating — if /var/log/nano_agent/decision.log exists
// and is non-empty, we add a diagnostic listing the count of decisions
// whose practiceName contains "writ".
//
// Gateway addr: docker:<openappsec-agent-container>

import { spawnSync } from 'node:child_process';
import type { SpecIR } from '@writ/core';
import * as yaml from 'js-yaml';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

interface EmittedPolicyShape {
  /** Practice names: e.g. writ-threat-prevention. */
  practices: string[];
  /** Specific-rule asset names: e.g. writ-asset-vapi. */
  assets: Array<{ name: string; host?: string }>;
  /** Triggers/responses for diagnostic completeness. */
  triggers: string[];
  customResponses: string[];
  /** Schema-validation entries from writ-extended. */
  schemaEntries: Array<{ name: string; endpoint: string }>;
}

export function parseOpenappsecPolicy(policyYaml: string): EmittedPolicyShape {
  const doc = (yaml.load(policyYaml) as Record<string, unknown> | undefined) ?? {};

  const practices: string[] = [];
  const pracRaw = doc.practices;
  if (Array.isArray(pracRaw)) {
    for (const p of pracRaw) {
      if (p && typeof p === 'object') {
        const name = (p as Record<string, unknown>).name;
        if (typeof name === 'string') practices.push(name);
      }
    }
  }

  const assets: Array<{ name: string; host?: string }> = [];
  const polRaw = doc.policies as Record<string, unknown> | undefined;
  const specific = polRaw?.['specific-rules'];
  if (Array.isArray(specific)) {
    for (const r of specific) {
      if (r && typeof r === 'object') {
        const obj = r as Record<string, unknown>;
        const name = typeof obj.name === 'string' ? obj.name : undefined;
        const host = typeof obj.host === 'string' ? obj.host : undefined;
        if (name) assets.push(host ? { name, host } : { name });
      }
    }
  }

  const triggers: string[] = [];
  const trigRaw = doc['log-triggers'];
  if (Array.isArray(trigRaw)) {
    for (const t of trigRaw) {
      if (t && typeof t === 'object') {
        const n = (t as Record<string, unknown>).name;
        if (typeof n === 'string') triggers.push(n);
      }
    }
  }

  const customResponses: string[] = [];
  const crRaw = doc['custom-responses'];
  if (Array.isArray(crRaw)) {
    for (const c of crRaw) {
      if (c && typeof c === 'object') {
        const n = (c as Record<string, unknown>).name;
        if (typeof n === 'string') customResponses.push(n);
      }
    }
  }

  const schemaEntries: Array<{ name: string; endpoint: string }> = [];
  const ext = doc['writ-extended'] as Record<string, unknown> | undefined;
  const sv = ext?.['schema-validation'];
  if (Array.isArray(sv)) {
    for (const s of sv) {
      if (!s || typeof s !== 'object') continue;
      const obj = s as Record<string, unknown>;
      const name = typeof obj.name === 'string' ? obj.name : undefined;
      const binding = obj.binding as Record<string, unknown> | undefined;
      const method = binding && typeof binding.method === 'string' ? binding.method : '';
      const path = binding && typeof binding.path === 'string' ? binding.path : '';
      if (name && method && path) schemaEntries.push({ name, endpoint: `${method} ${path}` });
    }
  }

  return { practices, assets, triggers, customResponses, schemaEntries };
}

/** Concat every relevant /etc/cp/conf/ file the agent might have loaded
 *  policy from. We don't know the exact filename (it varies by agent
 *  version), so dump anything in conf/ that's text. */
export function readAgentConf(container: string): string {
  // List candidate files then cat them. We deliberately scope to
  // *.yaml/*.policy/*.conf to avoid pulling binary state.
  const ls = spawnSync(
    'docker',
    [
      'exec',
      container,
      'sh',
      '-c',
      'find /etc/cp/conf -maxdepth 3 \\( -name "*.yaml" -o -name "*.policy" -o -name "*.conf" -o -name "*.json" \\) -type f 2>/dev/null'
    ],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  );
  if (ls.error) throw new Error(`docker exec ${container} find failed: ${ls.error.message}`);
  if (ls.status !== 0) {
    if (/No such container/i.test(ls.stderr || '')) {
      throw new Error(`gateway-unreachable: container "${container}" not found`);
    }
    return '';
  }
  const files = (ls.stdout || '').split('\n').map((s) => s.trim()).filter(Boolean);
  if (files.length === 0) return '';
  const cat = spawnSync(
    'docker',
    ['exec', container, 'sh', '-c', `cat ${files.map((f) => JSON.stringify(f)).join(' ')} 2>/dev/null`],
    { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
  );
  if (cat.error || cat.status !== 0) return '';
  return cat.stdout || '';
}

/** Count writ-attributed verdicts in /var/log/nano_agent/decision.log.
 *  Returns -1 if the log doesn't exist (most pre-traffic situations). */
export function countWritVerdicts(container: string): number {
  const r = spawnSync(
    'docker',
    [
      'exec',
      container,
      'sh',
      '-c',
      'test -f /var/log/nano_agent/decision.log && grep -c "writ" /var/log/nano_agent/decision.log || echo MISSING'
    ],
    { encoding: 'utf8', maxBuffer: 1 * 1024 * 1024 }
  );
  if (r.error || r.status !== 0) return -1;
  const out = (r.stdout || '').trim();
  if (out === 'MISSING' || out === '') return -1;
  const n = Number(out);
  return Number.isFinite(n) ? n : -1;
}

function policyToArtifacts(p: EmittedPolicyShape): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  const push = (id: string, endpoint: string, label: string) =>
    out.push({ id, kind: 'envoy-endpoint-policy', endpoint, label });

  for (const pr of p.practices) push(pr, '(practices)', `practice ${pr}`);
  for (const a of p.assets) push(a.name, `(asset) ${a.host ?? a.name}`, `asset ${a.name}`);
  for (const t of p.triggers) push(t, '(triggers)', `trigger ${t}`);
  for (const c of p.customResponses) push(c, '(custom-responses)', `custom-response ${c}`);
  for (const s of p.schemaEntries) push(s.name, s.endpoint, `schema-validation ${s.name}`);
  return out;
}

export const openappsecReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('openappsec');
    if (!gen) throw new Error('openappsec generator not available');
    const arts = await gen.generate(spec);
    const policy = arts.find((a) => a.path.endsWith('policy.yaml'));
    if (!policy) throw new Error('openappsec generator did not emit policy.yaml');
    return policyToArtifacts(parseOpenappsecPolicy(policy.content));
  },

  async readLoadedArtifacts(gateway: string): Promise<LoadedArtifact[]> {
    if (!gateway.startsWith('docker:')) {
      throw new Error(`openappsec gateway must be docker:<container> (got "${gateway}")`);
    }
    const container = gateway.slice('docker:'.length);
    const confBlob = readAgentConf(container);
    const out: LoadedArtifact[] = [];

    if (!confBlob) {
      out.push({
        id: '__no-policy-loaded__',
        kind: 'envoy-endpoint-policy',
        rejectionReason:
          '/etc/cp/conf/ on the openappsec agent contains no policy/yaml files — agent did not load any Writ policy'
      });
      return out;
    }

    // Anything name-like that the policy file mentions: practice names,
    // asset names, schema-validation entry names. Map by exact substring
    // presence in the on-agent text.
    // We treat each unique "writ-*" token as a present id.
    const presence = new Set<string>();
    const reToken = /\b(writ[-A-Za-z0-9_]+|(?:get|post|put|delete|patch|head|options)-[A-Za-z0-9_-]+)\b/gi;
    let m: RegExpExecArray | null;
    while ((m = reToken.exec(confBlob)) !== null) presence.add(m[1]!);
    for (const tok of presence) out.push({ id: tok, kind: 'envoy-endpoint-policy' });

    const verdicts = countWritVerdicts(container);
    if (verdicts >= 0) {
      out.push({
        id: '__verdict-count__',
        kind: 'envoy-endpoint-policy',
        rejectionReason: `verdicts:${verdicts}`
      });
    }
    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];
    const noPolicy = loaded.find((l) => l.id === '__no-policy-loaded__');
    if (noPolicy) diagnostics.push(noPolicy.rejectionReason ?? 'no policy loaded');

    const verdicts = loaded.find((l) => l.id === '__verdict-count__');
    if (verdicts && verdicts.rejectionReason) {
      const n = Number(verdicts.rejectionReason.replace(/^verdicts:/, ''));
      if (Number.isFinite(n)) {
        diagnostics.push(`/var/log/nano_agent/decision.log contains ${n} Writ-attributed verdict line(s)`);
      }
    }

    const loadedIds = new Set(
      loaded
        .filter((l) => l.id !== '__no-policy-loaded__' && l.id !== '__verdict-count__')
        .map((l) => l.id)
    );

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
      for (const a of arts) {
        if (!noPolicy && loadedIds.has(a.id)) {
          loadedCount++;
        } else {
          rejected.push({
            id: a.id,
            reason: noPolicy
              ? (noPolicy.rejectionReason ?? 'no policy loaded')
              : `name "${a.id}" not present in /etc/cp/conf — agent did not load this practice/asset`
          });
        }
      }
      const status: VerifyRow['status'] =
        rejected.length === 0 ? 'ok' : loadedCount === 0 ? 'failed' : 'partial';
      rows.push({ endpoint, emitted: arts.length, loaded: loadedCount, rejected, status });
    }
    rows.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
    return { rows, diagnostics };
  }
};
