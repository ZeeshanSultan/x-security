// BunkerWeb reader.
//
// BunkerWeb's topology is two containers:
//   - bw-scheduler: owns /data/configs/modsec/<service>/x-security.conf
//   - bunkerweb (nginx + libmodsec): the data-plane process that actually
//     parses + evaluates rules. The scheduler rsyncs its configs into
//     /etc/nginx/modsec*/ inside the bunkerweb container at reload time.
//
// The source of truth for "rules are actually loaded" is therefore the
// bunkerweb container's nginx config (resolved by `nginx -T`). Even if the
// scheduler holds a perfectly valid file, a reload failure or sync skew
// means the bunkerweb instance is enforcing something different.
//
// Strategy (mirrors wave-4 modsec-nginx reader):
//   1. EMITTED: ask the bunkerweb generator for `configs/modsec/x-security.conf`
//      and scan it for `id:NNNNNN` directives. Group by `# Source endpoints:`
//      comments which the generator emits before each rule block.
//   2. LOADED: `docker exec <bunkerweb> nginx -T`, then scan the resolved
//      config for each emitted rule id. A rule is loaded iff its id appears
//      verbatim in the resolved nginx config.
//   3. RECONCILE: per-endpoint coverage; surface scheduler-side
//      "rule present in scheduler config but missing from bunkerweb config"
//      as a sync-skew diagnostic when both containers are addressable.
//
// Gateway addr formats:
//   docker:<bunkerweb-container>
//   docker:<scheduler-container>+docker:<bunkerweb-container>

import { spawnSync } from 'node:child_process';
import type { SpecIR } from '@x-security/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

const RULE_ID_RE = /\bid:(\d{4,7})\b/g;
const SOURCE_ENDPOINTS_RE = /^#\s*Source endpoints?:\s*(.+)$/i;
const SECTION_HEADER_RE = /^#\s*x-security-generated [^\n]*$/i;

interface SplitGateway {
  bunkerweb: string;
  scheduler?: string;
}

export function parseBunkerwebGateway(gateway: string): SplitGateway {
  const parts = gateway.split('+').map((s) => s.trim()).filter(Boolean);
  // Convention: bunkerweb data-plane is the LAST docker: in the chain; any
  // earlier ones are scheduler/aux containers we cross-check against.
  if (parts.length === 0) throw new Error(`gateway: empty`);
  if (parts.length === 1) {
    const last = parts[0]!;
    if (!last.startsWith('docker:')) {
      throw new Error(`bunkerweb gateway must be docker:<container> (got "${gateway}")`);
    }
    return { bunkerweb: last.slice('docker:'.length) };
  }
  const last = parts[parts.length - 1]!;
  const first = parts[0]!;
  if (!last.startsWith('docker:') || !first.startsWith('docker:')) {
    throw new Error(`bunkerweb gateway parts must be docker:<container> (got "${gateway}")`);
  }
  return { bunkerweb: last.slice('docker:'.length), scheduler: first.slice('docker:'.length) };
}

/** Read the resolved nginx config from inside the BunkerWeb container. */
export function dumpNginxConfig(container: string): string {
  const r = spawnSync('docker', ['exec', container, 'nginx', '-T'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024
  });
  if (r.error) throw new Error(`docker exec ${container} nginx -T failed: ${r.error.message}`);
  if (r.status !== 0) {
    const stderr = (r.stderr || '').trim();
    if (/No such container/i.test(stderr)) {
      throw new Error(`gateway-unreachable: container "${container}" not found`);
    }
    // nginx -T may exit non-zero if a directive fails to parse; preserve
    // whatever it did print so we can still attribute partial loads.
    return (r.stdout || '') + '\n' + stderr;
  }
  return (r.stdout || '') + '\n' + (r.stderr || '');
}

/** Read the scheduler-side x-security.conf for sync-skew diagnostics. Best-
 *  effort: returns '' if not available. */
export function readSchedulerConf(container: string): string {
  const r = spawnSync(
    'docker',
    ['exec', container, 'sh', '-c', 'cat /data/configs/modsec/*/x-security.conf /data/configs/modsec/x-security.conf 2>/dev/null'],
    { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }
  );
  if (r.error || r.status !== 0) return '';
  return r.stdout || '';
}

interface ParsedRule {
  id: string;
  endpoint: string;
  label: string;
  line: number;
}

export function scanBunkerwebRules(conf: string): ParsedRule[] {
  const out: ParsedRule[] = [];
  const lines = conf.split('\n');
  let currentEndpoints: string[] = [];
  let inWritBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const src = line.match(SOURCE_ENDPOINTS_RE);
    if (src && src[1]) {
      currentEndpoints = src[1].split(',').map((s) => s.trim()).filter(Boolean);
      inWritBlock = true;
      continue;
    }
    if (SECTION_HEADER_RE.test(line)) {
      // Block of cross-endpoint rules (e.g. JWT auth shared across many
      // endpoints). Keep prior endpoint list if any, otherwise mark global.
      inWritBlock = true;
      if (currentEndpoints.length === 0) currentEndpoints = ['(engine-globals)'];
      continue;
    }
    if (!inWritBlock) continue;
    if (line.startsWith('# Settings below are NOT ModSec')) {
      inWritBlock = false;
      continue;
    }

    RULE_ID_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    const seen = new Set<string>();
    while ((m = RULE_ID_RE.exec(line)) !== null) {
      const id = m[1]!;
      if (seen.has(id)) continue;
      seen.add(id);
      // Per `id:` directive convention, one rule has one id even if the line
      // mentions another (tag/setvar). The first id captured is the rule id.
      // Emit one ParsedRule per (id × endpoint) to attribute coverage.
      const endpoints = currentEndpoints.length ? currentEndpoints : ['(engine-globals)'];
      for (const ep of endpoints) {
        out.push({
          id,
          endpoint: ep,
          label: line.trim().slice(0, 80),
          line: i + 1
        });
      }
      // Take only the first id per line — that's the rule id; subsequent
      // digits in the same directive are tx variables or limits.
      break;
    }
  }
  return out;
}

export const bunkerwebReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('bunkerweb');
    if (!gen) throw new Error('bunkerweb generator not available — cannot determine emitted artifacts');
    const arts = await gen.generate(spec);
    const conf = arts.find((a) => a.path.endsWith('configs/modsec/x-security.conf'));
    if (!conf) throw new Error('bunkerweb generator did not emit configs/modsec/x-security.conf');
    return scanBunkerwebRules(conf.content).map((r) => ({
      id: r.id,
      kind: 'coraza-rule' as const,
      endpoint: r.endpoint,
      label: r.label,
      line: r.line
    }));
  },

  async readLoadedArtifacts(gateway: string, _timeoutMs?: number): Promise<LoadedArtifact[]> {
    // No outbound HTTP here — `docker exec nginx -T`. timeoutMs n/a.
    const split = parseBunkerwebGateway(gateway);
    const dump = dumpNginxConfig(split.bunkerweb);
    const ids = new Set<string>();
    RULE_ID_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = RULE_ID_RE.exec(dump)) !== null) ids.add(m[1]!);
    const out: LoadedArtifact[] = [];
    for (const id of ids) out.push({ id, kind: 'coraza-rule' });
    if (ids.size === 0) {
      out.push({
        id: '__empty-dump__',
        kind: 'coraza-rule',
        rejectionReason:
          'nginx -T returned no x-security rule ids — the scheduler may not have synced configs/modsec into the bunkerweb container yet'
      });
    }

    // Optional scheduler-side cross-check.
    if (split.scheduler) {
      const schedConf = readSchedulerConf(split.scheduler);
      if (schedConf) {
        const schedIds = new Set<string>();
        for (const r of scanBunkerwebRules(schedConf)) schedIds.add(r.id);
        for (const sid of schedIds) {
          if (!ids.has(sid)) {
            out.push({
              id: `sync-skew:${sid}`,
              kind: 'coraza-rule',
              rejectionReason: `rule ${sid} present in scheduler config but missing from bunkerweb nginx -T output (sync skew)`
            });
          }
        }
      }
    }
    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];
    const empty = loaded.find((l) => l.id === '__empty-dump__');
    if (empty) diagnostics.push(empty.rejectionReason ?? 'no rules loaded');
    const skews = loaded.filter((l) => l.id.startsWith('sync-skew:'));
    for (const s of skews) diagnostics.push(s.rejectionReason ?? 'sync skew');

    const loadedIds = new Set(
      loaded
        .filter((l) => l.id !== '__empty-dump__' && !l.id.startsWith('sync-skew:'))
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
        if (loadedIds.has(a.id)) {
          loadedCount++;
        } else {
          rejected.push({
            id: a.id,
            ...(a.line !== undefined ? { line: a.line } : {}),
            reason: empty
              ? (empty.rejectionReason ?? 'no rules loaded')
              : `rule id:${a.id} not present in bunkerweb nginx -T output`
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
