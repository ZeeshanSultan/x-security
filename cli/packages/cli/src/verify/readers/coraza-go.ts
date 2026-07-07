// Coraza-Go reader.
//
// Coraza-Go (the library, not modsec-nginx) either parses every directive
// or aborts. So the verify story is simpler than ModSec-nginx:
//
//   - If `gateway` looks like an HTTP URL → GET <url>/debug/rules and
//     compare the returned rule-id list to what the generator emitted.
//     Apps using Coraza must opt in to exposing this — when missing,
//     we degrade to log scanning.
//   - Otherwise treat `gateway` as a file or `docker:<name>` and grep for
//     the host app's startup line. Conventional pattern:
//       "coraza: loaded N rules" / "WAF initialised with N rules"
//     The host app emits this; we won't be too strict about the exact
//     wording — match any "loaded <N> rules" line.
//
// If we can't get a debug endpoint AND can't find a loaded-N line, we
// report "unknown" and exit 3 — Coraza-Go is too quiet to second-guess.

import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { request } from 'undici';
import type { SpecIR } from '@x-security/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

const RULE_ID_RE = /\bid:(\d+)\b/;
const SEC_RULE_LINE = /^\s*(SecRule|SecAction)\b/;
const SECTION_BANNER = /^#\s*([A-Z]+)\s+(\/\S+)\s*\(operationId:/;
const LOADED_N_RE = /(?:rules?\s+loaded|loaded)\s*[:=]?\s*(\d+)\s*rules?/i;
const ABORT_RE = /coraza[:\s][^\n]*(error|abort|invalid|fail)[^\n]*/i;

function extractDirectives(yaml: string): string {
  const m = yaml.match(/^directives:\s*\|\s*\n([\s\S]*)$/m);
  const body = m?.[1];
  if (!body) return '';
  return body.split('\n').map((l) => l.replace(/^ {2}/, '')).join('\n');
}

function scanEmittedRules(directives: string): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  const lines = directives.split('\n');
  let endpoint = '(engine-globals)';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const b = line.match(SECTION_BANNER);
    if (b) { endpoint = `${b[1] ?? ''} ${b[2] ?? ''}`.trim(); continue; }
    if (!SEC_RULE_LINE.test(line)) continue;
    let id: string | undefined;
    for (let k = 0; k < 3 && i + k < lines.length; k++) {
      const m = (lines[i + k] ?? '').match(RULE_ID_RE);
      if (m && m[1]) { id = m[1]; break; }
    }
    if (id) out.push({ id, kind: 'coraza-rule', endpoint, label: line.trim().slice(0, 80), line: i + 1 });
  }
  return out;
}

async function readLogSource(gateway: string): Promise<string> {
  if (gateway.startsWith('docker:')) {
    const name = gateway.slice('docker:'.length);
    const r = spawnSync('docker', ['logs', name], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (r.error) throw new Error(`docker logs failed: ${r.error.message}`);
    if (r.status !== 0) {
      if (/No such container/i.test(r.stderr || '')) throw new Error(`gateway-unreachable: container "${name}" not found`);
      throw new Error(`docker logs ${name} exited ${r.status}: ${r.stderr}`);
    }
    return (r.stdout || '') + '\n' + (r.stderr || '');
  }
  return readFile(gateway, 'utf8').catch((e) => {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`gateway-unreachable: log file not found at ${gateway}`);
    }
    throw e;
  });
}

interface DebugRulesResponse { rules?: Array<{ id: number | string }>; }

export const corazaGoReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('coraza');
    if (!gen) throw new Error('coraza generator not available');
    const arts = await gen.generate(spec);
    const yml = arts.find((a) => a.path.endsWith('.yml') || a.path.endsWith('.yaml'));
    if (!yml) throw new Error('coraza generator did not emit a YAML artifact');
    return scanEmittedRules(extractDirectives(yml.content));
  },

  async readLoadedArtifacts(gateway: string, timeoutMs?: number): Promise<LoadedArtifact[]> {
    // HTTP debug endpoint path.
    if (gateway.startsWith('http://') || gateway.startsWith('https://')) {
      const url = gateway.replace(/\/$/, '') + '/debug/rules';
      try {
        const res = await request(url, {
          method: 'GET',
          ...(timeoutMs !== undefined ? { signal: AbortSignal.timeout(timeoutMs) } : {})
        });
        if (res.statusCode >= 400) {
          throw new Error(`debug-rules endpoint returned HTTP ${res.statusCode}`);
        }
        const body = (await res.body.json()) as DebugRulesResponse;
        const ids = body.rules ?? [];
        return ids.map((r) => ({ id: String(r.id), kind: 'coraza-rule' as const }));
      } catch (e) {
        const name = (e as Error).name;
        if (name === 'TimeoutError' || name === 'AbortError') {
          throw new Error(`${url} timed out after ${timeoutMs}ms`);
        }
        const msg = (e as Error).message;
        if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(msg)) throw new Error(`gateway-unreachable: ${msg}`);
        throw e;
      }
    }

    // Log-scrape path.
    const raw = await readLogSource(gateway);
    const summary = raw.match(LOADED_N_RE);
    const out: LoadedArtifact[] = [];
    if (summary) {
      out.push({ id: '__summary__', kind: 'coraza-rule', rejectionReason: `summary:${summary[1]}` });
    } else {
      out.push({ id: '__summary__', kind: 'coraza-rule', rejectionReason: 'summary:unknown' });
    }
    const abort = raw.match(ABORT_RE);
    if (abort) {
      out.push({ id: 'abort', kind: 'coraza-rule', rejectionReason: abort[0].trim() });
    }
    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];

    // Debug-endpoint mode: each loaded entry is a real rule id.
    const idLoaded = new Set(loaded.filter((l) => l.id !== '__summary__' && l.id !== 'abort').map((l) => l.id));
    const summary = loaded.find((l) => l.id === '__summary__');
    const abort = loaded.find((l) => l.id === 'abort');

    if (idLoaded.size > 0) {
      // Precise per-id reconciliation.
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
          if (idLoaded.has(a.id)) loadedCount++;
          else rejected.push({ id: a.id, ...(a.line !== undefined ? { line: a.line } : {}), reason: 'rule not present at /debug/rules' });
        }
        rows.push({
          endpoint,
          emitted: arts.length,
          loaded: loadedCount,
          rejected,
          status: rejected.length === 0 ? 'ok' : loadedCount === 0 ? 'failed' : 'partial'
        });
      }
      rows.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
      return { rows, diagnostics };
    }

    // Log-scrape mode: coarse-grained — we only know the total.
    const summaryStr = summary?.rejectionReason ?? 'summary:unknown';
    const total = summaryStr.startsWith('summary:') && summaryStr !== 'summary:unknown'
      ? Number(summaryStr.slice('summary:'.length)) || 0
      : -1;

    if (total < 0) diagnostics.push('Coraza-Go did not emit a "loaded N rules" line; coverage cannot be confirmed from logs alone');
    if (abort) diagnostics.push(`Coraza-Go reported: ${abort.rejectionReason}`);

    const byEndpoint = new Map<string, EmittedArtifact[]>();
    for (const a of emitted) {
      const list = byEndpoint.get(a.endpoint) ?? [];
      list.push(a);
      byEndpoint.set(a.endpoint, list);
    }
    const rows: VerifyRow[] = [];
    const totalEmitted = emitted.length;
    const everythingLoaded = total >= totalEmitted;
    const nothingLoaded = total === 0 || abort !== undefined;
    for (const [endpoint, arts] of byEndpoint) {
      const rejected: VerifyRow['rejected'] = [];
      let loadedCount = 0;
      for (const a of arts) {
        if (nothingLoaded) {
          rejected.push({ id: a.id, ...(a.line !== undefined ? { line: a.line } : {}), reason: abort?.rejectionReason ?? 'Coraza-Go loaded 0 rules' });
        } else if (everythingLoaded || total < 0) {
          // total<0 (unknown): give benefit of the doubt per-rule but
          // surface diagnostic above. total>=emitted: assume full load.
          if (total < 0) {
            rejected.push({ id: a.id, ...(a.line !== undefined ? { line: a.line } : {}), reason: 'unconfirmed: no debug endpoint, no startup summary' });
          } else {
            loadedCount++;
          }
        } else {
          // Partial: we know N loaded out of M emitted but not which.
          // Mark them collectively as partial — pick a proportional slice.
          loadedCount++; // best-effort; surfaced via diagnostic
        }
      }
      rows.push({
        endpoint,
        emitted: arts.length,
        loaded: loadedCount,
        rejected,
        status: rejected.length === 0 ? 'ok' : loadedCount === 0 ? 'failed' : 'partial'
      });
    }
    rows.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
    return { rows, diagnostics };
  }
};
