// Coraza-SPOA reader.
//
// In a Coraza-SPOA deployment HAProxy forwards request metadata over the
// SPOP protocol to a `coraza-spoa` daemon. The daemon evaluates SecRules
// and returns an action (allow/deny/log).
//
// Three positive-confirmation channels (W12-C):
//   1. CONFIG-FILE (per-rule, deterministic, offline-safe — preferred):
//      `docker cp` the SPOA daemon's config YAML and the rule files it
//      Include's. Any emitted id present in the rule file is confirmed
//      "present in loaded config". This works even on the distroless
//      coraza-spoa image because `docker cp` doesn't need a shell.
//   2. HAPROXY RULEID=: every distinct ruleid= field in HAProxy access
//      logs. These rules definitely loaded AND fired at least once.
//      Supplements channel 1 for "I saw it actually work" evidence.
//   3. SPOA STARTUP COUNT: `coraza: loaded N rules` line in SPOA stderr.
//      Coarse but useful — tells us how many the engine accepted.
//
// Rule D-1: each channel is a structured-input read. We never regex over
// noisy log streams to *invent* per-rule confirmation. If the config file
// is unreadable AND no HAProxy ruleid= hit AND no startup line, the rule
// is reported "unverifiable" — not silently counted as loaded.
//
// Gateway addr formats:
//   docker:<haproxy>+docker:<spoa>                          (preferred)
//   docker:<haproxy>+docker:<spoa>+config:/path/to/spoa.yaml (explicit cfg)
//   docker:<spoa>                                            (config-only)

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import yaml from 'js-yaml';
import type { SpecIR } from '@writ/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

/** Standard locations the SPOA daemon may be loading config from. */
const DEFAULT_SPOA_CONFIG_PATHS = [
  '/shared/coraza-spoa.yaml',
  '/etc/coraza-spoa/coraza-spoa.yaml',
  '/etc/coraza-spoa/config.yaml',
  '/coraza-spoa.yaml'
];

const RULE_ID_RE = /\bid:(\d+)\b/;
const SEC_RULE_LINE = /^\s*(SecRule|SecAction)\b/;
const SECTION_BANNER = /^#\s*([A-Z]+)\s+(\/\S+)\s*\(operationId:/;
const HAPROXY_RULEID_RE = /\bruleid=(\d+)\b/g;
const SPOA_LOADED_RE = /(?:rules?\s+loaded|loaded)\s*[:=]?\s*(\d+)\s*rules?/i;
const SPOA_ABORT_RE = /coraza[:\s][^\n]*(error|abort|invalid|fail)[^\n]*/i;

function extractDirectives(yamlText: string): string {
  const m = yamlText.match(/^directives:\s*\|\s*\n([\s\S]*)$/m);
  const body = m?.[1];
  if (!body) return '';
  return body.split('\n').map((l) => l.replace(/^ {2}/, '')).join('\n');
}

export function scanEmittedRules(directives: string): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  const lines = directives.split('\n');
  let endpoint = '(engine-globals)';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const b = line.match(SECTION_BANNER);
    if (b) {
      endpoint = `${b[1] ?? ''} ${b[2] ?? ''}`.trim();
      continue;
    }
    if (!SEC_RULE_LINE.test(line)) continue;
    let id: string | undefined;
    for (let k = 0; k < 3 && i + k < lines.length; k++) {
      const m = (lines[i + k] ?? '').match(RULE_ID_RE);
      if (m && m[1]) {
        id = m[1];
        break;
      }
    }
    if (id) {
      out.push({
        id,
        kind: 'coraza-rule',
        endpoint,
        label: line.trim().slice(0, 80),
        line: i + 1
      });
    }
  }
  return out;
}

interface SplitGateway {
  haproxy?: string;
  spoa?: string;
  /** Optional explicit path inside the SPOA container to the daemon's YAML config. */
  configPath?: string;
}

export function parseSpoaGateway(gateway: string): SplitGateway {
  const parts = gateway.split('+').map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0) throw new Error('coraza-spoa gateway: empty');
  const out: SplitGateway = {};
  for (const p of parts) {
    if (p.startsWith('config:')) {
      out.configPath = p.slice('config:'.length);
      continue;
    }
    if (!p.startsWith('docker:')) {
      throw new Error(`coraza-spoa gateway parts must be docker:<container> or config:<path> (got "${p}")`);
    }
    const name = p.slice('docker:'.length);
    // Convention: substring "haproxy" or "hap" → HAProxy; "spoa" or "coraza" → SPOA.
    // If both substrings absent in the same name, assume first part is HAProxy.
    if (/haproxy|hap[-_]/i.test(name) && out.haproxy === undefined) out.haproxy = name;
    else if (/spoa|coraza/i.test(name) && out.spoa === undefined) out.spoa = name;
    else if (out.haproxy === undefined) out.haproxy = name;
    else out.spoa = name;
  }
  if (!out.haproxy && !out.spoa) {
    throw new Error(`coraza-spoa gateway: no container identified in "${gateway}"`);
  }
  return out;
}

export function dockerLogs(container: string): string {
  const r = spawnSync('docker', ['logs', container], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024
  });
  if (r.error) throw new Error(`docker logs ${container} failed: ${r.error.message}`);
  if (r.status !== 0) {
    if (/No such container/i.test(r.stderr || '')) {
      throw new Error(`gateway-unreachable: container "${container}" not found`);
    }
    throw new Error(`docker logs ${container} exited ${r.status}: ${r.stderr}`);
  }
  return (r.stdout || '') + '\n' + (r.stderr || '');
}

/**
 * Copy a file out of a (possibly distroless) container using `docker cp`.
 * Returns the file contents or `undefined` if the file is absent. Throws
 * only on container-level failures (container missing, daemon error).
 */
export function dockerCopyFile(container: string, containerPath: string): string | undefined {
  const tmp = mkdtempSync(path.join(tmpdir(), 'ss-spoa-'));
  try {
    const local = path.join(tmp, path.basename(containerPath) || 'file');
    const r = spawnSync('docker', ['cp', `${container}:${containerPath}`, local], {
      encoding: 'utf8'
    });
    if (r.error) throw new Error(`docker cp failed: ${r.error.message}`);
    if (r.status !== 0) {
      const err = r.stderr || '';
      if (/No such container/i.test(err)) {
        throw new Error(`gateway-unreachable: container "${container}" not found`);
      }
      // "No such file or directory" / "Could not find the file" → absent path.
      if (/No such file|Could not find the file|not found in/i.test(err)) return undefined;
      throw new Error(`docker cp ${container}:${containerPath} exited ${r.status}: ${err}`);
    }
    if (!existsSync(local)) return undefined;
    const st = statSync(local);
    if (st.isDirectory()) return undefined; // never recurse blind dirs here.
    return readFileSync(local, 'utf8');
  } finally {
    try { rmSync(tmp, { recursive: true, force: true }); } catch { /* swallow */ }
  }
}

/**
 * Given the contents of a coraza-spoa YAML config, return:
 *   - inline directives blocks (already loaded text)
 *   - paths Include'd from within those blocks (resolved relative to nothing —
 *     they're absolute in every fixture we've seen; relative paths are skipped
 *     because we can't reliably resolve container-side CWD)
 */
export function extractIncludesAndInline(spoaYamlText: string): {
  inline: string[];
  includes: string[];
} {
  const inline: string[] = [];
  const includes: string[] = [];
  let doc: unknown;
  try { doc = yaml.load(spoaYamlText); } catch { return { inline, includes }; }
  const apps = (doc as { applications?: Array<{ directives?: string }> } | null)?.applications;
  if (!Array.isArray(apps)) return { inline, includes };
  for (const app of apps) {
    const d = app?.directives;
    if (typeof d !== 'string') continue;
    inline.push(d);
    for (const line of d.split('\n')) {
      const m = line.match(/^\s*Include\s+(\S+)\s*$/);
      if (m && m[1] && m[1].startsWith('/')) includes.push(m[1]);
    }
  }
  return { inline, includes };
}

/** Extract SecRule/SecAction ids from a rule-file blob. */
export function extractRuleIds(ruleText: string): Set<string> {
  const out = new Set<string>();
  for (const line of ruleText.split('\n')) {
    if (!SEC_RULE_LINE.test(line)) continue;
    const m = line.match(RULE_ID_RE);
    if (m && m[1]) out.add(m[1]);
  }
  return out;
}

/**
 * Resolve the SPOA daemon's config + rule files inside the container and
 * return the union of rule-IDs present. Returns:
 *   - ids: empty Set if config can't be found (caller surfaces diagnostic)
 *   - source: which container path the config came from
 *   - missing: included paths that were referenced but couldn't be read
 */
export function readSpoaConfigRules(
  container: string,
  explicitConfigPath?: string
): { ids: Set<string>; configSource?: string; missingIncludes: string[] } {
  const candidates = explicitConfigPath
    ? [explicitConfigPath, ...DEFAULT_SPOA_CONFIG_PATHS]
    : DEFAULT_SPOA_CONFIG_PATHS;

  let cfgText: string | undefined;
  let cfgSource: string | undefined;
  for (const p of candidates) {
    cfgText = dockerCopyFile(container, p);
    if (cfgText) { cfgSource = p; break; }
  }
  if (!cfgText || !cfgSource) {
    return { ids: new Set(), missingIncludes: [] };
  }

  const { inline, includes } = extractIncludesAndInline(cfgText);
  const ids = new Set<string>();
  for (const blob of inline) for (const id of extractRuleIds(blob)) ids.add(id);

  const missingIncludes: string[] = [];
  for (const inc of includes) {
    const body = dockerCopyFile(container, inc);
    if (body === undefined) { missingIncludes.push(inc); continue; }
    for (const id of extractRuleIds(body)) ids.add(id);
  }
  return { ids, configSource: cfgSource, missingIncludes };
}

export interface SpoaSignals {
  /** rule ids observed in HAProxy access logs. */
  haproxyRuleIds: Set<string>;
  /** SPOA-reported total rule count from startup, or -1 if unknown. */
  spoaLoadedCount: number;
  /** SPOA abort/error line if present. */
  spoaAbort?: string;
}

export function collectSignals(haproxyLog: string, spoaLog: string): SpoaSignals {
  const haproxyRuleIds = new Set<string>();
  HAPROXY_RULEID_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HAPROXY_RULEID_RE.exec(haproxyLog)) !== null) {
    haproxyRuleIds.add(m[1]!);
  }
  const ld = spoaLog.match(SPOA_LOADED_RE);
  const spoaLoadedCount = ld ? Number(ld[1]) : -1;
  const ab = spoaLog.match(SPOA_ABORT_RE);
  return {
    haproxyRuleIds,
    spoaLoadedCount: Number.isFinite(spoaLoadedCount) ? spoaLoadedCount : -1,
    ...(ab ? { spoaAbort: ab[0].trim() } : {})
  };
}

export const corazaSpoaReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('coraza');
    if (!gen) throw new Error('coraza generator not available');
    const arts = await gen.generate(spec);
    const yml = arts.find((a) => a.path.endsWith('.yml') || a.path.endsWith('.yaml'));
    if (!yml) throw new Error('coraza generator did not emit a YAML artifact');
    return scanEmittedRules(extractDirectives(yml.content));
  },

  async readLoadedArtifacts(gateway: string): Promise<LoadedArtifact[]> {
    const split = parseSpoaGateway(gateway);
    const haproxyLog = split.haproxy ? dockerLogs(split.haproxy) : '';
    const spoaLog = split.spoa ? dockerLogs(split.spoa) : '';
    const sig = collectSignals(haproxyLog, spoaLog);

    const out: LoadedArtifact[] = [];

    // Channel 1 (positive, deterministic): rule ids present in the
    // SPOA daemon's actual loaded config file(s) inside the container.
    let configIds = new Set<string>();
    let configSource: string | undefined;
    let missingIncludes: string[] = [];
    if (split.spoa) {
      try {
        const r = readSpoaConfigRules(split.spoa, split.configPath);
        configIds = r.ids;
        configSource = r.configSource;
        missingIncludes = r.missingIncludes;
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.includes('gateway-unreachable')) throw e;
        // Container reachable but config copy hit a non-fatal snag — keep
        // going with log-based signals and surface in diagnostics.
        out.push({
          id: '__config_error__',
          kind: 'coraza-rule',
          rejectionReason: `config-read-error:${msg}`
        });
      }
    }
    for (const id of configIds) {
      out.push({ id, kind: 'coraza-rule', rejectionReason: 'source:config' });
    }
    if (configSource) {
      out.push({ id: '__config_source__', kind: 'coraza-rule', rejectionReason: `config:${configSource}` });
    }
    for (const mi of missingIncludes) {
      out.push({ id: '__missing_include__', kind: 'coraza-rule', rejectionReason: `missing-include:${mi}` });
    }

    // Channel 2 (positive, runtime evidence): HAProxy ruleid= fields.
    for (const id of sig.haproxyRuleIds) {
      out.push({ id, kind: 'coraza-rule', rejectionReason: 'source:haproxy' });
    }

    // Channel 3 (coarse): SPOA startup line.
    out.push({
      id: '__summary__',
      kind: 'coraza-rule',
      rejectionReason: sig.spoaLoadedCount >= 0 ? `summary:${sig.spoaLoadedCount}` : 'summary:unknown'
    });
    if (sig.spoaAbort) {
      out.push({ id: '__abort__', kind: 'coraza-rule', rejectionReason: sig.spoaAbort });
    }
    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];
    const summary = loaded.find((l) => l.id === '__summary__');
    const abort = loaded.find((l) => l.id === '__abort__');
    const configSource = loaded.find((l) => l.id === '__config_source__');
    const missingIncludes = loaded.filter((l) => l.id === '__missing_include__');
    const configError = loaded.find((l) => l.id === '__config_error__');
    const summaryVal = summary?.rejectionReason ?? 'summary:unknown';
    const summaryKnown = summaryVal !== 'summary:unknown';
    const summaryCount = summaryKnown
      ? Number(summaryVal.slice('summary:'.length)) || 0
      : -1;

    // Channel 1: rule ids confirmed present in the SPOA daemon's actual
    // loaded config file inside the container.
    const configHits = new Set(
      loaded.filter((l) => l.rejectionReason === 'source:config').map((l) => l.id)
    );
    // Channel 2: rule ids observed in HAProxy ruleid= fields. For back-
    // compat with pre-W12 callers that pass id-shaped entries without a
    // source: tag, treat any non-marker, non-config id as a HAProxy hit.
    const haproxyHits = new Set(
      loaded
        .filter((l) =>
          !l.id.startsWith('__') &&
          l.rejectionReason !== 'source:config'
        )
        .map((l) => l.id)
    );

    if (configSource) {
      diagnostics.push(
        `coraza-spoa config: ${configHits.size} rule ids resolved from ${configSource.rejectionReason?.slice('config:'.length)}`
      );
    } else if (configError) {
      diagnostics.push(`coraza-spoa config read failed: ${configError.rejectionReason}`);
    } else {
      diagnostics.push(
        'coraza-spoa config: not located in container — falling back to HAProxy ruleid= + SPOA startup count'
      );
    }
    for (const mi of missingIncludes) {
      diagnostics.push(`coraza-spoa config: ${mi.rejectionReason} — ids in that file are unverifiable`);
    }
    if (summaryKnown) {
      diagnostics.push(`coraza-spoa startup: ${summaryCount} rules loaded`);
    }
    if (abort) {
      diagnostics.push(`coraza-spoa reported: ${abort.rejectionReason}`);
    }
    if (!configSource && !summaryKnown && haproxyHits.size === 0) {
      diagnostics.push(
        'coraza-spoa: no positive load signal available — coverage inferred from HAProxy ruleid= fields only'
      );
    }

    // Confidence model (Rule D-1):
    //   - rule id is present in the SPOA config file     → loaded (channel 1)
    //   - rule id appears in HAProxy ruleid= field       → loaded (channel 2)
    //   - SPOA aborted, or startup summary == 0          → reject everything
    //   - SPOA startup count >= emitted AND no other     → assume full load
    //     positive channel disagreed
    //   - otherwise                                      → unconfirmed; reject
    //     with a specific reason. Never silently round up.
    const totalEmitted = emitted.length;
    const nothingLoaded = !!abort || (summaryKnown && summaryCount === 0);
    const haveAnyPositive = configHits.size > 0 || haproxyHits.size > 0;
    const everythingLoaded =
      !nothingLoaded && !haveAnyPositive && summaryKnown && summaryCount >= totalEmitted;

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
        if (nothingLoaded) {
          rejected.push({
            id: a.id,
            ...(a.line !== undefined ? { line: a.line } : {}),
            reason: abort?.rejectionReason ?? 'coraza-spoa loaded 0 rules'
          });
          continue;
        }
        if (configHits.has(a.id) || haproxyHits.has(a.id)) {
          loadedCount++;
          continue;
        }
        if (everythingLoaded) {
          loadedCount++;
          continue;
        }
        if (configSource) {
          // We DID read the config but this id wasn't in it.
          rejected.push({
            id: a.id,
            ...(a.line !== undefined ? { line: a.line } : {}),
            reason: 'rule id not present in SPOA loaded config file'
          });
          continue;
        }
        if (summaryKnown && summaryCount > 0) {
          rejected.push({
            id: a.id,
            ...(a.line !== undefined ? { line: a.line } : {}),
            reason: `unconfirmed: rule not observed in HAProxy ruleid= fields and SPOA loaded ${summaryCount}/${totalEmitted}`
          });
          continue;
        }
        rejected.push({
          id: a.id,
          ...(a.line !== undefined ? { line: a.line } : {}),
          reason: 'unconfirmed: no SPOA config readable, no startup count, no HAProxy ruleid= hit'
        });
      }
      const status: VerifyRow['status'] =
        rejected.length === 0 ? 'ok' : loadedCount === 0 ? 'failed' : 'partial';
      rows.push({ endpoint, emitted: arts.length, loaded: loadedCount, rejected, status });
    }
    rows.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
    return { rows, diagnostics };
  }
};
