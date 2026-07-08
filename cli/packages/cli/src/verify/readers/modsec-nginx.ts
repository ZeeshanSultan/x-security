// ModSecurity-nginx reader.
//
// Strategy:
//   1. EMITTED = ask the Coraza generator for its current output, extract
//      the `directives:` block, scan for `SecRule .* "id:NNN,...` and
//      `SecAction ... id:NNN,...`. Each match becomes one EmittedArtifact
//      tagged with its endpoint (parsed from the section banner the
//      generator writes — `# METHOD /path  (operationId: ...)`).
//   2. LOADED = read the nginx error log (file path OR `docker logs <name>`).
//      Grep for the load-time error pattern
//      `[error] ... ModSecurity: Rules error. File: <path>. Line: <n>. Column: <c>. <msg>`
//      and for the "rules loaded inline/local/remote: X/Y/Z" startup
//      summary. Each Rules error → rejection on the specific line.
//   3. RECONCILE = a rule loaded iff (a) no Rules error pointed at its line
//      AND (b) the cumulative "rules loaded" count from the startup line
//      is non-zero. If the cumulative count is zero we mark every rule as
//      "rejected: parse-aborted before reach" — this is the showstopper
//      case from REPORT-v3 §3.1.
//
// Read-only: only reads files, runs `docker logs --no-follow`, never modifies
// gateway state.

import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import type { SpecIR } from '@x-security/core';
import { loadGenerator } from '../../registry.js';
import type { EmittedArtifact, GatewayReader, LoadedArtifact, VerifyRow } from '../index.js';

const SECTION_BANNER = /^#\s*([A-Z]+)\s+(\/\S+)\s*\(operationId:\s*([^)]+)\)/;
const RULE_ID_RE = /\bid:(\d+)\b/;
const SEC_RULE_LINE = /^\s*(SecRule|SecAction)\b/;

// Nginx error-log shape (varies a bit across releases; cover the common cases):
//   2026/05/22 ... [error] ... ModSecurity: Rules error. File: /etc/.../x-security.conf. Line: 144. Column: 17. <msg>
const RULES_ERROR_RE =
  /ModSecurity:\s*(?:Rules error\.?\s*)?File:\s*([^.]+?)\.\s*Line:\s*(\d+)\.\s*Column:\s*(\d+)\.\s*(.*)$/;
// Some libmodsecurity builds drop the "Rules error" prefix and just say
// "Something wrong with initcol: ..." — catch those too.
const GENERIC_PARSE_ERR_RE = /ModSecurity:\s*(Something wrong with [^.\n]+|SecDefaultActions[^.\n]+)/;
// Startup summary the nginx module emits. Format observed on owasp/modsecurity-crs:nginx:
//   ModSecurity-nginx v1.0.X  ... or  rules loaded inline/local/remote: 0/365/0
const RULES_LOADED_SUMMARY = /rules loaded inline\/local\/remote:\s*(\d+)\/(\d+)\/(\d+)/i;

/** If `gateway` is a docker:<name>, dump the running nginx config (read-only,
 *  `nginx -T`) so we can check whether the x-security rules file was actually
 *  Include'd. Returns the dump string, or '' if the source isn't a container. */
async function readNginxConfigDump(gateway: string): Promise<string> {
  if (!gateway.startsWith('docker:')) return '';
  const name = gateway.slice('docker:'.length);
  const r = spawnSync('docker', ['exec', name, 'nginx', '-T'], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024
  });
  // `nginx -T` returns 0 even when it prints warnings to stderr.
  if (r.error || r.status !== 0) return '';
  const dump = (r.stdout || '') + '\n' + (r.stderr || '');

  // `nginx -T` does NOT recurse into ModSecurity's rules_file — that's
  // parsed by libmodsecurity, not nginx. Find every
  // `modsecurity_rules_file <path>` and `cat` it (and its transitive
  // Includes, one level deep — enough for the survival-mount case where
  // setup.conf glob-Includes /etc/modsecurity.d/owasp-crs/rules/*.conf).
  const modsecFiles = new Set<string>();
  for (const line of dump.split('\n')) {
    const m = line.match(/^\s*modsecurity_rules_file\s+(\S+?);?\s*$/i);
    if (m && m[1]) modsecFiles.add(m[1]);
  }
  const extra: string[] = [];
  for (const path of modsecFiles) {
    const cat = spawnSync('docker', ['exec', name, 'cat', path], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024
    });
    if (cat.error || cat.status !== 0) continue;
    extra.push(`# configuration file ${path}:`);
    extra.push(cat.stdout || '');
  }
  return dump + '\n' + extra.join('\n');
}

// x-security header markers the Coraza generator emits at the top of every
// output file (see packages/cli/src/generators/coraza/index.ts:66-71).
const X_SECURITY_HEADER_MARKERS = [
  'x-security → Coraza',
  'generator: x-security-coraza'
];

/** Resolve a glob Include via `docker exec ls`. Returns matched file paths.
 *  Used only for `docker:<name>` gateways. */
function listGlobInContainer(container: string, glob: string): string[] {
  // `sh -c "ls -1 <glob>"` lets the container's shell expand the glob.
  // 2>/dev/null hides ENOENT noise; we treat empty stdout as "no match".
  const r = spawnSync('docker', ['exec', container, 'sh', '-c', `ls -1 ${glob} 2>/dev/null`], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024
  });
  if (r.error || r.status !== 0) return [];
  return (r.stdout || '').split('\n').map((s) => s.trim()).filter(Boolean);
}

/** Read the first few lines of a file inside the container and check for
 *  any x-security-emitted header marker. */
function fileHasWritHeader(container: string, path: string): boolean {
  const r = spawnSync('docker', ['exec', container, 'sh', '-c', `head -5 ${JSON.stringify(path)} 2>/dev/null`], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024
  });
  if (r.error || r.status !== 0) return false;
  const head = r.stdout || '';
  return X_SECURITY_HEADER_MARKERS.some((m) => head.includes(m));
}

/** True iff the running nginx config Include's something that resolves to a
 *  x-security-emitted .conf file. We accept:
 *   (1) a literal `Include .../x-security*.conf` directive,
 *   (2) a glob include (`Include /dir/*.conf`) where the glob matches a file
 *       whose name contains "x-security" OR whose first 5 lines carry the
 *       x-security generator header marker (survival-mount case — REPORT-v4
 *       Open-6: rules ride a CRS-style glob and the literal "x-security" is
 *       only in the resolved filename, not the directive). */
export function xSecurityRulesAreIncluded(nginxDump: string, container?: string): boolean {
  if (!nginxDump) return true; // unknown — benefit of doubt; rule-count summary catches real failure
  const lines = nginxDump.split('\n');
  const includes: string[] = [];
  for (const line of lines) {
    const m = line.match(/^\s*Include\s+(\S+)/i);
    if (m && m[1]) includes.push(m[1]);
  }
  // (1) Direct hit: any Include path text contains "x-security".
  if (includes.some((i) => /x-security/i.test(i))) return true;

  // (2) Glob hit: any glob Include whose resolved files include either a
  // file named *x-security* OR a file with our header marker. Only doable
  // when we have a container to `docker exec` into.
  if (!container) return false;
  const globs = includes.filter((i) => /[*?[]/.test(i));
  for (const glob of globs) {
    const matched = listGlobInContainer(container, glob);
    if (matched.some((p) => /x-security/i.test(p))) return true;
    for (const p of matched) {
      if (fileHasWritHeader(container, p)) return true;
    }
  }
  return false;
}

/** Container/path resolution: file path | docker:<name> | ssh://... (skip). */
async function readGatewaySource(gateway: string): Promise<string> {
  if (gateway.startsWith('ssh://')) {
    throw new Error(`ssh:// gateway sources are not yet supported (got ${gateway})`);
  }
  if (gateway.startsWith('docker:')) {
    const name = gateway.slice('docker:'.length);
    // --tail=all is the default but be explicit; --timestamps off so the parser
    // sees the same line shape it would in a mounted file.
    const r = spawnSync('docker', ['logs', name], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (r.error) throw new Error(`docker logs failed: ${r.error.message}`);
    if (r.status !== 0) {
      const stderr = (r.stderr || '').trim();
      if (/No such container/i.test(stderr)) {
        throw new Error(`gateway-unreachable: container "${name}" not found`);
      }
      throw new Error(`docker logs ${name} exited ${r.status}: ${stderr}`);
    }
    return (r.stdout || '') + '\n' + (r.stderr || '');
  }
  // Plain file path.
  try {
    return await readFile(gateway, 'utf8');
  } catch (e) {
    const msg = (e as NodeJS.ErrnoException).code === 'ENOENT'
      ? `gateway-unreachable: log file not found at ${gateway}`
      : (e as Error).message;
    throw new Error(msg);
  }
}

/** Extract the `directives: |` block from a Coraza generator YAML artifact. */
function extractDirectives(yaml: string): string {
  const m = yaml.match(/^directives:\s*\|\s*\n([\s\S]*)$/m);
  const body = m?.[1];
  if (!body) return '';
  // The block is everything indented at least 2 spaces under the key.
  // js-yaml dumps it with 2-space indent; reverse that.
  return body.split('\n').map((l) => l.replace(/^ {2}/, '')).join('\n');
}

/** Parse SecRule/SecAction blobs out of a directives string. Returns map keyed by id. */
function scanEmittedRules(directives: string): EmittedArtifact[] {
  const out: EmittedArtifact[] = [];
  const lines = directives.split('\n');
  let currentEndpoint = '(engine-globals)';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const banner = line.match(SECTION_BANNER);
    if (banner) {
      currentEndpoint = `${banner[1] ?? ''} ${banner[2] ?? ''}`.trim();
      continue;
    }
    if (!SEC_RULE_LINE.test(line)) continue;
    // A rule may span multiple chained lines; the `id:` only appears on
    // the head. Look for it on this line or the next two.
    let id: string | undefined;
    for (let k = 0; k < 3 && i + k < lines.length; k++) {
      const m = (lines[i + k] ?? '').match(RULE_ID_RE);
      if (m && m[1]) { id = m[1]; break; }
    }
    if (!id) continue;
    out.push({
      id,
      kind: 'coraza-rule',
      endpoint: currentEndpoint,
      label: line.trim().slice(0, 80),
      line: i + 1
    });
  }
  return out;
}

export const modsecNginxReader: GatewayReader = {
  async readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]> {
    const gen = await loadGenerator('coraza');
    if (!gen) throw new Error('coraza generator not available — cannot determine emitted artifacts');
    const arts = await gen.generate(spec);
    const yml = arts.find((a) => a.path.endsWith('.yml') || a.path.endsWith('.yaml'));
    if (!yml) throw new Error('coraza generator did not emit a YAML artifact');
    const directives = extractDirectives(yml.content);
    return scanEmittedRules(directives);
  },

  async readLoadedArtifacts(gateway: string, _timeoutMs?: number): Promise<LoadedArtifact[]> {
    // No outbound HTTP here — reads a log file / `docker logs`. timeoutMs n/a.
    const raw = await readGatewaySource(gateway);
    const out: LoadedArtifact[] = [];

    // Inclusion check via `nginx -T` — the most reliable load-side signal.
    // If x-security's rules file isn't Include'd by the running config, NO
    // rules of ours loaded regardless of what the count summary says.
    const nginxDump = await readNginxConfigDump(gateway);
    const container = gateway.startsWith('docker:') ? gateway.slice('docker:'.length) : undefined;
    const included = xSecurityRulesAreIncluded(nginxDump, container);
    if (nginxDump && !included) {
      out.push({
        id: '__not-included__',
        kind: 'coraza-rule',
        rejectionReason: 'x-security rules file is not Include\'d by the running nginx config (nginx -T) — every emitted rule is unloaded'
      });
    }

    // Pass 1: explicit Rules-error lines (the high-signal failure case).
    for (const line of raw.split('\n')) {
      const m = line.match(RULES_ERROR_RE);
      if (m && m[2]) {
        out.push({
          id: `parse-error@${m[2]}`,
          kind: 'coraza-rule',
          rejectionReason: (m[4] ?? '').trim() || 'parse error',
          rejectedAtLine: Number(m[2])
        });
        continue;
      }
      const g = line.match(GENERIC_PARSE_ERR_RE);
      if (g && g[1]) {
        out.push({
          id: 'parse-error',
          kind: 'coraza-rule',
          rejectionReason: g[1].trim()
        });
      }
    }

    // Pass 2: did ANYTHING load? Scan for the rules-loaded summary.
    const summary = raw.match(RULES_LOADED_SUMMARY);
    if (summary && summary[1] !== undefined && summary[2] !== undefined && summary[3] !== undefined) {
      const total = Number(summary[1]) + Number(summary[2]) + Number(summary[3]);
      out.push({ id: '__summary__', kind: 'coraza-rule', rejectionReason: `summary:${total}` });
    } else {
      out.push({ id: '__summary__', kind: 'coraza-rule', rejectionReason: 'summary:unknown' });
    }

    return out;
  },

  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]) {
    const diagnostics: string[] = [];
    const notIncluded = loaded.find((l) => l.id === '__not-included__');
    const summary = loaded.find((l) => l.id === '__summary__');
    const summaryVal = summary?.rejectionReason ?? 'summary:unknown';
    const totalLoadedFromSummary = summaryVal.startsWith('summary:')
      ? Number(summaryVal.slice('summary:'.length)) || 0
      : 0;
    const summaryKnown = summaryVal !== 'summary:unknown';

    if (summaryKnown) {
      diagnostics.push(`gateway summary: ${totalLoadedFromSummary} rules loaded total (across all .conf files)`);
    } else {
      diagnostics.push(`could not find "rules loaded inline/local/remote" startup line — coverage inferred from parse-error lines only`);
    }

    if (notIncluded) {
      diagnostics.push(notIncluded.rejectionReason ?? 'x-security rules file not included by gateway config');
    }

    const rejectionsByLine = new Map<number, LoadedArtifact>();
    const genericRejections: LoadedArtifact[] = [];
    for (const l of loaded) {
      if (l.id === '__summary__' || l.id === '__not-included__') continue;
      if (l.rejectedAtLine !== undefined) rejectionsByLine.set(l.rejectedAtLine, l);
      else if (l.id === 'parse-error') genericRejections.push(l);
    }

    // Group emitted rules by endpoint.
    const byEndpoint = new Map<string, EmittedArtifact[]>();
    for (const a of emitted) {
      const list = byEndpoint.get(a.endpoint) ?? [];
      list.push(a);
      byEndpoint.set(a.endpoint, list);
    }

    const rows: VerifyRow[] = [];
    // Heuristic: if the gateway loaded ZERO x-security rules (summary
    // shows 0 local, or all parse-aborted before any rule reached the
    // engine), mark every emitted rule as rejected with the most
    // informative generic reason we have.
    const everythingRejected = !!notIncluded || (summaryKnown && totalLoadedFromSummary === 0);
    const genericReason = notIncluded?.rejectionReason
      ?? genericRejections[0]?.rejectionReason
      ?? (everythingRejected ? 'no x-security rules loaded (file likely not included by nginx, or parse aborted at engine-globals)' : '');

    for (const [endpoint, arts] of byEndpoint) {
      const rejected: VerifyRow['rejected'] = [];
      let loadedCount = 0;
      for (const art of arts) {
        const rej = art.line !== undefined ? rejectionsByLine.get(art.line) : undefined;
        if (rej) {
          rejected.push({ id: art.id, ...(art.line !== undefined ? { line: art.line } : {}), reason: rej.rejectionReason ?? 'parse error' });
        } else if (everythingRejected) {
          rejected.push({ id: art.id, ...(art.line !== undefined ? { line: art.line } : {}), reason: genericReason });
        } else {
          loadedCount++;
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
