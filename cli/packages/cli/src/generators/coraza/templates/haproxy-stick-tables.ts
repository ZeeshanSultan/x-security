/**
 * HAProxy stick-tables emitter — closes W10-7's cross-request rate-limit gap
 * for the Coraza-SPOA chain.
 *
 * Why this exists: Coraza-Go's runtime rejects `setvar:ip.X` (only the TX
 * collection is legal at runtime — verified against ghcr.io/corazawaf/
 * coraza-spoa). Cross-request rate-limit cannot live inside the Coraza
 * ruleset for SPOA deployments. HAProxy already sits in front of the SPOA
 * daemon in the chain, and its `stick-table` mechanism is purpose-built
 * for in-memory L7 counters with TTL.
 *
 * This module emits a sibling artifact `haproxy-stick-tables.cfg` containing:
 *
 *   1. One `backend st_writ_<slug>` per rate-limited endpoint with a
 *      `stick-table type {ip|string} size 100k expire <window> store
 *      http_req_rate(<window>)` (and optionally `http_req_rate(1s)` when
 *      `burst` is declared).
 *
 *   2. A trailing `# === WRIT FRONTEND SNIPPET ===` block containing
 *      the `acl/http-request track-sc0/http-request deny` lines the operator
 *      pastes into their existing frontend (or, in the harness, the spoa-init
 *      sidecar merges automatically).
 *
 * Honest limitations (per Rule D-1, surfaced as warnings, never silenced):
 *
 *   - **Composite identifiers** (v0.5 `{components, combinator}`): HAProxy
 *     stick-tables key off ONE column. We honor the first component and
 *     emit a loud `downgrade` warning naming the dropped components.
 *
 *   - **Peer replication** (W13-D): stick-tables are in-memory per HAProxy
 *     process. Multi-instance HA fleets must opt in via the `peers` option
 *     (CLI: `--coraza-peers "node1:10.0.0.1:10000,node2:10.0.0.2:10000"`).
 *     When supplied we emit a `peers writ` section and attach
 *     `peers writ` to every stick-table block so HAProxy replicates
 *     the counters between the named instances. When omitted the artifact
 *     is byte-identical to the single-instance W11 emission.
 *
 *   - **`api-key` / `user-id` identifiers**: HAProxy can't see the JWT
 *     subject without a Lua/SPOE extractor; we key off the `Authorization`
 *     header value (best-effort identity-bearing key). This is documented
 *     in the generated comment block.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import type { RateLimit, RateLimitIdentifier } from '@writ/schema';
import { parseDurationSec } from '../rules.js';
import type { CorazaEngineName, EngineWarning } from '../profiles.js';

/** HAProxy stick-table window strings (must be one of HAProxy's units). */
function durationToHaproxy(window: string): string {
  // HAProxy understands `s`, `m`, `h`, `d`. Writ Duration uses the same
  // units, so a trim is enough; we just validate the string parses.
  const secs = parseDurationSec(window);
  if (!Number.isFinite(secs) || secs <= 0) return '1m';
  return window.trim();
}

/** Slugify "<METHOD> <path>" for backend names. ASCII alnum + `_` only. */
function slugify(method: string, path: string): string {
  const raw = `${method}_${path}`.toLowerCase();
  return raw
    .replace(/[{}]/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60);
}

/** Build an HAProxy ACL `path` predicate that matches the OpenAPI path template. */
function aclPathPredicate(aclName: string, path: string): string {
  // OpenAPI templated segments (`{id}`) become `-m beg`-prefix matchers split
  // at the first `{`. For non-templated paths we use exact match.
  const firstBrace = path.indexOf('{');
  if (firstBrace === -1) {
    return `acl ${aclName} path ${path}`;
  }
  const prefix = path.slice(0, firstBrace);
  return `acl ${aclName} path_beg ${prefix}`;
}

interface ResolvedKey {
  /** HAProxy `stick-table type` value: `ip` or `string len N`. */
  tableType: string;
  /** HAProxy fetch expression used by `track-sc0` and `sc0_*`. */
  fetch: string;
  /** Human label for the comment header. */
  label: string;
  /** Optional warning (composite, downgrade). */
  warning?: EngineWarning;
}

/** Normalize identifier into ordered string list. */
function flattenIdentifier(id: RateLimitIdentifier | undefined): {
  primary: string;
  dropped: string[];
} {
  if (id === undefined) return { primary: 'ip', dropped: [] };
  if (typeof id === 'string') return { primary: id, dropped: [] };
  if (Array.isArray(id)) return { primary: id[0] ?? 'ip', dropped: id.slice(1) };
  // {components, combinator}
  const comps = id.components ?? [];
  return { primary: comps[0] ?? 'ip', dropped: comps.slice(1) };
}

function resolveKey(
  rl: RateLimit,
  engine: CorazaEngineName,
  endpointId: string
): ResolvedKey {
  const { primary, dropped } = flattenIdentifier(rl.identifier);
  const droppedWarning: EngineWarning | undefined = dropped.length
    ? {
        severity: 'downgrade',
        engine,
        endpoint: endpointId,
        reason:
          `rateLimit.identifier composite: HAProxy stick-tables key off a single column. ` +
          `Honored "${primary}"; dropped: ${dropped.map((d) => `"${d}"`).join(', ')}. ` +
          `Operator should verify single-key enforcement is sufficient.`,
        detail: { honored: primary, dropped: dropped.join(','), engine },
      }
    : undefined;

  const withWarn = (base: Omit<ResolvedKey, 'warning'>): ResolvedKey =>
    droppedWarning ? { ...base, warning: droppedWarning } : { ...base };

  if (primary === 'ip' || primary === 'fingerprint') {
    return withWarn({
      tableType: 'ip',
      fetch: 'src',
      label: primary === 'fingerprint' ? 'fingerprint (downgraded to src)' : 'src',
    });
  }
  if (primary === 'user-id') {
    // Best-effort identity key from Authorization header.
    return withWarn({
      tableType: 'string len 128',
      fetch: 'req.hdr(Authorization)',
      label: 'user-id (Authorization header)',
    });
  }
  if (primary === 'api-key') {
    return withWarn({
      tableType: 'string len 128',
      fetch: 'req.hdr(X-API-Key)',
      label: 'api-key (X-API-Key header)',
    });
  }
  if (primary.startsWith('header:')) {
    const name = primary.slice('header:'.length).trim();
    return withWarn({
      tableType: 'string len 128',
      fetch: `req.hdr(${name})`,
      label: `header:${name}`,
    });
  }
  // Unknown identifier — fall back to src with a downgrade warning.
  return {
    tableType: 'ip',
    fetch: 'src',
    label: `${primary} (unknown identifier, downgraded to src)`,
    warning: {
      severity: 'downgrade',
      engine,
      endpoint: endpointId,
      reason: `rateLimit.identifier="${primary}" not natively supported by HAProxy stick-tables; downgraded to src (client IP).`,
      detail: { from: primary, to: 'src' },
    },
  };
}

/** Parsed `<name>:<host>:<port>` peer entry. */
export interface HaproxyPeer {
  name: string;
  host: string;
  port: number;
}

/** HAProxy peer-group name used in the emitted `peers <name>` section. */
const PEER_GROUP = 'writ';

/**
 * Parse the `--coraza-peers` CLI string. Format:
 *   `name1:host1:port1,name2:host2:port2,...`
 *
 * Malformed entries are rejected loudly (per Rule D-1): we return an empty
 * peers list and push a `downgrade` warning naming the offending input so
 * the operator notices that peer-replication is NOT active. Partial parsing
 * (silently dropping bad entries while keeping good ones) would let a typo
 * silently halve the peer-group — exactly the kind of "looks like it works"
 * failure mode the rule bans.
 */
export function parseCorazaPeers(
  raw: string | undefined,
  engine: CorazaEngineName,
  warnings: EngineWarning[]
): HaproxyPeer[] {
  if (!raw || raw.trim() === '') return [];
  const entries = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const peers: HaproxyPeer[] = [];
  const seenNames = new Set<string>();
  for (const entry of entries) {
    const parts = entry.split(':');
    if (parts.length !== 3) {
      warnings.push({
        severity: 'downgrade',
        engine,
        endpoint: '*',
        reason:
          `--coraza-peers entry "${entry}" is malformed (expected name:host:port); ` +
          `peer replication disabled — stick-tables remain single-instance.`,
        detail: { entry, raw },
      });
      return [];
    }
    const [name, host, portStr] = parts as [string, string, string];
    const port = Number(portStr);
    if (!name || !host || !Number.isInteger(port) || port <= 0 || port > 65535) {
      warnings.push({
        severity: 'downgrade',
        engine,
        endpoint: '*',
        reason:
          `--coraza-peers entry "${entry}" has invalid name/host/port; ` +
          `peer replication disabled — stick-tables remain single-instance.`,
        detail: { entry, raw },
      });
      return [];
    }
    if (seenNames.has(name)) {
      warnings.push({
        severity: 'downgrade',
        engine,
        endpoint: '*',
        reason:
          `--coraza-peers contains duplicate peer name "${name}"; ` +
          `peer replication disabled — stick-tables remain single-instance.`,
        detail: { entry, raw },
      });
      return [];
    }
    seenNames.add(name);
    peers.push({ name, host, port });
  }
  if (peers.length < 2) {
    warnings.push({
      severity: 'downgrade',
      engine,
      endpoint: '*',
      reason:
        `--coraza-peers needs at least 2 peers to replicate; got ${peers.length}. ` +
        `Peer replication disabled — stick-tables remain single-instance.`,
      detail: { raw },
    });
    return [];
  }
  return peers;
}

function expandRateLimits(ep: EndpointIR): RateLimit[] {
  const rl = ep.policy.rateLimit;
  if (!rl) return [];
  return Array.isArray(rl) ? rl : [rl];
}

/**
 * Build the haproxy-stick-tables.cfg artifact body. Returns `null` when no
 * endpoint declares a rateLimit (caller skips artifact emission).
 */
export function buildHaproxyStickTables(
  spec: SpecIR,
  engine: CorazaEngineName,
  warnings: EngineWarning[],
  peers: HaproxyPeer[] = []
): string | null {
  const sorted = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );

  interface Emission {
    backend: string;
    aclName: string;
    pathAcl: string;
    track: string;
    deny: string;
    /** Optional banner comment placed above the frontend snippet (gap C1). */
    frontendComment?: string;
  }
  const emissions: Emission[] = [];
  const seenBackends = new Set<string>();
  /** Short-window guard for the burst table (W24-C1). HAProxy unit string. */
  const BURST_WINDOW = '10s';
  /** Counter slot used for the burst table so the long-window sc0 is preserved. */
  const BURST_SC = 'sc1';

  for (const ep of sorted) {
    const rls = expandRateLimits(ep);
    if (rls.length === 0) continue;
    const epId = `${ep.method} ${ep.path}`;

    rls.forEach((rl, idx) => {
      const windowH = durationToHaproxy(rl.window);
      const key = resolveKey(rl, engine, epId);
      if (key.warning) warnings.push(key.warning);

      const slug = slugify(ep.method, ep.path) + (rls.length > 1 ? `_${idx}` : '');
      const backendName = `st_writ_${slug}`;
      if (seenBackends.has(backendName)) return;
      seenBackends.add(backendName);

      const peersClause = peers.length > 0 ? ` peers ${PEER_GROUP}` : '';
      const backendBlock = [
        `# ─ ${ep.method} ${ep.path} — ${rl.requests}/${rl.window} per ${key.label}`,
        `#   identifier: ${typeof rl.identifier === 'string' ? rl.identifier : JSON.stringify(rl.identifier ?? 'ip')}`,
        `backend ${backendName}`,
        `    stick-table type ${key.tableType} size 100k expire ${windowH} store http_req_rate(${windowH})${peersClause}`,
      ].join('\n');

      const aclName = `ss_${slug}`;
      const pathAcl = aclPathPredicate(aclName, ep.path);
      const methodAclName = `ss_m_${slug}`;
      const methodAcl = `acl ${methodAclName} method ${ep.method.toUpperCase()}`;

      const track = `http-request track-sc0 ${key.fetch} table ${backendName} if ${aclName} ${methodAclName}`;
      const deny = `http-request deny deny_status 429 hdr ratelimit-by "${key.label}" hdr ratelimit-backend "${backendName}" if ${aclName} ${methodAclName} { sc0_http_req_rate(${backendName}) gt ${rl.requests} }`;

      emissions.push({
        backend: backendBlock,
        aclName,
        pathAcl: `${pathAcl}\n${methodAcl}`,
        track,
        deny,
      });

      // W24-C1: separate per-route burst stick-table when `rateLimit.burst`
      // is set. A short-window (10s) table layered on the same identifier
      // catches credential-stuffing / OTP-brute spikes that would otherwise
      // hide under the long-window ceiling. We track on sc1 so the sc0
      // counter on the main table above is left untouched.
      if (typeof rl.burst === 'number' && rl.burst > 0) {
        const burstBackend = `${backendName}_burst`;
        if (seenBackends.has(burstBackend)) return;
        seenBackends.add(burstBackend);

        const burstBackendBlock = [
          `# ─ ${ep.method} ${ep.path} — BURST: ${rl.burst}/${BURST_WINDOW} per ${key.label} (gap C1)`,
          `#   Short-window guard layered atop the ${rl.requests}/${rl.window} table above:`,
          `#   the slow ceiling stops sustained abuse; this one closes the burst hole`,
          `#   (>${rl.burst} requests inside ${BURST_WINDOW}) before it ever reaches that ceiling.`,
          `#   identifier: ${typeof rl.identifier === 'string' ? rl.identifier : JSON.stringify(rl.identifier ?? 'ip')}`,
          `backend ${burstBackend}`,
          `    stick-table type ${key.tableType} size 100k expire ${BURST_WINDOW} store http_req_rate(${BURST_WINDOW})${peersClause}`,
        ].join('\n');

        const burstAcl = `ss_${slug}_burst`;
        const burstMethodAcl = `ss_m_${slug}_burst`;
        const burstPathAcl = aclPathPredicate(burstAcl, ep.path);
        const burstMethodLine = `acl ${burstMethodAcl} method ${ep.method.toUpperCase()}`;
        const burstTrack = `http-request track-${BURST_SC} ${key.fetch} table ${burstBackend} if ${burstAcl} ${burstMethodAcl}`;
        const burstDeny = `http-request deny deny_status 429 hdr ratelimit-by "${key.label}" hdr ratelimit-backend "${burstBackend}" if ${burstAcl} ${burstMethodAcl} { ${BURST_SC}_http_req_rate(${burstBackend}) gt ${rl.burst} }`;
        const burstComment = `# gap C1 — burst-headroom for ${ep.method} ${ep.path}. ${BURST_SC} is a fresh tracker so the long-window sc0 count above is untouched.`;

        emissions.push({
          backend: burstBackendBlock,
          aclName: burstAcl,
          pathAcl: `${burstPathAcl}\n${burstMethodLine}`,
          track: burstTrack,
          deny: burstDeny,
          frontendComment: burstComment,
        });
      }
    });
  }

  if (emissions.length === 0) return null;

  const out: string[] = [];
  out.push('# Writ → HAProxy stick-tables — auto-generated. DO NOT EDIT BY HAND.');
  out.push(`# engine:    ${engine}`);
  out.push(`# source:    ${spec.info.title} ${spec.info.version}`);
  out.push('#');
  out.push('# This file closes the cross-request rate-limit gap that Coraza-Go-family');
  out.push('# engines (coraza-go, coraza-spoa) cannot express in-band: the runtime');
  out.push('# only honors `setvar` on the TX collection (per-transaction). HAProxy');
  out.push('# stick-tables provide true cross-request counters at L7.');
  out.push('#');
  out.push('# How to integrate into an EXISTING haproxy.cfg:');
  out.push('#');
  out.push('#   1. Append every `backend st_writ_*` block below to your');
  out.push('#      haproxy.cfg (they are self-contained — no listener needed).');
  out.push('#   2. Inside your existing `frontend` block, paste the ACL/track/deny');
  out.push('#      snippet from the "WRIT FRONTEND SNIPPET" section.');
  out.push('#   3. Reload HAProxy. The counters live in-process; for HA fleets,');
  out.push('#      configure a `peers` block — see DEPLOYMENT.md.');
  out.push('');

  if (peers.length > 0) {
    out.push('# ════════════════════════════════════════════════════════════════');
    out.push(`# Peer replication (group: ${PEER_GROUP}) — ${peers.length} instance(s)`);
    out.push('# Each stick-table below references `peers writ` so HAProxy');
    out.push('# replicates counters between the listed nodes in near-real-time.');
    out.push('# ════════════════════════════════════════════════════════════════');
    out.push(`peers ${PEER_GROUP}`);
    for (const p of peers) {
      out.push(`    peer ${p.name} ${p.host}:${p.port}`);
    }
    out.push('');
  }

  out.push('# ════════════════════════════════════════════════════════════════');
  out.push('# Stick-table backend definitions');
  out.push('# ════════════════════════════════════════════════════════════════');
  out.push('');
  for (const e of emissions) {
    out.push(e.backend);
    out.push('');
  }

  out.push('# ════════════════════════════════════════════════════════════════');
  out.push('# === WRIT FRONTEND SNIPPET ===');
  out.push('# Paste the lines below into your existing `frontend` block. The');
  out.push('# harness preflight-spoa.sh script does this automatically.');
  out.push('# ════════════════════════════════════════════════════════════════');
  out.push('');
  for (const e of emissions) {
    // Unindented — the harness preflight script re-indents to match the
    // operator's existing frontend block. Manual operators reading this
    // file paste the lines into their `frontend ...` block at the same
    // indent the rest of their frontend uses.
    if (e.frontendComment) out.push(e.frontendComment);
    out.push(e.pathAcl);
    out.push(e.track);
    out.push(e.deny);
    out.push('');
  }

  return out.join('\n');
}
