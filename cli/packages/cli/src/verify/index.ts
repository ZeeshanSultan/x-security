// `x-security verify` — read-only feedback loop. Asks the gateway "which
// of the artifacts I emitted did you actually load?" and produces a
// per-endpoint coverage report.
//
// Born from REPORT-v3 §3: the Coraza generator emitted 365 SecRules but
// ModSecurity-nginx silently loaded zero of them. The test harness checked
// status codes — which were 403 from bundled CRS PL1, not from anything
// x-security wrote. Nobody noticed for two release waves.
//
// Design: per-target Reader implements re-emit (truth) + read-loaded
// (gateway) + reconcile. The orchestrator below picks the reader,
// computes the % loaded, and produces table/json/sarif output. No
// gateway mutation, ever — every reader uses GET / read-only file ops.

import type { SpecIR } from '@x-security/core';
import { loadSpec, buildResolverChain } from '@x-security/core';
import { kongReader } from './readers/kong.js';
import { modsecNginxReader } from './readers/modsec-nginx.js';
import { corazaGoReader } from './readers/coraza-go.js';
import { corazaSpoaReader } from './readers/coraza-spoa.js';
import { envoyReader } from './readers/envoy.js';
import { bunkerwebReader } from './readers/bunkerweb.js';
import { openappsecReader } from './readers/openappsec.js';
import { renderTable, renderJson, renderSarif } from './report.js';

export type VerifyTarget = 'kong' | 'coraza' | 'envoy' | 'bunkerweb' | 'openappsec';
export type VerifyEngine = 'modsec-nginx' | 'coraza-go' | 'coraza-spoa';
export type VerifyFormat = 'table' | 'json' | 'sarif';

/** Something the generator wrote out: a Kong plugin row, a Coraza SecRule, etc. */
export interface EmittedArtifact {
  /** Stable identifier — Kong plugin name keyed by route, or Coraza SecRule id. */
  id: string;
  /** Kind for grouping in the report. */
  kind:
    | 'kong-plugin' | 'kong-service' | 'kong-route'
    | 'coraza-rule'
    | 'envoy-http-filter'
    // wave-9 native-filter rev. `envoy-rate-limit-descriptor` is retained for
    // backwards compatibility with consumers but no longer emitted; the
    // wave-9 reader emits per-route stat-prefix `envoy-ratelimit-route` rows
    // instead, which the live admin /stats endpoint can confirm.
    | 'envoy-rate-limit-descriptor'
    | 'envoy-endpoint-policy'
    | 'envoy-jwt-rule'
    | 'envoy-rbac-policy'
    | 'envoy-ratelimit-route'
    | 'envoy-cors-route';
  /** Endpoint key (`METHOD path`) the artifact belongs to. Empty for engine-globals. */
  endpoint: string;
  /** Free-form display label. */
  label: string;
  /** Line in the emitted file, for cross-reference with gateway error logs. 1-indexed. */
  line?: number;
}

/** Something the gateway told us it has. */
export interface LoadedArtifact {
  id: string;
  kind: EmittedArtifact['kind'];
  /** If the gateway rejected this artifact, the reason it gave. */
  rejectionReason?: string;
  /** Line number the gateway pointed at when complaining. */
  rejectedAtLine?: number;
}

export interface VerifyRow {
  endpoint: string;
  emitted: number;
  loaded: number;
  rejected: Array<{ id?: string; line?: number; reason: string }>;
  status: 'ok' | 'partial' | 'failed' | 'unknown';
}

export interface VerifyReport {
  target: VerifyTarget;
  engine?: VerifyEngine;
  gateway: string;
  rows: VerifyRow[];
  totals: { emitted: number; loaded: number; coveragePct: number };
  thresholdPct: number;
  /** True when coveragePct ≥ thresholdPct. */
  passed: boolean;
  /** Surface-level diagnostics (e.g. "container not running"). */
  diagnostics: string[];
}

export interface GatewayReader {
  readEmittedArtifacts(spec: SpecIR): Promise<EmittedArtifact[]>;
  /** `timeoutMs`, when set, bounds any outbound HTTP request the reader makes.
   *  Readers that only touch Docker/files ignore it. */
  readLoadedArtifacts(gateway: string, timeoutMs?: number): Promise<LoadedArtifact[]>;
  reconcile(emitted: EmittedArtifact[], loaded: LoadedArtifact[]): {
    rows: VerifyRow[];
    diagnostics: string[];
  };
}

export interface VerifyOptions {
  target: VerifyTarget;
  /** Kong → admin URL; Coraza → file path / `docker:<name>` / debug URL. */
  gateway: string;
  /** Required when target=coraza. */
  engine?: VerifyEngine;
  format?: VerifyFormat;
  /** Coverage threshold (0..100). Default 90. */
  thresholdPct?: number;
  /** Abort outbound gateway HTTP requests after this many ms. Unset = no timeout. */
  timeoutMs?: number;
}

export interface VerifyRunResult {
  report: VerifyReport;
  rendered: string;
  /** 0 = ≥threshold, 2 = below threshold, 3 = gateway unreachable. */
  exitCode: 0 | 2 | 3;
}

const UNREACHABLE_MARKERS = ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'gateway-unreachable'];

export async function runVerify(specPath: string, opts: VerifyOptions): Promise<VerifyRunResult> {
  const threshold = opts.thresholdPct ?? 90;
  const reader = pickReader(opts);
  const resolver = buildResolverChain({});
  const spec = await loadSpec(specPath, { resolver, strict: false });

  let emitted: EmittedArtifact[] = [];
  let loaded: LoadedArtifact[] = [];
  const diagnostics: string[] = [];

  try {
    emitted = await reader.readEmittedArtifacts(spec);
  } catch (e) {
    diagnostics.push(`emit-side error: ${(e as Error).message}`);
  }

  let unreachable = false;
  try {
    loaded = await reader.readLoadedArtifacts(opts.gateway, opts.timeoutMs);
  } catch (e) {
    const msg = (e as Error).message;
    diagnostics.push(`gateway read error: ${msg}`);
    if (UNREACHABLE_MARKERS.some((m) => msg.includes(m))) unreachable = true;
  }

  const { rows, diagnostics: reconDiag } = reader.reconcile(emitted, loaded);
  diagnostics.push(...reconDiag);

  const totalsEmitted = rows.reduce((s, r) => s + r.emitted, 0);
  const totalsLoaded = rows.reduce((s, r) => s + r.loaded, 0);
  const coveragePct = totalsEmitted === 0 ? 0 : Math.round((totalsLoaded / totalsEmitted) * 100);
  const passed = totalsEmitted > 0 && coveragePct >= threshold;

  const report: VerifyReport = {
    target: opts.target,
    ...(opts.engine ? { engine: opts.engine } : {}),
    gateway: opts.gateway,
    rows,
    totals: { emitted: totalsEmitted, loaded: totalsLoaded, coveragePct },
    thresholdPct: threshold,
    passed,
    diagnostics
  };

  const rendered = renderReport(report, opts.format ?? 'table');
  const exitCode: 0 | 2 | 3 = unreachable ? 3 : passed ? 0 : 2;
  return { report, rendered, exitCode };
}

function pickReader(opts: VerifyOptions): GatewayReader {
  if (opts.target === 'kong') return kongReader;
  if (opts.target === 'envoy') return envoyReader;
  if (opts.target === 'bunkerweb') return bunkerwebReader;
  if (opts.target === 'openappsec') return openappsecReader;
  if (opts.target === 'coraza') {
    const engine = opts.engine ?? 'modsec-nginx';
    if (engine === 'modsec-nginx') return modsecNginxReader;
    if (engine === 'coraza-go') return corazaGoReader;
    if (engine === 'coraza-spoa') return corazaSpoaReader;
    throw new Error(`Unknown coraza engine: ${engine}`);
  }
  throw new Error(`Unknown target: ${opts.target}`);
}

function renderReport(r: VerifyReport, fmt: VerifyFormat): string {
  switch (fmt) {
    case 'json': return renderJson(r);
    case 'sarif': return renderSarif(r);
    case 'table':
    default: return renderTable(r);
  }
}
