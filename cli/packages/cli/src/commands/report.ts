// `lazy report --owasp|--coverage [--format <fmt>] <spec.yaml>`

import { loadSpec, buildResolverChain, StrictnessViolation } from '@writ/core';
import { buildOwaspReport, buildAnnotationCoverage } from '../reporters/owasp-analyze.js';
import { renderReport } from '../reporters/human.js';
import { toJson } from '../reporters/json.js';
import { owaspToSarif } from '../reporters/sarif.js';
import { reportToCsv } from '../reporters/csv.js';
import { reportToHtml } from '../reporters/html.js';
import { buildFeasibilityContext, parseTargetList } from '../reporters/feasibility.js';
import type { ReportFormat, ReportData } from '../reporters/types.js';

export interface ReportOptions {
  mode: 'owasp' | 'coverage';
  format: ReportFormat;
  strict?: boolean;
  vault?: boolean;
  awsSecrets?: boolean;
  vaultKvVersion?: 1 | 2;
  /** Comma-separated target list (e.g. "kong,coraza"). Only valid with --owasp. */
  feasible?: string;
  /** Fail with exit 4 if --feasible would produce ANY non-`feasible` verdict
   *  (i.e. any `Y` that drops to `Y*`/`~`). Computed from the SAME context as
   *  --feasible so the CLI exit and the report footnotes never disagree. */
  strictFidelity?: boolean;
}

export interface ReportResult {
  data: ReportData;
  rendered: string;
}

export async function runReport(specPath: string, opts: ReportOptions): Promise<ReportResult> {
  // Validation is best-effort here: report should still work on partially
  // annotated specs. Use lenient resolver so missing env vars don't blow up.
  const chainOpts: Parameters<typeof buildResolverChain>[0] = {};
  if (opts.vault) chainOpts.enableVault = true;
  if (opts.awsSecrets) chainOpts.enableAws = true;
  if (opts.vaultKvVersion) chainOpts.vaultKvVersion = opts.vaultKvVersion;
  const resolver = buildResolverChain(chainOpts);
  const spec = await loadSpec(specPath, { resolver, strict: false });

  let data: ReportData;
  if (opts.mode === 'owasp') {
    let feasCtx;
    if (opts.feasible && opts.feasible.length > 0) {
      const targets = parseTargetList(opts.feasible);
      feasCtx = await buildFeasibilityContext(targets);
    }
    data = buildOwaspReport(spec, feasCtx);
    // --strict-fidelity: scan the freshly-built rows for any feasibility
    // verdict that isn't `feasible` or `na`. We deliberately read from the
    // SAME OwaspCoverageRow.feasibility map the human renderer uses for `Y*`
    // footnotes — single source of truth.
    if (opts.strictFidelity) {
      if (!feasCtx) {
        throw new Error('--strict-fidelity requires --feasible <targets>.');
      }
      const offenders: Array<{ endpoint: string; id: string; status: string }> = [];
      if (data.kind === 'owasp') {
        for (const row of data.rows) {
          if (!row.feasibility) continue;
          for (const [id, verdict] of Object.entries(row.feasibility)) {
            if (verdict === 'partial' || verdict === 'none') {
              offenders.push({ endpoint: row.endpoint, id, status: verdict });
            }
          }
        }
      }
      if (offenders.length > 0) {
        const lines = [
          `${offenders.length} OWASP mitigation${offenders.length === 1 ? '' : 's'} declared but not fully enforceable by ${feasCtx.targets.join(',')}:`
        ];
        for (const o of offenders.slice(0, 20)) {
          lines.push(`  - ${o.endpoint}  ${o.id}: ${o.status}`);
        }
        if (offenders.length > 20) lines.push(`  ... +${offenders.length - 20} more`);
        throw new StrictnessViolation('S3', lines.join('\n'), { offenders });
      }
    }
  } else {
    if (opts.feasible) {
      throw new Error('--feasible is only valid with --owasp.');
    }
    if (opts.strictFidelity) {
      throw new Error('--strict-fidelity is only valid with --owasp --feasible.');
    }
    data = buildAnnotationCoverage(spec);
  }

  let rendered: string;
  switch (opts.format) {
    case 'json':
      rendered = toJson(data);
      break;
    case 'sarif':
      if (data.kind !== 'owasp') {
        throw new Error('SARIF output is only supported for --owasp reports.');
      }
      rendered = owaspToSarif(data, specPath);
      break;
    case 'csv':
      rendered = reportToCsv(data);
      break;
    case 'html':
      rendered = reportToHtml(data);
      break;
    case 'table':
    default:
      rendered = renderReport(data);
      break;
  }

  return { data, rendered };
}
