// Renderers for the verify report. Three formats:
//   - table  human-scannable (default)
//   - json   raw report object — CI plumbing
//   - sarif  static-analysis-tool format — surfaces in GH code-scanning UI
//
// The table format is the one operators read. It MUST surface (a) which
// endpoints lost coverage, (b) the gateway's exact reason (line + msg),
// and (c) the single bottom-line FAIL/PASS verdict tied to the
// configured threshold.

import type { VerifyReport, VerifyRow } from './index.js';

export function renderTable(r: VerifyReport): string {
  const lines: string[] = [];
  const targetLabel = r.engine ? `${r.target}/${r.engine}` : r.target;
  lines.push(`x-security verify — target=${targetLabel} — gateway=${r.gateway}`);
  lines.push('');

  if (r.diagnostics.length > 0) {
    for (const d of r.diagnostics) lines.push(`! ${d}`);
    lines.push('');
  }

  const headers = ['Endpoint', 'Emitted', 'Loaded', 'Status', 'Notes'];
  const widths = [34, 7, 6, 14, 0];
  lines.push(formatRow(headers, widths));
  lines.push(formatRow(headers.map((_, i) => '-'.repeat(widths[i] || 28)), widths));

  for (const row of r.rows) {
    const status = statusIcon(row);
    // Group rejections by reason — operators care WHY, and listing 18 identical
    // reasons per row drowns the signal. We summarise as "<reason> (lines a,b,c)".
    const groups = new Map<string, number[]>();
    for (const rej of row.rejected) {
      const list = groups.get(rej.reason) ?? [];
      if (rej.line !== undefined) list.push(rej.line);
      groups.set(rej.reason, list);
    }
    const grouped = [...groups.entries()];
    const first = grouped[0];
    const note = first
      ? formatGroup(first[0], first[1])
      : '';
    lines.push(formatRow([row.endpoint, String(row.emitted), String(row.loaded), status, note], widths));
    for (let i = 1; i < grouped.length; i++) {
      const entry = grouped[i];
      if (!entry) continue;
      lines.push(formatRow(['', '', '', '', `  ${formatGroup(entry[0], entry[1])}`], widths));
    }
  }

  lines.push('');
  const verdict = r.passed ? 'PASS' : 'FAIL';
  lines.push(
    `Summary: ${r.totals.emitted} emitted, ${r.totals.loaded} loaded ` +
      `(${r.totals.coveragePct}%) — ${verdict} (threshold ${r.thresholdPct}%)`
  );
  return lines.join('\n') + '\n';
}

function formatGroup(reason: string, lines: number[]): string {
  if (lines.length === 0) return reason;
  if (lines.length === 1) return `${reason} (line ${lines[0]})`;
  if (lines.length <= 4) return `${reason} (lines ${lines.join(', ')})`;
  return `${reason} (${lines.length} rules @ lines ${lines.slice(0, 3).join(', ')}, …)`;
}

function statusIcon(row: VerifyRow): string {
  if (row.status === 'ok') return 'ok';
  if (row.status === 'partial') return `partial`;
  if (row.status === 'failed') return `${row.rejected.length} rejected`;
  return 'unknown';
}

function formatRow(cells: string[], widths: number[]): string {
  return cells
    .map((c, i) => {
      const w = widths[i] ?? 0;
      if (w === 0) return c;
      return c.length >= w ? c : c + ' '.repeat(w - c.length);
    })
    .join('  ');
}

export function renderJson(r: VerifyReport): string {
  return JSON.stringify(r, null, 2) + '\n';
}

/** Minimal SARIF 2.1.0 envelope. Each rejected artifact becomes one result. */
export function renderSarif(r: VerifyReport): string {
  const results: Array<Record<string, unknown>> = [];
  for (const row of r.rows) {
    for (const rej of row.rejected) {
      results.push({
        ruleId: rej.id ?? 'writ.verify.load-failure',
        level: 'error',
        message: { text: `${row.endpoint}: ${rej.reason}` },
        locations: rej.line
          ? [{ physicalLocation: { artifactLocation: { uri: 'gateway-config' }, region: { startLine: rej.line } } }]
          : []
      });
    }
  }
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'x-security-verify',
            informationUri: 'https://github.com/writ/writ',
            rules: [
              {
                id: 'writ.verify.load-failure',
                name: 'GatewayLoadFailure',
                shortDescription: { text: 'Emitted artifact did not load in the gateway.' }
              }
            ]
          }
        },
        results,
        properties: {
          totals: r.totals,
          thresholdPct: r.thresholdPct,
          passed: r.passed
        }
      }
    ]
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}
