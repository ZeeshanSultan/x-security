// Human report renderer for `lazy emit --target report`.
//
// The headline is the audit cite-coverage proof, never a security score. Per
// the design's marketing-claim discipline: we print "100% of emitted rules
// cite your code" — NOT "100% secure" / "100% recall". A score=100 placeholder
// is banned (Rule D-1); coverage here is the measured cite-backed fraction.

import type { AuditResult } from './audit.js';

export interface ReportRoute {
  method: string;
  path: string;
}

export function renderReport(audit: AuditResult, routes: ReportRoute[]): string {
  const pct = (audit.coverage * 100).toFixed(1);
  const lines: string[] = [];
  lines.push('# x-security report');
  lines.push('');
  lines.push(`- Routes with a compiled policy: **${audit.routes}**`);
  lines.push(`- Enforced controls: **${audit.controls}**`);
  lines.push(
    audit.citeBacked
      ? `- Cite-backed: **yes** — 100% of emitted rules cite a byte-matching \`file:line\` in your code.`
      : `- Cite-backed: **no** — ${pct}% of controls cite a byte-matching \`file:line\`. See uncited list below.`,
  );
  lines.push('');

  if (routes.length > 0) {
    lines.push('## Routes');
    lines.push('');
    for (const r of routes.slice().sort((a, b) => a.method.localeCompare(b.method) || a.path.localeCompare(b.path))) {
      lines.push(`- \`${r.method.toUpperCase()} ${r.path}\``);
    }
    lines.push('');
  }

  if (audit.uncited.length > 0) {
    lines.push('## Controls requiring review (not cite-backed)');
    lines.push('');
    lines.push('These were NOT emitted as enforced rules — a vulnerability finding without a');
    lines.push('byte-matching source citation is dropped, never written as a fake rule (Rule D-3).');
    lines.push('');
    for (const u of audit.uncited) lines.push(`- ${u}`);
    lines.push('');
  }

  return lines.join('\n') + '\n';
}
