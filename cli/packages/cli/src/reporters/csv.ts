// CSV reporter for OWASP coverage and drift reports.

import type { OwaspId } from '@writ/schema';
import type {
  AnnotationCoverageReport,
  DriftReport,
  OwaspCoverageReport,
  ReportData
} from './types.js';

const OWASP_IDS: OwaspId[] = [
  'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
  'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023', 'API10:2023'
];

function escape(v: unknown): string {
  const s = v === null || v === undefined ? '' : String(v);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function owaspCsv(r: OwaspCoverageReport): string {
  const header = ['endpoint', ...OWASP_IDS].map(escape).join(',');
  const rows = r.rows.map((row) =>
    [row.endpoint, ...OWASP_IDS.map((id) => row.coverage[id])].map(escape).join(',')
  );
  return [header, ...rows].join('\n') + '\n';
}

function annotationCsv(r: AnnotationCoverageReport): string {
  const header = ['endpoint', 'fields'].map(escape).join(',');
  const rows = r.perEndpoint.map((e) =>
    [e.endpoint, e.fields.join(';')].map(escape).join(',')
  );
  return [header, ...rows].join('\n') + '\n';
}

export function reportToCsv(r: ReportData): string {
  return r.kind === 'owasp' ? owaspCsv(r) : annotationCsv(r);
}

export function driftToCsv(r: DriftReport): string {
  const header = ['severity', 'endpoint', 'field', 'expected', 'actual', 'message'];
  const rows = r.issues.map((i) =>
    [i.severity, i.endpoint, i.field, JSON.stringify(i.expected), JSON.stringify(i.actual), i.message]
      .map(escape)
      .join(',')
  );
  return [header.map(escape).join(','), ...rows].join('\n') + '\n';
}
