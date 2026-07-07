// Minimal self-contained HTML reporter for OWASP coverage. Designed for
// dropping into a static-site / artifact viewer — no external assets.

import type { OwaspId } from '@x-security/schema';
import type {
  AnnotationCoverageReport,
  OwaspCoverageReport,
  ReportData
} from './types.js';

const OWASP_IDS: OwaspId[] = [
  'API1:2023', 'API2:2023', 'API3:2023', 'API4:2023', 'API5:2023',
  'API6:2023', 'API7:2023', 'API8:2023', 'API9:2023', 'API10:2023'
];

function htmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const STYLE = `
body { font-family: -apple-system, system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
th { background: #f5f5f5; }
.yes { background: #d4edda; color: #155724; text-align: center; }
.no  { background: #f8d7da; color: #721c24; text-align: center; }
.partial { background: #fff3cd; color: #856404; text-align: center; }
.unprotected { color: #b00020; font-weight: 600; }
`;

function renderOwaspHtml(r: OwaspCoverageReport): string {
  const head = `<tr><th>Endpoint</th>${OWASP_IDS.map((id) => `<th>${id}</th>`).join('')}</tr>`;
  const body = r.rows
    .map((row) => {
      const cells = OWASP_IDS.map((id) => {
        const v = row.coverage[id];
        const cls = v === 'yes' ? 'yes' : v === 'partial' ? 'partial' : 'no';
        const txt = v === 'yes' ? '✓' : v === 'partial' ? '~' : '✗';
        return `<td class="${cls}">${txt}</td>`;
      }).join('');
      return `<tr><td>${htmlEscape(row.endpoint)}</td>${cells}</tr>`;
    })
    .join('');
  const unprotected = r.unprotected.length
    ? `<h2 class="unprotected">Unprotected endpoints</h2><ul>${r.unprotected
        .map((u) => `<li>${htmlEscape(u.method)} ${htmlEscape(u.path)}</li>`)
        .join('')}</ul>`
    : '';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>OWASP coverage — ${htmlEscape(r.spec.title)}</title><style>${STYLE}</style></head><body>
<h1>OWASP API Top 10 coverage — ${htmlEscape(r.spec.title)} v${htmlEscape(r.spec.version)}</h1>
<table>${head}${body}</table>
${unprotected}
</body></html>`;
}

function renderAnnotationHtml(r: AnnotationCoverageReport): string {
  const pct = r.totalEndpoints === 0
    ? 100
    : Math.round((r.annotatedEndpoints / r.totalEndpoints) * 100);
  const head = `<tr><th>Endpoint</th><th>Fields</th></tr>`;
  const body = r.perEndpoint
    .map(
      (e) =>
        `<tr><td>${htmlEscape(e.endpoint)}</td><td>${htmlEscape(e.fields.join(', '))}</td></tr>`
    )
    .join('');
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Coverage — ${htmlEscape(r.spec.title)}</title><style>${STYLE}</style></head><body>
<h1>Annotation coverage — ${htmlEscape(r.spec.title)} v${htmlEscape(r.spec.version)}</h1>
<p>${r.annotatedEndpoints} of ${r.totalEndpoints} endpoints annotated (${pct}%)</p>
<table>${head}${body}</table>
</body></html>`;
}

export function reportToHtml(r: ReportData): string {
  return r.kind === 'owasp' ? renderOwaspHtml(r) : renderAnnotationHtml(r);
}
