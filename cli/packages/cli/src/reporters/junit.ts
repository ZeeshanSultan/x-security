// JUnit XML reporter for the closed-loop `test` command. Consumed by CI
// systems (GitHub Actions, GitLab, Jenkins) for test result rendering.

import type { TestReport } from './types.js';

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function testToJunit(r: TestReport): string {
  const total = r.cases.length;
  const failures = r.cases.filter((c) => c.verdict === 'FAIL').length;
  const skipped = r.cases.filter((c) => c.verdict === 'SKIP').length;
  const totalDuration = r.cases.reduce((a, c) => a + c.durationMs, 0) / 1000;

  const cases = r.cases
    .map((c) => {
      const name = xmlEscape(`${c.endpoint} :: ${c.rule}`);
      const time = (c.durationMs / 1000).toFixed(3);
      if (c.verdict === 'PASS') {
        return `    <testcase classname="writ" name="${name}" time="${time}"/>`;
      }
      if (c.verdict === 'SKIP') {
        return `    <testcase classname="writ" name="${name}" time="${time}"><skipped/></testcase>`;
      }
      return `    <testcase classname="writ" name="${name}" time="${time}"><failure message="${xmlEscape(c.message)}"/></testcase>`;
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="writ" tests="${total}" failures="${failures}" skipped="${skipped}" time="${totalDuration.toFixed(3)}">
  <testsuite name="${xmlEscape(r.target)}" tests="${total}" failures="${failures}" skipped="${skipped}" time="${totalDuration.toFixed(3)}">
${cases}
  </testsuite>
</testsuites>
`;
}
