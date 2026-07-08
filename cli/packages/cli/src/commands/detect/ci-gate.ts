// CI gate renderer for `lazy emit --target ci`.
//
// The gate re-runs `lazy audit` in CI and fails the build when the
// cite-backed proof does not hold — i.e. when any emitted control lost its
// byte-matching citation (code drifted under a rule, Rule D-3). It does NOT
// gate on a security score; the product guarantee is "every emitted rule cites
// your code", and that is exactly what this checks.

const AUDIT_SCRIPT = [
  '#!/usr/bin/env bash',
  '# Fail CI if any emitted control lost its byte-matching citation (Rule D-3).',
  'set -euo pipefail',
  'OUT="$(npx --yes @x-security/cli audit .)"',
  'echo "$OUT"',
  'CITE_BACKED="$(printf \'%s\' "$OUT" | node -e \'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(String(JSON.parse(s).citeBacked)))\')"',
  'if [ "$CITE_BACKED" != "true" ]; then',
  '  echo "::error::x-security gate failed — an emitted control no longer cites your code." >&2',
  '  exit 1',
  'fi',
  '',
].join('\n');

const GITHUB_WORKFLOW = [
  'name: x-security gate',
  'on: [pull_request, push]',
  'jobs:',
  '  x-security-audit:',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - uses: actions/checkout@v4',
  '      - uses: actions/setup-node@v4',
  '        with:',
  "          node-version: '20'",
  '      - name: Audit cite-coverage',
  '        run: bash .x-security/ci/audit-gate.sh',
  '',
].join('\n');

const GITLAB_SNIPPET = [
  '# Append to .gitlab-ci.yml',
  'x-security-audit:',
  '  image: node:20',
  '  script:',
  '    - bash .x-security/ci/audit-gate.sh',
  '  rules:',
  '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
  '    - if: $CI_COMMIT_BRANCH',
  '',
].join('\n');

/** Filename → contents for the .x-security/ci/ directory. */
export function renderCiGate(): Record<string, string> {
  return {
    'audit-gate.sh': AUDIT_SCRIPT,
    'github-workflow.yml': GITHUB_WORKFLOW,
    'gitlab-ci.snippet.yml': GITLAB_SNIPPET,
  };
}
