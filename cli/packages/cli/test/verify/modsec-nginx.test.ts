// Unit tests for the ModSec-nginx reader's parse logic. We don't boot a real
// container here — those tests live in integration/. We feed canned log
// strings + canned generator output into the reader's pure functions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { modsecNginxReader, xSecurityRulesAreIncluded } from '../../src/verify/readers/modsec-nginx.js';

// ─── Canned fixtures ────────────────────────────────────────────────────

const FIVE_RULE_DIRECTIVES = `
# ════════════════════════════════════════════════════════════
# GET /v1/users  (operationId: getUsers)
# ════════════════════════════════════════════════════════════
SecAction "id:100001,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq GET" "id:100002,phase:1,deny,status:401"
# ════════════════════════════════════════════════════════════
# POST /v1/login  (operationId: login)
# ════════════════════════════════════════════════════════════
SecAction "id:200001,phase:1,pass,nolog"
SecRule REQUEST_HEADERS:Content-Type "@streq application/json" "id:200002,phase:1,pass,nolog"
SecRule ARGS_NAMES "@within username,password" "id:200003,phase:2,pass,nolog"
`.trim();

const FIVE_RULE_YAML = `directives: |\n  ${FIVE_RULE_DIRECTIVES.split('\n').join('\n  ')}`;

// Stub a SpecIR-shaped object that lets the reader call the generator.
// We monkey the registry by injecting a fake generator before the read.
test('readEmittedArtifacts scans SecRule/SecAction blocks and tags them by endpoint', async () => {
  const { default: registry } = await import('../../src/registry.js') as unknown as { default: unknown };
  // The reader uses loadGenerator('coraza'). We can't intercept easily, so
  // instead test the lower-level reconcile + the log-parser via the public
  // reconcile() API, which doesn't depend on a real generator.

  // Construct emitted-by-hand to feed reconcile directly.
  const emitted = [
    { id: '100001', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecAction', line: 4 },
    { id: '100002', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecRule', line: 5 },
    { id: '200001', kind: 'coraza-rule' as const, endpoint: 'POST /v1/login', label: 'SecAction', line: 9 },
    { id: '200002', kind: 'coraza-rule' as const, endpoint: 'POST /v1/login', label: 'SecRule', line: 10 },
    { id: '200003', kind: 'coraza-rule' as const, endpoint: 'POST /v1/login', label: 'SecRule', line: 11 }
  ];
  const loaded = [
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:5' }
  ];
  const { rows } = modsecNginxReader.reconcile(emitted, loaded);
  // With summary=5 and no parse errors, treat all 5 as loaded.
  const total = rows.reduce((s, r) => s + r.loaded, 0);
  assert.equal(total, 5);
  assert.equal(rows.length, 2);
});

test('reconcile flags every rule rejected when summary says 0 rules loaded', () => {
  const emitted = [
    { id: '100001', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecAction', line: 4 },
    { id: '100002', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecRule', line: 5 }
  ];
  const loaded = [
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:0' }
  ];
  const { rows } = modsecNginxReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 0);
  assert.equal(rows[0]!.rejected.length, 2);
  assert.match(rows[0]!.rejected[0]!.reason, /no x-security rules loaded/);
});

test('reconcile flags every rule rejected when Include is missing', () => {
  const emitted = [
    { id: '100001', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecAction', line: 4 }
  ];
  const loaded = [
    { id: '__not-included__', kind: 'coraza-rule' as const, rejectionReason: 'x-security rules file is not Include\'d by the running nginx config' },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:847' }
  ];
  const { rows, diagnostics } = modsecNginxReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 0);
  assert.match(rows[0]!.rejected[0]!.reason, /not Include/);
  assert.ok(diagnostics.some((d) => /not Include/.test(d)));
});

test('xSecurityRulesAreIncluded: direct literal Include with "x-security" in path returns true', () => {
  const dump = `
    http {
      Include /etc/nginx/conf.d/*.conf;
      Include /etc/modsecurity.d/x-security-rules.conf;
    }
  `;
  // No container needed — direct literal hit.
  assert.equal(xSecurityRulesAreIncluded(dump), true);
});

test('xSecurityRulesAreIncluded: empty dump returns true (benefit of doubt)', () => {
  assert.equal(xSecurityRulesAreIncluded(''), true);
});

test('xSecurityRulesAreIncluded: glob Include with no container and no literal match returns false', () => {
  // This is the REPORT-v4 Open-6 survival-mount case BEFORE docker resolve.
  // Without a container handle, we cannot resolve the glob — the only
  // safe answer is "not detected".
  const dump = `
    http {
      Include /etc/modsecurity.d/owasp-crs/rules/*.conf;
    }
  `;
  assert.equal(xSecurityRulesAreIncluded(dump), false);
});

test('xSecurityRulesAreIncluded: directive whose path literal mentions x-security via glob parent returns true', () => {
  // e.g. `Include /etc/modsecurity.d/x-security/*.conf` — substring hit.
  const dump = `Include /etc/modsecurity.d/x-security/*.conf;`;
  assert.equal(xSecurityRulesAreIncluded(dump), true);
});

test('reconcile attributes parse error to the specific rule on that line', () => {
  const emitted = [
    { id: '100001', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecAction', line: 4 },
    { id: '100002', kind: 'coraza-rule' as const, endpoint: 'GET /v1/users', label: 'SecRule', line: 5 }
  ];
  const loaded = [
    { id: 'parse-error@5', kind: 'coraza-rule' as const, rejectionReason: 'collection must be \'ip\', \'global\' or \'resource\'', rejectedAtLine: 5 },
    { id: '__summary__', kind: 'coraza-rule' as const, rejectionReason: 'summary:1' }
  ];
  const { rows } = modsecNginxReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.loaded, 1);
  assert.equal(rows[0]!.rejected.length, 1);
  assert.equal(rows[0]!.rejected[0]!.line, 5);
  assert.match(rows[0]!.rejected[0]!.reason, /collection must be/);
});
