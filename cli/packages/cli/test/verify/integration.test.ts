// Integration test: boot a minimal modsec-nginx container with a deliberately
// broken 5-rule Writ fixture, point `verify` at it, assert the right
// reasons surface. Skipped automatically when docker isn't available.
//
// This is the closest mirror of the wave-3 §3 showstopper: the container is
// healthy, returns 200s, but the Writ rules don't load. Verify must
// catch that the rules file isn't Include'd (or that parse errors fire on
// the right lines) and FAIL.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { modsecNginxReader } from '../../src/verify/readers/modsec-nginx.js';

function dockerAvailable(): boolean {
  const r = spawnSync('docker', ['info'], { stdio: 'ignore' });
  return r.status === 0;
}

const BROKEN_CONF = `# 5-rule fixture; rules 3+4 use 'user' collection which modsec-nginx rejects.
SecAction "id:990001,phase:1,pass,nolog"
SecRule REQUEST_METHOD "@streq GET" "id:990002,phase:1,deny,status:401"
SecAction "id:990003,phase:1,initcol:user=%{REMOTE_ADDR}"
SecRule REQUEST_HEADERS:Content-Type "@streq application/json" "id:990004,phase:1,pass,nolog"
SecAction "id:990005,phase:1,pass,nolog"
`;

test('integration: modsec-nginx with un-included writ.conf → all 5 rules flagged', { skip: !dockerAvailable() }, async () => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'writ-verify-it-'));
  try {
    writeFileSync(path.join(tmp, 'writ.conf'), BROKEN_CONF);
    const containerName = `writ-verify-it-${Date.now()}`;
    // Boot with the conf mounted under /etc/modsecurity.d/writ/ but
    // NOT Include'd — this mirrors the wave-3 chain's actual state.
    const up = spawnSync('docker', [
      'run', '-d',
      '--name', containerName,
      '-v', `${tmp}:/etc/modsecurity.d/writ:ro`,
      '-e', 'BACKEND=http://example.com',
      '-e', 'MODSEC_RULE_ENGINE=On',
      '-e', 'PARANOIA=1',
      'owasp/modsecurity-crs:nginx'
    ], { encoding: 'utf8' });
    if (up.status !== 0) {
      // Image may not be present locally; skip rather than fail CI.
      // The test still validated the parse logic in unit tests.
      rmSync(tmp, { recursive: true, force: true });
      return;
    }

    try {
      // Wait for nginx to actually be up + log the rules-loaded line.
      let ok = false;
      for (let i = 0; i < 30; i++) {
        const logs = spawnSync('docker', ['logs', containerName], { encoding: 'utf8' });
        if (/rules loaded inline\/local\/remote/.test(logs.stdout + logs.stderr)) { ok = true; break; }
        await new Promise((r) => setTimeout(r, 500));
      }
      assert.ok(ok, 'expected modsec-nginx to log the rules-loaded summary within 15s');

      const emitted = [
        { id: '990001', kind: 'coraza-rule' as const, endpoint: 'fixture', label: 'SecAction', line: 2 },
        { id: '990002', kind: 'coraza-rule' as const, endpoint: 'fixture', label: 'SecRule', line: 3 },
        { id: '990003', kind: 'coraza-rule' as const, endpoint: 'fixture', label: 'SecAction', line: 4 },
        { id: '990004', kind: 'coraza-rule' as const, endpoint: 'fixture', label: 'SecRule', line: 5 },
        { id: '990005', kind: 'coraza-rule' as const, endpoint: 'fixture', label: 'SecAction', line: 6 }
      ];

      const loaded = await modsecNginxReader.readLoadedArtifacts(`docker:${containerName}`);
      const { rows, diagnostics } = modsecNginxReader.reconcile(emitted, loaded);
      const row = rows[0];
      assert.ok(row, 'expected at least one row');
      // Our fixture isn't Include'd by the running config → all 5 rejected.
      assert.equal(row!.loaded, 0, 'expected 0 rules loaded — fixture is not Include\'d');
      assert.equal(row!.rejected.length, 5);
      assert.ok(
        diagnostics.some((d) => /not Include/i.test(d)) ||
          row!.rejected.some((r) => /not Include/i.test(r.reason)),
        'expected the "not included" diagnostic to surface'
      );
    } finally {
      spawnSync('docker', ['rm', '-f', containerName], { stdio: 'ignore' });
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
