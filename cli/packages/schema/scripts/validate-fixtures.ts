// Smoke: parse every fixture through its Zod schema. Exit non-zero on the
// first failure. Run via `pnpm -F @x-security/schema exec tsx scripts/validate-fixtures.ts`
// (with apps/api built so the workspace import resolves).
import { fixtureEndpoints, fixtureRules, fixtureOwasp, fixtureScanLog } from '../../../apps/api/src/fixtures/rules.js';
import { fixtureDeploys, fixtureManifests } from '../../../apps/api/src/fixtures/deploys.js';
import { fixtureAttackRuns, fixtureFindings } from '../../../apps/api/src/fixtures/attack-runs.js';
import { fixtureSites } from '../../../apps/api/src/fixtures/sites.js';
import { fixtureAuditEvents } from '../../../apps/api/src/fixtures/audit.js';
import {
  fixtureMembers, fixtureApiKeys, fixtureIntegrations,
  fixtureInvoices, fixtureUsage, fixtureOrg,
} from '../../../apps/api/src/fixtures/account.js';

const checks: Array<[string, () => unknown]> = [
  ['endpoints',    () => fixtureEndpoints()],
  ['rules',        () => fixtureRules()],
  ['owasp',        () => fixtureOwasp()],
  ['scan_log',     () => fixtureScanLog()],
  ['deploys',      () => fixtureDeploys()],
  ['manifests',    () => fixtureManifests()],
  ['attack_runs',  () => fixtureAttackRuns()],
  ['findings',     () => fixtureFindings('AR-0042')],
  ['sites',        () => fixtureSites()],
  ['audit',        () => fixtureAuditEvents()],
  ['members',      () => fixtureMembers()],
  ['api_keys',     () => fixtureApiKeys()],
  ['integrations', () => fixtureIntegrations()],
  ['invoices',     () => fixtureInvoices()],
  ['usage',        () => fixtureUsage()],
  ['org',          () => fixtureOrg()],
];

let failed = 0;
for (const [name, run] of checks) {
  try {
    run();
    // eslint-disable-next-line no-console
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    // eslint-disable-next-line no-console
    console.error(`  FAIL  ${name}:`, (err as Error).message);
  }
}

if (failed > 0) {
  // eslint-disable-next-line no-console
  console.error(`\n${failed} fixture(s) failed validation`);
  process.exit(1);
}
// eslint-disable-next-line no-console
console.log(`\nAll ${checks.length} fixtures validate cleanly.`);
