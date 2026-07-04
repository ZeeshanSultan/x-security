// Live Docker lifecycle test for the Kong target. Gated behind
// WRIT_DOCKER_TESTS=1 — the default `pnpm test` flow skips this so
// contributors without Docker installed are unaffected.
//
// When enabled, this test:
//   1. Generates Kong config from the example spec
//   2. Pulls (if needed) kong:3.4 + mendhak/http-https-echo:36
//   3. Creates a network and starts both containers
//   4. Waits for Kong to answer HTTP
//   5. Sends N+1 requests to /api/auth/login and asserts a 429 appears
//   6. Tears everything down (containers + network + temp dir)

import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runTest } from '../../src/commands/test.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');
const DOCKER_ENABLED = process.env['WRIT_DOCKER_TESTS'] === '1';

test('lifecycle: kong enforces rate limit end-to-end', { skip: DOCKER_ENABLED ? false : 'skip: WRIT_DOCKER_TESTS=1 not set' }, async () => {
  // Use random high ports to avoid collisions with any local services.
  const gatewayPort = 18000 + Math.floor(Math.random() * 1000);
  const upstreamPort = 19000 + Math.floor(Math.random() * 1000);

  const r = await runTest(SPEC, {
    target: 'kong',
    gatewayPort,
    upstreamPort,
    format: 'json'
  });

  // At least one rate-limit assertion ran.
  const rlCases = r.report.cases.filter((c) => c.rule === 'rateLimit');
  assert.ok(rlCases.length > 0, 'expected at least one rateLimit assertion');

  // The login endpoint's rate limit (5 req/min) should have been enforced.
  const loginRL = rlCases.find((c) => c.endpoint.includes('/api/auth/login'));
  assert.ok(loginRL, 'expected rateLimit case for /api/auth/login');
  assert.equal(
    loginRL.verdict,
    'PASS',
    `login rate-limit assertion did not pass: ${loginRL.message}`
  );
}, { timeout: 180_000 });
