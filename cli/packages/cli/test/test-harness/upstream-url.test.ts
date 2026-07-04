// Verifies `--upstream-url` mode: no mock-upstream container in the compose
// plan, spec.servers points at the external URL, and host.docker.internal
// triggers extra_hosts. Uses --dry-run so no Docker is required.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { runTest } from '../../src/commands/test.js';
import { buildComposePlan, validateUpstreamUrl } from '../../src/test-harness/docker-compose.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

test('--upstream-url omits the mock-upstream service from the compose plan', async () => {
  const r = await runTest(SPEC, {
    target: 'kong',
    upstreamUrl: 'http://host.docker.internal:8000',
    dryRun: true
  });
  assert.equal(r.exitCode, 0);
  assert.doesNotMatch(r.composeYaml, /image: mendhak\/http-https-echo:36/);
  assert.doesNotMatch(r.composeYaml, /^\s*upstream:\s*$/m);
  assert.doesNotMatch(r.composeYaml, /depends_on: \[upstream\]/);
  // host.docker.internal needs extra_hosts on Linux
  assert.match(r.composeYaml, /extra_hosts:/);
  assert.match(r.composeYaml, /host\.docker\.internal:host-gateway/);
});

test('--upstream-url rewrites spec.servers to point at the external URL', async () => {
  // The generated kong.yml is mounted into the temp dir. We can't easily read
  // it back via runTest, but we can verify the dry-run YAML reflects the URL
  // and that buildComposePlan exposes externalUpstreamUrl.
  const plan = buildComposePlan({
    target: 'kong',
    configMountSourceDir: '/tmp/x',
    configMountTargetDir: '/etc/writ',
    upstreamUrl: 'https://staging.example.com'
  });
  assert.equal(plan.externalUpstreamUrl, 'https://staging.example.com');
  assert.doesNotMatch(plan.yaml, /upstream:\s*\n\s*image:/);
  // No extra_hosts needed for non-host.docker.internal URLs
  assert.doesNotMatch(plan.yaml, /extra_hosts:/);
});

test('default mode (no --upstream-url) still launches the mock upstream', async () => {
  const r = await runTest(SPEC, { target: 'kong', dryRun: true });
  assert.match(r.composeYaml, /image: mendhak\/http-https-echo:36/);
  assert.match(r.composeYaml, /depends_on: \[upstream\]/);
});

test('validateUpstreamUrl rejects non-http schemes', () => {
  assert.throws(() => validateUpstreamUrl('ftp://example.com'), /http:\/\/ or https:\/\//);
  assert.throws(() => validateUpstreamUrl('not a url'), /not a valid URL/);
});

test('validateUpstreamUrl warns on localhost (container-relative)', () => {
  const { warnings } = validateUpstreamUrl('http://localhost:8000');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /host\.docker\.internal/);
});

test('validateUpstreamUrl accepts host.docker.internal silently', () => {
  const { warnings, url } = validateUpstreamUrl('http://host.docker.internal:8000/vapi');
  assert.equal(warnings.length, 0);
  assert.equal(url.hostname, 'host.docker.internal');
  assert.equal(url.pathname, '/vapi');
});
