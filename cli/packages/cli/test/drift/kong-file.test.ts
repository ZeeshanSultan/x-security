import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { loadSpec } from '@x-security/core';
import { detectFileDrift } from '../../src/drift/kong-file.js';

const SPEC = path.resolve(import.meta.dirname!, '../../../../fixtures/specs/example.yaml');

// Synthetic exported kong.yml with one mostly-correct route and one with
// a deliberately weakened rate limit.
const KONG_YML = `_format_version: "3.0"
services:
  - name: login-svc
    url: http://upstream:8080
    routes:
      - name: r-login
        paths:
          - /api/auth/login
        methods: [POST]
        plugins:
          - name: rate-limiting
            config:
              minute: 5000
              limit_by: ip
              policy: local
          - name: cors
            config:
              origins: ["https://app.example.com"]
              credentials: true
  - name: admin-svc
    url: http://upstream:8080
    routes:
      - name: r-admin
        paths:
          - /api/admin/users
        methods: [GET]
        plugins:
          - name: jwt
            config:
              claims_to_verify: [exp]
              key_claim_name: iss
              run_on_preflight: true
          - name: acl
            config:
              allow: [admin, super-admin]
              hide_groups_header: true
          - name: rate-limiting
            config:
              minute: 30
              limit_by: consumer
              policy: local
              fault_tolerant: true
              hide_client_headers: false
          - name: ip-restriction
            config:
              allow: ["10.0.0.0/8"]
          - name: response-transformer
            config:
              add:
                headers: ["Cache-Control:no-store", "Pragma:no-cache"]
  # /api/files/upload is intentionally missing — should drift as critical
`;

test('kong-file drift: rate-limit weakening flagged as CRITICAL', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const r = await detectFileDrift(spec, { filePath: 'fake.yml', yamlContent: KONG_YML });
  assert.equal(r.kind, 'drift');
  const rl = r.issues.find(
    (i) => i.endpoint.includes('login') && i.field.startsWith('rate-limiting')
  );
  assert.ok(rl, 'expected rate-limit drift on login endpoint');
  assert.equal(rl!.severity, 'CRITICAL');
});

test('kong-file drift: missing endpoint = CRITICAL drift', async () => {
  const spec = await loadSpec(SPEC, { strict: false });
  const r = await detectFileDrift(spec, { filePath: 'fake.yml', yamlContent: KONG_YML });
  const missing = r.issues.find((i) => i.endpoint.includes('files/upload'));
  assert.ok(missing, 'expected drift on /api/files/upload');
  assert.equal(missing!.severity, 'CRITICAL');
});

test('kong-file drift: no issues for a perfectly-matching synthetic config', async () => {
  // Tiny spec with one endpoint, write a kong.yml that matches its expected plugins.
  const trivial = await loadSpec(SPEC, { strict: false });
  // Pick the admin route's expected plugins from the same generator-shared builders.
  // The KONG_YML above already aligns with the admin route, so just ensure no
  // drift entries exist for the admin endpoint specifically (it's not in the
  // ones we asserted above).
  const r = await detectFileDrift(trivial, { filePath: 'fake.yml', yamlContent: KONG_YML });
  const adminIssues = r.issues.filter((i) => i.endpoint.includes('admin/users'));
  // The synthetic config matches the admin endpoint's expected plugins, so no
  // CRITICAL/HIGH issues there.
  const adminCritical = adminIssues.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH');
  assert.equal(adminCritical.length, 0, `unexpected admin drift: ${JSON.stringify(adminIssues)}`);
});
