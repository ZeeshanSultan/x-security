// Unit tests for the Kong reader reconciliation logic. The admin-API HTTP
// path is exercised in integration tests; here we test the pure reconcile().

import test from 'node:test';
import assert from 'node:assert/strict';
import { kongReader } from '../../src/verify/readers/kong.js';

test('reconcile reports ok when every emitted plugin/route is present', () => {
  const emitted = [
    { id: 'svc-foo', kind: 'kong-service' as const, endpoint: 'svc-foo', label: 'service svc-foo' },
    { id: 'route_get_users', kind: 'kong-route' as const, endpoint: 'route_get_users', label: 'route route_get_users' },
    { id: 'route_get_users|jwt', kind: 'kong-plugin' as const, endpoint: 'route_get_users', label: 'plugin jwt' }
  ];
  const loaded = [
    { id: 'svc-foo', kind: 'kong-service' as const },
    { id: 'route_get_users', kind: 'kong-route' as const },
    { id: 'route_get_users|jwt', kind: 'kong-plugin' as const }
  ];
  const { rows } = kongReader.reconcile(emitted, loaded);
  assert.ok(rows.every((r) => r.status === 'ok'));
});

test('reconcile flags an emitted plugin missing from /admin/plugins', () => {
  const emitted = [
    { id: 'route_login', kind: 'kong-route' as const, endpoint: 'route_login', label: 'route' },
    { id: 'route_login|rate-limiting', kind: 'kong-plugin' as const, endpoint: 'route_login', label: 'plugin rate-limiting' }
  ];
  const loaded = [
    { id: 'route_login', kind: 'kong-route' as const }
    // rate-limiting plugin missing — Kong rejected it.
  ];
  const { rows } = kongReader.reconcile(emitted, loaded);
  const r = rows.find((x) => x.endpoint === 'route_login')!;
  assert.equal(r.loaded, 1);
  assert.equal(r.rejected.length, 1);
  assert.match(r.rejected[0]!.reason, /rate-limiting/);
});

test('reconcile flags entire endpoint failed when every plugin is missing', () => {
  const emitted = [
    { id: 'route_x|jwt', kind: 'kong-plugin' as const, endpoint: 'route_x', label: 'plugin jwt' },
    { id: 'route_x|cors', kind: 'kong-plugin' as const, endpoint: 'route_x', label: 'plugin cors' }
  ];
  const loaded: never[] = [];
  const { rows } = kongReader.reconcile(emitted, loaded);
  assert.equal(rows[0]!.status, 'failed');
  assert.equal(rows[0]!.loaded, 0);
});
