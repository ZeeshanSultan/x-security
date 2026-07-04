// Regression: Flask route decorators that wrap the path in a single-string-literal
// helper call — e.g. redash's `@bp.route(org_scoped_rule("/ldap/login"), ...)` —
// must ground to the inner literal. Before WRAPPER_DECORATOR_RE these silently
// dropped (the path-helper is the default route shape across redash auth/embed/static,
// so missing it lost ~23 routes incl. the CVE-2020-36144 LDAP-injection sink).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseFlask } from '../src/frameworks/flask.js';

async function withFlaskFile(src: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'flask-wrap-'));
  try {
    await fs.writeFile(path.join(dir, 'auth.py'), src, 'utf8');
    await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test('grounds a path-helper-wrapped route to its inner literal + handler + methods', async () => {
  const src = [
    'from flask import request',
    '@blueprint.route(org_scoped_rule("/ldap/login"), methods=["GET", "POST"])',
    'def login(org_slug=None):',
    '    return auth_ldap_user(request.form["email"], request.form["password"])',
  ].join('\n');
  await withFlaskFile(src, async (dir) => {
    const routes = await parseFlask(dir);
    const post = routes.find((r) => r.method === 'POST' && r.path === '/ldap/login');
    assert.ok(post, 'POST /ldap/login should ground from the wrapped decorator');
    assert.equal(post?.handler, 'login');
    assert.ok(routes.some((r) => r.method === 'GET' && r.path === '/ldap/login'), 'GET variant too');
  });
});

test('does not double-count: a literal route still grounds exactly once', async () => {
  const src = [
    '@app.route("/health")',
    'def health():',
    '    return "ok"',
  ].join('\n');
  await withFlaskFile(src, async (dir) => {
    const routes = await parseFlask(dir);
    const health = routes.filter((r) => r.path === '/health');
    assert.equal(health.length, 1, 'literal route must not be matched by the wrapper regex too');
  });
});
