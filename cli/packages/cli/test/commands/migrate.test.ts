import test from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as os from 'node:os';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import * as yaml from 'js-yaml';
import { runMigrate } from '../../src/commands/migrate.js';

async function tmpDir(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), 'writ-migrate-'));
}

async function writeSpec(dir: string, name: string, doc: unknown): Promise<string> {
  const p = path.join(dir, name);
  await writeFile(p, yaml.dump(doc), 'utf8');
  return p;
}

// ---------- core auto-migration ----------

test('migrate: bare-array rateLimit.identifier expands to {components, combinator}', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/x': {
        get: {
          operationId: 'x-get',
          responses: { '200': { description: 'ok' } },
          'x-security': {
            rateLimit: { requests: 60, window: '1m', identifier: ['ip', 'header:X-Phone'] }
          }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const outPath = path.join(dir, 'out.yaml');
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: outPath });

  assert.equal(r.changed, true);
  assert.equal(r.applied.length, 1);
  assert.match(r.applied[0]!.location, /paths\.\/x\.get\.x-security\.rateLimit\.identifier/);
  assert.equal(r.writtenTo, outPath);

  const written = yaml.load(await readFile(outPath, 'utf8')) as Record<string, any>;
  const ident = written.paths['/x'].get['x-security'].rateLimit.identifier;
  assert.deepEqual(ident, { components: ['ip', 'header:X-Phone'], combinator: 'concat' });

  await rm(dir, { recursive: true, force: true });
});

test('migrate: scalar identifier is left alone', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/x': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { rateLimit: { requests: 60, window: '1m', identifier: 'ip' } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  assert.equal(r.changed, false);
  assert.equal(r.applied.length, 0);
  await rm(dir, { recursive: true, force: true });
});

test('migrate: already-object identifier is left alone (idempotence on v0.5 input)', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/x': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': {
            rateLimit: {
              requests: 60,
              window: '1m',
              identifier: { components: ['ip'], combinator: 'concat' }
            }
          }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  assert.equal(r.changed, false);
  assert.equal(r.applied.length, 0);
  await rm(dir, { recursive: true, force: true });
});

// ---------- round-trip determinism ----------

test('migrate: round-trip is deterministic — migrating once vs twice yields identical YAML', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/a': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { rateLimit: { requests: 10, window: '1s', identifier: ['ip', 'user-id'] } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const once = path.join(dir, 'once.yaml');
  const twice = path.join(dir, 'twice.yaml');
  const r1 = await runMigrate(specPath, { from: '0.4', to: '0.5', out: once, noSuggestions: true });
  assert.equal(r1.changed, true);
  const r2 = await runMigrate(once, { from: '0.4', to: '0.5', out: twice, noSuggestions: true });
  assert.equal(r2.changed, false); // already migrated
  const a = await readFile(once, 'utf8');
  const b = await readFile(twice, 'utf8');
  assert.equal(a, b);
  await rm(dir, { recursive: true, force: true });
});

// ---------- --in-place exit semantics ----------

test('migrate: --in-place writes when changes apply, leaves file untouched when no changes needed', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/x': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { rateLimit: { requests: 1, window: '1m', identifier: ['ip'] } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const originalBytes = await readFile(specPath, 'utf8');

  const r1 = await runMigrate(specPath, { from: '0.4', to: '0.5', inPlace: true });
  assert.equal(r1.changed, true);
  assert.equal(r1.writtenTo, specPath);
  const afterFirst = await readFile(specPath, 'utf8');
  assert.notEqual(afterFirst, originalBytes);

  // Re-run; nothing should change, file bytes preserved.
  const r2 = await runMigrate(specPath, { from: '0.4', to: '0.5', inPlace: true });
  assert.equal(r2.changed, false);
  assert.equal(r2.writtenTo, null);
  const afterSecond = await readFile(specPath, 'utf8');
  assert.equal(afterSecond, afterFirst);

  await rm(dir, { recursive: true, force: true });
});

// ---------- suggestion surfacing ----------

test('migrate: suggests outboundCalls on serversurfer-named endpoint with no declaration', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/vapi/serversurfer': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  const outbound = r.suggestions.find((s) => s.location.endsWith('outboundCalls'));
  assert.ok(outbound, `expected outboundCalls suggestion, got ${JSON.stringify(r.suggestions)}`);
  await rm(dir, { recursive: true, force: true });
});

test('migrate: suggests principal namespace for request.user.* / request.session.* refs', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/users/{id}': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': {
            authorization: {
              type: 'rule-based',
              rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'request.user.id' } }]
            }
          }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  const principal = r.suggestions.find((s) => /principal/i.test(s.message));
  assert.ok(principal, `expected principal-namespace suggestion, got ${JSON.stringify(r.suggestions)}`);
  // CRITICAL: must not auto-rewrite.
  const written = yaml.load(await readFile(path.join(dir, 'out.yaml'), 'utf8')) as Record<string, any>;
  assert.equal(written.paths['/users/{id}'].get['x-security'].authorization.rules[0].value.ref, 'request.user.id');
  await rm(dir, { recursive: true, force: true });
});

test('migrate: suggests JWT algorithm hardening when bearer-jwt has no allowed/banned list', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/a': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { authentication: { type: 'bearer-jwt' } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  const jwt = r.suggestions.find((s) => /JWT confusion|bannedAlgorithms/i.test(s.message));
  assert.ok(jwt, `expected JWT hardening suggestion, got ${JSON.stringify(r.suggestions)}`);
  await rm(dir, { recursive: true, force: true });
});

test('migrate: does NOT suggest JWT algorithms when allowedAlgorithms already set', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/a': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': { authentication: { type: 'bearer-jwt', allowedAlgorithms: ['RS256'] } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  const jwt = r.suggestions.find((s) => /JWT confusion|bannedAlgorithms/i.test(s.message));
  assert.equal(jwt, undefined);
  await rm(dir, { recursive: true, force: true });
});

test('migrate: suggests XXE hardening when application/xml accepted with no disableExternalEntities', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/x': {
        post: {
          responses: { '200': { description: 'ok' } },
          'x-security': { request: { contentType: ['application/xml'] } }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, { from: '0.4', to: '0.5', out: path.join(dir, 'out.yaml') });
  const xxe = r.suggestions.find((s) => /XXE|disableExternalEntities/i.test(s.message));
  assert.ok(xxe, `expected XXE suggestion, got ${JSON.stringify(r.suggestions)}`);
  await rm(dir, { recursive: true, force: true });
});

test('migrate: --no-suggestions silences advisories but still applies auto-migrations', async () => {
  const dir = await tmpDir();
  const spec = {
    openapi: '3.0.0',
    info: { title: 't', version: '1' },
    paths: {
      '/vapi/serversurfer': {
        get: {
          responses: { '200': { description: 'ok' } },
          'x-security': {
            authentication: { type: 'bearer-jwt' },
            rateLimit: { requests: 1, window: '1m', identifier: ['ip'] }
          }
        }
      }
    }
  };
  const specPath = await writeSpec(dir, 'in.yaml', spec);
  const r = await runMigrate(specPath, {
    from: '0.4',
    to: '0.5',
    out: path.join(dir, 'out.yaml'),
    noSuggestions: true
  });
  assert.equal(r.suggestions.length, 0);
  assert.equal(r.applied.length, 1); // identifier expansion still happened
  await rm(dir, { recursive: true, force: true });
});

// ---------- error handling ----------

test('migrate: rejects unsupported version pair', async () => {
  const dir = await tmpDir();
  const specPath = await writeSpec(dir, 'in.yaml', { openapi: '3.0.0', info: { title: 't', version: '1' }, paths: {} });
  await assert.rejects(
    () => runMigrate(specPath, { from: '0.4', to: '0.6' as '0.5' }),
    /unsupported version pair/
  );
  await rm(dir, { recursive: true, force: true });
});

test('migrate: rejects --in-place + --out together', async () => {
  const dir = await tmpDir();
  const specPath = await writeSpec(dir, 'in.yaml', { openapi: '3.0.0', info: { title: 't', version: '1' }, paths: {} });
  await assert.rejects(
    () => runMigrate(specPath, { from: '0.4', to: '0.5', inPlace: true, out: path.join(dir, 'x.yaml') }),
    /mutually exclusive/
  );
  await rm(dir, { recursive: true, force: true });
});

// ---------- live fixture: chain-vapi ----------

test('migrate: chain-vapi fixture round-trips with no auto-changes (all identifiers are scalars)', async () => {
  const fixture = path.resolve(import.meta.dirname!, '../../../../e2e/fixtures/chain-vapi/openapi.yaml');
  const dir = await tmpDir();
  const out = path.join(dir, 'migrated.yaml');
  const r = await runMigrate(fixture, { from: '0.4', to: '0.5', out });
  assert.equal(r.changed, false, `chain-vapi has no bare-array identifiers, expected no auto-migrations; got ${JSON.stringify(r.applied)}`);
  // Suggestions should fire for the serversurfer endpoint at minimum.
  const outboundSuggestion = r.suggestions.find((s) => /outboundCalls/i.test(s.message));
  assert.ok(outboundSuggestion, `expected outboundCalls suggestion on /vapi/serversurfer`);
  await rm(dir, { recursive: true, force: true });
});
