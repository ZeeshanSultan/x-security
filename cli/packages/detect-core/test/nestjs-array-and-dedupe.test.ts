// Regressions for the prototype-pollution anchor (nocodb CVE-2026-24766):
//  1. NestJS `@Post(['/v1/x','/v2/x'])` array-path decorators expand to one route per
//     literal (previously only single-string paths grounded).
//  2. dedupeRoutes: a spec route (OpenAPI, no handler body) adopts a colliding framework
//     route's handler LOCATION, so the sink behind a swagger-declared path is citable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseNestjs } from '../src/frameworks/nestjs.js';
import { dedupeRoutes } from '../src/index.js';

test('NestJS @Post array-of-paths grounds one route per literal at the method', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'nest-arr-'));
  try {
    const src = [
      '@Controller()',
      'export class UtilsController {',
      "  @Post(['/api/v1/db/meta/connection/test', '/api/v2/meta/connection/test'])",
      "  @Acl('testConnection', { scope: 'org' })",
      '  @HttpCode(200)',
      '  async testConnection(@Body() body: any) {',
      '    return this.svc.test({ ...body });',
      '  }',
      '}',
    ].join('\n');
    await fs.writeFile(path.join(dir, 'utils.controller.ts'), src, 'utf8');
    const routes = await parseNestjs(dir);
    const paths = routes.filter((r) => r.method === 'POST').map((r) => r.path).sort();
    assert.deepEqual(paths, ['/api/v1/db/meta/connection/test', '/api/v2/meta/connection/test']);
    assert.ok(routes.every((r) => r.handler === 'testConnection'), 'both alias routes cite the method');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('dedupe: a spec route with no handler adopts a framework route handler location', () => {
  const spec = { method: 'POST', path: '/api/v2/meta/connection/test', source: 'spec' as const, schemaHint: 'declared' as const, sourceFile: 'schema/swagger.json', sourceLine: 0 };
  const fw = { method: 'POST', path: '/api/v2/meta/connection/test', source: 'framework' as const, framework: 'nestjs', sourceFile: 'controllers/utils.controller.ts', sourceLine: 60, handler: 'testConnection' };
  const out = dedupeRoutes([spec as never, fw as never]);
  assert.equal(out.length, 1, 'collapsed to one route');
  const r = out[0]!;
  assert.equal(r.source, 'spec', 'keeps the spec source (richer schema)');
  assert.equal(r.schemaHint, 'declared', 'keeps the spec schema hint');
  assert.equal(r.sourceFile, 'controllers/utils.controller.ts', 'adopts the framework handler file');
  assert.equal(r.sourceLine, 60, 'adopts the framework handler line');
  assert.equal((r as { handler?: string }).handler, 'testConnection', 'adopts the framework handler symbol');
});

test('dedupe: a spec route with a real handler line is NOT overwritten', () => {
  const specWithBody = { method: 'GET', path: '/x', source: 'spec' as const, sourceFile: 'routes.ts', sourceLine: 10, handler: 'real' };
  const fw = { method: 'GET', path: '/x', source: 'framework' as const, sourceFile: 'other.ts', sourceLine: 99, handler: 'other' };
  const out = dedupeRoutes([specWithBody as never, fw as never]);
  assert.equal(out[0]!.sourceFile, 'routes.ts', 'existing handler location preserved');
  assert.equal(out[0]!.sourceLine, 10);
});
