// Rails routes.rb parser — nested namespace prefixes, resource/resources RESTful
// expansion with only:/except: filtering, member-action shorthand, and explicit verb
// routes. Modeled on spree's api/config/routes.rb (the framework-coverage gap the
// corpus-gap-scout surfaced via the spree checkout case).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseRails } from '../src/frameworks/rails.js';

async function withRoutes(src: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'rails-'));
  try {
    const cfg = path.join(dir, 'config');
    await fs.mkdir(cfg, { recursive: true });
    await fs.writeFile(path.join(cfg, 'routes.rb'), src, 'utf8');
    await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

const SPREE = [
  'Spree::Core::Engine.add_routes do',
  '  namespace :api, defaults: { format: :json } do',
  '    namespace :v2 do',
  '      namespace :storefront do',
  '        resource :checkout, controller: :checkout, only: %i[update] do',
  '          patch :advance',
  '          patch :complete',
  '        end',
  '        resources :products, only: %i[index show]',
  "        get '/countries/:iso', to: 'countries#show'",
  '      end',
  '    end',
  '  end',
  'end',
].join('\n');

test('singular resource only:%i[update] under nested namespaces → PATCH+PUT at the prefixed path', async () => {
  await withRoutes(SPREE, async (dir) => {
    const routes = await parseRails(dir);
    const upd = routes.filter((r) => r.path === '/api/v2/storefront/checkout');
    assert.deepEqual(upd.map((r) => r.method).sort(), ['PATCH', 'PUT'], 'update → PATCH and PUT only');
    assert.ok(upd.every((r) => r.handler === 'checkout#update'), 'handler is controller#action');
    // only: %i[update] suppresses show/create/destroy.
    assert.ok(!routes.some((r) => r.method === 'POST' && r.path === '/api/v2/storefront/checkout'), 'create suppressed by only:');
  });
});

test('member-action shorthand composes under the resource path', async () => {
  await withRoutes(SPREE, async (dir) => {
    const routes = await parseRails(dir);
    assert.ok(routes.some((r) => r.method === 'PATCH' && r.path === '/api/v2/storefront/checkout/advance'), 'patch :advance → /checkout/advance');
  });
});

test('plural resources only:%i[index show] expands collection + member with :id', async () => {
  await withRoutes(SPREE, async (dir) => {
    const routes = await parseRails(dir);
    assert.ok(routes.some((r) => r.method === 'GET' && r.path === '/api/v2/storefront/products'), 'index');
    assert.ok(routes.some((r) => r.method === 'GET' && r.path === '/api/v2/storefront/products/:id'), 'show with :id');
    assert.ok(!routes.some((r) => r.method === 'POST' && r.path === '/api/v2/storefront/products'), 'create suppressed');
  });
});

test('explicit verb route with to: ctrl#action grounds under the namespace prefix', async () => {
  await withRoutes(SPREE, async (dir) => {
    const routes = await parseRails(dir);
    const c = routes.find((r) => r.path === '/api/v2/storefront/countries/:iso');
    assert.ok(c, 'explicit get route grounds');
    assert.equal(c?.handler, 'countries#show');
  });
});
