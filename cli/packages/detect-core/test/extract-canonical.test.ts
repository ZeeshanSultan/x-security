// Route extraction + canonicalization + corpus-fixture regression for the
// extracted core. The corpus replay is the $0 regression: it proves the
// extracted V1 schema + canonicalization still accept the hand-authored ideal
// policies the security corpus ships.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';

import {
  extractRoutes,
  canonicalizePolicy,
  serializeStable,
  validateXSecurity,
} from '../src/index.js';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const CORPUS_BASELINE = path.resolve(
  __dirname,
  '../../../e2e/security-corpus/baseline-express-todo/fixture-emissions.json',
);

let dir: string;

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-extract-'));
  await fs.writeFile(
    path.join(dir, 'app.js'),
    [
      "const app = require('express')();",
      "app.get('/api/users/:id', (req, res) => res.json({}));",
      "app.post('/api/login', (req, res) => res.json({}));",
    ].join('\n'),
  );
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('extractRoutes finds express routes with file:line citations', async () => {
  const r = await extractRoutes(dir);
  const cited = r.routes.filter((x) => x.sourceFile && typeof x.sourceLine === 'number');
  assert.ok(cited.length >= 2, 'both express routes extracted with citations');
  const paths = new Set(r.routes.map((x) => `${x.method} ${x.path}`));
  assert.ok([...paths].some((p) => p.includes('/api/users/:id')));
});

// Regression: comment stripping must preserve line count so citations stay
// exact (Rule D-3). Before the fix, full-line `//` comments and multi-line
// block comments were DELETED from the parsed text, shifting every route below
// them up by the comment count — on mongo-express (CVE-2019-10758) this desynced
// the cited line by ~30, pointing reviewers at the wrong code. Toy fixtures
// masked it (sparse comments → ~0 shift); a comment-rich file exposes it.
test('extractRoutes cites the exact source line through comment blocks (D-3)', async () => {
  const cdir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-comments-'));
  try {
    const lines = [
      "const app = require('express')();", // 1
      '/*',                                 // 2  multi-line block comment
      ' * a license header',                // 3
      ' * spanning several lines',          // 4
      ' */',                                // 5
      '// a full-line comment',             // 6
      '// another full-line comment',       // 7
      '// a third full-line comment',       // 8
      'const x = 1;',                       // 9
      "app.get('/late/route', (req, res) => res.json({ x }));", // 10
    ];
    await fs.writeFile(path.join(cdir, 'app.js'), lines.join('\n'));
    const r = await extractRoutes(cdir);
    const late = r.routes.find((x) => x.path === '/late/route');
    assert.ok(late, 'route after the comment blocks was extracted');
    assert.equal(late!.sourceLine, 10, 'cited line equals the real source line, not shifted up by stripped comments');
  } finally {
    await fs.rm(cdir, { recursive: true, force: true });
  }
});

// Method-first PromiseRouter (Parse Server): `this.route('POST','/path', ...)`.
// Before the fix the file was skipped entirely (RE_HAS_ROUTE only knew
// app/router objects, not `this`), so every Parse Server /classes route was
// ungrounded — we'd measure extraction, not detection.
test('extractRoutes grounds method-first this.route(VERB, path) (PromiseRouter)', async () => {
  const pdir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-pr-'));
  try {
    await fs.writeFile(
      path.join(pdir, 'router.js'),
      [
        'class ClassesRouter extends PromiseRouter {',
        '  mountRoutes() {',
        "    this.route('GET', '/classes/:className', req => this.handleFind(req));",
        "    this.route('POST', '/classes/:className', mw, req => this.handleCreate(req));",
        '  }',
        '}',
      ].join('\n'),
    );
    const r = await extractRoutes(pdir);
    const post = r.routes.find((x) => x.method === 'POST' && x.path === '/classes/:className');
    assert.ok(post, 'method-first POST route grounded');
    assert.equal(post!.sourceLine, 4, 'cites the this.route line');
  } finally {
    await fs.rm(pdir, { recursive: true, force: true });
  }
});

// Laravel comment stripping must preserve line count too (Firefly III routes/api.php
// desynced citations by ~96 lines before the fix). Same D-3 guard as express.
test('parseLaravel cites the exact route line through comment blocks (D-3)', async () => {
  const ldir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-laravel-'));
  try {
    const lines = [
      '<?php',                                   // 1
      '/*',                                      // 2 block comment
      ' * a banner',                             // 3
      ' */',                                     // 4
      '// a full-line comment',                  // 5
      '# a hash comment',                        // 6
      "Route::get('users/{user}', ['uses' => 'UserController@show']);", // 7
    ];
    await fs.mkdir(path.join(ldir, 'routes'), { recursive: true });
    await fs.writeFile(path.join(ldir, 'routes', 'web.php'), lines.join('\n'));
    const r = await extractRoutes(ldir);
    const route = r.routes.find((x) => x.path.includes('users') && x.method === 'GET');
    assert.ok(route, 'laravel route extracted');
    assert.equal(route!.sourceLine, 7, 'cited line equals the real source line');
  } finally {
    await fs.rm(ldir, { recursive: true, force: true });
  }
});

// Express factory sub-apps: `var apiApp = express()` then `apiApp.post('/x', ...)`.
// Before the fix RE_HAS_ROUTE only gated files with app/router/*router* receivers,
// so an `*App`-named factory sub-app (FUXA's apiApp/authApp) was skipped → 0 routes.
test('extractRoutes grounds express factory sub-app receivers (apiApp = express())', async () => {
  const adir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-factory-'));
  try {
    await fs.writeFile(
      path.join(adir, 'api.js'),
      [
        "const express = require('express');",
        'let apiApp;',
        'function setup() {',
        '  apiApp = express();',
        "  apiApp.post('/api/signin', function (req, res) { res.json({}); });",
        "  apiApp.get('/api/settings', function (req, res) { res.json({}); });",
        '}',
      ].join('\n'),
    );
    const r = await extractRoutes(adir);
    const signin = r.routes.find((x) => x.method === 'POST' && x.path === '/api/signin');
    assert.ok(signin, 'factory sub-app route grounded');
  } finally {
    await fs.rm(adir, { recursive: true, force: true });
  }
});

// Laravel MULTI-LINE route with the modern array-callable handler form
// (`Route::get(\n '/p',\n [Ctrl::class,'m']\n)`). Before the fix the route tail
// terminated at the first newline, so the array-callable on a later line was never
// captured → route grounded but no handler symbol. Now the tail runs to the `;`.
test('parseLaravel grounds a multi-line array-callable route + captures the handler', async () => {
  const ldir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-laravel-mc-'));
  try {
    await fs.mkdir(path.join(ldir, 'routes'), { recursive: true });
    await fs.writeFile(
      path.join(ldir, 'routes', 'web.php'),
      [
        '<?php',
        'Route::group([], function () {',
        '    Route::get(',
        "        'locations/{id}/print',",
        '        [LocationsController::class, \'printAssigned\']',
        "    )->name('locations.print');",
        '});',
      ].join('\n'),
    );
    const r = await extractRoutes(ldir);
    const route = r.routes.find((x) => x.method === 'GET' && /locations\/.*print/.test(x.path));
    assert.ok(route, 'multi-line array-callable route grounded');
    assert.match(route!.handler ?? '', /LocationsController@printAssigned/, 'handler captured from the next-line array-callable');
  } finally {
    await fs.rm(ldir, { recursive: true, force: true });
  }
});

// Express array-path route: `router.get(['/', '/:id'], handler)`. Express accepts an
// array of paths; each is a route. A router file whose routes ALL use the array form
// otherwise grounds to zero routes (FlowiseAI leads/tools/variables).
test('extractRoutes grounds an array-of-paths express route', async () => {
  const adir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-arrpath-'));
  try {
    await fs.writeFile(
      path.join(adir, 'r.js'),
      [
        "const router = require('express').Router();",
        "router.get(['/', '/:id'], (req, res) => res.json({}));",
        "router.post('/', (req, res) => res.json({}));",
      ].join('\n'),
    );
    const r = await extractRoutes(adir);
    const paths = new Set(r.routes.map((x) => `${x.method} ${x.path}`));
    assert.ok([...paths].some((p) => p === 'GET /:id'), 'second array path grounded');
    assert.ok([...paths].some((p) => p === 'GET /'), 'first array path grounded');
  } finally {
    await fs.rm(adir, { recursive: true, force: true });
  }
});

// NestJS controllers declare routes as PascalCase verb decorators on methods inside
// an `@Controller('prefix')` class; the path is controller-prefix + method-path (+
// optional setGlobalPrefix). Before the parser, a whole NestJS app grounded to zero
// routes (Postiz SSRF GHSA-89v5-38xr-9m4j was unreachable).
test('extractRoutes grounds NestJS @Controller/@Post methods with prefix composition', async () => {
  const ndir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-nest-'));
  try {
    await fs.writeFile(
      path.join(ndir, 'main.ts'),
      ["const app = await NestFactory.create(AppModule);", "app.setGlobalPrefix('api');"].join('\n'),
    );
    await fs.writeFile(
      path.join(ndir, 'webhooks.controller.ts'),
      [
        "@Controller('/webhooks')",
        'export class WebhooksController {',
        "  @Get('/')",
        '  async getStatistics(@GetOrgFromRequest() org) { return []; }',
        '',
        "  @Post('/send')",
        '  @UseGuards(AuthGuard)',
        '  async sendWebhook(@Body() body: any, @Query(\'url\') url: string) {',
        '    return fetch(url);',
        '  }',
        '}',
      ].join('\n'),
    );
    const r = await extractRoutes(ndir);
    const paths = new Set(r.routes.map((x) => `${x.method} ${x.path}`));
    assert.ok([...paths].some((p) => p === 'POST /api/webhooks/send'), `global+controller prefix composed (got ${[...paths].join(', ')})`);
    assert.ok([...paths].some((p) => p === 'GET /api/webhooks'), 'empty method path resolves to the controller path');
    const send = r.routes.find((x) => x.method === 'POST' && x.path === '/api/webhooks/send');
    assert.equal(send!.handler, 'sendWebhook', 'handler is the decorated method, past the @UseGuards decorator');
    assert.ok(send!.sourceFile && typeof send!.sourceLine === 'number', 'cites file:line (D-3)');
  } finally {
    await fs.rm(ndir, { recursive: true, force: true });
  }
});

// Django wires function/class views via `path("route/", view)` in urls.py modules,
// include()'d from a root urls.py under a prefix. Before the parser a whole Django app
// grounded to zero routes. `path()` carries no HTTP verb → routes ground as ANY.
test('extractRoutes grounds Django path() routes with include() prefix composition', async () => {
  const ddir = await fs.mkdtemp(path.join(os.tmpdir(), 'detect-core-django-'));
  try {
    await fs.writeFile(
      path.join(ddir, 'urls.py'),
      [
        'from django.urls import include, path',
        'urlpatterns = [',
        '    path("api/", include(("api_app.urls", "api_app"), namespace="api_app")),',
        '    path("", include(("sql.urls", "sql"), namespace="sql")),',
        ']',
      ].join('\n'),
    );
    await fs.mkdir(path.join(ddir, 'sql'), { recursive: true });
    await fs.writeFile(
      path.join(ddir, 'sql', 'urls.py'),
      [
        'from django.urls import path',
        'from sql import instance, views',
        'urlpatterns = [',
        '    path("index/", views.index),',
        '    # path("ghost/", views.ghost),',
        '    path("instance/describetable/", instance.describe),',
        ']',
      ].join('\n'),
    );
    await fs.mkdir(path.join(ddir, 'api_app'), { recursive: true });
    await fs.writeFile(
      path.join(ddir, 'api_app', 'urls.py'),
      ['from django.urls import path', 'from api_app import api_user', 'urlpatterns = [', '    path("v1/user/<int:pk>/", api_user.UserDetail.as_view()),', ']'].join('\n'),
    );
    const r = await extractRoutes(ddir);
    const byKey = new Map(r.routes.map((x) => [`${x.method} ${x.path}`, x]));
    const target = byKey.get('ANY /instance/describetable');
    assert.ok(target, `target Django route grounded (got ${[...byKey.keys()].join(', ')})`);
    assert.equal(target!.handler, 'instance.describe', 'handlerSymbol is the dotted view ref');
    assert.equal(target!.framework, 'django');
    assert.equal(target!.sourceFile, path.join('sql', 'urls.py'), 'cites the urls.py that declared it');
    assert.equal(target!.sourceLine, 6, 'cites the exact path() line, undisturbed by the stripped comment (D-3)');
    const cbv = byKey.get('ANY /api/v1/user/:pk');
    assert.ok(cbv, 'api-prefixed class-based-view route grounded with prefix + :pk');
    assert.equal(cbv!.handler, 'api_user.UserDetail.as_view', 'class-based view handler is <Ctrl>.as_view');
    assert.ok(!byKey.has('ANY /ghost'), 'commented-out path() did not ground (comment strip)');
  } finally {
    await fs.rm(ddir, { recursive: true, force: true });
  }
});

test('canonicalizePolicy is idempotent + order-independent', () => {
  const a = canonicalizePolicy({
    profile: 'standard-crud',
    mitigates: ['API3:2023', 'API1:2023'],
    request: { schema: { id: { type: 'string', pattern: '\\d+' } } },
  } as never);
  const b = canonicalizePolicy({
    request: { schema: { id: { type: 'string', pattern: '[0-9]+' } } },
    mitigates: ['API1:2023', 'API3:2023'],
    profile: 'standard-crud',
  } as never);
  assert.equal(serializeStable(a), serializeStable(b), 'semantically-equal policies canonicalize identically');
});

test('corpus regression: every baseline ideal policy is V1-schema valid', async () => {
  const raw = JSON.parse(await fs.readFile(CORPUS_BASELINE, 'utf8')) as {
    emissions: Array<{ endpointId: string; policy: unknown }>;
  };
  let checked = 0;
  for (const e of raw.emissions) {
    if (e.policy === null || e.policy === undefined) continue;
    const res = validateXSecurity(e.policy);
    assert.equal(res.valid, true, `${e.endpointId} ideal policy must be schema-valid: ${JSON.stringify((res as { errors?: unknown }).errors)}`);
    // Canonicalization must not break validity.
    const canon = canonicalizePolicy(structuredClone(e.policy) as never);
    assert.equal(validateXSecurity(canon).valid, true, `${e.endpointId} stays valid after canonicalization`);
    checked += 1;
  }
  assert.ok(checked > 0, 'corpus fixture had at least one policy to check');
});
