// Unit checks for the recall-max detection plan (2026-06-05):
//   (a) a stub/empty policy over a route with an object-id surface yields a
//       hard `unguarded-object-id` depth gap;
//   (b) a correct authorization policy (ownership rule on the id) yields no gap;
//   (c) the V4 authz round-trip demotes an ownership rule on a field that is
//       ABSENT from request.schema (the dvrestaurant PUT /profile over-block,
//       miss E) — the omit-the-field positive is blocked;
//   (d) a substantive policy with the ownership field ALSO in request.schema
//       passes (omission is independently a block, so the rule is coherent).
//
// Also exercises the phase-D SSRF evaluator (blockPrivateRanges) and the
// phase-B/C surface signals end-to-end through the deterministic primitives.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  assessRouteDepth,
  buildEvidencePacks,
  deriveCandidateFindings,
  deriveMassAssignmentCandidates,
  routeAnalysisIncomplete,
  evaluatePolicy,
  evaluateParam,
  generatePositive,
  generatePositiveOwnershipAbsent,
  generatePositiveBodyOwnershipAbsent,
  generateAuthzNegative,
  isSelfMutationBodyOwnership,
  checkTightness,
  compileAssumptionsToPolicy,
  type EvidencePack,
  type ObjectIdSurface,
  type PolicyEmission,
  type XSecurityPolicy,
  type RouteInventoryEntry,
} from '../src/index.js';

function packWithIdSurface(over: Partial<ObjectIdSurface> = {}): EvidencePack {
  const param = {
    name: 'username',
    source: 'path' as const,
    file: 'app/users.js',
    line: 42,
    excerpt: 'const u = await User.findOne({ username: req.params.username })',
  };
  const surface: ObjectIdSurface = {
    param,
    usedInFetchOrMutate: true,
    comparedToPrincipal: false,
    ...over,
  };
  return {
    endpointId: 'GET /api/user/:username',
    handlerSnippet: {
      file: 'app/users.js',
      lineStart: 40,
      lineEnd: 48,
      snippet: 'function getUser(req,res){ const u = User.findOne({username:req.params.username}); res.json(u); }',
      truncated: false,
    },
    observedInputs: [param],
    observedValidators: [{ name: 'findOne', kind: 'orm-binding', file: 'app/users.js', line: 42, excerpt: param.excerpt }],
    observedOutputs: [{ kind: 'json', file: 'app/users.js', line: 43, excerpt: 'res.json(u)' }],
    objectIdParams: [surface],
    bodyParsed: null,
    bytes: 100,
  };
}

const STUB_POLICY: XSecurityPolicy = { request: { schema: {} } } as XSecurityPolicy;

// (a) — stub/empty policy + object-id surface ⇒ unguarded-object-id hard gap.
test('(a) stub policy with an objectIdSurface yields unguarded-object-id', () => {
  const pack = packWithIdSurface();
  const res = assessRouteDepth({
    policy: STUB_POLICY,
    pack,
    method: 'GET',
    path: '/api/user/:username',
    auth: { chain: ['requireAuth'], inlineSymbols: [] }, // non-public: carve-out off
  });
  const gap = res.gaps.find((g) => g.kind === 'unguarded-object-id');
  assert.ok(gap, 'expected an unguarded-object-id gap');
  assert.ok(gap!.surface, 'gap must carry a surface cite (D-3)');
  assert.equal(gap!.surface!.file, 'app/users.js');
  assert.equal(gap!.surface!.line, 42);
});

// (b) — a correct authorization policy (rule on the id) clears the gap.
test('(b) a correct authz policy yields no unguarded-object-id gap', () => {
  const pack = packWithIdSurface();
  const policy: XSecurityPolicy = {
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'request.path.username', operator: 'equals', value: { ref: 'jwt.username' } }],
    },
  } as XSecurityPolicy;
  const res = assessRouteDepth({
    policy,
    pack,
    method: 'GET',
    path: '/api/user/:username',
    auth: { chain: ['requireAuth'], inlineSymbols: [] },
  });
  assert.equal(res.gaps.filter((g) => g.kind === 'unguarded-object-id').length, 0);
});

// The miss-E route: PUT /profile with an ownership rule on body.username, but
// username is NOT in request.schema. A legit clean update omits username.
const PROFILE_ROUTE: RouteInventoryEntry = {
  method: 'PUT',
  path: '/profile',
  sourceFile: '<synthetic>',
  sourceLine: 0,
};

function profilePolicy(usernameInSchema: boolean): XSecurityPolicy {
  const schema: Record<string, unknown> = { displayName: { type: 'string', maxLength: 80 } };
  if (usernameInSchema) schema['username'] = { type: 'string', maxLength: 40 };
  return {
    authentication: { type: 'bearer-jwt' },
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'request.body.username', operator: 'equals', value: { ref: 'jwt.username' } }],
    },
    request: { schema },
  } as XSecurityPolicy;
}

// (c) — username NOT in schema ⇒ the omit-the-field positive is BLOCKED (the
// over-block V4 demotes on). And the wrong-owner negative IS blocked (rule bites).
test('(c) V4 demotes an authz rule on a field absent from request.schema', () => {
  const policy = profilePolicy(false);
  const absent = generatePositiveOwnershipAbsent(PROFILE_ROUTE, policy);
  const absentResult = evaluatePolicy(absent, policy);
  assert.equal(
    absentResult.decision,
    'block',
    'omit-the-username positive must be BLOCKED when username is not request-required (the demote trigger)',
  );

  const neg = generateAuthzNegative(PROFILE_ROUTE, policy);
  assert.ok(neg, 'expected an authz negative');
  assert.equal(evaluatePolicy(neg!, policy).decision, 'block', 'wrong-owner request must block');
});

// (d) — username IN schema on a self-mutation route (PUT /profile) STILL
// over-blocks: marking the body owner id required is itself the over-block (a
// legit clean update omits its own principal). The omit-body-owner positive is
// blocked → V4 demotes. (Iteration-2 FIX 1: required-in-schema must NOT suppress
// the self-mutation demote.)
test('(d) self-mutation PUT /profile with body owner required STILL demotes', () => {
  const policy = profilePolicy(true);
  assert.ok(
    isSelfMutationBodyOwnership(PROFILE_ROUTE, policy),
    'PUT /profile with body.username ownership is a self-mutation route',
  );
  const absent = generatePositiveBodyOwnershipAbsent(PROFILE_ROUTE, policy);
  assert.equal(
    evaluatePolicy(absent, policy).decision,
    'block',
    'omit-the-body-owner positive must be BLOCKED even when username is in schema (the demote trigger)',
  );
  // The wrong-owner negative still bites (the rule is not too loose).
  const neg = generateAuthzNegative(PROFILE_ROUTE, policy);
  assert.ok(neg);
  assert.equal(evaluatePolicy(neg!, policy).decision, 'block', 'wrong-owner must still block');
});

// ===========================================================================
// Iteration-2 FIX cases (blind 4-app re-test defects).
// ===========================================================================

// FIX 1 — keystone. PUT /profile with `authz body.username == jwt.sub` and
// username REQUIRED in schema → DEMOTE (self-mutation must pin the principal
// server-side). A query/path id ownership rule where the legit carries the id
// (GET /getNote `query.username` in schema) → NOT self-mutation → PASS.
const GETNOTE_ROUTE: RouteInventoryEntry = {
  method: 'GET',
  path: '/api/getNote',
  sourceFile: '<synthetic>',
  sourceLine: 0,
};

test('FIX1: PUT /profile body-owner-required demotes; GET /getNote query-id passes', () => {
  // self-mutation, username required → demote (omit positive blocked).
  const profile = profilePolicy(true);
  assert.ok(isSelfMutationBodyOwnership(PROFILE_ROUTE, profile));
  const absent = generatePositiveBodyOwnershipAbsent(PROFILE_ROUTE, profile);
  assert.equal(evaluatePolicy(absent, profile).decision, 'block', 'PUT /profile must demote');

  // GET /getNote: query.username ownership, username in schema → NOT self-mutation.
  const getNotePolicy: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt' },
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'request.query.username', operator: 'equals', value: { ref: 'jwt.username' } }],
    },
    request: { schema: { username: { type: 'string', maxLength: 40 } } },
  } as XSecurityPolicy;
  assert.equal(
    isSelfMutationBodyOwnership(GETNOTE_ROUTE, getNotePolicy),
    false,
    'a query-id ownership rule is not a self-mutation body-owner over-block',
  );
  // The legit positive (carries query.username == principal) passes; wrong-owner blocks.
  const pos = generatePositive(GETNOTE_ROUTE, getNotePolicy);
  assert.equal(evaluatePolicy(pos, getNotePolicy).decision, 'allow', 'GET /getNote legit must PASS');
  const neg = generateAuthzNegative(GETNOTE_ROUTE, getNotePolicy);
  assert.ok(neg);
  assert.equal(evaluatePolicy(neg!, getNotePolicy).decision, 'block', 'wrong-owner blocks');
});

// FIX 2 — an ssrfGuard controlHint compiles to blockPrivateRanges:true on the
// url param, the param is tight (survives V6), and the metadata-IP negative
// blocks while a public host passes.
test('FIX2: ssrfGuard hint compiles blockPrivateRanges:true and the metadata IP blocks', () => {
  const emission: PolicyEmission = {
    endpointId: 'POST /api/addNoteWithLink',
    policy: null,
    reviewRequired: true,
    assumptions: [
      {
        field: 'request.schema.url',
        assumption: 'server-side fetch of a user-supplied URL (SSRF)',
        confidence: 'high',
        cite: { file: 'app/notes.js', lineStart: 10, lineEnd: 10, quote: 'fetch(req.body.url)' },
        controlHint: { kind: 'ssrfGuard', param: 'url', blockPrivateRanges: true },
      },
    ],
  };
  const prev = process.env['COMPILE_ASSUMPTIONS'];
  process.env['COMPILE_ASSUMPTIONS'] = '1';
  let compiled;
  try {
    compiled = compileAssumptionsToPolicy(emission);
  } finally {
    if (prev === undefined) delete process.env['COMPILE_ASSUMPTIONS'];
    else process.env['COMPILE_ASSUMPTIONS'] = prev;
  }
  const ps = (compiled.emission.policy as XSecurityPolicy)?.request?.schema?.['url'];
  assert.ok(ps, 'url param schema must be emitted');
  assert.equal(ps!.type, 'url');
  assert.equal(ps!.blockPrivateRanges, true, 'blockPrivateRanges:true must be compiled');
  // Tight on its own (no domainAllowlist needed) → survives V6.
  assert.equal(checkTightness(ps!), null, 'a url with blockPrivateRanges is tight');
  // The metadata-IP negative blocks; a public host passes.
  assert.ok(evaluateParam('http://169.254.169.254/latest/meta-data/', ps!, 'url'), 'metadata IP blocked');
  assert.equal(evaluateParam('https://example.com/x', ps!, 'url'), null, 'public host passes');
});

// FIX 3 — auth-endpoint-no-rate-limit. A login route policy with no rateLimit
// yields the gap (cited at the credential-check line); the same route WITH a
// rateLimit yields no gap. A non-auth route never fires.
function loginPack(): EvidencePack {
  return {
    endpointId: 'POST /api/login',
    handlerSnippet: {
      file: 'app/auth.js',
      lineStart: 20,
      lineEnd: 24,
      snippet:
        'function login(req,res){\n  const u = User.findOne({ username: req.body.username, password: req.body.password });\n  if(!password_verify(req.body.password,u.hash)) return res.status(401);\n  res.json({token});\n}',
      truncated: false,
    },
    observedInputs: [
      { name: 'username', source: 'body', file: 'app/auth.js', line: 21, excerpt: 'req.body.username' },
      { name: 'password', source: 'body', file: 'app/auth.js', line: 21, excerpt: 'req.body.password' },
    ],
    observedValidators: [
      { name: 'password_verify', kind: 'auth-check', file: 'app/auth.js', line: 22, excerpt: 'if(!password_verify(req.body.password,u.hash))' },
    ],
    observedOutputs: [{ kind: 'json', file: 'app/auth.js', line: 23, excerpt: 'res.json({token})' }],
    objectIdParams: [],
    bodyParsed: { kind: 'json', file: 'app/auth.js', line: 21 },
    bytes: 200,
  };
}

test('FIX3: login route without rateLimit gaps; with rateLimit no gap', () => {
  const pack = loginPack();
  const noRl: XSecurityPolicy = {
    authentication: { type: 'bearer-jwt' },
    request: { contentType: ['application/json'], schema: { username: { type: 'string', maxLength: 40 }, password: { type: 'string', maxLength: 200 } } },
  } as XSecurityPolicy;
  const res = assessRouteDepth({ policy: noRl, pack, method: 'POST', path: '/api/login', auth: { chain: [], inlineSymbols: [] } });
  const gap = res.gaps.find((g) => g.kind === 'auth-endpoint-no-rate-limit');
  assert.ok(gap, 'expected an auth-endpoint-no-rate-limit gap');
  assert.ok(gap!.surface, 'gap must carry a byte-matched surface cite (D-3)');
  assert.equal(gap!.surface!.file, 'app/auth.js');
  assert.equal(gap!.surface!.line, 22, 'cite points at the credential-check line');

  const withRl: XSecurityPolicy = {
    ...noRl,
    rateLimit: { requests: 5, window: '1m', identifier: 'ip' },
  } as XSecurityPolicy;
  const res2 = assessRouteDepth({ policy: withRl, pack, method: 'POST', path: '/api/login', auth: { chain: [], inlineSymbols: [] } });
  assert.equal(res2.gaps.filter((g) => g.kind === 'auth-endpoint-no-rate-limit').length, 0, 'rateLimit clears the gap');

  // Non-auth route (no auth path token, no credential check) never fires.
  const plainPack: EvidencePack = {
    endpointId: 'GET /api/health',
    handlerSnippet: { file: 'app/health.js', lineStart: 1, lineEnd: 2, snippet: 'function health(req,res){ res.json({ok:true}); }', truncated: false },
    observedInputs: [],
    observedValidators: [],
    observedOutputs: [{ kind: 'json', file: 'app/health.js', line: 1, excerpt: 'res.json({ok:true})' }],
    objectIdParams: [],
    bodyParsed: null,
    bytes: 50,
  };
  const res3 = assessRouteDepth({ policy: { request: { schema: {} } } as XSecurityPolicy, pack: plainPack, method: 'GET', path: '/api/health', auth: { chain: [], inlineSymbols: [] } });
  assert.equal(res3.gaps.filter((g) => g.kind === 'auth-endpoint-no-rate-limit').length, 0, 'non-auth route never fires');
});

// FIX 4 — auth-less GET id-route. GET /orders/{order_id} with a request-visible
// `query.owner` and no authz rule → unguarded-object-id gap citing the fetch,
// EVEN with no auth chain. A public GET /products/{id} with no owner field and a
// non-user-scoped resource → no gap.
function ordersPack(): EvidencePack {
  const idParam = { name: 'order_id', source: 'path' as const, file: 'app/orders.js', line: 12, excerpt: 'const o = Order.findOne({ id: req.params.order_id })' };
  const ownerParam = { name: 'owner', source: 'query' as const, file: 'app/orders.js', line: 11, excerpt: 'const owner = req.query.owner' };
  return {
    endpointId: 'GET /orders/{order_id}',
    handlerSnippet: { file: 'app/orders.js', lineStart: 10, lineEnd: 14, snippet: 'function getOrder(req,res){\n  const owner = req.query.owner;\n  const o = Order.findOne({ id: req.params.order_id });\n  res.json(o);\n}', truncated: false },
    observedInputs: [ownerParam, idParam],
    observedValidators: [{ name: 'findOne', kind: 'orm-binding', file: 'app/orders.js', line: 12, excerpt: idParam.excerpt }],
    observedOutputs: [{ kind: 'json', file: 'app/orders.js', line: 13, excerpt: 'res.json(o)' }],
    objectIdParams: [
      { param: idParam, usedInFetchOrMutate: true, comparedToPrincipal: false, ownerFieldCandidate: ownerParam },
    ],
    bodyParsed: null,
    bytes: 200,
  };
}

test('FIX4: auth-less GET /orders/{id} with owner field gaps; public GET /products/{id} does not', () => {
  const pack = ordersPack();
  const res = assessRouteDepth({
    policy: { request: { schema: {} } } as XSecurityPolicy,
    pack,
    method: 'GET',
    path: '/orders/{order_id}',
    auth: { chain: [], inlineSymbols: [] }, // NO auth chain — old carve-out would skip
  });
  const gap = res.gaps.find((g) => g.kind === 'unguarded-object-id');
  assert.ok(gap, 'expected an unguarded-object-id gap on an auth-less user-scoped GET');
  assert.ok(gap!.surface, 'gap cites the fetch (D-3)');
  assert.equal(gap!.surface!.line, 12);
  assert.match(gap!.detail, /request\.query\.owner == jwt/, 'detail instructs pinning the owner field');

  // Public product listing: bare `id`, non-user-scoped resource, no owner field → no gap.
  const idParam = { name: 'id', source: 'path' as const, file: 'app/products.js', line: 5, excerpt: 'const p = Product.findOne({ id: req.params.id })' };
  const productPack: EvidencePack = {
    endpointId: 'GET /products/{id}',
    handlerSnippet: { file: 'app/products.js', lineStart: 4, lineEnd: 7, snippet: 'function getProduct(req,res){\n  const p = Product.findOne({ id: req.params.id });\n  res.json(p);\n}', truncated: false },
    observedInputs: [idParam],
    observedValidators: [{ name: 'findOne', kind: 'orm-binding', file: 'app/products.js', line: 5, excerpt: idParam.excerpt }],
    observedOutputs: [{ kind: 'json', file: 'app/products.js', line: 6, excerpt: 'res.json(p)' }],
    objectIdParams: [{ param: idParam, usedInFetchOrMutate: true, comparedToPrincipal: false }],
    bodyParsed: null,
    bytes: 150,
  };
  const res2 = assessRouteDepth({
    policy: { request: { schema: {} } } as XSecurityPolicy,
    pack: productPack,
    method: 'GET',
    path: '/products/{id}',
    auth: { chain: [], inlineSymbols: [] },
  });
  assert.equal(
    res2.gaps.filter((g) => g.kind === 'unguarded-object-id').length,
    0,
    'a public non-user-scoped GET with no owner field must NOT fire',
  );
});

// Phase D — SSRF: blockPrivateRanges rejects the metadata IP + non-http schemes,
// allows a public host.
test('(D) blockPrivateRanges rejects metadata/private/non-http, allows public', () => {
  const ps = { type: 'url' as const, blockPrivateRanges: true };
  assert.ok(evaluateParam('http://169.254.169.254/latest/meta-data/', ps, 'u'), 'metadata IP blocked');
  assert.ok(evaluateParam('http://127.0.0.1/x', ps, 'u'), 'loopback blocked');
  assert.ok(evaluateParam('http://10.1.2.3/x', ps, 'u'), 'RFC1918 blocked');
  assert.ok(evaluateParam('http://localhost/x', ps, 'u'), 'localhost blocked');
  assert.ok(evaluateParam('file:///etc/passwd', ps, 'u'), 'non-http scheme blocked');
  assert.equal(evaluateParam('https://example.com/x', ps, 'u'), null, 'public host allowed');
});

// Phase D — an empty domainAllowlist on a url param is NOT a constraint (the
// evaluator keeps the length>0 guard; the V4-side demote catches the no-op).
test('(D) empty domainAllowlist does not constrain in the evaluator', () => {
  const ps = { type: 'url' as const, domainAllowlist: [] };
  assert.equal(evaluateParam('https://evil.example.org/x', ps, 'u'), null);
});

// #1 dismissal-tightening — on a MUTATE of a user-scoped resource, a cite near the
// BOLA surface clears the gap ONLY if its quote is a principal-vs-id ownership
// comparison. A bare/role-gate cite does NOT clear it (→ gap persists → demote).
function deleteUserPack(): EvidencePack {
  const idParam = { name: 'username', source: 'path' as const, file: 'api_views/users.py', line: 207, excerpt: "user = User.query.filter_by(username=username).first()" };
  return {
    endpointId: 'DELETE /users/v1/{username}',
    handlerSnippet: { file: 'api_views/users.py', lineStart: 206, lineEnd: 213, snippet: 'def delete_user(username):\n  user = User.query.filter_by(username=username).first()\n  db.session.delete(user)\n  db.session.commit()', truncated: false },
    observedInputs: [idParam],
    observedValidators: [{ name: 'filter_by', kind: 'orm-binding', file: 'api_views/users.py', line: 207, excerpt: idParam.excerpt }],
    observedOutputs: [],
    objectIdParams: [{ param: idParam, usedInFetchOrMutate: true, comparedToPrincipal: false }],
    bodyParsed: null,
    bytes: 200,
  };
}

test('#1: DELETE user-scoped BOLA — a non-ownership dismissal cite does NOT clear the gap', () => {
  const pack = deleteUserPack();
  const res = assessRouteDepth({
    policy: { request: { schema: {} } } as XSecurityPolicy,
    pack, method: 'DELETE', path: '/users/v1/{username}',
    auth: { chain: ['isAuthenticated'], inlineSymbols: [] },
    // cite anchors the surface line but is just the fetch line / an admin role gate —
    // neither is a principal-vs-id ownership compare.
    dismissalCites: [{ file: 'api_views/users.py', lineStart: 207, lineEnd: 212, quote: "if g.user.role == 'admin':" }],
  });
  assert.ok(res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'role-gate dismissal must NOT clear a mutate BOLA — demote to reviewRequired');
});

test('#1: DELETE user-scoped BOLA — a real principal-vs-id ownership cite DOES clear it', () => {
  const pack = deleteUserPack();
  const res = assessRouteDepth({
    policy: { request: { schema: {} } } as XSecurityPolicy,
    pack, method: 'DELETE', path: '/users/v1/{username}',
    auth: { chain: ['isAuthenticated'], inlineSymbols: [] },
    dismissalCites: [{ file: 'api_views/users.py', lineStart: 207, lineEnd: 208, quote: "if username != current_user.username: abort(403)" }],
  });
  assert.ok(!res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'a principal-vs-id ownership compare clears the gap');
});

test('#1: PUBLIC (unauthed) GET user-scoped read keeps the soft (location-only) exit', () => {
  const pack = deleteUserPack();
  // A genuine PUBLIC read (no auth chain) keeps the soft location exit — any covering
  // cite clears it. (An AUTHED user-scoped GET is now strict, per #1b.)
  const res = assessRouteDepth({
    policy: { request: { schema: {} } } as XSecurityPolicy,
    pack, method: 'GET', path: '/users/v1/{username}',
    auth: { chain: [], inlineSymbols: [] }, // PUBLIC — soft exit
    dismissalCites: [{ file: 'api_views/users.py', lineStart: 207, lineEnd: 208, quote: "# public profile view, no owner restriction" }],
  });
  assert.ok(!res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'public GET read dismissal stays location-only');
});

// #2 cross-file handler resolution — the route decl is in routes/app.js but the
// handler body (where req.body.login → SQL sink) is in controllers/ctrl.js. The
// extractor's handlerSymbol is the FIRST middleware (unreliable); the decl-line
// parse takes the LAST arg (the real handler) and find/grep resolves its body.
test('#2: cross-file handler — pack snippet is the controller body, inputs populated', async () => {
  const decl = "  router.post('/users/search', auth.required, userCtrl.search)";
  const body = "module.exports.search = function (req, res) {\n  const q = \"SELECT * FROM users WHERE login='\" + req.body.login + \"'\";\n  db.query(q);\n};";
  const tools = {
    list_files: async () => [],
    read_file: async (p, ls) => {
      if (p === 'routes/app.js') return { path: 'routes/app.js', lineStart: ls ?? 1, lineEnd: ls ?? 1, content: decl, truncated: false };
      if (p === 'controllers/ctrl.js') return { path: 'controllers/ctrl.js', lineStart: 9, lineEnd: 12, content: body, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat) => (/search/.test(pat) ? [{ file: 'controllers/ctrl.js', line: 9 }] : []),
    find_definition: async () => [{ file: 'controllers/ctrl.js', line: 9, preview: 'module.exports.search = function' }],
    find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/users/search', sourceFile: 'routes/app.js', sourceLine: 1, handlerSymbol: 'auth.required' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /users/search')!;
  assert.ok(pack, 'pack built');
  assert.equal(pack.handlerSnippet?.file, 'controllers/ctrl.js', 'snippet is the controller body, not the router decl');
  assert.ok(pack.observedInputs.some((i) => i.source === 'body' && i.name === 'login'), 'body.login surfaced from the real handler');
});

// #2b inline Express handler that is the LAST arg, wrapped in a HOF (error_catcher),
// after middleware whose own args carry a `{}` block (passport.authenticate options).
// Reading from `router.post(` the body-trim used to close on that options object before
// the real handler; re-anchoring to the trailing handler arg surfaces `(req.body||{}).dest`
// (saltcorn CVE-2026-42259 open-redirect). The `|| {}` defensive idiom must surface too.
test('#2b: inline HOF-wrapped trailing handler re-anchors; (req.body||{}).field surfaces', async () => {
  const decl = [
    'router.post(',
    '  "/login",',
    '  ipLimiter,',
    '  passport.authenticate("local", {',
    '    failureRedirect: "/auth/login",',
    '    failureFlash: true,',
    '  }),',
    '  error_catcher(async (req, res) => {',
    '    if ((req.body || {}).remember) keep(req);',
    '    if ((req.body || {}).dest && is_relative_url((req.body || {}).dest))',
    '      res.redirect((req.body || {}).dest);',
    '    else res.redirect("/");',
    '  })',
    ');',
  ].join('\n');
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) =>
      p === 'routes/auth.js'
        ? { path: 'routes/auth.js', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + decl.split('\n').length, content: decl, truncated: false }
        : { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false },
    grep: async () => [],
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/login', sourceFile: 'routes/auth.js', sourceLine: 1, handlerSymbol: 'ipLimiter' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /login')!;
  assert.ok(pack, 'pack built');
  assert.ok(/res\.redirect\(\(req\.body \|\| \{\}\)\.dest\)/.test(pack.handlerSnippet?.snippet ?? ''), 'snippet re-anchored to the error_catcher closure (reaches the dest redirect)');
  assert.ok(pack.observedInputs.some((i) => i.source === 'body' && i.name === 'dest'), '(req.body||{}).dest surfaced');
});

// #2c NestJS controller method whose body sink sits BELOW multi-line TS decorators that
// carry their own `{}` options (`@Acl('x',{scope:'org'})`). The body-trim must skip the
// decorators and balance the METHOD body, else it closes on the @Acl options brace and the
// `{ ...body }` proto-pollution spread never surfaces (nocodb CVE-2026-24766).
test('#2c: TS-decorated NestJS method — body-trim skips decorator options to reach the sink', async () => {
  const body = [
    "  @Post(['/api/v2/meta/connection/test'])",
    "  @Acl('testConnection', {",
    "    scope: 'org',",
    '  })',
    '  @HttpCode(200)',
    '  async testConnection(@Body() body: any) {',
    '    body.pool = { min: 0, max: 1 };',
    '    let config = { ...body };',
    '    return this.svc.test({ body: config });',
    '  }',
  ].join('\n');
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) =>
      p === 'utils.controller.ts'
        ? { path: 'utils.controller.ts', lineStart: ls ?? 60, lineEnd: (ls ?? 60) + body.split('\n').length, content: body, truncated: false }
        : { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false },
    grep: async () => [],
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/api/v2/meta/connection/test', sourceFile: 'utils.controller.ts', sourceLine: 60, handler: 'testConnection', framework: 'nestjs' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /api/v2/meta/connection/test')!;
  assert.ok(pack, 'pack built');
  assert.ok(/\{ \.\.\.body \}/.test(pack.handlerSnippet?.snippet ?? ''), 'body-trim reached the { ...body } spread past the @Acl options brace');
});

// #1 candidate-finding taint pass — deterministic injection candidates from the
// resolved handler body. Direct taint (input on the sink line), one-hop (via a var),
// no-input sink (skip), clean line (skip).
function packFor(snippet: string, inputs: { name: string; source: 'body'|'query'|'path' }[]): EvidencePack {
  return {
    endpointId: 'POST /x',
    handlerSnippet: { file: 'h.js', lineStart: 10, lineEnd: 10 + snippet.split('\n').length - 1, snippet, truncated: false },
    observedInputs: inputs.map((i) => ({ ...i, file: 'h.js', line: 10, excerpt: '' })),
    observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null, bytes: 50,
  };
}

// Reflected XSS via an f-string returned as the HTML response body, tainted by a Flask
// path param (changedetection.io GHSA-8whx-v8qq-pq64, rss/tag.py:36:
// `return f"Tag with UUID {tag_uuid} not found", 404`). The path param is the taint
// source; the f-string-into-response is the sink → xss:<param>.
test('#C: f-string-into-html return with a path param → xss (changedetection.io)', () => {
  const snippet = [
    'def rss_tag_feed(tag_uuid):',
    "    tag = datastore.data['settings']['application'].get('tags', {}).get(tag_uuid)",
    '    if not tag:',
    '        return f"Tag with UUID {tag_uuid} not found", 404',
  ].join('\n');
  const cand = deriveCandidateFindings(packFor(snippet, [{ name: 'tag_uuid', source: 'path' }])).find((x) => x.sink === 'xss');
  assert.ok(cand, 'xss candidate from f-string-into-html return');
  assert.equal(cand!.param, 'tag_uuid');
  assert.match(cand!.cite.quote, /return f"Tag with UUID \{tag_uuid\}/);
});

// FP guard: a jsonify body / plain return with the input present must NOT be xss.
test('#C: jsonify / plain return with input present yields no xss false positive', () => {
  const benign = 'def h(name):\n    return jsonify({"hi": name})\n    return "ok", 200';
  const xss = deriveCandidateFindings(packFor(benign, [{ name: 'name', source: 'query' }])).filter((x) => x.sink === 'xss');
  assert.equal(xss.length, 0, 'jsonify / plain return is not an f-string-into-html sink');
});

test('#1: direct taint — exec(\"ping \"+req.body.address) → os-command/address', () => {
  const c = deriveCandidateFindings(packFor("exec('ping ' + req.body.address, cb);", [{ name: 'address', source: 'body' }]));
  assert.equal(c.length, 1);
  assert.equal(c[0]!.sink, 'os-command');
  assert.equal(c[0]!.param, 'address');
  assert.equal(c[0]!.taint, 'direct');
  assert.equal(c[0]!.cite.lineStart, 10);
});

test('#1: one-hop taint — var = input; sink(var) → medium confidence', () => {
  const snippet = "const t = req.body.eqn;\nconst out = mathjs.eval(t);";
  const c = deriveCandidateFindings(packFor(snippet, [{ name: 'eqn', source: 'body' }]));
  const cand = c.find((x) => x.sink === 'code-eval');
  assert.ok(cand, 'code-eval candidate via one-hop');
  assert.equal(cand!.param, 'eqn');
  assert.equal(cand!.taint, 'one-hop');
  assert.equal(cand!.confidence, 'medium');
});

test('#1: a sink with NO request input reaching it yields no candidate', () => {
  const c = deriveCandidateFindings(packFor("db.query('SELECT 1');", [{ name: 'address', source: 'body' }]));
  assert.equal(c.length, 0, 'no input on the sink line → no false candidate');
});

test('#1: dedup — direct beats one-hop for the same (sink,param)', () => {
  const snippet = "const q = \"SELECT * WHERE login='\" + req.body.login + \"'\";\ndb.query(q);";
  const c = deriveCandidateFindings(packFor(snippet, [{ name: 'login', source: 'body' }]));
  const sqls = c.filter((x) => x.sink === 'sql');
  assert.equal(sqls.length, 1, 'one sql candidate per param');
  assert.equal(sqls[0]!.taint, 'direct');
});

// Method-first PromiseRouter handler resolution (Parse Server CVE-2024-47183):
// `this.route('POST','/classes/:className', mw, req => this.handleCreate(req))`.
// The extractor's handlerSymbol catches the middleware `mw`; the real handler is
// the delegated method `handleCreate`, in the same file far from the decl. The
// pack must read handleCreate's body, not the middleware or the arrow.
test('method-first + arrow-delegating handler resolves the delegated method body', async () => {
  const decl = "    this.route('POST', '/classes/:className', promiseEnsureIdempotency, req => {\n      return this.handleCreate(req);\n    });";
  const body = 'handleCreate(req) {\n  return rest.create(req.config, req.auth, this.className(req), req.body);\n}';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'ClassesRouter.js' && (ls ?? 0) <= 10) return { path: 'ClassesRouter.js', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 3, content: decl, truncated: false };
      if (p === 'ClassesRouter.js') return { path: 'ClassesRouter.js', lineStart: 108, lineEnd: 110, content: body, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => (/handleCreate/.test(pat) ? [{ file: 'ClassesRouter.js', line: 108, match: '' }] : []),
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/classes/:className', sourceFile: 'ClassesRouter.js', sourceLine: 6, handlerSymbol: 'promiseEnsureIdempotency' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /classes/:className')!;
  assert.equal(pack.handlerSnippet?.lineStart, 108, 'pack reads handleCreate body (delegated method), not the middleware or arrow');
  assert.ok(/rest\.create/.test(pack.handlerSnippet?.snippet ?? ''), 'handler body is the real create path');
});

// Fail-loud coverage. A route whose handler body cannot be resolved on a risk
// surface (write or id-bearing) is UNANALYZED → analysisIncomplete=true so the
// host agent marks reviewRequired instead of reporting it clean. A resolved route
// stays complete; a trivial param-less GET we couldn't resolve is NOT flagged.
function failLoudTools(grepHits: Array<{ file: string; line: number }>) {
  return {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (/^r\.js$/.test(p)) return { path: 'r.js', lineStart: ls ?? 1, lineEnd: ls ?? 1, content: "router.post('/widgets/:id', someHandler);", truncated: false };
      if (/handlers\.js$/.test(p)) return { path: 'handlers.js', lineStart: 9, lineEnd: 11, content: 'function someHandler(req, res) {\n  res.json({});\n}', truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: "router.get('/health', someHandler);", truncated: false };
    },
    grep: async () => grepHits.map((h) => ({ ...h, match: '' })),
    find_definition: async () => [],
    find_references: async () => [],
  };
}
test('fail-loud: unresolvable handler on a write/id route → analysisIncomplete', async () => {
  const inv = [{ method: 'POST', path: '/widgets/:id', sourceFile: 'r.js', sourceLine: 1, handlerSymbol: 'someHandler' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: failLoudTools([]) as never }); // grep finds no def
  const pack = packs.get('POST /widgets/:id')!;
  assert.equal(pack.coverage?.complete, false, 'unresolved handler on a risk surface is incomplete');
  assert.equal(pack.coverage?.handlerResolution, 'unresolved');
  assert.equal(routeAnalysisIncomplete(pack), true);
});
test('fail-loud: resolved handler stays complete (no spurious review)', async () => {
  const inv = [{ method: 'POST', path: '/widgets/:id', sourceFile: 'r.js', sourceLine: 1, handlerSymbol: 'someHandler' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: failLoudTools([{ file: 'handlers.js', line: 9 }]) as never });
  const pack = packs.get('POST /widgets/:id')!;
  assert.equal(pack.coverage?.complete, true, 'resolved handler is complete');
  assert.equal(routeAnalysisIncomplete(pack), false);
});
test('fail-loud: trivial param-less GET we cannot resolve is NOT flagged (no noise)', async () => {
  const inv = [{ method: 'GET', path: '/health', sourceFile: 'other.js', sourceLine: 1, handlerSymbol: 'someHandler' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: failLoudTools([]) as never });
  const pack = packs.get('GET /health')!;
  assert.equal(routeAnalysisIncomplete(pack), false, 'no risk surface → not flagged despite unresolved');
});

// Laravel BOLA (Firefly III GHSA-5q8v-j673-m5v4). A controller action
// `'uses'=>'UserController@show'` must resolve to the CONTROLLER METHOD body (not
// the route file), and the route-model-bound param `show(User $user)` for route
// `{user}` is an object-id surface. The unguarded show() is a BOLA candidate; the
// guarded destroy() (with `$admin->id === $user->id`) is not.
function laravelTools(showBody: string) {
  return {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'routes/api.php') return { path: 'routes/api.php', lineStart: ls ?? 1, lineEnd: ls ?? 1, content: "Route::get('{user}', ['uses' => 'UserController@show', 'as' => 'show']);", truncated: false };
      if (/UserController\.php$/.test(p)) return { path: p, lineStart: 126, lineEnd: 126 + showBody.split('\n').length - 1, content: showBody, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => {
      if (/class\\s\+UserController/.test(pat) || /class.*UserController/.test(pat)) return [{ file: 'app/Api/V1/Controllers/System/UserController.php', line: 44, match: '' }];
      if (/function.*show/.test(pat)) return [{ file: 'app/Api/V1/Controllers/System/UserController.php', line: 126, match: '' }];
      return [];
    },
    find_definition: async () => [],
    find_references: async () => [],
  };
}
test('Laravel controller action resolves to the method body + route-model-bound BOLA surface', async () => {
  const showBody = 'public function show(User $user): JsonResponse\n{\n  $resource = new Item($user, new UserTransformer());\n  return $this->respond($resource);\n}';
  const inv = [{ method: 'GET', path: '/api/v1/users/:user', sourceFile: 'routes/api.php', sourceLine: 1, handlerSymbol: 'UserController@show' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: laravelTools(showBody) as never });
  const pack = packs.get('GET /api/v1/users/:user')!;
  assert.ok(/UserController\.php$/.test(pack.handlerSnippet?.file ?? ''), 'handler is the controller method, not routes/api.php');
  const surf = pack.objectIdParams.find((s) => s.param.name === 'user');
  assert.ok(surf, 'route-model-bound {user} is an object-id surface');
  assert.equal(surf!.usedInFetchOrMutate, true);
  assert.equal(surf!.comparedToPrincipal, false, 'show() has no ownership check → BOLA candidate');
});
test('Laravel ownership check (admin->id === user->id) clears the BOLA surface', async () => {
  const destroyBody = 'public function show(User $user): JsonResponse\n{\n  $admin = auth()->user();\n  if ($admin->id === $user->id) { throw new Exception("no self"); }\n  return $this->respond($user);\n}';
  const inv = [{ method: 'GET', path: '/api/v1/users/:user', sourceFile: 'routes/api.php', sourceLine: 1, handlerSymbol: 'UserController@show' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: laravelTools(destroyBody) as never });
  const surf = packs.get('GET /api/v1/users/:user')!.objectIdParams.find((s) => s.param.name === 'user');
  assert.equal(surf!.comparedToPrincipal, true, 'ownership comparison present → not flagged');
});

// Mounted HOF-wrapped handler (saltcorn). A route mounted at `/sync` whose handler
// is `error_catcher(async (req,res) => {...})`: route.path is the MOUNTED path but the
// decl line has the LOCAL path, so before the suffix-match fix the scanner failed the
// path match and fell back to the extractor's handlerSymbol (= error_catcher, the HOF
// wrapper) — reading the wrapper body, not the real handler. Now it resolves the
// inline arrow (the decl region holds it).
test('mounted route with a HOF-wrapped inline handler resolves the real body, not the wrapper', async () => {
  const decl = "router.post('/load', error_catcher(async (req, res) => {\n  const rows = await getRows(req.body);\n  res.json(rows);\n}));";
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'routes/sync.js') return { path: 'routes/sync.js', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 3, content: decl, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async () => [],
    find_definition: async () => [], find_references: async () => [],
  };
  // route.path is the MOUNTED path (/sync/load); the decl has the local '/load'.
  const inv = [{ method: 'POST', path: '/sync/load', sourceFile: 'routes/sync.js', sourceLine: 1, handlerSymbol: 'error_catcher' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /sync/load')!;
  assert.equal(pack.handlerSnippet?.file, 'routes/sync.js', 'reads the route body, not a resolved wrapper file');
  assert.ok(/getRows\(req\.body\)/.test(pack.handlerSnippet?.snippet ?? ''), 'the real inline handler body is captured');
});

// Cross-module taint via PARAMETER propagation. `findOne(req.body)` passes the whole
// request object into a callee param (`user`), which is passed onward into a SQL sink
// (`... + user.name`). The taint must flow THROUGH the param, and the real field is
// recovered from the `user.name` property access at the sink. A bare param with no
// property access at the sink must NOT emit (false-positive guard).
test('param-propagated taint reaches a 2-hop SQL sink, field recovered from param.prop', async () => {
  const handler = 'function login(req, res) {\n  users.findOne(req.body);\n}';
  const findOne = 'function findOne(user) {\n  return store.getUsers(user);\n}';
  const getUsers = 'function getUsers(u) {\n  return db.query("SELECT * FROM users WHERE name = \'" + u.name + "\'");\n}';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'r.js') return { path: 'r.js', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 2, content: handler, truncated: false };
      if (p === 'q.js') return { path: 'q.js', lineStart: 10, lineEnd: 12, content: findOne, truncated: false };
      if (p === 's.js') return { path: 's.js', lineStart: 20, lineEnd: 22, content: getUsers, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => {
      if (/findOne/.test(pat)) return [{ file: 'q.js', line: 10, match: '' }];
      if (/getUsers/.test(pat)) return [{ file: 's.js', line: 20, match: '' }];
      return [];
    },
    find_definition: async () => [], find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/login', sourceFile: 'r.js', sourceLine: 1, handlerSymbol: 'login' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /login')!;
  assert.ok(pack.resolvedCallees?.some((c) => /getUsers/.test(c.via)), 'param chain reached getUsers');
  const cand = deriveCandidateFindings(pack).find((x) => x.sink === 'sql');
  assert.ok(cand, 'sql candidate surfaced through the param chain');
  assert.equal(cand!.param, 'name', 'field recovered from u.name at the sink (not the bare param)');
});

// Saltcorn POST /sync/load_changes SQLi (CVE shape). Exercises the multi-param taint
// engine end-to-end: destructured `{ syncInfos, loadUntil } = req.body`, a `for…of
// Object.entries(syncInfos)` loop var, a call passing TWO tainted args + `req.user`,
// and a MULTI-LINE `db.query(\`…\`)` whose raw `${syncInfo.maxLoadedId}` is the sink
// while `${db.sqlsanitize(tblName)}` (sanitized) and `${user.id}` (auth, not attacker
// input) must NOT fire. The vuln only surfaces if every leg works together.
test('multi-param taint + multi-line SQL template → sql:maxLoadedId, no sanitized/auth FP', async () => {
  const handler = [
    'function loadChanges(req, res) {',
    '  const { syncInfos, loadUntil } = req.body;',
    '  for (const [tblName, syncInfo] of Object.entries(syncInfos)) {',
    '    const table = Table.findOne({ name: tblName });',
    '    getSyncRows(syncInfo, table, loadUntil, req.user);',
    '  }',
    '}',
  ].join('\n');
  const getSyncRows = [
    'function getSyncRows(syncInfo, table, syncUntil, user) {',
    '  const { rows } = db.query(',
    '    `select * from "${db.sqlsanitize(table.name)}"',
    '     where id > ${syncInfo.maxLoadedId}',
    '     ${user.id ? `and owner = ${user.id}` : ""}`',
    '  );',
    '  return rows;',
    '}',
  ].join('\n');
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'r.js') return { path: 'r.js', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 6, content: handler, truncated: false };
      if (p === 'g.js') return { path: 'g.js', lineStart: 30, lineEnd: 37, content: getSyncRows, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => (/getSyncRows/.test(pat) ? [{ file: 'g.js', line: 30, match: '' }] : []),
    find_definition: async () => [], find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/sync/load_changes', sourceFile: 'r.js', sourceLine: 1, handlerSymbol: 'loadChanges' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /sync/load_changes')!;
  const sql = deriveCandidateFindings(pack).filter((x) => x.sink === 'sql');
  assert.ok(sql.some((c) => c.param === 'maxLoadedId'), 'raw ${syncInfo.maxLoadedId} interpolation is the SQLi sink');
  assert.ok(!sql.some((c) => c.param === 'id'), 'auth ${user.id} is not attacker input — no FP');
  assert.ok(!sql.some((c) => c.param === 'name'), 'db.sqlsanitize(table.name) is sanitized — no FP');
});

// Python (FastAPI/Flask) path-param BOLA (PraisonAI CVE-2026-47415). A signature
// path param `def get_issue(issue_id: str)` bound to `@router.get("/{issue_id}")`,
// fetched via `svc.get(issue_id)` with NO workspace/owner scoping, is an
// attacker-controlled object-id BOLA. The generic INPUTS table misses Python
// signature params; this derives them and distinguishes vulnerable (no ownership
// check) from guarded (owner_id == current_user comparison present).
function pyTools(handlerBody: string) {
  // FastAPI/Flask: the decorator + def + body are contiguous in one file, so the
  // decl-region read IS the handler (handlerSymbolFor returns inline → read at
  // sourceLine). Model that: one file, decorator then the handler.
  const content = '@router.get("/{issue_id}")\n' + handlerBody;
  return {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => ({ path: p, lineStart: ls ?? 1, lineEnd: (ls ?? 1) + content.split('\n').length - 1, content, truncated: false }),
    grep: async () => [],
    find_definition: async () => [], find_references: async () => [],
  };
}
test('Python signature path-param with unscoped fetch → BOLA surface (compared=false)', async () => {
  const body = 'async def get_issue(workspace_id: str, issue_id: str, user = Depends(require_member)):\n    svc = IssueService(session)\n    issue = await svc.get(issue_id)\n    return issue';
  const inv = [{ method: 'GET', path: '/:issue_id', sourceFile: 'routes.py', sourceLine: 1, handlerSymbol: 'get_issue' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: pyTools(body) as never });
  const s = packs.get('GET /:issue_id')!.objectIdParams.find((x) => x.param.name === 'issue_id');
  assert.ok(s, 'issue_id surfaced as a path object-id');
  assert.equal(s!.usedInFetchOrMutate, true);
  assert.equal(s!.comparedToPrincipal, false, 'svc.get(issue_id) has no ownership scoping → BOLA');
});
test('Python handler with an ownership check is not flagged (compared=true)', async () => {
  const body = 'async def get_issue(workspace_id: str, issue_id: str, current_user = Depends(get_user)):\n    issue = await svc.get(issue_id)\n    if issue.owner_id != current_user.id:\n        raise HTTPException(403)\n    return issue';
  const inv = [{ method: 'GET', path: '/:issue_id', sourceFile: 'routes.py', sourceLine: 1, handlerSymbol: 'get_issue' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: pyTools(body) as never });
  const s = packs.get('GET /:issue_id')!.objectIdParams.find((x) => x.param.name === 'issue_id');
  assert.equal(s!.comparedToPrincipal, true, 'owner_id != current_user.id → guarded, not a BOLA');
});

// FastAPI binds the request body to a Pydantic-model parameter and the fields are
// read as attributes (`form_data.url`), which the generic INPUTS table (req.body.x /
// request.json.get) never matches — so the body taint source was invisible
// (open-webui SSRF: observedInputs []). Derive each dereferenced field of the
// body-model param as a `body` input. Framework params (Request) and DI params
// (Depends/Query/...) must NOT be treated as the body model.
test('FastAPI Pydantic body-model fields surface as body inputs (not Request/Depends params)', async () => {
  const body = [
    'async def process_web(request: Request, form_data: ProcessUrlForm, user = Depends(get_verified_user)):',
    '    content = get_content_from_url(request, form_data.url)',
    '    coll = form_data.collection_name',
    '    return content',
  ].join('\n');
  const inv = [{ method: 'POST', path: '/process/web', sourceFile: 'retrieval.py', sourceLine: 1, handlerSymbol: 'process_web' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: pyTools(body) as never });
  const inputs = packs.get('POST /process/web')!.observedInputs.filter((i) => i.source === 'body').map((i) => i.name);
  assert.ok(inputs.includes('url'), 'form_data.url recognized as a body field');
  assert.ok(inputs.includes('collection_name'), 'form_data.collection_name recognized');
  assert.ok(!inputs.includes('request') && !inputs.includes('user'), 'Request / Depends params are not body fields');
});

// Django binds `Form(request.POST)` and the fields live as class attributes on the form
// (`url = forms.CharField(...)`), invisible to the INPUTS table — so the perimeter never
// saw GeoNode's `url`. Surfacing the form fields lets the policy layer emit a tight schema
// per field (the product control — a `url` field gets blockPrivateRanges regardless of any
// sink). No taint required.
test('Django Form(request.POST) fields surface as body inputs (GeoNode url)', async () => {
  const handler = 'def register_service(request):\n  form = CreateServiceForm(request.POST)\n  if form.is_valid():\n    pass';
  const formDef = 'class CreateServiceForm(forms.Form):\n  url = forms.CharField(max_length=512)\n  type = forms.ChoiceField(choices=[])\n  title = forms.CharField(required=False)';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'views.py') return { path: 'views.py', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 3, content: handler, truncated: false };
      if (p === 'forms.py') return { path: 'forms.py', lineStart: 30, lineEnd: 34, content: formDef, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => (/class\\s\+CreateServiceForm/.test(pat) || /CreateServiceForm/.test(pat) ? [{ file: 'forms.py', line: 30, match: '' }] : []),
    find_definition: async () => [], find_references: async () => [],
  };
  const packs = await buildEvidencePacks({ inventory: [{ method: 'POST', path: '/register', sourceFile: 'views.py', sourceLine: 1, handlerSymbol: 'register_service' }] as never, tools: tools as never });
  const inputs = packs.get('POST /register')!.observedInputs.filter((i) => i.source === 'body').map((i) => i.name);
  assert.ok(inputs.includes('url') && inputs.includes('type') && inputs.includes('title'), `form fields surfaced (got ${inputs.join(',')})`);
});

// A tainted value bound as a query PARAMETER (`execute("… %s", (q,))` / `text("… :id")`,
// `…, {id: x}`) is escaped by the driver — NOT SQLi. Only a value built INTO the query
// string (concat / f-string / template) is. This guards the parameterized-ORM false
// positive (path/body field on a `session.execute` bind) while keeping concat SQLi.
test('parameterized query (bind param) is NOT a sql candidate; concatenated one IS', async () => {
  const parameterized = 'def search(req, res) {\n  const q = req.query.q;\n  db.execute("SELECT * FROM items WHERE name = %s", [q]);\n}';
  const concatenated = 'def search2(req, res) {\n  const q = req.query.q;\n  db.execute("SELECT * FROM items WHERE name = \'" + q + "\'");\n}';
  const mk = (handler: string, sym: string) => ({
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => ({ path: p, lineStart: ls ?? 1, lineEnd: (ls ?? 1) + handler.split('\n').length - 1, content: handler, truncated: false }),
    grep: async () => [], find_definition: async () => [], find_references: async () => [],
  });
  const packsP = await buildEvidencePacks({ inventory: [{ method: 'GET', path: '/search', sourceFile: 'a.js', sourceLine: 1, handlerSymbol: 'search' }] as never, tools: mk(parameterized, 'search') as never });
  const sqlP = deriveCandidateFindings(packsP.get('GET /search')!).filter((x) => x.sink === 'sql');
  assert.equal(sqlP.length, 0, 'a bound %s parameter is not SQLi');

  const packsC = await buildEvidencePacks({ inventory: [{ method: 'GET', path: '/search', sourceFile: 'b.js', sourceLine: 1, handlerSymbol: 'search2' }] as never, tools: mk(concatenated, 'search2') as never });
  const sqlC = deriveCandidateFindings(packsC.get('GET /search')!).filter((x) => x.sink === 'sql');
  assert.ok(sqlC.some((x) => x.param === 'q'), 'a concatenated value IS SQLi');
});

// Two coupled gaps: (1) a MULTI-LINE call `describe_table(\n db_name, tb_name\n)` must be
// followed (per-line call scanning missed it); (2) a Python SQL var built by an f-string
// `sql = f"…{tb_name}…"` then run on a separate `query(sql=sql)` line is a sink the
// verb-line scan can't see. Archery GHSA-9jvj-8h33-6cqp shape (one-def case).
test('multi-line cross-file call + f-string-built SQL var → sql candidate', async () => {
  const handler = 'def describe(request):\n  tb_name = request.POST.get("tb_name")\n  return engine.describe_table(\n    db_name, tb_name\n  )';
  const callee = 'def describe_table(self, db_name, tb_name):\n  sql = f"show create table `{tb_name}`;"\n  return self.query(db_name=db_name, sql=sql)';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'instance.py') return { path: 'instance.py', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 4, content: handler, truncated: false };
      if (p === 'mysql.py') return { path: 'mysql.py', lineStart: 10, lineEnd: 12, content: callee, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => (/describe_table/.test(pat) ? [{ file: 'mysql.py', line: 10, match: '' }] : (/\bdescribe\b/.test(pat) ? [{ file: 'instance.py', line: 1, match: '' }] : [])),
    find_definition: async () => [], find_references: async () => [],
  };
  const packs = await buildEvidencePacks({ inventory: [{ method: 'POST', path: '/describe', sourceFile: 'instance.py', sourceLine: 1, handlerSymbol: 'describe' }] as never, tools: tools as never });
  const pack = packs.get('POST /describe')!;
  assert.ok(pack.resolvedCallees?.some((c) => /describe_table/.test(c.via)), 'multi-line call to describe_table was followed');
  const sql = deriveCandidateFindings(pack).filter((x) => x.sink === 'sql');
  assert.ok(sql.some((x) => x.param === 'tb_name'), 'f-string-built sql var with the tainted tb_name is a SQLi candidate');
});

// Polymorphic dispatch (Archery): `engine.describe_table(db, tb)` resolves to several
// per-engine defs. (1) The Python METHOD def carries an implicit `self`, so arg→param
// mapping must skip it (else tb→db_name, mislabeled). (2) Only SAME-SIGNATURE siblings
// are followed — an unrelated same-name def (different sig) must NOT be, or it
// false-positives (the firefly regression).
test('polymorphic method dispatch: self-offset binding + same-signature filter', async () => {
  const handler = 'def view(request):\n  tb_name = request.POST.get("tb_name")\n  return engine.run_q(db, tb_name)';
  const sibling = 'def run_q(self, db_name, tb_name):\n  sql = f"select * from {tb_name}"\n  return self.query(sql)';
  const unrelated = 'def run_q(opts):\n  return os.system(opts)'; // different signature — must be skipped
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'v.py') return { path: 'v.py', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 2, content: handler, truncated: false };
      if (p === 'mysql.py') return { path: 'mysql.py', lineStart: 10, lineEnd: 12, content: sibling, truncated: false };
      if (p === 'helper.py') return { path: 'helper.py', lineStart: 5, lineEnd: 6, content: unrelated, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => (/run_q/.test(pat) ? [{ file: 'mysql.py', line: 10, match: '' }, { file: 'helper.py', line: 5, match: '' }] : (/\bview\b/.test(pat) ? [{ file: 'v.py', line: 1, match: '' }] : [])),
    find_definition: async () => [], find_references: async () => [],
  };
  const packs = await buildEvidencePacks({ inventory: [{ method: 'POST', path: '/view', sourceFile: 'v.py', sourceLine: 1, handlerSymbol: 'view' }] as never, tools: tools as never });
  const cands = deriveCandidateFindings(packs.get('POST /view')!);
  assert.ok(cands.some((x) => x.sink === 'sql' && x.param === 'tb_name'), 'tb maps to tb_name (self skipped), f-string sink');
  assert.ok(!cands.some((x) => x.sink === 'os-command'), 'the different-signature run_q(opts) is not followed → no os-command FP');
});

// Express handlers are written with both `req` and `request` as the param name. The
// JS INPUTS table matched only `req.body.x`, so a `request.body.url → fetch(url)`
// SSRF went blind (SillyTavern GHSA-cccp-94vg-j92r, observedInputs []). Match both.
test('request.body.<field> (not just req.body) is captured → SSRF fetch candidate fires', async () => {
  const handler = 'function download(request, res) {\n  const url = request.body.url;\n  const r = await fetch(url);\n  return r;\n}';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => ({ path: p, lineStart: ls ?? 1, lineEnd: (ls ?? 1) + handler.split('\n').length - 1, content: handler, truncated: false }),
    grep: async () => [], find_definition: async () => [], find_references: async () => [],
  };
  const packs = await buildEvidencePacks({ inventory: [{ method: 'POST', path: '/download', sourceFile: 'a.js', sourceLine: 1, handlerSymbol: 'download' }] as never, tools: tools as never });
  const pack = packs.get('POST /download')!;
  assert.ok(pack.observedInputs.some((i) => i.name === 'url' && i.source === 'body'), 'request.body.url captured as a body input');
  assert.ok(deriveCandidateFindings(pack).some((x) => x.sink === 'ssrf' && x.param === 'url'), 'fetch(url) → ssrf candidate');
});

// #2 mass-assignment (Parse Server CVE-2024-47183). A handler that persists the
// WHOLE req.body (multi-line `rest.create(\n ..., req.body, ...)`) lets a client
// set server-controlled fields. The candidate must cite the req.body LINE (not the
// call head) and suggest reserved denyFields. A NAMED access (req.body.name) is not
// wholesale and must NOT fire.
test('#2: multi-line wholesale req.body persist → mass-assignment candidate', () => {
  const snippet = 'handleCreate(req) {\n  return rest.create(\n    req.config,\n    req.auth,\n    this.className(req),\n    req.body,\n    req.info.clientSDK,\n  );\n}';
  const pack = {
    endpointId: 'POST /classes/:className',
    handlerSnippet: { file: 'ClassesRouter.js', lineStart: 108, lineEnd: 116, snippet, truncated: false },
    observedInputs: [], observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null, bytes: 80,
  } as never;
  const c = deriveMassAssignmentCandidates(pack);
  assert.equal(c.length, 1, 'one mass-assignment candidate');
  assert.equal(c[0]!.kind, 'massAssignment');
  assert.equal(c[0]!.cite.file, 'ClassesRouter.js');
  assert.equal(c[0]!.cite.lineStart, 113, 'cites the req.body line, not the create( head at 109');
  assert.ok(c[0]!.suggestedDenyFields.includes('objectId') && c[0]!.suggestedDenyFields.includes('__proto__'), 'suggests structural reserved keys');
  assert.ok(!c[0]!.suggestedDenyFields.includes('roles'), 'does NOT blanket-deny app-specific privilege fields (over-block risk)');
});

test('#2: named body access (req.body.name) is not wholesale — no candidate', () => {
  const snippet = 'const u = await User.create({ name: req.body.name, email: req.body.email });';
  const pack = {
    endpointId: 'POST /users',
    handlerSnippet: { file: 'h.js', lineStart: 1, lineEnd: 1, snippet, truncated: false },
    observedInputs: [], observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null, bytes: 50,
  } as never;
  assert.equal(deriveMassAssignmentCandidates(pack).length, 0, 'named field access is not mass-assignment');
});

// Higher-order middleware factory (your_spotify validating-wrapped routes). The
// FIRST middleware is a factory CALL `validating(schema, 'params')`; before the
// fix, handlerSymbolFor's regex parse broke on its inner parens / the multi-line
// decl and fell back to the extractor's handlerSymbol (= `validating`), resolving
// the FACTORY body as the handler and silently missing the sink behind the auth
// middleware that follows it. The handler must resolve to the real (inline) body,
// the factory must NOT shadow the auth middleware, and the nosql sink must surface.
test('factory middleware does not shadow the handler or the auth middleware after it', async () => {
  const decl = "router.get(\n  '/:ids',\n  validating(schema, 'params'),\n  isLoggedOrGuest,\n  async (req, res) => res.send({ items: req.items }),\n);";
  const isLoggedOrGuest = 'const isLoggedOrGuest = async (req, res, next) => {\n  const token = req.query.token;\n  const u = await getUser(token);\n  if (u) req.items = u;\n  next();\n};';
  const getUser = 'export const getUser = (token) => UserModel.findOne({ publicToken: token });';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'routes.ts') return { path: 'routes.ts', lineStart: ls ?? 1, lineEnd: (ls ?? 1) + 5, content: decl, truncated: false };
      if (p === 'mw.ts') return { path: 'mw.ts', lineStart: 10, lineEnd: 15, content: isLoggedOrGuest, truncated: false };
      if (p === 'q.ts') return { path: 'q.ts', lineStart: 5, lineEnd: 5, content: getUser, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => {
      if (/isLoggedOrGuest/.test(pat)) return [{ file: 'mw.ts', line: 10, match: '' }];
      if (/getUser/.test(pat)) return [{ file: 'q.ts', line: 5, match: '' }];
      return []; // validating has no body resolved here — must not break the chain
    },
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'GET', path: '/:ids', sourceFile: 'routes.ts', sourceLine: 1, handlerSymbol: 'validating' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('GET /:ids')!;
  assert.equal(pack.handlerSnippet?.file, 'routes.ts', 'handler is the route body, not the validating factory (mw.ts:18)');
  assert.ok(!/export const validating/.test(pack.handlerSnippet?.snippet ?? ''), 'did not resolve the factory def as the handler');
  assert.ok(pack.resolvedCallees?.some((c) => /getUser/.test(c.via) && c.taintedInput === 'token'), 'auth middleware after the factory was still traversed to the sink');
  const cand = deriveCandidateFindings(pack).find((x) => x.sink === 'nosql' && x.param === 'token');
  assert.ok(cand, 'nosql candidate surfaced despite the factory-wrapped registration');
});

// Multi-hop middleware taint traversal (your_spotify CVE-2024-28192). The route
// handler has NO inputs (just res.send) — the nosql sink lives 2 hops away through
// the auth MIDDLEWARE: requireAuth reads req.query.token → getUser(token) →
// UserModel.findOne({ publicToken: token }). The candidate must surface via the
// middleware chain, citing the findOne in the deepest callee with param=token.
test('multi-hop middleware traversal surfaces a nosql candidate from the auth chain', async () => {
  const decl = "  router.get('/me', requireAuth, meHandler);";
  const meHandler = 'const meHandler = (req, res) => res.send({ user: req.user });';
  const requireAuth = 'const requireAuth = async (req, res, next) => {\n  const token = req.query.token;\n  const u = await getUser(token);\n  if (u) req.user = u;\n  next();\n};';
  const getUser = 'export const getUser = (token) => {\n  return UserModel.findOne({ publicToken: token });\n};';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'routes.ts') return { path: 'routes.ts', lineStart: ls ?? 1, lineEnd: ls ?? 1, content: decl, truncated: false };
      if (p === 'handlers.ts') return { path: 'handlers.ts', lineStart: 1, lineEnd: 1, content: meHandler, truncated: false };
      if (p === 'mw.ts') return { path: 'mw.ts', lineStart: 10, lineEnd: 16, content: requireAuth, truncated: false };
      if (p === 'queries.ts') return { path: 'queries.ts', lineStart: 5, lineEnd: 7, content: getUser, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => {
      if (/meHandler/.test(pat)) return [{ file: 'handlers.ts', line: 1, match: '' }];
      if (/requireAuth/.test(pat)) return [{ file: 'mw.ts', line: 10, match: '' }];
      if (/getUser/.test(pat)) return [{ file: 'queries.ts', line: 5, match: '' }];
      return [];
    },
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'GET', path: '/me', sourceFile: 'routes.ts', sourceLine: 1, handlerSymbol: 'requireAuth' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('GET /me')!;
  assert.ok(pack.resolvedCallees?.some((c) => /getUser/.test(c.via) && c.taintedInput === 'token'), 'getUser resolved through the middleware chain, tainted by token');
  const cand = deriveCandidateFindings(pack).find((x) => x.sink === 'nosql');
  assert.ok(cand, 'nosql candidate surfaced from the middleware-reached sink');
  assert.equal(cand!.param, 'token');
  assert.equal(cand!.taint, 'wrapped');
  assert.equal(cand!.cite.file, 'queries.ts');
});

// #3 cross-file wrapped sink — the dangerous call is in a project-local callee the
// handler invoked with a tainted input (mongo-express CVE-2019-10758: bson.toBSON(doc)
// → vm.runInNewContext(eval()) one file away). The candidate must cite the callee's
// real sink line with taint='wrapped'.
test('#3: wrapped sink in resolved callee → code-eval candidate cites the callee line', () => {
  const pack: EvidencePack = {
    endpointId: 'POST /db/:database/:collection',
    handlerSnippet: {
      file: 'lib/routes/document.js', lineStart: 40, lineEnd: 42,
      snippet: 'var doc = req.body.document;\nvar docBSON = bson.toBSON(doc);\ncollection.insert(docBSON);',
      truncated: false,
    },
    observedInputs: [{ name: 'document', source: 'body', file: 'lib/routes/document.js', line: 41, excerpt: '' }],
    observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null,
    resolvedCallees: [{
      file: 'lib/bson.js', lineStart: 54, lineEnd: 62, via: 'bson.toBSON(doc)', taintedInput: 'document',
      snippet: 'exports.toBSON = function (string) {\n  var sandbox = exports.getSandbox();\n\n\n\n\n  vm.runInNewContext(\'doc = eval((\' + string + \'));\', sandbox);\n  return sandbox.doc;\n};',
    }],
    bytes: 80,
  };
  const c = deriveCandidateFindings(pack);
  const cand = c.find((x) => x.sink === 'code-eval');
  assert.ok(cand, 'wrapped code-eval candidate surfaced from the callee');
  assert.equal(cand!.param, 'document');
  assert.equal(cand!.taint, 'wrapped');
  assert.equal(cand!.cite.file, 'lib/bson.js');
  assert.equal(cand!.cite.lineStart, 60, 'cites the real vm.runInNewContext line in the callee');
});

// #3 integration — buildEvidencePacks must follow the tainted call into the callee
// file and attach it as a resolvedCallee, so the wrapped candidate is reachable
// end-to-end (the path the model actually consumes).
test('#3: buildEvidencePacks resolves a project-local wrapper carrying a tainted arg', async () => {
  const handler = 'module.exports.addDocument = function (req, res) {\n  var doc = req.body.document;\n  var docBSON = bson.toBSON(doc);\n  res.json({ ok: true });\n};';
  const callee = 'exports.toBSON = function (string) {\n  vm.runInNewContext(\'doc = eval((\' + string + \'));\', sandbox);\n  return sandbox.doc;\n};';
  const tools = {
    list_files: async () => [],
    read_file: async (p: string, ls?: number) => {
      if (p === 'router.js') return { path: 'router.js', lineStart: ls ?? 1, lineEnd: ls ?? 1, content: "  appRouter.post('/db/:database/:collection', mw, routes.addDocument)", truncated: false };
      if (p === 'document.js') return { path: 'document.js', lineStart: 1, lineEnd: 5, content: handler, truncated: false };
      if (p === 'bson.js') return { path: 'bson.js', lineStart: 54, lineEnd: 56, content: callee, truncated: false };
      return { path: p, lineStart: 1, lineEnd: 1, content: '', truncated: false };
    },
    grep: async (pat: string) => {
      if (/addDocument/.test(pat)) return [{ file: 'document.js', line: 1, match: '' }];
      if (/toBSON/.test(pat)) return [{ file: 'bson.js', line: 54, match: '' }];
      return [];
    },
    find_definition: async () => [],
    find_references: async () => [],
  };
  const inv = [{ method: 'POST', path: '/db/:database/:collection', sourceFile: 'router.js', sourceLine: 1, handlerSymbol: 'mw' }];
  const packs = await buildEvidencePacks({ inventory: inv as never, tools: tools as never });
  const pack = packs.get('POST /db/:database/:collection')!;
  assert.ok(pack.resolvedCallees?.some((c) => c.via.includes('toBSON') && c.taintedInput === 'document'), 'bson.toBSON(doc) resolved as a tainted callee');
  const cand = deriveCandidateFindings(pack).find((x) => x.sink === 'code-eval');
  assert.ok(cand, 'end-to-end wrapped code-eval candidate');
  assert.equal(cand!.cite.file, 'bson.js');
  assert.equal(cand!.taint, 'wrapped');
});

// #1b — authed user-scoped GET read: a non-ownership cite (e.g. a nosql guard at the
// fetch line) must NOT clear the BOLA gap; an ownership cite does; a PUBLIC (unauthed)
// read keeps the soft location exit.
function getUserPack(): EvidencePack {
  const idParam = { name: 'username', source: 'path' as const, file: 'controllers.js', line: 391, excerpt: 'const u = await User.findOne({ username: req.params.username })' };
  return {
    endpointId: 'GET /api/user/:username',
    handlerSnippet: { file: 'controllers.js', lineStart: 390, lineEnd: 393, snippet: 'exports.getUser = async (req,res) => {\n  const u = await User.findOne({ username: req.params.username });\n  res.json(u);\n};', truncated: false },
    observedInputs: [idParam], observedValidators: [], observedOutputs: [],
    objectIdParams: [{ param: idParam, usedInFetchOrMutate: true, comparedToPrincipal: false }],
    bodyParsed: null, bytes: 120,
  };
}
test('#1b: authed GET user-scoped — a nosql-guard cite does NOT clear the BOLA gap', () => {
  const res = assessRouteDepth({
    policy: { request: { schema: { username: { injectionGuard: ['nosql'] } } } } as XSecurityPolicy,
    pack: getUserPack(), method: 'GET', path: '/api/user/:username',
    auth: { chain: ['verifyToken'], inlineSymbols: [] }, // AUTHED
    dismissalCites: [{ file: 'controllers.js', lineStart: 391, lineEnd: 391, quote: 'const u = await User.findOne({ username: req.params.username })' }],
  });
  assert.ok(res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'nosql cite near the fetch must NOT clear an authed user-scoped GET BOLA');
});
test('#1b: authed GET user-scoped — an ownership cite DOES clear it', () => {
  const res = assessRouteDepth({
    policy: { request: { schema: { username: { injectionGuard: ['nosql'] } } } } as XSecurityPolicy,
    pack: getUserPack(), method: 'GET', path: '/api/user/:username',
    auth: { chain: ['verifyToken'], inlineSymbols: [] },
    dismissalCites: [{ file: 'controllers.js', lineStart: 391, lineEnd: 391, quote: 'if (req.params.username !== req.user.username) return res.sendStatus(403)' }],
  });
  assert.ok(!res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'a principal-vs-id cite clears it');
});
test('#1b: PUBLIC (unauthed) GET user-scoped keeps the soft location exit', () => {
  const res = assessRouteDepth({
    policy: { request: { schema: { username: { injectionGuard: ['nosql'] } } } } as XSecurityPolicy,
    pack: getUserPack(), method: 'GET', path: '/api/user/:username',
    auth: { chain: [], inlineSymbols: [] }, // PUBLIC
    dismissalCites: [{ file: 'controllers.js', lineStart: 391, lineEnd: 391, quote: 'const u = await User.findOne({ username: req.params.username })' }],
  });
  assert.ok(!res.gaps.find((g) => g.kind === 'unguarded-object-id'), 'public read keeps the soft dismissal');
});

// #2b content-type: a contentType allowlist that CONTRADICTS the parsed body type
// (json on a urlencoded-parser route) fires the gap (over-block prevention).
test('#2b: contentType excluding the parsed body type fires body-route-no-content-type', () => {
  const pack: EvidencePack = {
    endpointId: 'POST /app/x', handlerSnippet: { file: 'h.js', lineStart: 1, lineEnd: 1, snippet: 'const x=req.body.login;', truncated: false },
    observedInputs: [{ name: 'login', source: 'body', file: 'h.js', line: 1, excerpt: '' }],
    observedValidators: [], observedOutputs: [], objectIdParams: [],
    bodyParsed: { kind: 'form', file: 'h.js', line: 1 }, bytes: 50,
  };
  const policy = { request: { contentType: ['application/json'], denyUnknownFields: true, schema: { login: { type: 'free-text', maxLength: 99 } } } } as XSecurityPolicy;
  const res = assessRouteDepth({ policy, pack, method: 'POST', path: '/app/x' });
  const g = res.gaps.find((x) => x.kind === 'body-route-no-content-type');
  assert.ok(g, 'json contentType on a form-parser route over-blocks → gap');
  assert.match(g!.detail, /x-www-form-urlencoded/);
  // correct contentType (form) → no gap
  const ok = { request: { contentType: ['application/x-www-form-urlencoded'], denyUnknownFields: true, schema: { login: { type: 'free-text', maxLength: 99 } } } } as XSecurityPolicy;
  assert.ok(!assessRouteDepth({ policy: ok, pack, method: 'POST', path: '/app/x' }).gaps.find((x) => x.kind === 'body-route-no-content-type'), 'matching form contentType clears it');
});
