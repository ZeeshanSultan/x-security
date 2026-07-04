// HARD regression gate (Rule D-4 precision side): the hand-authored ideal
// corpus policies are COMPLETE and CORRECT — the enforcement ceiling. Running
// V2 (completeness) + V4 (round-trip) + V5 (cross-route) over them must NEVER
// demote a single route. A demote here is a verifier FALSE POSITIVE: it would
// drop a correct policy to reviewRequired and collapse corpus recall (the VAmPI
// 7/9 → 4/9 incident this gate is born from).
//
// The ideal emissions live in e2e/security-corpus/<app>/fixture-emissions.json.
// They reference the request fields each route's handler reads; to exercise the
// real V2/V4 handler-scoped param discovery we synthesize a faithful handler per
// route whose named-reads are EXACTLY the route's request-schema fields (the
// contract the corpus asserts) — plus framework idioms (`request.args.get`, an
// Authorization header read, a sibling handler) that the buggy verifiers
// mis-captured. If the accuracy + scoping fixes regress, those idioms leak back
// in as "uncovered params" and this gate fails.
//
// Positive controls below prove the gate still BITES: an under-enumerated
// denyUnknownFields policy (handler reads a field the schema omits) DOES demote;
// a mass-assignment field (bulk-assigned, never named-read) does NOT.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  v2Completeness,
  v4RoundTrip,
  v5CrossRouteConsistency,
  runVerifiers,
  discoverHandlerParams,
  type AgentOutput,
  type PolicyEmission,
  type RouteInventoryEntry,
  type XSecurityPolicy,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CORPUS = path.resolve(__dirname, '../../../e2e/security-corpus');
const APPS = ['vampi', 'dvapi', 'dvna', 'vulnbank', 'dvwa'] as const;

interface FixtureEmission {
  endpointId: string;
  reviewRequired: boolean;
  policy: XSecurityPolicy | null;
}

async function readEmissions(app: string): Promise<FixtureEmission[]> {
  const raw = await fs.readFile(
    path.join(CORPUS, app, 'fixture-emissions.json'),
    'utf8',
  );
  const parsed = JSON.parse(raw) as { emissions: FixtureEmission[] };
  return parsed.emissions;
}

// --- handler synthesis -----------------------------------------------------

const PATH_PARAM_RE = /[:{]([A-Za-z_][A-Za-z0-9_]*)\}?/g;

function pathParamsOf(routePath: string): string[] {
  const out: string[] = [];
  for (const m of routePath.matchAll(PATH_PARAM_RE)) if (m[1]) out.push(m[1]);
  return out;
}

function methodOf(endpointId: string): string {
  return endpointId.split(' ')[0]!.toUpperCase();
}
function pathOf(endpointId: string): string {
  return endpointId.split(' ').slice(1).join(' ');
}

function safeFnName(endpointId: string): string {
  return (
    'h_' +
    endpointId.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase()
  );
}

/**
 * Synthesize a JS/Express handler whose named-reads are EXACTLY the route's
 * request-schema body fields + path params, plus an Authorization header read
 * and a `req.query.get`-style idiom. The accuracy + scoping fixes must keep the
 * header and the method name OUT of the discovered params.
 */
function synthHandler(
  fnName: string,
  reqFields: string[],
  pathParams: string[],
): string {
  const lines: string[] = [];
  lines.push(`function ${fnName}(req, res) {`);
  // Auth plumbing — header read. Must NOT be captured as a param.
  lines.push(`  const auth = req.headers['authorization'];`);
  for (const p of pathParams) lines.push(`  const _${p} = req.params.${p};`);
  for (const f of reqFields) lines.push(`  const _b_${f} = req.body.${f};`);
  // Framework-idiom noise: a Map-like .get on a body container. `get` must be
  // filtered out (METHOD_LIKE_NAMES).
  lines.push(`  const _probe = req.body.get;`);
  lines.push(`  return res.json({ ok: true });`);
  lines.push(`}`);
  return lines.join('\n');
}

interface BuiltApp {
  output: AgentOutput;
  repoDir: string;
}

async function buildAppOutput(app: string): Promise<BuiltApp> {
  const emissions = await readEmissions(app);
  const repoDir = await fs.mkdtemp(path.join(os.tmpdir(), `ideal-${app}-`));
  const handlerLines: string[] = [];
  const inventory: RouteInventoryEntry[] = [];
  const policyEmissions: PolicyEmission[] = [];

  // A sibling handler with a UNIQUE field — proves scoping (its `__sibling__`
  // field must never leak into any real route's discovered params).
  handlerLines.push(`function __sibling__(req, res) {`);
  handlerLines.push(`  const x = req.body.__sibling_only_field__;`);
  handlerLines.push(`  return res.json({ x });`);
  handlerLines.push(`}`);

  for (const em of emissions) {
    const method = methodOf(em.endpointId);
    const routePath = pathOf(em.endpointId);
    const reqFields = Object.keys(em.policy?.request?.schema ?? {});
    const pathParams = pathParamsOf(routePath);
    // Path params are also schema fields in some routes; don't double-read.
    const bodyOnly = reqFields.filter((f) => !pathParams.includes(f));
    const fnName = safeFnName(em.endpointId);
    const sourceLine = handlerLines.length + 1; // 1-based line of the def
    handlerLines.push(synthHandler(fnName, bodyOnly, pathParams));

    inventory.push({
      method,
      path: routePath,
      sourceFile: 'handlers.js',
      sourceLine,
      handlerSymbol: fnName,
    });
    policyEmissions.push({
      endpointId: `${method} ${routePath}`,
      policy: em.policy,
      reviewRequired: false,
      assumptions: [],
    });
  }

  await fs.writeFile(path.join(repoDir, 'handlers.js'), handlerLines.join('\n'));

  const output: AgentOutput = {
    routeInventory: inventory,
    profiles: {},
    emissions: policyEmissions,
    coverage: { filesRead: [], grepQueriesIssued: [] },
  };
  return { output, repoDir };
}

// --------------------------------------------------------------------------
// THE GATE: every ideal-fixture route passes V2 + V4 + V5 (no demote).
// --------------------------------------------------------------------------

for (const app of APPS) {
  test(`ideal-fixtures-no-demote: ${app} — every ideal route passes V2+V4+V5`, async () => {
    const { output, repoDir } = await buildAppOutput(app);
    try {
      const run = await runVerifiers(
        { output, repoDir },
        [v2Completeness, v4RoundTrip, v5CrossRouteConsistency],
      );
      const demoted: string[] = [];
      for (const [endpointId, composed] of run.composedByEndpoint) {
        if (composed.verdict !== 'pass') {
          demoted.push(`${endpointId}: ${composed.verdict} :: ${composed.reasons.join(' | ')}`);
        }
      }
      assert.equal(
        demoted.length,
        0,
        `${app}: ideal policies must never demote, but these did:\n  ${demoted.join('\n  ')}`,
      );
    } finally {
      await fs.rm(repoDir, { recursive: true, force: true });
    }
  });
}

// --------------------------------------------------------------------------
// Scoping proof: no sibling field leaks into a real route's discovery.
// --------------------------------------------------------------------------

test('handler-scoping: a sibling handler field never leaks into another route', async () => {
  const { output, repoDir } = await buildAppOutput('vampi');
  try {
    for (const inv of output.routeInventory) {
      const d = await discoverHandlerParams(repoDir, inv.sourceFile, {
        handlerSymbol: inv.handlerSymbol,
        sourceLine: inv.sourceLine,
      });
      assert.ok(d.scoped, `${inv.path}: handler span should resolve`);
      assert.ok(
        !d.params.has('__sibling_only_field__'),
        `${inv.path}: sibling-only field leaked into discovery`,
      );
      assert.ok(!d.params.has('get'), `${inv.path}: method name 'get' captured`);
      assert.ok(
        !d.params.has('authorization') && !d.params.has('Authorization'),
        `${inv.path}: Authorization header captured as a param`,
      );
    }
  } finally {
    await fs.rm(repoDir, { recursive: true, force: true });
  }
});

// --------------------------------------------------------------------------
// The gate still BITES: under-enumeration demotes, completeness passes.
// --------------------------------------------------------------------------

const TMP_PREFIX = 'verifier-bite-';

async function singleRouteRun(
  handlerSrc: string,
  handlerSymbol: string,
  sourceLine: number,
  policy: XSecurityPolicy,
  method = 'POST',
  routePath = '/login',
): Promise<{ verdict: string; reasons: string[] }> {
  const repoDir = await fs.mkdtemp(path.join(os.tmpdir(), TMP_PREFIX));
  try {
    await fs.writeFile(path.join(repoDir, 'h.js'), handlerSrc);
    const output: AgentOutput = {
      routeInventory: [
        { method, path: routePath, sourceFile: 'h.js', sourceLine, handlerSymbol },
      ],
      profiles: {},
      emissions: [
        { endpointId: `${method} ${routePath}`, policy, reviewRequired: false, assumptions: [] },
      ],
      coverage: { filesRead: [], grepQueriesIssued: [] },
    };
    const run = await runVerifiers({ output, repoDir }, [v2Completeness, v4RoundTrip, v5CrossRouteConsistency]);
    const composed = run.composedByEndpoint.get(`${method} ${routePath}`)!;
    return { verdict: composed.verdict, reasons: composed.reasons };
  } finally {
    await fs.rm(repoDir, { recursive: true, force: true });
  }
}

const HANDLER_USERNAME_PASSWORD = [
  'function login(req, res) {',
  '  const u = req.body.username;',
  '  const p = req.body.password;',
  '  return res.json({ ok: true });',
  '}',
].join('\n');

test('under-enum-demotes: denyUnknownFields + schema omits a field the handler reads → V4 demote', async () => {
  // Handler reads {username, password}; policy schema only has username under
  // denyUnknownFields → the handler-derived positive carries password → blocked.
  const policy: XSecurityPolicy = {
    authentication: { type: 'none' },
    request: {
      denyUnknownFields: true,
      schema: { username: { type: 'string', maxLength: 64 } },
    },
  } as XSecurityPolicy;
  const { verdict, reasons } = await singleRouteRun(
    HANDLER_USERNAME_PASSWORD,
    'login',
    1,
    policy,
  );
  assert.equal(verdict, 'demote-to-review', `expected demote, got ${verdict}: ${reasons.join(' | ')}`);
  assert.ok(
    reasons.some((r) => r.includes('positive sample rejected')),
    `expected a V4 positive-sample rejection, got: ${reasons.join(' | ')}`,
  );
});

test('complete-passes: denyUnknownFields + schema covers every handler-read field → pass', async () => {
  const policy: XSecurityPolicy = {
    authentication: { type: 'none' },
    request: {
      denyUnknownFields: true,
      schema: {
        username: { type: 'string', maxLength: 64 },
        password: { type: 'string', maxLength: 128 },
      },
    },
  } as XSecurityPolicy;
  const { verdict, reasons } = await singleRouteRun(
    HANDLER_USERNAME_PASSWORD,
    'login',
    1,
    policy,
  );
  assert.equal(verdict, 'pass', `expected pass, got ${verdict}: ${reasons.join(' | ')}`);
});

test('mass-assign-no-false-demote: a bulk-assigned (never named-read) field does NOT demote', async () => {
  // Mass-assignment shape: the handler bulk-spreads req.body and never NAMES the
  // privileged field. Handler-scoped discovery finds NO field name, so the
  // positive carries no spurious field, so denyUnknownFields doesn't false-block.
  const handler = [
    'function createUser(req, res) {',
    '  const u = req.body.username;',
    '  const account = Object.assign(new User(), req.body);', // bulk assign, no named privileged field
    '  return res.json({ ok: true });',
    '}',
  ].join('\n');
  const policy: XSecurityPolicy = {
    authentication: { type: 'none' },
    request: {
      denyUnknownFields: true,
      schema: { username: { type: 'string', maxLength: 64 } },
    },
  } as XSecurityPolicy;
  const { verdict, reasons } = await singleRouteRun(handler, 'createUser', 1, policy);
  assert.equal(verdict, 'pass', `mass-assignment must not false-demote; got ${verdict}: ${reasons.join(' | ')}`);
});
