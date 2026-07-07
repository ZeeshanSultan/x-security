import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFeasibility, type FeasibilityContext } from '../../src/reporters/feasibility.js';
import type { XSecurityPolicy } from '@x-security/schema';

// Build a FeasibilityContext from literal per-target matrices, bypassing
// generator loading so we can pin the rollup/normalization semantics directly.
function ctx(perTarget: Record<string, Record<string, string>>): FeasibilityContext {
  const targets = Object.keys(perTarget) as FeasibilityContext['targets'];
  const merged: Record<string, string> = {};
  for (const t of targets) {
    for (const [k, v] of Object.entries(perTarget[t]!)) {
      if (!(k in merged)) merged[k] = v;
    }
  }
  return {
    targets,
    merged: merged as FeasibilityContext['merged'],
    perTarget: perTarget as unknown as FeasibilityContext['perTarget']
  };
}

test('chain rollup is monotonic: one full target survives an unsupported peer', () => {
  // API4 contributing field = rateLimit. Target A enforces it fully; B can't.
  // A chain of [A, B] must NOT downgrade below A's own verdict.
  const policy = { rateLimit: { window: '1m', max: 10 } } as unknown as XSecurityPolicy;

  const single = evaluateFeasibility('API4:2023', policy, ctx({ kong: { rateLimit: 'full' } }));
  assert.equal(single.verdict, 'full');

  const chain = evaluateFeasibility(
    'API4:2023',
    policy,
    ctx({ kong: { rateLimit: 'full' }, coraza: { rateLimit: 'unsupported' } })
  );
  assert.equal(chain.verdict, 'full', 'chain must stay full when any target is full');
});

test('capKey normalization: type= variant credits the specific subtype', () => {
  // probe key is `authorization.rbac`; bunkerweb spells it `authorization.type=rbac`.
  const policy = { authorization: { type: 'rbac' } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API5:2023',
    policy,
    ctx({ bunkerweb: { 'authorization.type=rbac': 'full' } })
  );
  assert.equal(r.verdict, 'full');
});

test('capKey normalization: generic parent key is capped at partial (no over-claim)', () => {
  // envoy exposes a generic `authorization: full` that does NOT prove abac support.
  // Crediting it `full` for abac would over-claim, so it must cap at partial.
  const policy = { authorization: { type: 'abac' } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API5:2023',
    policy,
    ctx({ envoy: { authorization: 'full' } })
  );
  assert.equal(r.verdict, 'partial');
});

test('child rollup: all-children-full rolls up to full', () => {
  // envoy expresses response-header support only via response.headers.csp etc,
  // all `full`. API8 (misconfig) probes `response.headers`, which must roll up.
  const policy = { response: { headers: { csp: "default-src 'self'" } } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API8:2023',
    policy,
    ctx({ envoy: { 'response.headers.csp': 'full', 'response.headers.hsts': 'full' } })
  );
  assert.equal(r.verdict, 'full');
});

test('child rollup: mixed children cap at partial', () => {
  // API3 (object-property) probes `request.schema`; mixed children → partial.
  const policy = { request: { schema: { foo: { type: 'string' } } } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API3:2023',
    policy,
    ctx({ coraza: { 'request.schema.minLength': 'full', 'request.schema.type': 'partial' } })
  );
  assert.equal(r.verdict, 'partial');
});

test('all-unsupported chain yields none', () => {
  const policy = { rateLimit: { window: '1m', max: 10 } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API4:2023',
    policy,
    ctx({ coraza: { rateLimit: 'unsupported' } })
  );
  assert.equal(r.verdict, 'none');
});

// ---------------------------------------------------------------------------
// v0.7 edge-enforceable-residuals: new probes + synthetic ids.
// ---------------------------------------------------------------------------

test('SSEC-PROMPT: ai-prompt guard is feasible only on a target that enforces injectionGuard', () => {
  const policy = {
    request: { schema: { prompt: { injectionGuard: ['ai-prompt'] } } }
  } as unknown as XSecurityPolicy;

  const enforced = evaluateFeasibility(
    'SSEC-PROMPT',
    policy,
    ctx({ coraza: { 'request.schema.injectionGuard': 'full' } })
  );
  assert.equal(enforced.verdict, 'full');

  const unenforced = evaluateFeasibility(
    'SSEC-PROMPT',
    policy,
    ctx({ kong: { 'request.schema.injectionGuard': 'unsupported' } })
  );
  assert.equal(unenforced.verdict, 'none');
});

test('SSEC-AUDIT: logging probe resolves against the flat `logging` capKey', () => {
  const policy = { logging: { events: ['auth-failure'] } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'SSEC-AUDIT',
    policy,
    ctx({ coraza: { logging: 'full' } })
  );
  assert.equal(r.verdict, 'full');
});

// Regression: the new v0.7 capKeys are deliberately flat/exact. They must
// resolve via the exact-match branch of resolveStatus, NOT roll up from an
// unintended generic-parent cap (which would silently downgrade `full` →
// `partial`). We assert each new flat key returns `full` when the matrix names
// it exactly, and that a generic parent of the same dotted prefix does NOT
// credit it.
test('v0.7 flat capKeys resolve exact, never via a generic-parent cap', () => {
  // authentication.passwordPolicy: exact `full` stays full. passwordPolicy is
  // the ONLY contributing field here (no `type`), so the verdict reflects this
  // capKey alone — proving it resolved via the exact branch.
  const pw = { authentication: { passwordPolicy: { minLength: 12 } } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('API2:2023', pw, ctx({ coraza: { 'authentication.passwordPolicy': 'full' } })).verdict,
    'full'
  );
  // A generic `authentication: full` must NOT silently credit passwordPolicy as
  // full — passwordPolicy is the only contributing field here, and a generic
  // parent caps at partial.
  const pwOnly = { authentication: { passwordPolicy: { minLength: 12 } } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('API2:2023', pwOnly, ctx({ envoy: { authentication: 'full' } })).verdict,
    'partial'
  );

  // authentication.accountLockout: exact full.
  const lock = { authentication: { accountLockout: { attempts: 5, window: '5m', identifier: 'header:X-User' } } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('API2:2023', lock, ctx({ coraza: { 'authentication.accountLockout': 'full' } })).verdict,
    'full'
  );

  // response.forbidArrayRoot: exact full.
  const arr = { response: { forbidArrayRoot: true } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('API3:2023', arr, ctx({ coraza: { 'response.forbidArrayRoot': 'full' } })).verdict,
    'full'
  );

  // request.idempotencyKey: exact full.
  const idem = { request: { idempotencyKey: { header: 'Idempotency-Key', ttl: '10m' } } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('API6:2023', idem, ctx({ coraza: { 'request.idempotencyKey': 'full' } })).verdict,
    'full'
  );

  // logging: exact full.
  const log = { logging: { events: ['request'] } } as unknown as XSecurityPolicy;
  assert.equal(
    evaluateFeasibility('SSEC-AUDIT', log, ctx({ coraza: { logging: 'full' } })).verdict,
    'full'
  );
});

// ---------------------------------------------------------------------------
// v0.8 deferred-residuals: graphql per-op authz, static limits, serializeBy,
// dataAtRest. The whole credibility of the wave is that override-only and
// advisory-only fields are visibly NOT `full` — they cap at `partial` (Y*) and
// carry an operator/app-responsibility disclaimer (Rule D-1: no "looks
// enforced" illusion).
// ---------------------------------------------------------------------------

test('API1/API5: graphql.operations[].authz is override-only — never full, carries operator-handoff disclaimer', () => {
  const policy = {
    graphql: { operations: [{ name: 'me', authz: { type: 'rule-based' } }] }
  } as unknown as XSecurityPolicy;

  // Even when a target advertises `full` on the capKey, the cell stays the
  // matrix status; with a realistic override-only matrix the verdict is partial.
  const r = evaluateFeasibility(
    'API1:2023',
    policy,
    ctx({ envoy: { 'graphql.operations.authz': 'override-only' } })
  );
  assert.equal(r.verdict, 'partial', 'override-only must resolve to partial, NOT full');
  assert.ok(
    r.disclaimers.some((d) => d.includes('operator-supplied GraphQL')),
    'must surface the operator-handoff disclaimer'
  );

  // Same field also attributes to API5 (per-resolver BFLA).
  const r5 = evaluateFeasibility(
    'API5:2023',
    policy,
    ctx({ envoy: { 'graphql.operations.authz': 'override-only' } })
  );
  assert.equal(r5.verdict, 'partial');
});

test('API4: graphql.staticLimits is override-only — partial with cost-limit disclaimer', () => {
  const policy = { graphql: { maxDepth: 8, maxComplexity: 500 } } as unknown as XSecurityPolicy;
  const r = evaluateFeasibility(
    'API4:2023',
    policy,
    ctx({ coraza: { 'graphql.staticLimits': 'override-only' } })
  );
  assert.equal(r.verdict, 'partial');
  assert.ok(r.disclaimers.some((d) => d.includes('GraphQL')));
});

test('API6: request.serializeBy is partial at best — edge-only disclaimer, never full', () => {
  const policy = {
    request: { serializeBy: { key: 'jwt.sub', scope: 'per-identifier' } }
  } as unknown as XSecurityPolicy;

  // coraza partial → verdict partial; disclaimer states it is not in-handler atomic.
  const r = evaluateFeasibility(
    'API6:2023',
    policy,
    ctx({ coraza: { 'request.serializeBy': 'partial' } })
  );
  assert.equal(r.verdict, 'partial');
  assert.ok(r.disclaimers.some((d) => d.includes('in-handler')));

  // unsupported everywhere → none, disclaimer still attached.
  const none = evaluateFeasibility(
    'API6:2023',
    policy,
    ctx({ kong: { 'request.serializeBy': 'unsupported' } })
  );
  assert.equal(none.verdict, 'none');
});

test('SSEC-STORAGE: dataAtRest is advisory-only — partial at best, NOT full, with advisory disclaimer', () => {
  const policy = {
    request: { dataAtRest: { fields: ['ssn'], protection: 'encrypted' } }
  } as unknown as XSecurityPolicy;

  // Hard-pinned override-only on every target → verdict can never be full.
  const r = evaluateFeasibility(
    'SSEC-STORAGE',
    policy,
    ctx({ coraza: { 'request.dataAtRest': 'override-only' } })
  );
  assert.equal(r.verdict, 'partial', 'advisory-only must NOT resolve to full');
  assert.ok(
    r.disclaimers.some((d) => d.includes('advisory') && d.includes('NOT gateway-enforced')),
    'must surface the advisory / not-gateway-enforced disclaimer'
  );

  // unsupported everywhere → none (still a finding, never an enforcement cell).
  const none = evaluateFeasibility(
    'SSEC-STORAGE',
    policy,
    ctx({ kong: { 'request.dataAtRest': 'unsupported' } })
  );
  assert.equal(none.verdict, 'none');
});
