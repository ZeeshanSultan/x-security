/**
 * Coraza engine-profile matrix tests.
 *
 * Validates that each engine profile (`modsec-nginx`, `modsec-apache`,
 * `coraza-go`, `coraza-spoa`) produces directive syntax the corresponding
 * runtime can parse without manual sanitization.
 *
 * The hard acceptance criteria for `modsec-nginx` come from REPORT-v3 §3:
 *   1. No `coraza.yml` — must emit `writ.conf` (plain directives).
 *   2. No `SecDefaultAction` — crs-setup.conf already calls it once per phase.
 *   3. No `initcol:user=` / `initcol:apikey=` — libmodsecurity3 v3.0.15 only
 *      accepts `ip`, `global`, `resource` as collection names.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { EndpointIR, SpecIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

import { createCorazaGenerator } from '../../src/generators/coraza/index.js';
import {
  CORAZA_GO_PROFILE,
  MODSEC_NGINX_PROFILE,
  MODSEC_APACHE_PROFILE,
  CORAZA_SPOA_PROFILE,
  getEngineProfile,
} from '../../src/generators/coraza/profiles.js';
import { buildPolicyRules } from '../../src/generators/coraza/rules.js';

function ep(method: EndpointIR['method'], path: string, policy: XSecurityPolicy): EndpointIR {
  return {
    method,
    path,
    operationId: `${method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_')}`,
    policy,
    parameters: [],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    raw: {} as any,
    resolvedVars: new Map(),
  };
}

/** Minimal SpecIR fixture exercising the three REPORT-v3 §3 incompatibilities. */
function fixtureSpec(): SpecIR {
  return {
    info: { title: 'engine-matrix-fixture', version: '1.0.0' },
    endpoints: [
      ep('POST', '/login', {
        authentication: { type: 'none' },
        rateLimit: { requests: 5, window: '1m', identifier: 'ip' },
        request: { contentType: ['application/json'], maxBodySize: '10KB' },
      }),
      // user-id identifier — the one libmodsecurity3 rejects.
      ep('POST', '/api/users/{id}', {
        authentication: { type: 'bearer-jwt' },
        rateLimit: { requests: 30, window: '1m', identifier: 'user-id' },
        request: {
          contentType: ['application/json'],
          allowedFields: ['username', 'password', 'email'],
        },
      }),
      // api-key identifier and header:X identifier.
      ep('GET', '/api/data', {
        authentication: { type: 'api-key', headerName: 'X-API-Key' },
        rateLimit: { requests: 100, window: '1h', identifier: 'api-key' },
      }),
      ep('GET', '/api/tenant', {
        authentication: { type: 'bearer-jwt' },
        rateLimit: { requests: 50, window: '5m', identifier: 'header:X-Tenant-Id' },
      }),
    ],
    raw: {} as unknown as SpecIR['raw'],
  } as SpecIR;
}

describe('coraza-engines: profile constants', () => {
  it('modsec-nginx legal collections = {ip, global, resource}', () => {
    assert.deepEqual(
      [...MODSEC_NGINX_PROFILE.legalCollections].sort(),
      ['global', 'ip', 'resource']
    );
    assert.equal(MODSEC_NGINX_PROFILE.emitEngineGlobals, false);
    assert.equal(MODSEC_NGINX_PROFILE.fileExt, 'conf');
    assert.equal(MODSEC_NGINX_PROFILE.supportsArbitraryCollection, false);
    assert.equal(MODSEC_NGINX_PROFILE.jsonBodyProcessorCtl, true);
  });

  it('coraza-go legal collections = {tx} only (runtime setvar TX-only)', () => {
    // W10-7 honest finding: ghcr.io/corazawaf/coraza-spoa rejects setvar:ip.X
    // with "expected collection TX" at WAF init. supportsPersistentCollections
    // is false — cross-request rate-limits require HAProxy stick-tables.
    assert.deepEqual([...CORAZA_GO_PROFILE.legalCollections], ['tx']);
    assert.equal(CORAZA_GO_PROFILE.legalCollections.has('user'), false);
    assert.equal(CORAZA_GO_PROFILE.emitEngineGlobals, true);
    assert.equal(CORAZA_GO_PROFILE.fileExt, 'yml');
    assert.equal(CORAZA_GO_PROFILE.supportsArbitraryCollection, false);
    assert.equal(CORAZA_GO_PROFILE.supportsPersistentCollections, false);
    assert.equal(CORAZA_GO_PROFILE.supportsDetectSQLi, true);
  });

  it('getEngineProfile() rejects unknown names', () => {
    assert.throws(() => getEngineProfile('modsec-haproxy'), /Unknown --coraza-engine/);
  });
});

describe('coraza-engines: modsec-nginx output is libmodsecurity3-safe', () => {
  it('emits writ.conf (not coraza.yml) with no YAML wrapper', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string; format: string }>;
    const conf = arts.find((a) => a.path === 'writ.conf');
    assert.ok(conf, 'must emit writ.conf');
    assert.equal(conf!.format, 'conf');
    assert.doesNotMatch(conf!.content, /^directives: \|/m, 'no YAML wrapper');
    assert.doesNotMatch(conf!.content, /^generator: writ-coraza/m, 'no YAML metadata header');
    // The companion include snippet must exist with a stable mount path.
    const inc = arts.find((a) => a.path === 'writ-include.conf');
    assert.ok(inc, 'must emit writ-include.conf');
    assert.match(inc!.content, /Include \/etc\/modsecurity\.d\/writ\.conf/);
  });

  it('emits NO SecDefaultAction (crs-setup.conf already sets them)', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const conf = arts.find((a) => a.path === 'writ.conf')!;
    assert.doesNotMatch(
      conf.content,
      /^SecDefaultAction/m,
      'libmodsecurity3 aborts with "SecDefaultActions can only be placed once per phase"'
    );
    assert.doesNotMatch(conf.content, /^SecRuleEngine On$/m, 'host already sets engine globals');
    assert.doesNotMatch(conf.content, /^SecRequestBodyAccess On$/m);
  });

  it('emits NO initcol:user= or initcol:apikey= (only ip/global/resource)', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const conf = arts.find((a) => a.path === 'writ.conf')!;

    assert.doesNotMatch(conf.content, /initcol:user=/, 'libmodsecurity3 rejects user collection');
    assert.doesNotMatch(conf.content, /initcol:apikey=/, 'apikey is not a legal collection');
    assert.doesNotMatch(conf.content, /initcol:session=/, 'session is not legal in libmodsecurity3');

    // Every initcol must use a legal collection.
    const initcols = Array.from(conf.content.matchAll(/initcol:([a-z]+)=/g)).map((m) => m[1]);
    for (const col of initcols) {
      assert.ok(
        MODSEC_NGINX_PROFILE.legalCollections.has(col!),
        `initcol:${col}= is not in modsec-nginx legalCollections {ip, global, resource}`
      );
    }
    // user-id, api-key, header:X all downgraded to global.
    assert.match(conf.content, /initcol:global=/);
    assert.match(conf.content, /initcol:ip=%\{REMOTE_ADDR\}/);
  });

  it('emits ctl:requestBodyProcessor=JSON for endpoints with application/json content-type', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const conf = arts.find((a) => a.path === 'writ.conf')!;
    // wave-8: ctl emission decoupled from allowlist — fires for any JSON endpoint.
    assert.match(conf.content, /ctl:requestBodyProcessor=JSON/);
    assert.match(conf.content, /Content-Type "@rx \^application\/\(json\|vnd/);
    // Allowlist rule still present (the ctl rule is now a sibling, not a child).
    assert.match(conf.content, /SecRule ARGS_NAMES "!@rx \^json\\\.\(username\|password\|email\)\$"/);
  });

  it('emits WARNINGS.md with downgrade entries for user-id/api-key/header', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const warn = arts.find((a) => a.path === 'WARNINGS.md');
    assert.ok(warn, 'must emit WARNINGS.md when downgrades occurred');
    assert.match(warn!.content, /Downgrades/);
    assert.match(warn!.content, /rateLimit\.identifier=user-id/);
    assert.match(warn!.content, /rateLimit\.identifier=api-key/);
    assert.match(warn!.content, /rateLimit\.identifier=header:X-Tenant-Id/);
    assert.match(warn!.content, /'user' not supported on modsec-nginx/);
    // Generator-level warnings stream surfaces them too.
    assert.ok(gen.lastWarnings.length >= 3);
    assert.match(gen.lastWarnings.join('\n'), /coraza:modsec-nginx:downgrade/);
  });
});

describe('coraza-engines: modsec-apache mirrors modsec-nginx', () => {
  it('emits writ.conf with Apache-style include snippet, no SecDefaultAction', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-apache' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const conf = arts.find((a) => a.path === 'writ.conf');
    const inc = arts.find((a) => a.path === 'writ-include.conf');
    assert.ok(conf);
    assert.ok(inc);
    assert.doesNotMatch(conf!.content, /^SecDefaultAction/m);
    assert.doesNotMatch(conf!.content, /initcol:user=/);
    assert.match(inc!.content, /Include \/etc\/modsecurity\/writ\.conf/);
  });
});

describe('coraza-engines: coraza-go emits YAML wrapper + TX-only collections', () => {
  it('emits coraza.yml (YAML wrapper) with engine globals + TX collection for rate-limits', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-go' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string; format: string }>;
    const yml = arts.find((a) => a.path === 'coraza.yml');
    assert.ok(yml, 'must emit coraza.yml');
    assert.equal(yml!.format, 'yaml');
    assert.match(yml!.content, /^directives: \|/m, 'YAML wrapper with directives: |');
    assert.match(yml!.content, /SecRuleEngine On/);
    assert.match(yml!.content, /SecDefaultAction "phase:1/);
    // W10-7 honest finding: Coraza-Go runtime enforces setvar TX-only; ALL
    // identifier modes (ip / user-id / api-key / header:X) downgrade to TX.
    assert.match(yml!.content, /initcol:tx=%\{REMOTE_ADDR\}/);
    assert.match(yml!.content, /initcol:tx=%\{REQUEST_HEADERS\.Authorization\}/);
    assert.match(yml!.content, /initcol:tx=%\{REQUEST_HEADERS\.X-API-Key\}/);
    assert.match(yml!.content, /initcol:tx=%\{REQUEST_HEADERS\.X-Tenant-Id\}/);
    assert.doesNotMatch(yml!.content, /initcol:user=/);
    assert.doesNotMatch(yml!.content, /initcol:ip=/);
    const warn = arts.find((a) => a.path === 'WARNINGS.md');
    assert.ok(warn, 'must emit WARNINGS.md describing the TX downgrade');
    assert.match(warn!.content, /only honors setvar on the TX collection/);
    assert.match(warn!.content, /HAProxy stick-tables/);
    assert.ok(gen.lastWarnings.length >= 4);
  });

  it('coraza-go emits ctl:requestBodyProcessor=JSON for JSON endpoints (wave-8 body-inspection fix)', () => {
    // wave-8: SPOE / Coraza-Go don't auto-parse JSON bodies the way modsec-nginx's
    // bundled setup.conf does. We now emit the ctl directive on every engine so
    // ARGS_NAMES is populated for application/json requests and phase-2
    // schema / mass-assignment rules can actually see the body keys.
    const gen = createCorazaGenerator({ engine: 'coraza-go' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const yml = arts.find((a) => a.path === 'coraza.yml')!;
    assert.match(yml.content, /ctl:requestBodyProcessor=JSON/);
    assert.match(yml.content, /enable JSON body processor/);
    // The match regex covers the vnd.*+json variant family too.
    assert.match(yml.content, /Content-Type "@rx \^application\/\(json\|vnd\\\.\[\\w\.\+-\]\+\\\+json\)\\b"/);
  });
});

describe('coraza-engines: coraza-spoa parity with coraza-go', () => {
  it('emits a YAML artifact with the same directive surface', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const yml = arts.find((a) => a.path === 'coraza.yml');
    assert.ok(yml);
    assert.match(yml!.content, /engine: coraza-spoa/);
    // wave-5: coraza-spoa shares coraza-go's TX-only legalCollections (same library).
    assert.match(yml!.content, /initcol:tx=/);
    assert.doesNotMatch(yml!.content, /initcol:user=/);
    assert.equal(CORAZA_SPOA_PROFILE.fileExt, 'yml');
    // wave-8: SPOA also gets the JSON body-processor ctl — same emission path.
    assert.match(yml!.content, /ctl:requestBodyProcessor=JSON/);
  });
});

describe('coraza-engines: wave-8 body-inspection — ctl:requestBodyProcessor=JSON matrix', () => {
  // The body-processor ctl directive must appear on every engine profile so
  // mass-assignment / phase-2 schema rules fire identically across them. On
  // libmodsecurity3 (modsec-nginx / modsec-apache) the bundled setup.conf
  // already emits id:200001 with the same ctl; the redundant per-endpoint
  // emission is harmless (setting the same processor twice is idempotent).
  for (const engine of ['modsec-nginx', 'modsec-apache', 'coraza-go', 'coraza-spoa'] as const) {
    it(`${engine}: emits ctl:requestBodyProcessor=JSON for application/json endpoints`, () => {
      const gen = createCorazaGenerator({ engine });
      const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
      const out = arts.find((a) => a.path.endsWith('.conf') || a.path.endsWith('.yml'))!;
      assert.match(out.content, /ctl:requestBodyProcessor=JSON/);
      assert.match(out.content, /enable JSON body processor/);
    });
  }
});

describe('coraza-engines: configure() switches profile in place', () => {
  it('default singleton is coraza-go; configure({engine}) flips to modsec-nginx', () => {
    const gen = createCorazaGenerator();
    assert.equal(gen.engine, 'coraza-go');
    let arts = gen.generate(fixtureSpec()) as Array<{ path: string }>;
    assert.ok(arts.find((a) => a.path === 'coraza.yml'));
    gen.configure({ engine: 'modsec-nginx' });
    assert.equal(gen.engine, 'modsec-nginx');
    arts = gen.generate(fixtureSpec()) as Array<{ path: string }>;
    assert.ok(arts.find((a) => a.path === 'writ.conf'));
    assert.ok(!arts.find((a) => a.path === 'coraza.yml'));
  });
});

describe('coraza-engines: buildPolicyRules profile threading', () => {
  it('user-id identifier under modsec-nginx → global collection + warning', () => {
    const warnings: Array<{ severity: string; reason: string }> = [];
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'user-id' } }),
      MODSEC_NGINX_PROFILE,
      warnings as never
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:global=%\{REQUEST_HEADERS\.Authorization\}/);
    assert.doesNotMatch(j, /initcol:user=/);
    assert.match(j, /SecRule GLOBAL:rl_post__x "@gt 5"/);
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0]!.severity, 'downgrade');
  });

  it('user-id identifier under coraza-go → tx collection + downgrade warning', () => {
    // wave-5: Coraza v3 setvar only accepts TX. user-id now downgrades to tx
    // (per-transaction; cross-request enforcement lost) and emits a loud warning.
    const warnings: Array<{ severity: string; reason: string }> = [];
    const rules = buildPolicyRules(
      ep('POST', '/x', { rateLimit: { requests: 5, window: '1m', identifier: 'user-id' } }),
      CORAZA_GO_PROFILE,
      warnings as never
    );
    const j = rules.join('\n');
    assert.match(j, /initcol:tx=%\{REQUEST_HEADERS\.Authorization\}/);
    assert.doesNotMatch(j, /initcol:user=/);
    assert.match(j, /SecRule TX:rl_post__x "@gt 5"/);
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0]!.severity, 'downgrade');
    assert.match(warnings[0]!.reason, /TX collection/);
  });
});

// ---------- C-1: response-body inspection across the engine matrix ----------
describe('coraza-engines C-1: response.* support across all profiles', () => {
  const profiles = [
    { name: 'modsec-nginx', profile: MODSEC_NGINX_PROFILE },
    { name: 'modsec-apache', profile: MODSEC_APACHE_PROFILE },
    { name: 'coraza-go', profile: CORAZA_GO_PROFILE },
    { name: 'coraza-spoa', profile: CORAZA_SPOA_PROFILE },
  ];
  for (const { name, profile } of profiles) {
    it(`${name}: declares supportsResponseBodyAccess=true`, () => {
      assert.equal(profile.supportsResponseBodyAccess, true);
    });

    it(`${name}: response.schema.<maxLength> emits a phase-4 SecRule + perf-cost warning`, () => {
      const warnings: any[] = [];
      const rules = buildPolicyRules(
        ep('GET', '/api3/comment', {
          response: { schema: { secret: { maxLength: 64 } } },
        }),
        profile,
        warnings as never
      );
      const joined = rules.join('\n');
      assert.match(joined, /phase:4/);
      assert.match(joined, /writ-api3-bopla/);
      assert.match(joined, /Writ: response\.secret exceeds maxLength=64/);
      // perf-cost warning is loud, with engine identity attached.
      const downgrade = warnings.find(
        (w: any) => w.severity === 'downgrade' && /response inspection/.test(w.reason)
      );
      assert.ok(downgrade, `expected perf-cost downgrade warning for engine ${name}`);
      assert.equal(downgrade.engine, name);
    });
  }

  it('engine globals: SecResponseBodyAccess only flips on when at least one endpoint asks for it', () => {
    const baseEp = ep('GET', '/no-response', { authentication: { type: 'bearer-jwt' } });
    const respEp = ep('GET', '/api3/comment', { response: { schema: { secret: { maxLength: 16 } } } });
    const noResp: SpecIR = { info: { title: 't', version: '1' }, endpoints: [baseEp], servers: [] };
    const withResp: SpecIR = { info: { title: 't', version: '1' }, endpoints: [respEp], servers: [] };

    const genGo = createCorazaGenerator({ engine: 'coraza-go' });
    const noText = genGo.generate(noResp).find((a) => a.path === 'coraza.yml')!.content;
    const yesText = genGo.generate(withResp).find((a) => a.path === 'coraza.yml')!.content;
    assert.match(noText, /SecResponseBodyAccess Off/);
    assert.match(yesText, /SecResponseBodyAccess On/);
  });

  it('libmodsecurity3 engines override the host default with SecResponseBodyAccess On when needed', () => {
    // modsec-nginx / modsec-apache skip the engine-globals block normally
    // because the host's crs-setup.conf owns SecDefaultAction. But
    // SecResponseBodyAccess is repeatable and we MUST set it ourselves —
    // otherwise the host's likely-default Off means RESPONSE_BODY never
    // populates and the phase-4 SecRules below would be dead code.
    const respEp = ep('GET', '/api3/comment', { response: { schema: { secret: { maxLength: 16 } } } });
    const spec: SpecIR = { info: { title: 't', version: '1' }, endpoints: [respEp], servers: [] };
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const text = gen.generate(spec).find((a) => a.path === 'writ.conf')!.content;
    assert.match(text, /C-1: response-body inspection required by spec/);
    assert.match(text, /SecResponseBodyAccess On/);
  });
});

// ─────────────────────────────────────────────────────────────────────
// W11: HAProxy stick-tables emission (closes W10-7 architectural deferral)
// ─────────────────────────────────────────────────────────────────────
describe('coraza-engines: W11 HAProxy stick-tables for coraza-spoa', () => {
  it('emits haproxy-stick-tables.cfg only when an endpoint declares rateLimit', () => {
    const noRl: SpecIR = {
      info: { title: 'no-rl', version: '1' },
      endpoints: [ep('GET', '/x', { authentication: { type: 'none' } })],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      raw: {} as any,
    } as SpecIR;
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(noRl) as Array<{ path: string }>;
    assert.ok(!arts.find((a) => a.path === 'haproxy-stick-tables.cfg'));
  });

  it('emits a stick-table backend + frontend snippet per rate-limited endpoint', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const cfg = arts.find((a) => a.path === 'haproxy-stick-tables.cfg');
    assert.ok(cfg, 'haproxy-stick-tables.cfg must be emitted');
    // Backend block with stick-table for the IP-keyed /login endpoint.
    assert.match(cfg!.content, /backend st_writ_post_login/);
    assert.match(cfg!.content, /stick-table type ip size 100k expire 1m store http_req_rate\(1m\)/);
    // Frontend snippet — ACL/track/deny lines for /login (5/min).
    assert.match(cfg!.content, /=== WRIT FRONTEND SNIPPET ===/);
    assert.match(cfg!.content, /http-request track-sc0 src table st_writ_post_login/);
    assert.match(cfg!.content, /http-request deny deny_status 429 .* sc0_http_req_rate\(st_writ_post_login\) gt 5/);
  });

  it('user-id identifier → string-keyed table on Authorization header', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const cfg = arts.find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.match(cfg.content, /stick-table type string len 128 .* store http_req_rate\(1m\)/);
    assert.match(cfg.content, /http-request track-sc0 req\.hdr\(Authorization\) table st_writ_post_api_users_id/);
  });

  it('api-key identifier → req.hdr(X-API-Key)', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const cfg = arts.find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.match(cfg.content, /http-request track-sc0 req\.hdr\(X-API-Key\) table st_writ_get_api_data/);
  });

  it('header:X identifier → req.hdr(X)', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>;
    const cfg = arts.find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.match(cfg.content, /http-request track-sc0 req\.hdr\(X-Tenant-Id\) table st_writ_get_api_tenant/);
  });

  it('burst → separate sc1-tracked stick-table with 10s window (W24-C1)', () => {
    const burstEp = ep('POST', '/burst', {
      rateLimit: { requests: 60, window: '1m', identifier: 'ip', burst: 5 },
    });
    const spec: SpecIR = { info: { title: 't', version: '1' }, endpoints: [burstEp], servers: [] } as SpecIR;
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const cfg = (gen.generate(spec) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    // Main long-window table is untouched (no `,http_req_rate(1s)` glommed on).
    assert.match(cfg.content, /backend st_writ_post_burst\n\s+stick-table type ip size 100k expire 1m store http_req_rate\(1m\)\s*$/m);
    // Separate burst backend, 10s window.
    assert.match(cfg.content, /backend st_writ_post_burst_burst\n\s+stick-table type ip size 100k expire 10s store http_req_rate\(10s\)/);
    // Long-window deny on sc0.
    assert.match(cfg.content, /sc0_http_req_rate\(st_writ_post_burst\) gt 60/);
    // Burst deny on sc1 against the burst backend.
    assert.match(cfg.content, /track-sc1 src table st_writ_post_burst_burst/);
    assert.match(cfg.content, /sc1_http_req_rate\(st_writ_post_burst_burst\) gt 5/);
  });

  it('composite identifier {components} → honors first component + LOUD downgrade warning (Rule D-1)', () => {
    const compEp = ep('POST', '/comp', {
      rateLimit: {
        requests: 5,
        window: '1m',
        identifier: { components: ['ip', 'header:X-User-Id', 'api-key'] },
      },
    });
    const spec: SpecIR = { info: { title: 't', version: '1' }, endpoints: [compEp], servers: [] } as SpecIR;
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = gen.generate(spec) as Array<{ path: string; content: string }>;
    const cfg = arts.find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    // First component (ip) honored.
    assert.match(cfg.content, /http-request track-sc0 src table st_writ_post_comp/);
    // Loud warning surfaced in lastWarnings — never silent.
    const w = gen.lastWarnings.join('\n');
    assert.match(w, /composite.*Honored "ip".*dropped: "header:X-User-Id", "api-key"/);
  });

  it('coraza-go (library mode) also emits haproxy-stick-tables.cfg when rateLimit declared', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-go' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string }>;
    assert.ok(arts.find((a) => a.path === 'haproxy-stick-tables.cfg'));
  });

  it('modsec-nginx does NOT emit haproxy-stick-tables.cfg (uses native ip-collection)', () => {
    const gen = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = gen.generate(fixtureSpec()) as Array<{ path: string }>;
    assert.ok(!arts.find((a) => a.path === 'haproxy-stick-tables.cfg'));
  });
});

// ─────────────────────────────────────────────────────────────────────
// W13-D: HAProxy peer-replication for multi-instance stick-tables
// ─────────────────────────────────────────────────────────────────────
describe('coraza-engines: W13-D HAProxy peer replication', () => {
  it('no --coraza-peers → no peers block emitted (regression: W11 byte-identical)', () => {
    const gen = createCorazaGenerator({ engine: 'coraza-spoa' });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.doesNotMatch(cfg.content, /^peers /m);
    assert.doesNotMatch(cfg.content, /peers writ$/m);
    // Sanity: stick-table line ends at `store http_req_rate(...)` without trailing ` peers ...`.
    assert.match(cfg.content, /stick-table type ip size 100k expire 1m store http_req_rate\(1m\)\n/);
  });

  it('--coraza-peers two nodes → emits peers section + each stick-table opts in', () => {
    const gen = createCorazaGenerator({
      engine: 'coraza-spoa',
      peers: 'node1:10.0.0.1:10000,node2:10.0.0.2:10000',
    });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.match(cfg.content, /^peers writ$/m);
    assert.match(cfg.content, /^    peer node1 10\.0\.0\.1:10000$/m);
    assert.match(cfg.content, /^    peer node2 10\.0\.0\.2:10000$/m);
    // Every stick-table line must end with `peers writ`.
    const stickTableLines = cfg.content
      .split('\n')
      .filter((l) => l.trimStart().startsWith('stick-table '));
    assert.ok(stickTableLines.length > 0, 'expected at least one stick-table line');
    for (const line of stickTableLines) {
      assert.match(line, / peers writ$/, `missing peer opt-in on: ${line}`);
    }
    // No downgrade warning since the input was well-formed.
    const w = gen.lastWarnings.join('\n');
    assert.doesNotMatch(w, /--coraza-peers/);
  });

  it('malformed --coraza-peers → loud warning + omit peers (Rule D-1, no silent half-config)', () => {
    const gen = createCorazaGenerator({
      engine: 'coraza-spoa',
      peers: 'node1:10.0.0.1,node2:10.0.0.2:10000', // first entry missing port
    });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.doesNotMatch(cfg.content, /^peers /m);
    assert.doesNotMatch(cfg.content, / peers writ$/m);
    const w = gen.lastWarnings.join('\n');
    assert.match(w, /--coraza-peers entry "node1:10\.0\.0\.1" is malformed/);
    assert.match(w, /peer replication disabled/);
  });

  it('--coraza-peers with only one peer → warning + omit (need >=2 to replicate)', () => {
    const gen = createCorazaGenerator({
      engine: 'coraza-spoa',
      peers: 'lonely:10.0.0.1:10000',
    });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.doesNotMatch(cfg.content, /^peers /m);
    const w = gen.lastWarnings.join('\n');
    assert.match(w, /needs at least 2 peers/);
  });

  it('--coraza-peers with invalid port → warning + omit', () => {
    const gen = createCorazaGenerator({
      engine: 'coraza-spoa',
      peers: 'a:10.0.0.1:99999,b:10.0.0.2:10000',
    });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.doesNotMatch(cfg.content, /^peers /m);
    const w = gen.lastWarnings.join('\n');
    assert.match(w, /invalid name\/host\/port/);
  });

  it('--coraza-peers with duplicate name → warning + omit', () => {
    const gen = createCorazaGenerator({
      engine: 'coraza-spoa',
      peers: 'node1:10.0.0.1:10000,node1:10.0.0.2:10000',
    });
    const cfg = (gen.generate(fixtureSpec()) as Array<{ path: string; content: string }>)
      .find((a) => a.path === 'haproxy-stick-tables.cfg')!;
    assert.doesNotMatch(cfg.content, /^peers /m);
    const w = gen.lastWarnings.join('\n');
    assert.match(w, /duplicate peer name "node1"/);
  });
});
