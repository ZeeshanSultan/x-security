/**
 * Drift-closure emission tests for the 13 fields from the
 * capability-drift-matrix (lifecycle, CSRF, HPP, response.contentType,
 * extended CORS, modsec-nginx server-side directives).
 *
 * Pattern mirrors coraza-c2-c3.test.ts: each rule's id:/status:/tag:
 * literal substring must appear in the generated yaml.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { EndpointIR, SpecIR } from '@x-security/core';
import type { XSecurityPolicy } from '@x-security/schema';

import { buildLifecycleRules } from '../../src/generators/coraza/lifecycle-rules.ts';
import { buildCsrfRules } from '../../src/generators/coraza/csrf-rules.ts';
import { buildDuplicateParamRules } from '../../src/generators/coraza/duplicate-param-rules.ts';
import { buildResponseContentTypeRules } from '../../src/generators/coraza/response-content-type-rules.ts';
import { buildCorsRules } from '../../src/generators/coraza/cors-rules.ts';
import { buildModsecNginxServerConf } from '../../src/generators/coraza/templates/modsec-nginx-server.ts';
import { createCorazaGenerator } from '../../src/generators/coraza/index.ts';
import {
  CORAZA_GO_PROFILE,
  CORAZA_SPOA_PROFILE,
  MODSEC_NGINX_PROFILE,
} from '../../src/generators/coraza/profiles.ts';

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

describe('coraza drift: lifecycle (deprecated/sunsetDate/replacementEndpoint)', () => {
  it('emits id:269 SecAction with status:410 when deprecated:true', () => {
    const rules = buildLifecycleRules(ep('GET', '/api/old', { deprecated: true }), CORAZA_SPOA_PROFILE);
    const joined = rules.join('\n');
    assert.match(joined, /id:269/);
    assert.match(joined, /status:410/);
    assert.match(joined, /phase:1/);
    assert.match(joined, /x-security-lifecycle-410/);
    assert.match(joined, /SecAction/);
  });

  it('emits id:270 setenv Sunset header when sunsetDate set', () => {
    const rules = buildLifecycleRules(
      ep('GET', '/api/v1/legacy', { sunsetDate: '2026-12-31' }),
      CORAZA_GO_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:270/);
    assert.match(joined, /setenv:Sunset=2026-12-31/);
    assert.match(joined, /phase:3/);
    assert.match(joined, /x-security-lifecycle-sunset/);
  });

  it('emits id:271 setenv Link successor-version when replacementEndpoint set', () => {
    const rules = buildLifecycleRules(
      ep('GET', '/api/old', { replacementEndpoint: '/api/v2/new' }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:271/);
    assert.match(joined, /setenv:Link=/);
    assert.match(joined, /successor-version/);
    assert.match(joined, /x-security-lifecycle-replacement/);
  });

  it('emits nothing when no lifecycle fields set', () => {
    assert.deepEqual(buildLifecycleRules(ep('GET', '/api/x', {}), CORAZA_GO_PROFILE), []);
  });
});

describe('coraza drift: CSRF', () => {
  it('skips emission on safe methods (GET/HEAD)', () => {
    const rules = buildCsrfRules(
      ep('GET', '/api/x', {
        csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] },
      }),
      CORAZA_SPOA_PROFILE
    );
    assert.deepEqual(rules, []);
  });

  it('emits id:272 origin-check deny on state-changing method', () => {
    const rules = buildCsrfRules(
      ep('POST', '/api/transfer', {
        csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] },
      }),
      CORAZA_SPOA_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:272/);
    assert.match(joined, /status:403/);
    assert.match(joined, /Origin/);
    assert.match(joined, /x-security-csrf/);
  });

  it('emits double-submit capture + verify rules', () => {
    const rules = buildCsrfRules(
      ep('POST', '/api/transfer', {
        csrf: { method: 'double-submit', tokenCookie: 'XSRF-TOKEN', tokenHeader: 'X-XSRF-Token' },
      }),
      CORAZA_GO_PROFILE
    );
    const joined = rules.join('\n');
    assert.equal(rules.length, 2, 'double-submit emits a capture + verify pair');
    assert.match(joined, /XSRF-TOKEN/);
    assert.match(joined, /X-XSRF-Token/);
    assert.match(joined, /setvar:tx\.x_security_csrf_/);
    assert.match(joined, /CSRF token mismatch/);
  });

  it('emits id:272 custom-header presence check', () => {
    const rules = buildCsrfRules(
      ep('PUT', '/api/profile', {
        csrf: { method: 'custom-header', tokenHeader: 'X-CSRF-Protection' },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:272/);
    assert.match(joined, /X-CSRF-Protection/);
    assert.match(joined, /@eq 0/);
    assert.match(joined, /x-security-csrf/);
  });
});

describe('coraza drift: HPP (duplicateParamPolicy=reject)', () => {
  it('emits id:275 per schema field when policy=reject', () => {
    const rules = buildDuplicateParamRules(
      ep('POST', '/api/x', {
        request: {
          duplicateParamPolicy: 'reject',
          schema: { userId: { type: 'string' }, role: { type: 'string' } },
        },
      }),
      CORAZA_SPOA_PROFILE
    );
    assert.equal(rules.length, 2);
    const joined = rules.join('\n');
    assert.match(joined, /id:275/);
    assert.match(joined, /&ARGS:userId/);
    assert.match(joined, /&ARGS:role/);
    assert.match(joined, /x-security-hpp-reject/);
    assert.match(joined, /@gt 1/);
  });

  it('emits nothing when policy=first or last', () => {
    const policies: Array<'first' | 'last'> = ['first', 'last'];
    for (const p of policies) {
      assert.deepEqual(
        buildDuplicateParamRules(
          ep('POST', '/api/x', {
            request: { duplicateParamPolicy: p, schema: { x: { type: 'string' } } },
          }),
          CORAZA_GO_PROFILE
        ),
        []
      );
    }
  });
});

describe('coraza drift: response.contentType allowlist', () => {
  it('emits id:276 phase:3 deny for non-allowlisted Content-Type', () => {
    const rules = buildResponseContentTypeRules(
      ep('GET', '/api/users', {
        response: { contentType: ['application/json', 'application/vnd.api+json'] },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:276/);
    assert.match(joined, /phase:3/);
    assert.match(joined, /status:500/);
    assert.match(joined, /RESPONSE_HEADERS:Content-Type/);
    assert.match(joined, /x-security-response-ct/);
  });

  it('emits nothing when response.contentType absent', () => {
    assert.deepEqual(
      buildResponseContentTypeRules(ep('GET', '/api/x', {}), CORAZA_GO_PROFILE),
      []
    );
  });
});

describe('coraza drift: extended CORS (credentials/exposeHeaders/maxAge)', () => {
  it('emits id:333 setenv Access-Control-Allow-Credentials when credentials:true', () => {
    const rules = buildCorsRules(
      ep('POST', '/api/login', {
        cors: { allowedOrigins: ['https://app.example.com'], credentials: true },
      }),
      CORAZA_SPOA_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:333/);
    assert.match(joined, /setenv:Access-Control-Allow-Credentials=true/);
  });

  it('emits id:334 setenv Access-Control-Expose-Headers', () => {
    const rules = buildCorsRules(
      ep('GET', '/api/data', {
        cors: {
          allowedOrigins: ['https://app.example.com'],
          exposeHeaders: ['X-Total-Count', 'X-Page'],
        },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:334/);
    assert.match(joined, /setenv:Access-Control-Expose-Headers=X-Total-Count, X-Page/);
  });

  it('emits id:335 setenv Access-Control-Max-Age', () => {
    const rules = buildCorsRules(
      ep('OPTIONS', '/api/data', {
        cors: { allowedOrigins: ['https://app.example.com'], maxAge: 3600 },
      }),
      CORAZA_GO_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:335/);
    assert.match(joined, /setenv:Access-Control-Max-Age=3600/);
  });
});

describe('coraza drift: modsec-nginx server.conf', () => {
  function buildSpec(endpoints: EndpointIR[]): SpecIR {
    return {
      info: { title: 'T', version: '1.0' },
      servers: [],
      endpoints,
      unprotectedEndpoints: [],
    };
  }

  it('returns null when no timeout/tls/lifecycle declared', () => {
    const spec = buildSpec([ep('GET', '/api/x', {})]);
    assert.equal(buildModsecNginxServerConf(spec), null);
  });

  it('emits proxy_*_timeout from timeout.connect/read/write', () => {
    const spec = buildSpec([
      ep('GET', '/api/x', { timeout: { connect: 5, read: 30, write: 10 } }),
    ]);
    const conf = buildModsecNginxServerConf(spec);
    assert.ok(conf);
    assert.match(conf, /proxy_connect_timeout 5s;/);
    assert.match(conf, /proxy_read_timeout 30s;/);
    assert.match(conf, /proxy_send_timeout 10s;/);
  });

  it('emits ssl_protocols TLSv1.3 when minVersion=TLSv1.3', () => {
    const spec = buildSpec([ep('GET', '/api/x', { tls: { minVersion: 'TLSv1.3' } })]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /ssl_protocols TLSv1\.3;/);
  });

  it('emits ssl_protocols TLSv1.2 TLSv1.3 when minVersion=TLSv1.2', () => {
    const spec = buildSpec([ep('GET', '/api/x', { tls: { minVersion: 'TLSv1.2' } })]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /ssl_protocols TLSv1\.2 TLSv1\.3;/);
  });

  it('emits ssl_ciphers from allowedCipherSuites', () => {
    const spec = buildSpec([
      ep('GET', '/api/x', {
        tls: { allowedCipherSuites: ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'] },
      }),
    ]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;/);
  });

  it('emits return 410 when deprecated:true', () => {
    const spec = buildSpec([ep('GET', '/api/old', { deprecated: true })]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /return 410;/);
  });

  it('emits add_header Sunset when sunsetDate set', () => {
    const spec = buildSpec([ep('GET', '/api/x', { sunsetDate: '2026-12-31' })]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /add_header Sunset "2026-12-31" always;/);
  });

  it('emits add_header Link successor-version when replacementEndpoint set', () => {
    const spec = buildSpec([
      ep('GET', '/api/v1/x', { replacementEndpoint: '/api/v2/x' }),
    ]);
    const conf = buildModsecNginxServerConf(spec);
    assert.match(conf!, /add_header Link "<\/api\/v2\/x>; rel=\\"successor-version\\"" always;/);
  });
});

describe('coraza drift: nginx-server.conf artifact emission gating', () => {
  function buildSpec(): SpecIR {
    return {
      info: { title: 'T', version: '1.0' },
      servers: [],
      endpoints: [ep('GET', '/api/x', { timeout: { read: 30 }, tls: { minVersion: 'TLSv1.3' } })],
      unprotectedEndpoints: [],
    };
  }

  it('emits nginx-server.conf only for modsec-nginx profile', async () => {
    const nginx = createCorazaGenerator({ engine: 'modsec-nginx' });
    const arts = await nginx.generate(buildSpec());
    assert.ok(arts.find((a) => a.path === 'nginx-server.conf'), 'nginx-server.conf required');
  });

  it('does NOT emit nginx-server.conf for coraza-spoa', async () => {
    const spoa = createCorazaGenerator({ engine: 'coraza-spoa' });
    const arts = await spoa.generate(buildSpec());
    assert.equal(
      arts.find((a) => a.path === 'nginx-server.conf'),
      undefined,
      'no stray nginx conf for non-modsec-nginx profile'
    );
  });

  it('does NOT emit nginx-server.conf for coraza-go', async () => {
    const go = createCorazaGenerator({ engine: 'coraza-go' });
    const arts = await go.generate(buildSpec());
    assert.equal(arts.find((a) => a.path === 'nginx-server.conf'), undefined);
  });

  it('does NOT emit nginx-server.conf for modsec-apache', async () => {
    const apache = createCorazaGenerator({ engine: 'modsec-apache' });
    const arts = await apache.generate(buildSpec());
    assert.equal(arts.find((a) => a.path === 'nginx-server.conf'), undefined);
  });
});
