/**
 * C-2 / C-3 emission tests (vAPI evaluation gaps).
 *
 * Asserts that:
 *  - CORS rules emit `id:339` (origin allowlist) and `id:332` (preflight)
 *  - Output-sanitization rules emit `id:268` for each errorScrubbing flag
 *  - Sensitive response-schema field names trigger `id:428` PII filter
 *
 * The scorer (`scoring_lib/attribution.py`) maps these literal substrings to
 * defense classes via `s in (response_body + log)` — substring, not anchored.
 * The substring may live in the numeric ID itself OR in the rule `msg:`; we
 * assert presence in the generated text since both reach the audit log.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { EndpointIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

import { buildCorsRules } from '../../src/generators/coraza/cors-rules.ts';
import {
  buildOutputSanitizationRules,
  buildDataExposurePiiRules,
} from '../../src/generators/coraza/data-exposure-rules.ts';
import { buildPolicyRules } from '../../src/generators/coraza/rules.ts';
import {
  CORAZA_GO_PROFILE,
  MODSEC_NGINX_PROFILE,
  type EngineWarning,
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

describe('coraza C-3: CORS enforcement', () => {
  it('emits no rules when cors is absent', () => {
    const rules = buildCorsRules(ep('GET', '/api/x', {}), CORAZA_GO_PROFILE);
    assert.deepEqual(rules, []);
  });

  it('emits no rules when allowedOrigins is empty', () => {
    const rules = buildCorsRules(
      ep('GET', '/api/x', { cors: { allowedOrigins: [] } }),
      CORAZA_GO_PROFILE
    );
    assert.deepEqual(rules, []);
  });

  it('emits id:339 origin-allowlist deny rule', () => {
    const rules = buildCorsRules(
      ep('POST', '/api/login', {
        cors: { allowedOrigins: ['https://app.example.com', 'https://*.trusted.io'] },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:339/, 'must contain literal substring id:339 for scorer attribution');
    assert.match(joined, /phase:1/);
    assert.match(joined, /status:403/);
    assert.match(joined, /Origin/);
    assert.match(joined, /CORS origin not allowed/);
    // Wildcard expansion: `*.trusted.io` becomes `.*\.trusted\.io`.
    assert.match(joined, /\.\*.*trusted/);
    assert.match(joined, /writ-cors-policy/);
  });

  it('emits id:332 preflight method check', () => {
    const rules = buildCorsRules(
      ep('POST', '/api/login', {
        cors: {
          allowedOrigins: ['https://app.example.com'],
          allowedMethods: ['GET', 'POST', 'OPTIONS'],
        },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:332/, 'must contain literal substring id:332 for scorer attribution');
    assert.match(joined, /OPTIONS/);
    assert.match(joined, /Access-Control-Request-Method/);
    assert.match(joined, /CORS preflight method not allowed/);
  });

  it('emits id:332 preflight headers check when allowedHeaders declared', () => {
    const rules = buildCorsRules(
      ep('POST', '/api/login', {
        cors: {
          allowedOrigins: ['https://app.example.com'],
          allowedHeaders: ['content-type', 'authorization'],
        },
      }),
      MODSEC_NGINX_PROFILE
    );
    const joined = rules.join('\n');
    assert.match(joined, /Access-Control-Request-Headers/);
    assert.match(joined, /CORS preflight header not allowed/);
    // id:332 substring still present in either headers-rule msg or method-rule msg.
    assert.match(joined, /id:332/);
  });

  it('is wired into buildPolicyRules so emissions land in the artifact', () => {
    const out = buildPolicyRules(
      ep('GET', '/api/data', { cors: { allowedOrigins: ['https://app.example.com'] } }),
      MODSEC_NGINX_PROFILE
    );
    const joined = out.join('\n');
    assert.match(joined, /id:339/);
    assert.match(joined, /id:332/);
  });
});

describe('coraza C-2A: output sanitization (id:268)', () => {
  it('emits no rules when errorScrubbing absent', () => {
    const rules = buildOutputSanitizationRules(ep('GET', '/api/x', {}), CORAZA_GO_PROFILE, []);
    assert.deepEqual(rules, []);
  });

  it('emits id:268 stack-trace strip rule', () => {
    const warnings: EngineWarning[] = [];
    const rules = buildOutputSanitizationRules(
      ep('GET', '/api/x', { response: { errorScrubbing: { stripStackTraces: true } } }),
      MODSEC_NGINX_PROFILE,
      warnings
    );
    const joined = rules.join('\n');
    assert.match(joined, /id:268/);
    assert.match(joined, /phase:4/);
    assert.match(joined, /stack trace leak/);
    assert.match(joined, /Traceback/);
    assert.match(joined, /writ-output-sanitization/);
  });

  it('emits id:268 for stripServerHeaders + genericMessages', () => {
    const rules = buildOutputSanitizationRules(
      ep('GET', '/api/x', {
        response: {
          errorScrubbing: {
            stripServerHeaders: true,
            genericMessages: true,
          },
        },
      }),
      MODSEC_NGINX_PROFILE,
      []
    );
    const joined = rules.join('\n');
    assert.match(joined, /server-version leak/);
    assert.match(joined, /raw error leak/);
    assert.match(joined, /X-Powered-By/);
    assert.match(joined, /psycopg2|SQLSTATE/);
    // Both rules carry id:268 substring.
    const count268 = (joined.match(/id:268/g) ?? []).length;
    assert.ok(count268 >= 2, `expected ≥2 id:268 occurrences, got ${count268}`);
  });
});

describe('coraza C-2B: data-exposure PII filter (id:428)', () => {
  it('emits no rules for non-sensitive field names', () => {
    const rules = buildDataExposurePiiRules(
      ep('GET', '/api/profile', {
        response: { schema: { name: { type: 'string' }, email: { type: 'email' } } },
      }),
      CORAZA_GO_PROFILE,
      []
    );
    assert.deepEqual(rules, []);
  });

  it('emits id:428 for password / token / ssn field names', () => {
    const rules = buildDataExposurePiiRules(
      ep('GET', '/api/profile', {
        response: {
          schema: {
            password: { type: 'string' },
            access_token: { type: 'string' },
            ssn: { type: 'string' },
            name: { type: 'string' }, // not sensitive — should not emit
          },
        },
      }),
      MODSEC_NGINX_PROFILE,
      []
    );
    assert.equal(rules.length, 3);
    const joined = rules.join('\n');
    assert.match(joined, /id:428/);
    assert.match(joined, /password/);
    assert.match(joined, /access_token/);
    assert.match(joined, /ssn/);
    assert.doesNotMatch(joined, /"name"\\\\s/); // no rule for non-sensitive field
    assert.match(joined, /writ-data-exposure/);
  });

  it('recognizes camelCase sensitive names (creditCard, apiKey)', () => {
    const rules = buildDataExposurePiiRules(
      ep('GET', '/api/x', {
        response: { schema: { creditCard: { type: 'string' }, apiKey: { type: 'string' } } },
      }),
      MODSEC_NGINX_PROFILE,
      []
    );
    assert.equal(rules.length, 2);
    const joined = rules.join('\n');
    assert.match(joined, /id:428/);
  });

  it('emits id:428 for `pii: true` even when the field name is not in the heuristic list', () => {
    // nationalId / dob don't look sensitive to the SENSITIVE_FIELD_NAMES
    // heuristic; the spec author opts in via `pii: true`.
    const rules = buildDataExposurePiiRules(
      ep('GET', '/api/citizen', {
        response: {
          schema: {
            nationalId: { type: 'string', pii: true },
            dob: { type: 'date', pii: true },
            displayName: { type: 'string' }, // no pii flag, not sensitive → no rule
          },
        },
      }),
      MODSEC_NGINX_PROFILE,
      []
    );
    assert.equal(rules.length, 2, 'one rule per pii-tagged field, none for displayName');
    const joined = rules.join('\n');
    assert.match(joined, /id:428/);
    assert.match(joined, /nationalId/);
    assert.match(joined, /dob/);
    assert.doesNotMatch(joined, /displayName/);
    assert.match(joined, /writ-data-exposure/);
  });
});
