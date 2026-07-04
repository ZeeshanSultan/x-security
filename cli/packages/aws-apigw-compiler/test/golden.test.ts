import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/index.js';
import { makeEndpoint, makeSpec } from './fixtures.js';

const here = dirname(fileURLToPath(import.meta.url));

test('golden: auth + ratelimit on POST /api/login matches expected rule shape', () => {
  const spec = makeSpec([
    makeEndpoint({
      method: 'POST',
      path: '/api/login',
      policy: {
        authentication: { type: 'api-key' },
        rateLimit: { requests: 500, window: '5m', identifier: 'ip' }
      }
    })
  ]);
  const r = compile(spec, { mode: 'shadow' });
  const expected = JSON.parse(readFileSync(join(here, 'fixtures/auth-and-ratelimit.expected.json'), 'utf8'));

  const ruleTypes = r.webAclRules.map(x => x.writ.rule_type);
  assert.deepEqual(ruleTypes, expected.ruleTypes);

  const rl = r.webAclRules.find(x => x.writ.rule_type === 'ratelimit-0');
  assert.equal(rl?.Statement.RateBasedStatement?.Limit, expected.rateBasedLimit);
  assert.equal(rl?.Statement.RateBasedStatement?.EvaluationWindowSec, expected.rateBasedWindowSec);
  assert.equal(rl?.Statement.RateBasedStatement?.AggregateKeyType, expected.rateBasedKey);
});
