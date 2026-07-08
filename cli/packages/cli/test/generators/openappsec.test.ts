import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { loadSpec, EnvResolver, type SpecIR, type EndpointIR } from '@x-security/core';
import type { XSecurityPolicy } from '@x-security/schema';
import { openappsecGenerator } from '../../src/generators/openappsec/index.js';
import {
  buildDoc,
  buildOpenApiFragment,
  buildSchemaValidation,
  extractHost,
  parseByteSize,
  durationToUnit,
  sanitizeName,
} from '../../src/generators/openappsec/policy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const exampleSpec = path.resolve(__dirname, '../../../../fixtures/specs/example.yaml');
const expectedFixture = path.resolve(
  __dirname,
  '../../../../fixtures/configs/openappsec/example.expected.yml',
);

const resolver = new EnvResolver({
  JWKS_ENDPOINT: 'https://auth.example.com/.well-known/jwks.json',
  AUTH_ISSUER: 'https://auth.example.com',
  AUTH_AUDIENCE: 'api',
});

test('parseByteSize parses canonical sizes', () => {
  assert.equal(parseByteSize('10KB'), 10 * 1024);
  assert.equal(parseByteSize('50MB'), 50 * 1024 * 1024);
  assert.equal(parseByteSize('512B'), 512);
  assert.equal(parseByteSize(undefined), undefined);
  assert.equal(parseByteSize('garbage'), undefined);
});

test('durationToUnit normalizes windows', () => {
  assert.deepEqual(durationToUnit('1m'), { unit: 'minute', factor: 1 });
  assert.deepEqual(durationToUnit('30s'), { unit: 'second', factor: 30 });
  assert.deepEqual(durationToUnit('2h'), { unit: 'minute', factor: 120 });
});

test('sanitizeName produces safe identifiers', () => {
  assert.equal(sanitizeName('POST /api/auth/login'), 'post-api-auth-login');
  assert.equal(sanitizeName('!!!'), 'endpoint');
});

test('generator name + targets', () => {
  assert.equal(openappsecGenerator.name, 'openappsec');
  assert.deepEqual([...openappsecGenerator.targets], ['openappsec']);
});

test('capability matrix reflects honest open-appsec coverage (wave-7)', () => {
  const caps = openappsecGenerator.capabilities();
  // Per-property schema rules are NOT consumed by open-appsec — it expects
  // an OpenAPI spec via configmap. We keep our rich block under
  // `x-security-extended:` but cannot honestly claim `full` coverage.
  assert.equal(caps.fields['request.schema'], 'partial');
  assert.equal(caps.fields['rateLimit'], 'partial');
  assert.equal(caps.fields['authentication.type'], 'unsupported');
  assert.equal(caps.fields['request.signature'], 'unsupported');
  assert.equal(caps.fields['authorization'], 'unsupported');
  assert.equal(caps.fields['mtls'], 'unsupported');
});

test('schemaValidation block built for login endpoint', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const login = ir.endpoints.find((e) => e.path === '/api/auth/login')!;
  const sv = buildSchemaValidation(login);
  assert.ok(sv, 'schemaValidation should be produced');
  assert.equal(sv.enforcementLevel, 'strict');
  assert.equal(sv.overrideMode, 'prevent');
  assert.equal(sv.schemas.request.contentType?.[0], 'application/json');
  assert.equal(sv.schemas.request.maxBodySizeBytes, 10 * 1024);
  assert.equal(sv.schemas.request.properties['email']?.format, 'email');
  assert.equal(sv.schemas.request.properties['email']?.maxLength, 254);
  assert.equal(sv.schemas.request.properties['password']?.minLength, 8);
  assert.ok(Array.isArray(sv.schemas.request.properties['email']?.mitigates));
});

test('upload endpoint emits binary mime + size rules', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const upload = ir.endpoints.find((e) => e.path === '/api/files/upload')!;
  const sv = buildSchemaValidation(upload)!;
  const file = sv.schemas.request.properties['file'];
  assert.ok(file);
  assert.deepEqual(file['allowed-mime-types'], [
    'image/png',
    'image/jpeg',
    'application/pdf',
  ]);
  assert.equal(file['max-size-bytes'], 50 * 1024 * 1024);
});

test('buildDoc emits one schemaValidation per request-bearing endpoint', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const doc = buildDoc(ir);
  // login + upload have request bodies; admin/listUsers has neither request nor response → skipped.
  // Per-endpoint schema details live under the x-security-internal `x-security-extended`
  // key — open-appsec does not consume per-property rules in its flat policy format.
  assert.equal(doc['x-security-extended']?.['schema-validation'].length, 2);
  assert.equal(doc.policies.default.mode, 'prevent-learn');
  assert.ok(doc.practices.some((p) => p.type === 'rate-limit'));
  assert.ok(doc.practices.some((p) => p.type === 'threat-prevention'));
  // No top-level `triggers:` — must be `log-triggers:` per upstream schema.
  assert.ok(doc['log-triggers'].length > 0);
  // No `apiVersion:` — flat local_policy.yaml format does not include it.
  assert.equal((doc as Record<string, unknown>)['apiVersion'], undefined);
});

test('rate-limit rules emitted per endpoint', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const doc = buildDoc(ir);
  const rl = doc.practices.find((p) => p.type === 'rate-limit')!;
  assert.ok(rl['rate-limit']);
  const rules = rl['rate-limit']!.rules;
  // login (5/m), admin (30/m), upload (20/m)
  assert.equal(rules.length, 3);
  assert.ok(rules.every((r) => r.unit === 'minute'));
  assert.ok(rules.every((r) => r.action === 'prevent'));
});

test('generate() returns policy + openapi-schema artifacts (wave-8)', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const artifacts = await openappsecGenerator.generate(ir);
  assert.equal(artifacts.length, 2);
  const policy = artifacts.find((a) => a.path === 'openappsec/policy.yaml');
  const schema = artifacts.find((a) => a.path === 'openappsec/openapi-schema.yaml');
  assert.ok(policy, 'policy.yaml artifact missing');
  assert.ok(schema, 'openapi-schema.yaml artifact missing');
  assert.equal(policy.format, 'yaml');
  assert.equal(schema.format, 'yaml');
  assert.ok(policy.content.startsWith('# Generated by x-security'));
  // Yaml body must parse cleanly.
  const parsed = yaml.load(policy.content) as Record<string, unknown>;
  assert.ok(parsed['policies']);
  assert.ok(parsed['log-triggers']);
  assert.ok(parsed['practices']);
  // Sanity: `apiVersion` and top-level `schemaValidation` are NOT part of
  // the flat open-appsec local_policy.yaml schema.
  assert.equal(parsed['apiVersion'], undefined);
  assert.equal(parsed['schemaValidation'], undefined);

  // Schema fragment must parse and contain paths from the spec.
  const schemaDoc = yaml.load(schema.content) as Record<string, unknown>;
  assert.equal(schemaDoc['openapi'], '3.0.3');
  const paths = schemaDoc['paths'] as Record<string, unknown>;
  assert.ok(paths['/api/auth/login'], 'schema fragment missing /api/auth/login');
  assert.ok(paths['/api/files/upload'], 'schema fragment missing /api/files/upload');
});

test('extractHost strips path + default ports (wave-8 host-field fix)', () => {
  // Wave-7 bug: emitted `host: api.example.com/api/auth/login`. Wave-8: just hostname.
  assert.equal(extractHost('https://api.example.com/v1/anything'), 'api.example.com');
  assert.equal(extractHost('http://vapi:80'), 'vapi');
  assert.equal(extractHost('https://api.example.com:443'), 'api.example.com');
  assert.equal(extractHost('http://vapi:8080'), 'vapi:8080');
  assert.equal(extractHost('http://vapi'), 'vapi');
  assert.equal(extractHost(undefined), '*');
  assert.equal(extractHost('not a url'), '*');
});

test('specific-rules host is bare hostname, never host+path (wave-8)', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const doc = buildDoc(ir);
  const rules = doc.policies['specific-rules'];
  assert.ok(rules.length > 0);
  for (const r of rules) {
    assert.ok(!r.host.includes('/'), `host "${r.host}" must not contain "/"`);
    assert.ok(!r.host.startsWith('http'), `host "${r.host}" must not include scheme`);
  }
  // One rule per unique host. example.yaml has one server → one specific-rule.
  assert.equal(rules.length, 1);
  assert.equal(rules[0]!.host, 'api.example.com');
});

test('threat-prevention practice references openapi schema file (wave-8)', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const doc = buildDoc(ir);
  const tp = doc.practices.find((p) => p.name === 'x-security-threat-prevention');
  assert.ok(tp);
  const sv = tp['openapi-schema-validation'];
  assert.ok(sv, 'threat-prevention must carry openapi-schema-validation');
  assert.deepEqual(sv.files, ['/ext/appsec/openapi-schema.yaml']);
});

test('buildOpenApiFragment preserves paths + operations from spec (wave-8)', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const frag = buildOpenApiFragment(ir);
  assert.equal(frag.openapi, '3.0.3');
  assert.ok(frag.paths['/api/auth/login']);
  assert.ok(frag.paths['/api/auth/login']!['post'], 'POST /api/auth/login op missing');
  assert.ok(frag.paths['/api/files/upload']);
  assert.ok(frag.paths['/api/files/upload']!['post'], 'POST upload op missing');
});

test('openappsec W11-A: ssrf-policy-missing warning fires on url-typed param without policy', () => {
  const spec: SpecIR = {
    openapi: '3.0.0', dialect: '3.0', info: { title: 't', version: '1' },
    servers: [], unprotectedEndpoints: [],
    endpoints: [
      {
        operationId: 'redir', method: 'GET', path: '/redirect',
        parameters: [], resolvedVars: new Map(), raw: {} as EndpointIR['raw'],
        policy: { request: { schema: { url: { type: 'url' } } } } as XSecurityPolicy,
      } as EndpointIR,
    ],
  };
  openappsecGenerator.generate(spec);
  const joined = openappsecGenerator.lastWarnings.join('\n');
  assert.match(joined, /\[openappsec:ssrf-policy-missing\] GET \/redirect/);
  assert.match(joined, /parameter "url"/);
});

test('output matches expected fixture (snapshot)', async () => {
  const ir = await loadSpec(exampleSpec, { resolver });
  const [artifact] = await openappsecGenerator.generate(ir);
  assert.ok(artifact);
  const actual = artifact.content;

  if (process.env['UPDATE_FIXTURES']) {
    fs.mkdirSync(path.dirname(expectedFixture), { recursive: true });
    fs.writeFileSync(expectedFixture, actual);
  }

  const expected = fs.readFileSync(expectedFixture, 'utf8');
  // Compare parsed YAML (resilient to trivial reformatting) AND raw content.
  assert.deepEqual(yaml.load(actual), yaml.load(expected));
});
