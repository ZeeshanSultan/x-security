import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ChainResolver,
  EnvResolver,
  StubVaultResolver,
  resolveVariables
} from '../src/variables.js';
import { UnresolvedVariableError } from '../src/errors.js';

test('env resolver substitutes ${VAR}', () => {
  const r = new EnvResolver({ FOO: 'bar' });
  assert.equal(r.resolve('${FOO}'), 'bar');
  assert.equal(r.resolve('${MISSING}'), undefined);
});

test('vault resolver substitutes $vault.path', () => {
  const r = new StubVaultResolver({ 'auth/issuer': 'https://issuer.example' });
  assert.equal(r.resolve('$vault.auth/issuer'), 'https://issuer.example');
});

test('chain resolver tries each in order (async)', async () => {
  const r = new ChainResolver([
    new EnvResolver({}),
    new StubVaultResolver({ secret: 'value' })
  ]);
  assert.equal(await r.resolve('$vault.secret'), 'value');
});

test('chain resolver awaits async resolvers', async () => {
  const asyncRes = {
    resolve: async (ref: string) => (ref === '$vault.async/key' ? 'async-val' : undefined)
  };
  const r = new ChainResolver([new EnvResolver({}), asyncRes]);
  assert.equal(await r.resolve('$vault.async/key'), 'async-val');
});

test('resolveVariables walks objects recursively (async)', async () => {
  const input = {
    authentication: {
      jwksUri: '${JWKS}',
      issuer: '$vault.issuer'
    },
    nested: [{ key: '${KEY}' }]
  };
  const resolver = new ChainResolver([
    new EnvResolver({ JWKS: 'https://j', KEY: 'k1' }),
    new StubVaultResolver({ issuer: 'issuer-1' })
  ]);
  const { value, resolved, unresolved } = await resolveVariables(input, { resolver });
  assert.equal((value.authentication.jwksUri as string), 'https://j');
  assert.equal((value.authentication.issuer as string), 'issuer-1');
  assert.equal((value.nested[0]!.key as string), 'k1');
  assert.equal(resolved.size, 3);
  assert.equal(unresolved.length, 0);
});

test('strict mode throws on unresolved', async () => {
  const resolver = new EnvResolver({});
  await assert.rejects(
    () => resolveVariables({ a: '${MISSING}' }, { resolver, strict: true }),
    UnresolvedVariableError
  );
});

test('lenient mode preserves unresolved refs', async () => {
  const resolver = new EnvResolver({});
  const { value, unresolved } = await resolveVariables(
    { a: '${MISSING}' },
    { resolver, strict: false }
  );
  assert.equal(value.a, '${MISSING}');
  assert.deepEqual(unresolved, ['${MISSING}']);
});
