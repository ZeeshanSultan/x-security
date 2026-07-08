import test from 'node:test';
import assert from 'node:assert/strict';
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher } from 'undici';
import { VaultResolver } from '../../src/resolvers/hashicorp.js';

const VAULT_ADDR = 'http://vault.test:8200';

function withMock(fn: (pool: ReturnType<MockAgent['get']>) => Promise<void>) {
  return async () => {
    const prev = getGlobalDispatcher();
    const agent = new MockAgent();
    agent.disableNetConnect();
    setGlobalDispatcher(agent);
    try {
      const pool = agent.get(VAULT_ADDR);
      await fn(pool);
    } finally {
      await agent.close();
      setGlobalDispatcher(prev);
    }
  };
}

test('KV v2 happy path returns the requested key', withMock(async (pool) => {
  pool.intercept({ path: '/v1/kv/data/x-security', method: 'GET' }).reply(200, {
    data: { data: { jwks: 'https://issuer/.well-known/jwks.json' } },
    lease_duration: 0
  });
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root' });
  const v = await r.resolve('$vault.kv/x-security#jwks');
  assert.equal(v, 'https://issuer/.well-known/jwks.json');
}));

test('KV v1 reads from /v1/<engine>/<path>', withMock(async (pool) => {
  pool.intercept({ path: '/v1/secret/foo', method: 'GET' }).reply(200, {
    data: { token: 's3cret' }
  });
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root', kvVersion: 1 });
  assert.equal(await r.resolve('$vault.secret/foo#token'), 's3cret');
}));

test('AppRole login obtains a token then reads', withMock(async (pool) => {
  pool
    .intercept({ path: '/v1/auth/approle/login', method: 'POST' })
    .reply(200, { auth: { client_token: 'derived-token', lease_duration: 3600 } });
  pool
    .intercept({
      path: '/v1/kv/data/app',
      method: 'GET',
      headers: { 'x-vault-token': 'derived-token' }
    })
    .reply(200, { data: { data: { key: 'val' } } });
  const r = new VaultResolver({
    address: VAULT_ADDR,
    roleId: 'rid',
    secretId: 'sid'
  });
  assert.equal(await r.resolve('$vault.kv/app#key'), 'val');
}));

test('lease cache: second read hits cache, not the API', withMock(async (pool) => {
  pool
    .intercept({ path: '/v1/kv/data/cached', method: 'GET' })
    .reply(200, { data: { data: { k: 'v1' } }, lease_duration: 60 });
  // No second mock — if it tried to call again, MockAgent would throw.
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root' });
  assert.equal(await r.resolve('$vault.kv/cached#k'), 'v1');
  assert.equal(await r.resolve('$vault.kv/cached#k'), 'v1');
}));

test('404 from Vault returns undefined (lenient)', withMock(async (pool) => {
  pool.intercept({ path: '/v1/kv/data/missing', method: 'GET' }).reply(404, { errors: [] });
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root' });
  assert.equal(await r.resolve('$vault.kv/missing#x'), undefined);
}));

test('namespace header is forwarded when set', withMock(async (pool) => {
  pool
    .intercept({
      path: '/v1/kv/data/ns',
      method: 'GET',
      headers: { 'x-vault-namespace': 'tenant-a' }
    })
    .reply(200, { data: { data: { k: 'ns-val' } } });
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root', namespace: 'tenant-a' });
  assert.equal(await r.resolve('$vault.kv/ns#k'), 'ns-val');
}));

test('non-matching ref returns undefined', async () => {
  const r = new VaultResolver({ address: VAULT_ADDR, token: 'root' });
  assert.equal(await r.resolve('${ENV_VAR}'), undefined);
});

test('fromEnv returns undefined when VAULT_ADDR missing', () => {
  assert.equal(VaultResolver.fromEnv({}), undefined);
});

test('fromEnv throws when address is set without credentials', () => {
  assert.throws(() => VaultResolver.fromEnv({ VAULT_ADDR: VAULT_ADDR }));
});
