import test from 'node:test';
import assert from 'node:assert/strict';
import { mockClient } from 'aws-sdk-client-mock';
import {
  SecretsManagerClient,
  GetSecretValueCommand
} from '@aws-sdk/client-secrets-manager';
import { AwsSecretsResolver } from '../../src/resolvers/aws-secrets.js';

test('extracts a JSON key from SecretString', async () => {
  const sm = mockClient(SecretsManagerClient);
  sm.on(GetSecretValueCommand, { SecretId: 'writ/prod' }).resolves({
    SecretString: JSON.stringify({ JWKS_ENDPOINT: 'https://i/.well-known/jwks.json', other: 'x' })
  });
  const client = new SecretsManagerClient({ region: 'us-east-1' });
  const r = new AwsSecretsResolver({ client });
  assert.equal(
    await r.resolve('$aws.writ/prod#JWKS_ENDPOINT'),
    'https://i/.well-known/jwks.json'
  );
  sm.restore();
});

test('returns raw SecretString when no #key given', async () => {
  const sm = mockClient(SecretsManagerClient);
  sm.on(GetSecretValueCommand, { SecretId: 'plain' }).resolves({ SecretString: 'plain-value' });
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  assert.equal(await r.resolve('$aws.plain'), 'plain-value');
  sm.restore();
});

test('returns undefined when the secret does not exist', async () => {
  const sm = mockClient(SecretsManagerClient);
  const err = new Error('not found') as Error & { name: string };
  err.name = 'ResourceNotFoundException';
  sm.on(GetSecretValueCommand).rejects(err);
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  assert.equal(await r.resolve('$aws.missing#k'), undefined);
  sm.restore();
});

test('rethrows non-not-found errors with context', async () => {
  const sm = mockClient(SecretsManagerClient);
  const err = new Error('access denied') as Error & { name: string };
  err.name = 'AccessDeniedException';
  sm.on(GetSecretValueCommand).rejects(err);
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  await assert.rejects(() => r.resolve('$aws.secret#k'), /AWS Secrets Manager fetch failed/);
  sm.restore();
});

test('returns undefined when JSON parse fails for a #key request', async () => {
  const sm = mockClient(SecretsManagerClient);
  sm.on(GetSecretValueCommand).resolves({ SecretString: 'not-json' });
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  assert.equal(await r.resolve('$aws.broken#key'), undefined);
  sm.restore();
});

test('fromEnv picks up AWS_REGION', () => {
  const r = AwsSecretsResolver.fromEnv({ AWS_REGION: 'eu-west-1' });
  assert.ok(r instanceof AwsSecretsResolver);
});

test('non-matching ref returns undefined', async () => {
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  assert.equal(await r.resolve('${ENV}'), undefined);
});

test('cache: second call doesn\'t hit the API', async () => {
  const sm = mockClient(SecretsManagerClient);
  sm.on(GetSecretValueCommand, { SecretId: 'cache-me' }).resolves({
    SecretString: JSON.stringify({ k: 'v' })
  });
  const r = new AwsSecretsResolver({ client: new SecretsManagerClient({}) });
  assert.equal(await r.resolve('$aws.cache-me#k'), 'v');
  assert.equal(await r.resolve('$aws.cache-me#k'), 'v');
  // mockClient counts calls — verify at most one
  const calls = sm.commandCalls(GetSecretValueCommand);
  assert.equal(calls.length, 1);
  sm.restore();
});
