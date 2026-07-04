// AWS Secrets Manager resolver.
//
// Reference syntax:
//   $aws.<secret-id>[#<json-key>]
//
// Behavior:
//   - If `#<key>` is present, the SecretString is JSON-parsed and `key` is extracted.
//   - Otherwise the raw SecretString is returned.
//
// The AWS SDK is an optional peer dep, loaded via dynamic import so users who
// don't enable AWS don't pay the cost of installing/loading it.

import type { VariableResolver } from '../variables.js';

const REF_RE = /^\$aws\.([^#]+)(?:#(.+))?$/;

export interface AwsSecretsResolverOptions {
  /** AWS region. Defaults to AWS_REGION env. */
  region?: string;
  /** Cache TTL in ms. Default: 5 min. */
  ttlMs?: number;
  /** Inject a pre-built SecretsManagerClient (mainly for tests). */
  client?: unknown;
}

interface CacheEntry {
  value: string;
  expiresAt: number;
}

export class AwsSecretsResolver implements VariableResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly ttlMs: number;
  private readonly region: string | undefined;
  private clientPromise: Promise<unknown> | undefined;

  constructor(opts: AwsSecretsResolverOptions = {}) {
    this.ttlMs = opts.ttlMs ?? 5 * 60_000;
    this.region = opts.region;
    if (opts.client) this.clientPromise = Promise.resolve(opts.client);
  }

  static fromEnv(env: NodeJS.ProcessEnv = process.env): AwsSecretsResolver {
    const opts: AwsSecretsResolverOptions = {};
    if (env.AWS_REGION) opts.region = env.AWS_REGION;
    return new AwsSecretsResolver(opts);
  }

  async resolve(ref: string): Promise<string | undefined> {
    const m = ref.match(REF_RE);
    if (!m) return undefined;
    const secretId = m[1]!;
    const jsonKey = m[2];

    const raw = await this.fetchSecret(secretId);
    if (raw === undefined) return undefined;
    if (!jsonKey) return raw;
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const v = parsed[jsonKey];
      if (v === undefined || v === null) return undefined;
      return typeof v === 'string' ? v : JSON.stringify(v);
    } catch {
      // Secret wasn't JSON — can't extract a key.
      return undefined;
    }
  }

  private async fetchSecret(secretId: string): Promise<string | undefined> {
    const cached = this.cache.get(secretId);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    const client = await this.getClient();
    // Late-bind GetSecretValueCommand via dynamic import so the SDK is fully optional.
    let CommandCtor: new (args: { SecretId: string }) => unknown;
    try {
      const mod = (await import('@aws-sdk/client-secrets-manager')) as {
        GetSecretValueCommand: new (args: { SecretId: string }) => unknown;
      };
      CommandCtor = mod.GetSecretValueCommand;
    } catch (e) {
      throw new Error(
        '@aws-sdk/client-secrets-manager is not installed. Run `npm i @aws-sdk/client-secrets-manager` to use $aws references.'
      );
    }
    const cmd = new CommandCtor({ SecretId: secretId });
    let resp: { SecretString?: string } | undefined;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      resp = await (client as any).send(cmd);
    } catch (e) {
      const err = e as { name?: string; message?: string };
      if (err.name === 'ResourceNotFoundException') return undefined;
      throw new Error(`AWS Secrets Manager fetch failed for "${secretId}": ${err.message ?? String(e)}`);
    }
    const value = resp?.SecretString;
    if (value === undefined) return undefined;
    this.cache.set(secretId, { value, expiresAt: Date.now() + this.ttlMs });
    return value;
  }

  private async getClient(): Promise<unknown> {
    if (this.clientPromise) return this.clientPromise;
    this.clientPromise = (async () => {
      let mod;
      try {
        mod = (await import('@aws-sdk/client-secrets-manager')) as {
          SecretsManagerClient: new (cfg: { region?: string }) => unknown;
        };
      } catch (e) {
        throw new Error(
          '@aws-sdk/client-secrets-manager is not installed. Run `npm i @aws-sdk/client-secrets-manager` to use $aws references.'
        );
      }
      const cfg: { region?: string } = {};
      if (this.region) cfg.region = this.region;
      return new mod.SecretsManagerClient(cfg);
    })();
    return this.clientPromise;
  }

  /** Test helper. */
  clearCache(): void {
    this.cache.clear();
  }
}
