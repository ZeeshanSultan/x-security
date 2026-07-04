// HashiCorp Vault resolver.
//
// Reference syntax:
//   $vault.<engine>/<path>[#<key>]
//
// Defaults:
//   - engine: `secret` (KV v2) — i.e. `$vault.secret/foo#bar` → GET /v1/secret/data/foo
//     returns data.data.bar
//   - if KV version is 1, the request goes to /v1/<engine>/<path> and returns data.<key>
//   - if `#<key>` is absent, the entire JSON string of the secret is returned
//
// Auth: VAULT_TOKEN (preferred) or AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID).
// VAULT_NAMESPACE is sent as the X-Vault-Namespace header when set.
//
// In-process cache: keyed by `<engine>/<path>`. TTL is the secret's
// `lease_duration` if present, otherwise `defaultTtlMs` (5 minutes).

import { request } from 'undici';
import type { VariableResolver } from '../variables.js';

export interface VaultResolverOptions {
  /** Vault address, e.g. https://vault.example.com:8200. Required. */
  address: string;
  /** Static Vault token. One of `token` or AppRole credentials must be supplied. */
  token?: string;
  /** AppRole role_id (paired with secretId). */
  roleId?: string;
  /** AppRole secret_id. */
  secretId?: string;
  /** Vault namespace (Enterprise). Sent as X-Vault-Namespace header. */
  namespace?: string;
  /** KV engine version (1 or 2). Default: 2. */
  kvVersion?: 1 | 2;
  /** Default cache TTL in ms when the secret has no lease_duration. Default: 5 min. */
  defaultTtlMs?: number;
  /** Override fetch (for tests). Must match undici.request signature. */
  requestFn?: typeof request;
}

interface CacheEntry {
  data: Record<string, unknown>;
  expiresAt: number;
}

const REF_RE = /^\$vault\.([^#]+)(?:#(.+))?$/;

export class VaultResolver implements VariableResolver {
  private readonly cache = new Map<string, CacheEntry>();
  private cachedToken: string | undefined;
  private tokenExpiresAt = 0;
  private readonly defaultTtlMs: number;
  private readonly kvVersion: 1 | 2;
  private readonly req: typeof request;

  constructor(private readonly opts: VaultResolverOptions) {
    if (!opts.address) throw new Error('VaultResolver: `address` is required');
    if (!opts.token && !(opts.roleId && opts.secretId)) {
      throw new Error('VaultResolver: provide either `token` or `roleId`+`secretId`');
    }
    this.defaultTtlMs = opts.defaultTtlMs ?? 5 * 60_000;
    this.kvVersion = opts.kvVersion ?? 2;
    this.req = opts.requestFn ?? request;
    if (opts.token) this.cachedToken = opts.token;
  }

  /**
   * Build a VaultResolver from environment variables, returns undefined if VAULT_ADDR
   * is unset (so the CLI can opt-in cleanly).
   */
  static fromEnv(env: NodeJS.ProcessEnv = process.env, overrides: Partial<VaultResolverOptions> = {}): VaultResolver | undefined {
    const address = env.VAULT_ADDR;
    if (!address) return undefined;
    const opts: VaultResolverOptions = { address, ...overrides };
    if (env.VAULT_TOKEN) opts.token = env.VAULT_TOKEN;
    if (env.VAULT_ROLE_ID) opts.roleId = env.VAULT_ROLE_ID;
    if (env.VAULT_SECRET_ID) opts.secretId = env.VAULT_SECRET_ID;
    if (env.VAULT_NAMESPACE) opts.namespace = env.VAULT_NAMESPACE;
    if (env.VAULT_KV_VERSION === '1' || env.VAULT_KV_VERSION === '2') {
      opts.kvVersion = Number(env.VAULT_KV_VERSION) as 1 | 2;
    }
    if (!opts.token && !(opts.roleId && opts.secretId)) {
      throw new Error(
        'Vault enabled (VAULT_ADDR set) but no credentials found. Set VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID.'
      );
    }
    return new VaultResolver(opts);
  }

  async resolve(ref: string): Promise<string | undefined> {
    const m = ref.match(REF_RE);
    if (!m) return undefined;
    const enginePath = m[1]!;
    const key = m[2];

    const slash = enginePath.indexOf('/');
    if (slash === -1) return undefined; // need at least `<engine>/<path>`
    const engine = enginePath.slice(0, slash);
    const secretPath = enginePath.slice(slash + 1);

    const data = await this.readSecret(engine, secretPath);
    if (!data) return undefined;

    if (!key) {
      // Return whole secret as JSON.
      return JSON.stringify(data);
    }
    const v = data[key];
    if (v === undefined || v === null) return undefined;
    return typeof v === 'string' ? v : JSON.stringify(v);
  }

  private async readSecret(engine: string, secretPath: string): Promise<Record<string, unknown> | undefined> {
    const cacheKey = `${engine}/${secretPath}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.data;

    const url =
      this.kvVersion === 2
        ? `${this.trimAddr()}/v1/${engine}/data/${secretPath}`
        : `${this.trimAddr()}/v1/${engine}/${secretPath}`;

    const token = await this.getToken();
    const headers: Record<string, string> = { 'X-Vault-Token': token };
    if (this.opts.namespace) headers['X-Vault-Namespace'] = this.opts.namespace;

    let res;
    try {
      res = await this.req(url, { method: 'GET', headers });
    } catch (e) {
      throw new Error(`Vault unreachable at ${this.opts.address}: ${(e as Error).message}`);
    }

    if (res.statusCode === 404) return undefined;
    if (res.statusCode < 200 || res.statusCode >= 300) {
      const body = await res.body.text();
      throw new Error(`Vault read failed (${res.statusCode}): ${body.slice(0, 200)}`);
    }

    const body = (await res.body.json()) as {
      data?: Record<string, unknown> | { data?: Record<string, unknown> };
      lease_duration?: number;
    };

    let secretData: Record<string, unknown> | undefined;
    if (this.kvVersion === 2) {
      const outer = body.data as { data?: Record<string, unknown> } | undefined;
      secretData = outer?.data;
    } else {
      secretData = body.data as Record<string, unknown> | undefined;
    }
    if (!secretData) return undefined;

    const ttl = body.lease_duration && body.lease_duration > 0
      ? body.lease_duration * 1000
      : this.defaultTtlMs;
    this.cache.set(cacheKey, { data: secretData, expiresAt: Date.now() + ttl });
    return secretData;
  }

  private async getToken(): Promise<string> {
    if (this.opts.token) return this.opts.token;
    if (this.cachedToken && this.tokenExpiresAt > Date.now()) return this.cachedToken;
    // AppRole login.
    const url = `${this.trimAddr()}/v1/auth/approle/login`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.opts.namespace) headers['X-Vault-Namespace'] = this.opts.namespace;
    let res;
    try {
      res = await this.req(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ role_id: this.opts.roleId, secret_id: this.opts.secretId })
      });
    } catch (e) {
      throw new Error(`Vault unreachable at ${this.opts.address}: ${(e as Error).message}`);
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
      const body = await res.body.text();
      throw new Error(`Vault AppRole login failed (${res.statusCode}): ${body.slice(0, 200)}`);
    }
    const body = (await res.body.json()) as {
      auth?: { client_token?: string; lease_duration?: number };
    };
    const tok = body.auth?.client_token;
    if (!tok) throw new Error('Vault AppRole login returned no client_token');
    this.cachedToken = tok;
    const lease = body.auth?.lease_duration;
    this.tokenExpiresAt = Date.now() + (lease && lease > 0 ? lease * 1000 : this.defaultTtlMs);
    return tok;
  }

  private trimAddr(): string {
    return this.opts.address.replace(/\/+$/, '');
  }

  /** Test helper: clear the in-memory cache. */
  clearCache(): void {
    this.cache.clear();
  }
}
