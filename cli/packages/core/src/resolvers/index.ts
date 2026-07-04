// Factory for assembling a resolver chain from CLI flags + env.

import { ChainResolver, EnvResolver, type VariableResolver } from '../variables.js';
import { VaultResolver } from './hashicorp.js';
import { AwsSecretsResolver } from './aws-secrets.js';

export { VaultResolver } from './hashicorp.js';
export { AwsSecretsResolver } from './aws-secrets.js';

export interface BuildResolverChainOptions {
  enableVault?: boolean;
  enableAws?: boolean;
  env?: NodeJS.ProcessEnv;
  /** Override KV version (CLI --vault-kv-version=2). */
  vaultKvVersion?: 1 | 2;
}

/**
 * Build a resolver chain. Always includes EnvResolver. Vault and AWS are opt-in
 * via flags; if the corresponding env vars (VAULT_ADDR / AWS_REGION) are missing,
 * the helpers return undefined and we just skip them.
 */
export function buildResolverChain(opts: BuildResolverChainOptions = {}): VariableResolver {
  const env = opts.env ?? process.env;
  const chain: VariableResolver[] = [new EnvResolver(env)];

  if (opts.enableVault) {
    const overrides: { kvVersion?: 1 | 2 } = {};
    if (opts.vaultKvVersion) overrides.kvVersion = opts.vaultKvVersion;
    const vault = VaultResolver.fromEnv(env, overrides);
    if (!vault) {
      throw new Error(
        '`--vault` was set but VAULT_ADDR is not configured. Export VAULT_ADDR (and VAULT_TOKEN or VAULT_ROLE_ID+VAULT_SECRET_ID).'
      );
    }
    chain.push(vault);
  }

  if (opts.enableAws) {
    chain.push(AwsSecretsResolver.fromEnv(env));
  }

  return new ChainResolver(chain);
}
