import { UnresolvedVariableError } from './errors.js';

export interface VariableResolver {
  /**
   * Resolve a variable reference. May return synchronously or asynchronously.
   * Synchronous resolvers (env, in-memory stub) return a string|undefined; remote
   * resolvers (HashiCorp Vault, AWS Secrets Manager) return a Promise.
   */
  resolve(ref: string): string | undefined | Promise<string | undefined>;
}

export class EnvResolver implements VariableResolver {
  constructor(private env: NodeJS.ProcessEnv = process.env) {}
  resolve(ref: string): string | undefined {
    const m = ref.match(/^\$\{([A-Z_][A-Z0-9_]*)\}$/);
    if (!m) return undefined;
    return this.env[m[1]!];
  }
}

/**
 * In-memory stub vault resolver. Kept for tests and back-compat; production
 * deployments should use VaultResolver / AwsSecretsResolver from `./resolvers`.
 */
export class StubVaultResolver implements VariableResolver {
  constructor(private secrets: Record<string, string> = {}) {}
  resolve(ref: string): string | undefined {
    const m = ref.match(/^\$vault\.(.+)$/);
    if (!m) return undefined;
    return this.secrets[m[1]!];
  }
}

export class ChainResolver implements VariableResolver {
  constructor(private resolvers: VariableResolver[]) {}
  async resolve(ref: string): Promise<string | undefined> {
    for (const r of this.resolvers) {
      const v = await r.resolve(ref);
      if (v !== undefined) return v;
    }
    return undefined;
  }
}

const VAR_PATTERN = /(\$\{[A-Z_][A-Z0-9_]*\}|\$vault\.[A-Za-z0-9_./#-]+|\$aws\.[A-Za-z0-9_./#:-]+)/g;

export interface ResolveOptions {
  resolver: VariableResolver;
  /** If true, throws on unresolved. If false, leaves them as-is (lenient). */
  strict?: boolean;
}

export interface ResolveResult<T> {
  value: T;
  resolved: Map<string, string>;
  unresolved: string[];
}

/**
 * Recursively walk a value and replace all variable references in string leaves.
 * Async — resolvers may perform network I/O (Vault, AWS).
 * R1.14, R2.10.
 */
export async function resolveVariables<T>(input: T, opts: ResolveOptions): Promise<ResolveResult<T>> {
  const resolved = new Map<string, string>();
  const unresolvedSet = new Set<string>();

  // Two-pass: collect refs, resolve them all (concurrently, deduped), then substitute.
  const refs = new Set<string>();
  const collect = (v: unknown): void => {
    if (v === null || v === undefined) return;
    if (typeof v === 'string') {
      const matches = v.match(VAR_PATTERN);
      if (matches) for (const m of matches) refs.add(m);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach(collect);
      return;
    }
    if (typeof v === 'object') {
      for (const val of Object.values(v as Record<string, unknown>)) collect(val);
    }
  };
  collect(input);

  // Resolve all references (deduped) — concurrent. Errors propagate so e.g.
  // a "Vault unreachable" is surfaced rather than silently treated as unresolved.
  const entries = await Promise.all(
    Array.from(refs).map(async (ref) => {
      const v = await opts.resolver.resolve(ref);
      return [ref, v] as const;
    })
  );
  const lookup = new Map<string, string | undefined>(entries);

  const walk = (v: unknown): unknown => {
    if (v === null || v === undefined) return v;
    if (typeof v === 'string') {
      return v.replace(VAR_PATTERN, (match) => {
        const r = lookup.get(match);
        if (r !== undefined) {
          resolved.set(match, r);
          return r;
        }
        unresolvedSet.add(match);
        return match;
      });
    }
    if (Array.isArray(v)) return v.map(walk);
    if (typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = walk(val);
      return out;
    }
    return v;
  };

  const value = walk(input) as T;
  const unresolved = Array.from(unresolvedSet);
  if (opts.strict && unresolved.length > 0) {
    throw new UnresolvedVariableError(unresolved);
  }
  return { value, resolved, unresolved };
}
