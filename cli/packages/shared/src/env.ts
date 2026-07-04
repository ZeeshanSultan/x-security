// Centralised env loader. Each app/worker declares a zod schema; this loader
// parses `process.env`, rejects dev-sentinel defaults in production, and
// surfaces clear errors that point at the missing var.
//
// Why centralised: per-app loaders drifted. `.env.example` listed
// `OAUTH_ENC_KEY` but the api read `WRIT_ENCRYPTION_KEY`; the
// github-app accepted hex OR base64 keys while @writ/crypto accepted
// only base64 (silent data corruption when both apps wrote to the same
// encrypted column). The audit's Wave-1 plan calls for one loader that
// (a) names every secret it touches, (b) refuses dev defaults in prod, and
// (c) documents alias relationships explicitly.
//
// Usage:
//   const env = loadEnv(z.object({ DATABASE_URL: z.string().url(), ... }));
//   // env is typed, validated, and aliased per the declared schema.
import { z, type ZodTypeAny } from "zod";

/** Default set of dev-sentinel values that production must reject. */
export const DEV_SENTINELS: readonly string[] = Object.freeze([
  "change-me-internal",
  "dev-secret-do-not-use-in-prod",
  "changeme",
  "postgres", // POSTGRES_PASSWORD default
]);

export interface LoadEnvOptions {
  /** Source of env vars. Defaults to `process.env`. */
  source?: NodeJS.ProcessEnv;
  /** When true, reject dev-sentinel values. Defaults to `NODE_ENV === 'production'`. */
  rejectDevSentinels?: boolean;
  /** Extra sentinel strings to reject in addition to {@link DEV_SENTINELS}. */
  extraSentinels?: readonly string[];
  /**
   * Aliases: map of canonical-name → list of alternate env-var names to read
   * if the canonical one is unset. Resolved BEFORE schema validation. Each
   * alias resolution logs a one-line deprecation warning.
   */
  aliases?: Record<string, readonly string[]>;
  /** Override the prod-mode probe (defaults to `source.NODE_ENV === 'production'`). */
  isProduction?: (source: NodeJS.ProcessEnv) => boolean;
  /** Logger for alias-deprecation warnings. Defaults to console.warn. */
  warn?: (msg: string) => void;
}

export class EnvLoadError extends Error {
  constructor(
    message: string,
    public readonly issues: readonly string[],
  ) {
    super(message);
    this.name = "EnvLoadError";
  }
}

/**
 * Parse `source` against `schema`, returning a typed config. Throws
 * `EnvLoadError` with a list of issue strings on any validation failure.
 */
export function loadEnv<S extends z.ZodObject<Record<string, ZodTypeAny>>>(
  schema: S,
  opts: LoadEnvOptions = {},
): z.infer<S> {
  const source = opts.source ?? process.env;
  const isProd = opts.isProduction
    ? opts.isProduction(source)
    : source.NODE_ENV === "production";
  const rejectSentinels = opts.rejectDevSentinels ?? isProd;
  const sentinels = new Set<string>([...DEV_SENTINELS, ...(opts.extraSentinels ?? [])]);
  const warn = opts.warn ?? ((m: string) => console.warn(m));

  // Resolve aliases. We copy the source into a mutable map so the original
  // process.env is never mutated.
  const resolved: Record<string, string | undefined> = { ...source };
  for (const [canonical, alts] of Object.entries(opts.aliases ?? {})) {
    if (resolved[canonical] !== undefined && resolved[canonical] !== "") continue;
    for (const alt of alts) {
      if (resolved[alt] !== undefined && resolved[alt] !== "") {
        resolved[canonical] = resolved[alt];
        warn(`env: ${alt} is deprecated — use ${canonical} instead`);
        break;
      }
    }
  }

  // Apply zod parse.
  const parsed = schema.safeParse(resolved);
  const issues: string[] = [];
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      issues.push(`${issue.path.join(".") || "<root>"}: ${issue.message}`);
    }
  }

  // Sentinel rejection: only runs when parse succeeded (so we have typed data),
  // and only in prod-mode. We re-check the RAW source (not the parsed value)
  // because zod may coerce.
  if (parsed.success && rejectSentinels) {
    for (const key of Object.keys(schema.shape)) {
      const raw = resolved[key];
      if (typeof raw === "string" && sentinels.has(raw)) {
        issues.push(
          `${key}: matches a known dev-sentinel ("${raw}") — refusing to boot in production`,
        );
      }
    }
  }

  if (issues.length > 0) {
    throw new EnvLoadError(
      `Environment validation failed (${issues.length} issue${issues.length === 1 ? "" : "s"}):\n  - ${issues.join("\n  - ")}`,
      issues,
    );
  }
  return parsed.data!;
}

// -- Reusable schema fragments ------------------------------------------

/** Postgres connection string. */
export const DatabaseUrl = z.string().min(1).startsWith("postgres", { message: "must start with 'postgres'" });

/** Redis connection string. */
export const RedisUrl = z.string().min(1).startsWith("redis", { message: "must start with 'redis'" });

/** Strong-secret string (≥ 32 chars; pick what fits your KDF). */
export const StrongSecret = z
  .string()
  .min(32, { message: "must be at least 32 chars (e.g. `openssl rand -hex 32`)" });

/** Base64-encoded 32-byte key (AES-256-GCM). 44 chars unpadded, 44 padded. */
export const Base64Key32 = z
  .string()
  .regex(/^[A-Za-z0-9+/]{43}=?$/, {
    message: "must be base64-encoded 32 bytes (e.g. `openssl rand -base64 32`)",
  });

/** Hex-encoded 32-byte key. */
export const HexKey32 = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/, {
    message: "must be hex-encoded 32 bytes (e.g. `openssl rand -hex 32`)",
  });

/** TCP port number. */
export const Port = z.coerce
  .number()
  .int()
  .min(1)
  .max(65535);

/** URL with explicit scheme. */
export const HttpUrl = z.string().url();
