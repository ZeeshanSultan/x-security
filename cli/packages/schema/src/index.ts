import Ajv2020Mod, { type ErrorObject } from 'ajv/dist/2020.js';
import addFormatsMod from 'ajv-formats';
import Ajv04Mod from 'ajv-draft-04';
import schema from './x-security.schema.json' with { type: 'json' };
import owaspMapping from './owasp-mapping.json' with { type: 'json' };

// Ajv ships CJS; under ESM the default export materializes on `.default` at runtime.
// TS sees the namespace object, so we go through `any` to grab the actual constructor.
interface ValidateFn {
  (v: unknown): boolean;
  errors?: ErrorObject[] | null;
}
type AjvCtor = new (opts?: object) => { compile(s: object): ValidateFn };
type AddFormatsFn = (ajv: object) => void;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Ajv2020 = ((Ajv2020Mod as any).default ?? Ajv2020Mod) as unknown as AjvCtor;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Ajv04 = ((Ajv04Mod as any).default ?? Ajv04Mod) as unknown as AjvCtor;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addFormats = ((addFormatsMod as any).default ?? addFormatsMod) as unknown as AddFormatsFn;

export { schema as xSecuritySchema, owaspMapping };

// Dashboard API contracts (Zod). Available at the package root as `api.*`
// and also as the deep import `@x-security/schema/api`.
export * as api from './api/index.js';

export type {
  XSecurityPolicy,
  Authentication,
  JwtAlgorithm,
  Authorization,
  AuthorizationRule,
  AuthorizationRuleValue,
  ResourceLookup,
  RuleRef,
  AccountLockout,
  PasswordPolicy,
  Csrf,
  CsrfMethod,
  RateLimit,
  RateLimitIdentifier,
  Timeout,
  Cacheable,
  Cors,
  Mtls,
  IpPolicy,
  RequestPolicy,
  RequestSignature,
  IdempotencyKey,
  SerializeBy,
  DataAtRest,
  ResponsePolicy,
  ResponseHeaders,
  ErrorScrubbing,
  Hsts,
  OutboundCall,
  Tls,
  Logging,
  LoggingEvent,
  LoggingSink,
  CookieDefaults,
  GraphqlPolicy,
  GraphqlOperation,
  WebsocketPolicy,
  BotProtection,
  ParamSchema,
  SemanticType,
  TargetOverrides,
  OwaspId,
  SsecId,
  SecurityCategoryId,
  VarRef,
  StringOrVarRef,
  Duration,
  ByteSize,
  Cidr
} from './types.js';

export type ValidationResult =
  | { valid: true }
  | { valid: false; errors: ErrorObject[] };

const ajv2020 = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv2020);
const ajv04 = new Ajv04({ allErrors: true, strict: false });
addFormats(ajv04);

// For Ajv04 we strip the 2020-12 meta-schema reference — the x-security schema
// itself is dialect-agnostic; the dialect parameter only affects how parameter
// schemas are interpreted at use-time (handled in @x-security/core).
const schema04 = { ...(schema as Record<string, unknown>) };
delete schema04.$schema;

const validator2020 = ajv2020.compile(schema);
const validator04 = ajv04.compile(schema04);

/**
 * Validate an `x-security` block.
 * @param dialect "2020-12" for OpenAPI 3.1, "draft-04" for OpenAPI 3.0.
 */
export function validateXSecurity(
  value: unknown,
  dialect: '2020-12' | 'draft-04' = '2020-12'
): ValidationResult {
  const v = dialect === '2020-12' ? validator2020 : validator04;
  const ok = v(value);
  if (ok) return { valid: true };
  return { valid: false, errors: v.errors ?? [] };
}

// Bumped to match x-security.schema.json's $id. The drift test in
// test/schema-version.test.ts asserts this constant matches the version
// embedded in $id so the two cannot silently diverge.
export const SCHEMA_VERSION = '0.8.0';

/**
 * Extract the semver-ish version from the schema's $id, e.g.
 *   "https://usewaf.com/schemas/x-security/v0.4.json" → "0.4.0"
 * Trailing patch defaults to .0 if missing (the $id only encodes major.minor).
 */
export function extractSchemaVersionFromId(id: string): string | null {
  const m = id.match(/\/v(\d+)\.(\d+)(?:\.(\d+))?(?:\.json)?$/);
  if (!m) return null;
  return `${m[1]}.${m[2]}.${m[3] ?? '0'}`;
}
