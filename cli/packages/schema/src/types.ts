// Hand-curated types mirroring x-security.schema.json.
// Will be auto-regenerated via `pnpm gen:types` (json-schema-to-typescript) — keep in sync.

export type OwaspId =
  | 'API1:2023' | 'API2:2023' | 'API3:2023' | 'API4:2023' | 'API5:2023'
  | 'API6:2023' | 'API7:2023' | 'API8:2023' | 'API9:2023' | 'API10:2023';

/**
 * v0.6 W19: x-security-native security category id for classes OWASP-API-2023
 * does not enumerate. Kept separate from OwaspId so the 10 pure OWASP cells
 * cannot be overloaded (Rule D-1: overloading API8 would silently corrupt the
 * meaning of every existing API8 cell and re-open the DVAPI scoring bug).
 */
export type SsecId = 'SSEC-INJECTION' | 'SSEC-PROMPT' | 'SSEC-AUDIT' | 'SSEC-STORAGE';

/**
 * Union of OWASP-API ids and x-security-native ids. Reporters that iterate the
 * full category list (owasp-analyze, feasibility) key on this; `mitigates`
 * arrays authored on a policy stay OwaspId-only — SSEC attribution is *derived*
 * by probing capabilities (e.g. request.schema.<f>.injectionGuard), never
 * hand-authored, so the OWASP regex stays pure.
 */
export type SecurityCategoryId = OwaspId | SsecId;

export type VarRef = string; // ${ENV_VAR} or $vault.path
export type StringOrVarRef = string;
export type Duration = string; // e.g. "5m"
export type ByteSize = string; // e.g. "1MB"
export type Cidr = string;

export type SemanticType =
  | 'string' | 'integer' | 'float' | 'boolean'
  | 'email' | 'phone' | 'url' | 'date' | 'datetime'
  | 'uuid' | 'ip-address' | 'name' | 'free-text' | 'binary';

// v0.3 PW-1 (extended in v0.5 S-10): ref to a value resolved at request time.
// Pattern: ^(jwt|principal|session|header|request|resource)\.[A-Za-z0-9_.-]+$
export interface RuleRef {
  ref: string;
}

export type JwtAlgorithm =
  | 'RS256' | 'RS384' | 'RS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'EdDSA'
  | 'PS256' | 'PS384' | 'PS512';

/** v0.4 S-2: full algorithm space including symmetric + 'none' for the denylist. */
export type JwtBannedAlgorithm = JwtAlgorithm | 'HS256' | 'HS384' | 'HS512' | 'none';

export interface Authentication {
  type: 'bearer-jwt' | 'api-key' | 'oauth2' | 'mtls' | 'basic' | 'none' | 'custom-token';
  scopes?: string[];
  issuer?: StringOrVarRef;
  audience?: StringOrVarRef;
  jwksUri?: StringOrVarRef;
  headerName?: string;
  /** v0.4 S-1: required when type === 'custom-token'. Wire format of the opaque token. */
  tokenFormat?: 'opaque' | 'base64' | 'jwt';
  /** v0.4 S-1: optional introspection endpoint for opaque custom tokens. */
  validationEndpoint?: string;
  /** v0.3: required when type === 'bearer-jwt'. Asymmetric algorithms only. */
  allowedAlgorithms?: JwtAlgorithm[];
  /** v0.4 S-2: explicit denylist. Must not overlap with allowedAlgorithms. */
  bannedAlgorithms?: JwtBannedAlgorithm[];
  /** v0.5 S-12: MFA required for this endpoint. */
  mfaRequired?: boolean;
  /** v0.5 S-12: which locations the token may arrive in. */
  tokenSources?: ('header' | 'cookie' | 'query')[];
  /** v0.5 S-12: per-identifier brute-force lockout policy. */
  accountLockout?: AccountLockout;
  /** v0.5 S-12: password strength policy for body-carried passwords. */
  passwordPolicy?: PasswordPolicy;
  /** v0.5 S-16: rotate session id on successful auth (anti session-fixation). */
  sessionRotateOnAuth?: boolean;
  mitigates?: OwaspId[];
}

export interface AccountLockout {
  attempts: number;
  window: Duration;
  /** e.g. 'header:X-Username' or 'request.body.email' */
  identifier: string;
}

export interface PasswordPolicy {
  minLength?: number;
  requireUppercase?: boolean;
  requireDigit?: boolean;
  requireSymbol?: boolean;
  blocklist?: string[];
}

export type AuthorizationRuleValue =
  | string | number | boolean | Array<string | number | boolean>
  | RuleRef;

export interface AuthorizationRule {
  field: string;
  operator: 'equals' | 'not-equals' | 'in' | 'not-in' | 'matches' | 'contains';
  value: AuthorizationRuleValue;
}

export interface ResourceLookup {
  /** Path template, e.g. /users/{id} */
  endpoint: string;
  /** e.g. request.params.id */
  identifierFrom: string;
  /** Fields exposed to rules under the `resource.` namespace. */
  expose: string[];
}

export interface Authorization {
  type: 'rbac' | 'rule-based' | 'abac';
  roles?: string[];
  rules?: AuthorizationRule[];
  /** v0.3: resolve a resource before evaluating rules (BOLA defense). */
  resourceLookup?: ResourceLookup;
  attributes?: Record<string, unknown>;
  mitigates?: OwaspId[];
}

export type CsrfMethod = 'origin-check' | 'double-submit' | 'custom-header';

export interface Csrf {
  method: CsrfMethod;
  /** Required when method === 'origin-check'. */
  allowedOrigins?: string[];
  /** Required when method === 'double-submit' or 'custom-header'. */
  tokenHeader?: string;
  /** Required when method === 'double-submit'. */
  tokenCookie?: string;
}

export type RateLimitIdentifier =
  | string
  | string[]
  | { components: string[]; combinator?: 'concat' | 'distinct' | 'min-of' };

export interface RateLimit {
  requests: number;
  window: Duration;
  /** v0.4 S-6 array form / v0.5 S-14 object form with explicit combinator. */
  identifier?: RateLimitIdentifier;
  burst?: number;
  when?: 'authenticated' | 'unauthenticated';
  mitigates?: OwaspId[];
}

export interface Timeout {
  connect?: number;
  read?: number;
  write?: number;
}

export type Cacheable =
  | boolean
  | {
      enabled: boolean;
      ttl?: number;
      varyBy?: string[];
      /** v0.3: request headers stripped before cache-key compute. */
      unkeyedHeadersStrip?: string[];
    };

export interface Cors {
  allowedOrigins?: string[];
  allowedMethods?: ('GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS')[];
  allowedHeaders?: string[];
  exposeHeaders?: string[];
  maxAge?: number;
  credentials?: boolean;
}

export interface Mtls {
  enabled: boolean;
  clientCertRef?: VarRef;
  pinnedCertificates?: string[];
}

export interface IpPolicy {
  allow?: Cidr[] | VarRef;
  deny?: Cidr[] | VarRef;
}

export interface ParamSchema {
  type?: SemanticType;
  minLength?: number;
  maxLength?: number;
  fixedLength?: number;
  min?: number;
  max?: number;
  pattern?: string;
  domainAllowlist?: string[];
  /** v0.4 S-4: SSRF defense for url-typed params. Reject hosts resolving to RFC1918, link-local, loopback, ULA, or non-HTTP(S) schemes. */
  blockPrivateRanges?: boolean;
  /** v0.5 S-15: open-redirect defense — allowed redirect-target domains (literal or '*.example.com' glob). Only meaningful when type === 'url'. */
  redirectAllowedDomains?: string[];
  allowedMimeTypes?: string[];
  maxSize?: ByteSize;
  /** v0.3: verify declared MIME matches detected magic bytes. */
  magicByteCheck?: boolean;
  /** v0.3: lowercase, dot-prefixed extensions, e.g. ['.png','.jpg']. */
  extensionAllowlist?: string[];
  /** v0.3: reject double-extension filenames (e.g. invoice.pdf.exe). */
  denyDoubleExtension?: boolean;
  /**
   * v0.6 W19 (v0.7 adds 'deserialization' + 'ai-prompt'): opt-in per-arg
   * injection hardening. Declares which injection sink(s) this field flows
   * into so coraza/bunkerweb emit a native operator on
   * ARGS:<field>|ARGS:json.<field> ('sql' → @detectSQLi, 'os-command' →
   * shell-metachar denylist, 'nosql' → operator-token denylist, 'xss' →
   * @detectXSS, 'deserialization' → unsafe-deserialization preamble denylist
   * (node-serialize/Java rO0/PHP O:<n>:/python pickle), 'ai-prompt' → LLM
   * prompt-injection heuristic denylist, etc.). Per-arg and explicit,
   * replacing the implicit string-type heuristic. All sinks EXCEPT 'ai-prompt'
   * are attributed to SSEC-INJECTION; 'ai-prompt' is the distinct
   * x-security-native SSEC-PROMPT class. Never an OWASP-API cell.
   * Edge-enforceable on coraza/bunkerweb only.
   */
  injectionGuard?: ('sql' | 'nosql' | 'os-command' | 'xpath' | 'ldap' | 'code-eval' | 'xss' | 'deserialization' | 'ai-prompt')[];
  /**
   * Mark this parameter / response field as PII or otherwise sensitive.
   * Drives the data-exposure (id:428) filter in addition to the
   * SENSITIVE_FIELD_NAMES heuristic so spec authors can tag a field whose
   * name doesn't look sensitive (e.g. `nationalId`, `dob`).
   */
  pii?: boolean;
  mitigates?: OwaspId[];
}

export interface RequestSignature {
  algorithm: 'hmac-sha256' | 'hmac-sha1' | 'ed25519';
  headerName: string;
  secretRef: VarRef;
  body: 'raw' | 'canonical';
  timestampHeader?: string;
  /** 1..3600 seconds. */
  timestampToleranceSeconds?: number;
  /** v0.5 S-17: header carrying the per-request nonce. Required when nonceCacheTtl is set. */
  nonceHeader?: string;
  /** v0.5 S-17: dedupe TTL — reject any nonce seen within this window. Requires nonceHeader. */
  nonceCacheTtl?: Duration;
}

export interface IdempotencyKey {
  /** Header carrying the client idempotency key, e.g. 'Idempotency-Key'. */
  header: string;
  /** Dedupe window — a repeated key within this TTL is treated as a replay. */
  ttl: Duration;
}

/**
 * v0.8 (deferred-residuals, API6): live-concurrency serialization for a
 * sensitive business flow. PARTIAL AT BEST — the gateway can serialize
 * same-key requests at the edge but CANNOT make the app handler transaction
 * atomic. coraza/bunkerweb partial (crude SecCollection cap, not a mutex),
 * envoy override-only (operator-supplied limiter), kong/aws-apigw/cloudflare/
 * firewall/openappsec unsupported. Never full.
 */
export interface SerializeBy {
  /** RuleRef-style key, e.g. 'request.body.account_id' or 'jwt.sub'. */
  key: string;
  scope?: 'global' | 'per-identifier';
}

/**
 * v0.8 (deferred-residuals, SSEC-STORAGE): ADVISORY-DECLARATION ONLY. Declares
 * the at-rest protection posture the app is supposed to apply to named body
 * fields. NOT gateway-enforced — compiles to NOTHING enforcing (the gateway
 * never sees the DB write). Capability hard-pinned override-only/unsupported on
 * every target (never full, never partial). Documents posture + drives an
 * out-of-band SSEC-STORAGE scan finding; a finding, not a control.
 */
export interface DataAtRest {
  fields: string[];
  protection: 'encrypted' | 'hashed' | 'tokenized';
}

export interface RequestPolicy {
  contentType?: string[];
  maxBodySize?: ByteSize;
  schema?: Record<string, ParamSchema>;
  /** v0.3 PW-2: reject body fields outside `schema`. */
  denyUnknownFields?: boolean;
  /** v0.4 S-8: shorthand allowlist of top-level body fields. Cannot coexist with denyUnknownFields:false. */
  allowedFields?: string[];
  /** v0.8 (API6): DENYLIST of server-controlled fields a client must never set in
   *  the body — the mass-assignment defense that does NOT need a full allowlist.
   *  Reject the request if any of these top-level fields is present. Use for
   *  reserved/privileged keys (objectId, _id, role, isAdmin, __proto__, etc.) when
   *  the route persists `req.body` wholesale and the legitimate field set is open
   *  (schemaless create). Distinct from denyUnknownFields, which needs the allowed
   *  set enumerated. */
  denyFields?: string[];
  /** v0.4 S-3: server-side HTTP method enforcement (separate from CORS preflight). */
  allowedMethods?: ('GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS')[];
  /** v0.4 S-5: XXE defense — disable external entity / DTD resolution. */
  disableExternalEntities?: boolean;
  /** v0.4 S-5: reject application/xml, text/xml, application/*+xml. */
  disallowXml?: boolean;
  /** v0.3: webhook HMAC/Ed25519 signature verification. */
  signature?: RequestSignature;
  /** v0.7 (API6): replay / double-submit defense keyed on a client header. Partial — stops replay, not in-handler races. */
  idempotencyKey?: IdempotencyKey;
  /** v0.8 (API6): live-concurrency serialization key. Partial — edge serialization only, NOT in-handler atomicity. */
  serializeBy?: SerializeBy;
  /** v0.8 (API6): max in-flight requests for the serializeBy key (1 == strict serialize). Partial — edge only. */
  concurrencyLimit?: number;
  /** v0.8 (SSEC-STORAGE): ADVISORY-ONLY at-rest posture declaration. NOT gateway-enforced — compiles to nothing; drives a scan finding. */
  dataAtRest?: DataAtRest;
  /** v0.3: Host header allowlist. */
  allowedHosts?: string[];
  /** v0.3: HTTP Parameter Pollution defense. */
  duplicateParamPolicy?: 'first' | 'last' | 'reject';
  /** v0.3: reject CR/LF/NUL in header values. */
  headerInjectionGuard?: boolean;
  /** v0.3: canonicalize path before pattern checks. */
  pathCanonicalization?: boolean;
}

export interface CookieDefaults {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  path?: string;
  domain?: string;
  maxAge?: number;
}

export interface Hsts {
  maxAge: number;
  includeSubDomains?: boolean;
  preload?: boolean;
}

export interface ResponseHeaders {
  csp?: string;
  hsts?: Hsts;
  frameOptions?: 'DENY' | 'SAMEORIGIN';
  contentTypeOptions?: 'nosniff';
  referrerPolicy?:
    | 'no-referrer'
    | 'no-referrer-when-downgrade'
    | 'origin'
    | 'origin-when-cross-origin'
    | 'same-origin'
    | 'strict-origin'
    | 'strict-origin-when-cross-origin'
    | 'unsafe-url';
  permissionsPolicy?: string;
  coop?: 'unsafe-none' | 'same-origin-allow-popups' | 'same-origin';
  coep?: 'unsafe-none' | 'require-corp' | 'credentialless';
  corp?: 'same-site' | 'same-origin' | 'cross-origin';
  cacheControl?: string;
}

export interface ErrorScrubbing {
  stripStackTraces?: boolean;
  stripServerHeaders?: boolean;
  genericMessages?: boolean;
  /** Map of HTTP status (4xx/5xx) to replacement body. */
  statusOverride?: Record<string, string>;
}

export interface ResponsePolicy {
  contentType?: string[];
  schema?: Record<string, ParamSchema>;
  stripUnknownFields?: boolean;
  /** v0.7 (API3): JSON-hijacking defense — reject a bare top-level array response body. Default false. */
  forbidArrayRoot?: boolean;
  /** v0.3: response hardening headers. */
  headers?: ResponseHeaders;
  /** v0.3: Set-Cookie defaults. */
  cookies?: { defaults: CookieDefaults };
  /** v0.5 S-13: outbound error sanitization. */
  errorScrubbing?: ErrorScrubbing;
}

/**
 * v0.8 (deferred-residuals): per-OPERATION GraphQL policy bound to a named
 * field/operation the single POST /graphql route funnels. authz reuses the
 * Authorization grammar (rule-based jwt.sub==resource.owner → API1:2023 BOLA;
 * rbac → API5:2023 BFLA); per-operation cost limits override the block-level
 * coarse limits (API4:2023). OVERRIDE-ONLY on every target — a gateway cannot
 * evaluate per-resolver authz/cost without an operator-supplied GraphQL-aware
 * processor (the same gap as the response-schema ext_proc). x-security emits
 * scaffolding only; enforcement depends on the operator supplying the
 * processor. capKey graphql.operations.authz (authz) is distinct from the
 * coarse graphql.staticLimits capKey.
 */
export interface GraphqlOperation {
  name: string;
  operationType?: 'query' | 'mutation' | 'subscription';
  authz?: Authorization;
  maxDepth?: number;
  maxComplexity?: number;
  maxAliases?: number;
}

export interface GraphqlPolicy {
  maxDepth?: number;
  maxComplexity?: number;
  maxAliases?: number;
  batchLimit?: number;
  disableIntrospection?: boolean;
  allowedOperations?: ('query' | 'mutation' | 'subscription')[];
  /**
   * v0.8: per-operation policy (override-only everywhere; capKey
   * graphql.operations.authz). Additive — block-level limits stay coarse
   * (capKey graphql.staticLimits).
   */
  operations?: GraphqlOperation[];
}

export interface WebsocketPolicy {
  allowedOrigins: string[];
  maxMessageSize?: ByteSize;
  messageRateLimit?: { messages: number; window: Duration };
  maxConnectionsPerIdentifier?: number;
  idleTimeout?: Duration;
}

export interface BotProtection {
  provider: 'turnstile' | 'recaptcha' | 'hcaptcha';
  secretRef: VarRef;
  /** 0..1, default 0.5. */
  threshold?: number;
  mode: 'enforce' | 'observe';
}

export type TargetOverrides = Partial<Record<
  'kong' | 'kong-enterprise' | 'coraza' | 'bunkerweb' | 'openappsec' | 'firewall' | 'cloudflare' | 'aws-apigw',
  Record<string, unknown>
>>;

export interface OutboundCall {
  endpoint: string;
  signatureAlgorithm?: 'hmac-sha256' | 'hmac-sha512' | 'ed25519' | 'none';
  secretRef?: StringOrVarRef;
  timestampToleranceSeconds?: number;
  /** OpenAPI 3.0-style schema fragment for the expected response. */
  responseSchema?: Record<string, unknown>;
  timeoutMs?: number;
  allowedTlsVersions?: ('TLSv1.2' | 'TLSv1.3')[];
  mitigates?: OwaspId[];
}

export interface Tls {
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  allowedCipherSuites?: string[];
}

export type LoggingEvent =
  | 'auth-failure' | 'auth-success' | 'authz-deny'
  | 'rate-limit-trip' | 'injection-block' | 'request' | 'response';

export type LoggingSink = 'stdout' | 'file' | 'syslog' | 'http-collector';

/** v0.7 (SSEC-AUDIT): declarative audit/access logging policy. */
export interface Logging {
  events: LoggingEvent[];
  /** Defaults to 'stdout'. 'http-collector' requires sinkRef. */
  sink?: LoggingSink;
  /** Collector endpoint reference; required when sink === 'http-collector'. */
  sinkRef?: VarRef;
  /** Mask/omit declared pii fields from the emitted log line. Default false. */
  piiRedaction?: boolean;
}

export interface XSecurityPolicy {
  profile?: 'auth-endpoint' | 'standard-crud' | 'file-upload' | 'webhook-receiver' | 'public-read-only' | 'admin-panel' | 'server-rendered-page' | 'graphql-resolver' | 'grpc-method' | 'internal-rpc' | 'static-asset' | 'unknown';
  authentication?: Authentication;
  authorization?: Authorization;
  /** v0.3 */
  csrf?: Csrf;
  rateLimit?: RateLimit | RateLimit[];
  timeout?: Timeout;
  cacheable?: Cacheable;
  cors?: Cors;
  mtls?: Mtls;
  ipPolicy?: IpPolicy;
  request?: RequestPolicy;
  response?: ResponsePolicy;
  /** v0.7 (SSEC-AUDIT): declarative audit/access logging policy. */
  logging?: Logging;
  /** v0.3 */
  graphql?: GraphqlPolicy;
  /** v0.3 */
  websocket?: WebsocketPolicy;
  /** v0.3 */
  botProtection?: BotProtection;
  deprecated?: boolean;
  sunsetDate?: string;
  replacementEndpoint?: string;
  targetOverrides?: TargetOverrides;
  mitigates?: OwaspId[];
  /** v0.5 S-11: declared outbound calls (signed-request enforcement, response schema, TLS floor). */
  outboundCalls?: OutboundCall[];
  /** v0.5 S-18: TLS floor for inbound traffic to this endpoint. */
  tls?: Tls;
}
