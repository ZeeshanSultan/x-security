/**
 * AWS WAFv2 + API Gateway shapes.
 *
 * We only model the fields we emit. The WAFv2 API (`@aws-sdk/client-wafv2`)
 * accepts unknown fields but rejects unexpected ones — we mirror the documented
 * Statement shapes from the AWS WAFv2 API reference closely.
 *
 * Refs:
 *   https://docs.aws.amazon.com/waf/latest/APIReference/API_Statement.html
 *   https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html
 *   https://docs.aws.amazon.com/apigateway/latest/api/API_UsagePlan.html
 */

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';
/**
 * Mode passed to the compiler.
 * - 'observe': blocking rules emit WAFv2 `Count`; Lambda authorizers
 *   always Allow but log `wouldDeny: true`. **Default for newly generated
 *   policies** per the rev 3 rollout plan.
 * - 'shadow': legacy alias for 'observe'. Kept for backward compat.
 * - 'enforce': blocking rules use `Block`; authorizers actually deny.
 */
export type DeployMode = 'observe' | 'shadow' | 'enforce';

/** Per-field observe-mode classification (mirrors the Cloudflare compiler). */
export type ObserveModeSupport =
  | 'simulatable'      // would-be block becomes Count / authorizer Allow + log.
  | 'always-applied'   // applied regardless of mode (request validators, gateway responses, integration responses, CloudFront response-headers policy).
  | 'partial';         // some sub-behavior simulatable, some always-applied.

/** WAFv2 rule action — `Count` is shadow/log, `Block` enforces. */
export type WafRuleActionKind = 'Allow' | 'Block' | 'Count' | 'Challenge' | 'CAPTCHA';

export interface WafRuleAction {
  Allow?: Record<string, unknown>;
  Block?: { CustomResponse?: { ResponseCode: number } };
  Count?: Record<string, unknown>;
  Challenge?: Record<string, unknown>;
  CAPTCHA?: Record<string, unknown>;
}

/** Field-to-match (request component WAFv2 inspects). */
export type FieldToMatch =
  | { Body: { OversizeHandling?: 'CONTINUE' | 'MATCH' | 'NO_MATCH' } }
  | { Headers: { MatchPattern: { All?: Record<string, never>; IncludedHeaders?: string[] }; MatchScope: 'ALL' | 'KEY' | 'VALUE'; OversizeHandling?: 'CONTINUE' | 'MATCH' | 'NO_MATCH' } }
  | { SingleHeader: { Name: string } }
  | { Method: Record<string, never> }
  | { QueryString: Record<string, never> }
  | { UriPath: Record<string, never> }
  | { SingleQueryArgument: { Name: string } }
  | { JsonBody: { MatchPattern: { All?: Record<string, never>; IncludedPaths?: string[] }; MatchScope: 'ALL' | 'KEY' | 'VALUE'; InvalidFallbackBehavior?: 'MATCH' | 'NO_MATCH' | 'EVALUATE_AS_STRING' } };

export type TextTransformation = {
  Priority: number;
  Type: 'NONE' | 'COMPRESS_WHITE_SPACE' | 'HTML_ENTITY_DECODE' | 'LOWERCASE' | 'URL_DECODE' | 'CMD_LINE' | 'BASE64_DECODE';
};

export interface ByteMatchStatement {
  SearchString: string;
  FieldToMatch: FieldToMatch;
  TextTransformations: TextTransformation[];
  PositionalConstraint: 'EXACTLY' | 'STARTS_WITH' | 'ENDS_WITH' | 'CONTAINS' | 'CONTAINS_WORD';
}

export interface SqliMatchStatement {
  FieldToMatch: FieldToMatch;
  TextTransformations: TextTransformation[];
  SensitivityLevel?: 'LOW' | 'HIGH';
}

export interface XssMatchStatement {
  FieldToMatch: FieldToMatch;
  TextTransformations: TextTransformation[];
}

export interface SizeConstraintStatement {
  FieldToMatch: FieldToMatch;
  ComparisonOperator: 'EQ' | 'NE' | 'LE' | 'LT' | 'GE' | 'GT';
  Size: number;
  TextTransformations: TextTransformation[];
}

export interface IPSetReferenceStatement {
  ARN: string;
}

export interface RegexPatternSetReferenceStatement {
  ARN: string;
  FieldToMatch: FieldToMatch;
  TextTransformations: TextTransformation[];
}

export interface RateBasedStatement {
  Limit: number;
  AggregateKeyType: 'IP' | 'FORWARDED_IP' | 'CUSTOM_KEYS' | 'CONSTANT';
  EvaluationWindowSec?: 60 | 120 | 300 | 600;
  ScopeDownStatement?: WafStatement;
  ForwardedIPConfig?: { HeaderName: string; FallbackBehavior: 'MATCH' | 'NO_MATCH' };
}

export interface LabelMatchStatement {
  Scope: 'LABEL' | 'NAMESPACE';
  Key: string;
}

export interface ManagedRuleGroupStatement {
  VendorName: string;
  Name: string;
  Version?: string;
  ExcludedRules?: { Name: string }[];
  RuleActionOverrides?: { Name: string; ActionToUse: WafRuleAction }[];
}

/** Recursive WAFv2 statement — only one field set at a time. */
export interface WafStatement {
  ByteMatchStatement?: ByteMatchStatement;
  SqliMatchStatement?: SqliMatchStatement;
  XssMatchStatement?: XssMatchStatement;
  SizeConstraintStatement?: SizeConstraintStatement;
  IPSetReferenceStatement?: IPSetReferenceStatement;
  RegexPatternSetReferenceStatement?: RegexPatternSetReferenceStatement;
  RateBasedStatement?: RateBasedStatement;
  LabelMatchStatement?: LabelMatchStatement;
  ManagedRuleGroupStatement?: ManagedRuleGroupStatement;
  AndStatement?: { Statements: WafStatement[] };
  OrStatement?: { Statements: WafStatement[] };
  NotStatement?: { Statement: WafStatement };
}

export interface WafV2Rule {
  /** Stable ID: `x-security-<mode>-<endpoint-hash>-<rule-type>` */
  Name: string;
  /** Priority, lower runs first. Assigned deterministically by compiler. */
  Priority: number;
  Statement: WafStatement;
  Action?: WafRuleAction;          // mutually exclusive with OverrideAction
  OverrideAction?: { None: Record<string, never> } | { Count: Record<string, never> };
  VisibilityConfig: {
    SampledRequestsEnabled: boolean;
    CloudWatchMetricsEnabled: boolean;
    MetricName: string;
  };
  /** Effective mode for this rule. observe → Count; enforce → Block. */
  mode: DeployMode;
  /** x-security provenance — round-tripped via the Name (AWS WAF has no `ref` field). */
  xSecurity: {
    endpoint_id: string;
    rule_type: string;
    source_field: string;
    confidence: Confidence;
    schema_version: string;
  };
}

export interface IPSetSpec {
  Name: string;
  Description: string;
  Scope: 'CLOUDFRONT' | 'REGIONAL';
  IPAddressVersion: 'IPV4' | 'IPV6';
  Addresses: string[];
}

export interface RegexPatternSetSpec {
  Name: string;
  Description: string;
  Scope: 'CLOUDFRONT' | 'REGIONAL';
  RegularExpressionList: { RegexString: string }[];
}

/** Fragment that the caller stitches into an API Gateway resource policy doc. */
export interface ApiGatewayPolicyFragment {
  Effect: 'Allow' | 'Deny';
  Principal: '*' | { AWS: string[] };
  Action: 'execute-api:Invoke' | string;
  Resource: string;     // arn:aws:execute-api:<region>:<acct>:<api-id>/<stage>/<method>/<path>
  Condition?: Record<string, Record<string, string | string[]>>;
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * API Gateway Request Validator + Model. Emitted when v0.3 features
 * `request.denyUnknownFields` or `request.schema` need server-side enforcement
 * at the Gateway tier (API GW JSON Schema model w/ `additionalProperties: false`).
 */
export interface RequestValidatorSpec {
  /** Resource name customer uses in CloudFormation/CDK. */
  Name: string;
  /** API Gateway validator flags. */
  ValidateRequestBody: boolean;
  ValidateRequestParameters: boolean;
  /** Reference to a Model resource (JSON Schema). */
  ModelName?: string;
  Model?: ApiGatewayModelSpec;
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/** API Gateway Model (JSON Schema body validator). */
export interface ApiGatewayModelSpec {
  Name: string;
  ContentType: 'application/json' | string;
  Schema: Record<string, unknown>; // JSON Schema (draft-04 for REST APIs)
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * Gateway Response override — API Gateway emits the configured headers on
 * matching response types. Used for 4xx/5xx hardening header injection.
 */
export interface GatewayResponseSpec {
  /** API Gateway ResponseType (e.g. DEFAULT_4XX, DEFAULT_5XX, UNAUTHORIZED). */
  ResponseType: string;
  StatusCode?: string;
  ResponseParameters?: Record<string, string>;  // gatewayresponse.header.* keys
  ResponseTemplates?: Record<string, string>;
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * Lambda authorizer config emitted when API Gateway lacks a native primitive
 * (HMAC verification, JWT alg allowlist enforcement, RuleRef resolution,
 * resourceLookup, CSRF double-submit, bot-protection siteverify, etc).
 *
 * The compiler does NOT emit Lambda source — it emits the authorizer config
 * + a `template` field describing what the function must implement. The
 * connector / customer wires the runtime.
 */
export interface LambdaAuthorizerSpec {
  Name: string;
  Type: 'REQUEST' | 'TOKEN';
  IdentitySource?: string[];
  /** Result TTL, seconds. 0 disables caching. */
  AuthorizerResultTtlInSeconds?: number;
  /** What the authorizer must enforce — used as a code-gen hint. */
  template: {
    kind:
      | 'jwt-alg-allowlist'
      | 'jwt-ruleref'
      | 'resource-lookup'
      | 'hmac-signature'
      | 'csrf-double-submit'
      | 'csrf-custom-header'
      | 'bot-protection-siteverify'
      | 'mime-magic-byte'
      | 'duplicate-param-policy'
      | 'graphql-limits'
      | 'composite';
    config: Record<string, unknown>;
  };
  /**
   * Effective mode. In `observe` the authorizer always returns Allow but emits a
   * CloudWatch log entry with `wouldDeny: true, reasons: [...]`. In `enforce`
   * it returns Deny on policy failure. The handler reads `process.env.MODE`
   * to switch behavior at runtime — flipping the env var promotes observe →
   * enforce without redeploy.
   */
  mode: DeployMode;
  /** Env var the handler reads: `MODE=observe` or `MODE=enforce`. */
  envBinding: { name: 'MODE'; value: 'observe' | 'enforce' };
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * CloudFront cache policy emitted when the customer's API is fronted by
 * CloudFront and `cacheable.unkeyedHeadersStrip` is set. The compiler emits
 * this even when scope=REGIONAL but adds a warning.
 */
export interface CloudFrontCachePolicySpec {
  Name: string;
  ParametersInCacheKeyAndForwardedToOrigin: {
    HeadersConfig: {
      /** "none" so the listed unkeyed headers aren't part of the key. */
      HeaderBehavior: 'none' | 'whitelist' | 'allViewer';
      Headers?: string[];
    };
    CookiesConfig: { CookieBehavior: 'none' | 'whitelist' | 'all' };
    QueryStringsConfig: { QueryStringBehavior: 'none' | 'whitelist' | 'all' };
    EnableAcceptEncodingGzip: boolean;
    EnableAcceptEncodingBrotli: boolean;
  };
  /** Headers the policy strips from the request before forwarding. */
  StrippedRequestHeaders: string[];
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * Integration response parameter mapping (REST API) for response-header
 * injection on 2xx and Set-Cookie defaults.
 *
 * Maps to API Gateway `IntegrationResponse.ResponseParameters`, keyed by
 * `method.response.header.<Name>` → static or `'integration.response.header.<Name>'`.
 */
export interface IntegrationResponseMappingSpec {
  /** HTTP status code this mapping applies to (e.g. "200", "default"). */
  StatusCode: string;
  /** Map of API GW response-parameter keys → mapping expressions. */
  ResponseParameters: Record<string, string>;
  /** Optional VTL transforms for Set-Cookie defaults. */
  ResponseTemplates?: Record<string, string>;
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * WebSocket route config (for $connect handshake controls). API GW WebSocket
 * APIs gate origin/auth at the $connect route.
 */
export interface WebSocketRouteSpec {
  /** Conceptual route key, e.g. `$connect`. */
  RouteKey: '$connect' | '$disconnect' | '$default' | string;
  /** Origin allowlist enforced via the WAF rule + Lambda authorizer. */
  AllowedOrigins: string[];
  /** Per-connection limits (advisory — enforced by usage plan / custom auth). */
  IdleTimeoutSeconds?: number;
  MaxConnectionsPerIdentifier?: number;
  /** Per-message constraints — enforced by attached Lambda. */
  MaxMessageSizeBytes?: number;
  MessageRateLimit?: { messages: number; windowSeconds: number };
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

/**
 * Per-feature capability classification — surfaced in the output so the UI /
 * deploy summary can show how completely each v0.3 directive was mapped to
 * AWS primitives. The matrix is intentionally a flat array indexed by
 * `(endpoint_id, field)`; consumers can pivot as needed.
 */
export type CapabilityLevel = 'full' | 'partial' | 'override-only' | 'unsupported';

export interface CapabilityEntry {
  endpoint_id: string;
  field: string;
  level: CapabilityLevel;
  primitive: string;
  note?: string;
  /**
   * How this field behaves in observe-mode. Helps customers (and dashboards)
   * answer "is this field fully simulatable while the policy is in observe,
   * or is it always-applied regardless of mode?"
   */
  shadowModeSupport?: ObserveModeSupport;
}

/**
 * Per-(endpoint, field) note about whether the policy can be faithfully
 * simulated in observe-mode. Surfaces "always-applied" fields (request
 * validators, gateway responses, integration response mapping, CloudFront
 * response-headers policy) so customers don't assume "observe" means
 * "absolutely nothing changes."
 */
export interface ObserveModeNote {
  endpoint_id?: string;
  field: string;
  support: ObserveModeSupport;
  message: string;
}

/** Usage Plan (API key-scoped throttling). API GW emits in this shape. */
export interface UsagePlanSpec {
  Name: string;
  Description: string;
  Throttle: { RateLimit: number; BurstLimit: number };
  Quota?: { Limit: number; Period: 'DAY' | 'WEEK' | 'MONTH' };
  ApiStages?: { ApiId: string; Stage: string }[];
  xSecurity: {
    endpoint_id: string;
    source_field: string;
  };
}

export interface CompileWarning {
  endpoint_id?: string;
  field: string;
  message: string;
  severity: 'info' | 'warn';
}

export interface UnsupportedDirective {
  endpoint_id?: string;
  directive: string;
  reason: string;
}

export interface AwsCompileOutput {
  /** Rules to insert into the customer's WebACL (callers append to existing rules). */
  webAclRules: WafV2Rule[];
  /** IP allow/deny sets — caller creates these and substitutes ARNs into rules. */
  ipSets: IPSetSpec[];
  /** Regex pattern sets (e.g. AI footgun, allowlist). */
  regexPatternSets: RegexPatternSetSpec[];
  /** API Gateway resource-policy statements. */
  apiGatewayResourcePolicies: ApiGatewayPolicyFragment[];
  /** Usage plans for API-key-scoped rate limits. */
  usagePlans: UsagePlanSpec[];
  /** v0.3: request validators + JSON Schema models (denyUnknownFields). */
  requestValidators: RequestValidatorSpec[];
  /** v0.3: Gateway Responses (4xx/5xx header injection). */
  gatewayResponses: GatewayResponseSpec[];
  /** v0.3: Lambda authorizers (HMAC, JWT alg, RuleRef, resourceLookup, CSRF, bot, etc). */
  lambdaAuthorizers: LambdaAuthorizerSpec[];
  /** v0.3: CloudFront cache policies (unkeyedHeadersStrip; requires CF in front). */
  cloudFrontCachePolicies: CloudFrontCachePolicySpec[];
  /** v0.3: Integration response parameter mappings (2xx response headers + cookie defaults). */
  integrationResponses: IntegrationResponseMappingSpec[];
  /** v0.3: WebSocket route specs. */
  webSocketRoutes: WebSocketRouteSpec[];
  /** v0.3: per-(endpoint, field) capability classification. */
  capabilityMatrix: CapabilityEntry[];
  /** Soft warnings — cost callouts, plan limits, rounding. */
  warnings: CompileWarning[];
  /** Hard-unsupported directives (e.g. IDOR/BOLA mitigations not possible in WAF). */
  unsupportedDirectives: UnsupportedDirective[];
  /**
   * Per-field observe-mode notes. Surfaces always-applied fields (request
   * validators, gateway responses, etc.) so customers know which directives
   * still take effect during the observation window.
   */
  observeModeNotes: ObserveModeNote[];
  /** Schema-level fatal errors (e.g. bearer-jwt missing allowedAlgorithms) — fail-closed. */
  errors: CompileError[];
  /** Stable SHA-256 of the entire compiled output for drift detection. */
  contentHash: string;
}

export interface CompileError {
  endpoint_id?: string;
  field: string;
  message: string;
}

/** Plan/region selection for the compiler. */
export type AwsScope = 'REGIONAL' | 'CLOUDFRONT';

export interface AwsCompileOptions {
  /**
   * Deploy mode. Defaults to `'observe'` per the rev 3 rollout plan — newly
   * generated policies never auto-enforce. In observe mode WAFv2 rules use
   * `Count`, Lambda authorizers always return Allow but log `wouldDeny: true`.
   */
  mode?: DeployMode;
  /** `REGIONAL` for API Gateway, `CLOUDFRONT` for CloudFront-fronted APIs. Default REGIONAL. */
  scope?: AwsScope;
  /** Schema version stamped on each rule. */
  schemaVersion?: string;
  /** Ruleset name prefix — defaults to `x-security-shadow` (shadow) / `x-security` (enforce). */
  namePrefix?: string;
  /** Initial priority offset (rules get sequential priorities starting here). Default 0. */
  basePriority?: number;
  /** Enable AWS Managed Bot Control rule group if `x-security.botProtection` is true. */
  enableManagedBotControl?: boolean;
}
