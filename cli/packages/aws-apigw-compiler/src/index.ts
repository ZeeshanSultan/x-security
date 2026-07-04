// @writ/aws-apigw-compiler
// Pure-function policy compiler. Input: parsed/normalized OpenAPI spec
// (SpecIR from @writ/core). Output: AWS WAFv2 rules + API Gateway
// resource-policy fragments + Usage Plan specs.
// PRD v2 §6 (P1 — AWS API Gateway target). Deterministic; all blocking
// rules default to `Count` in shadow mode.

export { compile, stableStringify } from './compile.js';
export {
  endpointHash,
  endpointId,
  endpointNameSegment,
  normalizePath,
  pathMatchRegex
} from './endpoint.js';
export {
  parseByteSize,
  parseDurationSeconds,
  and,
  or,
  not,
  uriPathExact,
  methodEquals,
  headerPresent,
  headerMissing,
  headerStartsWith,
  headerEquals,
  headerIn,
  bodySizeGt
} from './statements.js';
export type {
  ApiGatewayModelSpec,
  ApiGatewayPolicyFragment,
  AwsCompileOptions,
  AwsCompileOutput,
  AwsScope,
  CapabilityEntry,
  CapabilityLevel,
  CloudFrontCachePolicySpec,
  CompileError,
  CompileWarning,
  Confidence,
  DeployMode,
  GatewayResponseSpec,
  IntegrationResponseMappingSpec,
  IPSetSpec,
  LambdaAuthorizerSpec,
  ObserveModeNote,
  ObserveModeSupport,
  RegexPatternSetSpec,
  RequestValidatorSpec,
  UnsupportedDirective,
  UsagePlanSpec,
  WafRuleAction,
  WafRuleActionKind,
  WafStatement,
  WafV2Rule,
  WebSocketRouteSpec
} from './types.js';
export { isObserveMode, modePrefix } from './shared.js';
export { capabilities, lookupCapability, AWS_APIGW_CAPABILITIES } from './capabilities.js';
