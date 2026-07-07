import type { EndpointIR } from '@x-security/core';
import type {
  CapabilityEntry,
  CapabilityLevel,
  CloudFrontCachePolicySpec,
  CompileError,
  CompileWarning,
  DeployMode,
  GatewayResponseSpec,
  IntegrationResponseMappingSpec,
  LambdaAuthorizerSpec,
  ObserveModeNote,
  ObserveModeSupport,
  RegexPatternSetSpec,
  RequestValidatorSpec,
  UnsupportedDirective,
  WafV2Rule,
  WebSocketRouteSpec
} from './types.js';
import { isObserveMode } from './shared.js';

export interface V3Builder {
  endpoint: EndpointIR;
  ehash: string;
  eid: string;
  ename: string;
  mode: DeployMode;
  scope: 'REGIONAL' | 'CLOUDFRONT';
  schemaVersion: string;
  prefix: string;
  warnings: CompileWarning[];
  unsupported: UnsupportedDirective[];
  errors: CompileError[];
  rules: WafV2Rule[];
  regexSets: RegexPatternSetSpec[];
  requestValidators: RequestValidatorSpec[];
  gatewayResponses: GatewayResponseSpec[];
  lambdaAuthorizers: LambdaAuthorizerSpec[];
  cloudFrontCachePolicies: CloudFrontCachePolicySpec[];
  integrationResponses: IntegrationResponseMappingSpec[];
  webSocketRoutes: WebSocketRouteSpec[];
  capabilityMatrix: CapabilityEntry[];
  observeModeNotes: ObserveModeNote[];
  priorityCursor: { value: number };
}

/**
 * Push a Lambda authorizer with mode + env-binding stamped automatically.
 * Callers pass the spec WITHOUT `mode`/`envBinding`; this helper stamps them
 * from the builder so every authorizer respects observe-mode uniformly.
 */
export function pushAuthorizer(
  b: V3Builder,
  spec: Omit<LambdaAuthorizerSpec, 'mode' | 'envBinding'>
): void {
  const envValue: 'observe' | 'enforce' = isObserveMode(b.mode) ? 'observe' : 'enforce';
  b.lambdaAuthorizers.push({
    ...spec,
    mode: b.mode,
    envBinding: { name: 'MODE', value: envValue }
  });
}

export function pushCapability(
  b: V3Builder,
  field: string,
  level: CapabilityLevel,
  primitive: string,
  note?: string,
  shadowModeSupport?: ObserveModeSupport
): void {
  const entry: CapabilityEntry = { endpoint_id: b.eid, field, level, primitive };
  if (typeof note === 'string') entry.note = note;
  if (shadowModeSupport !== undefined) entry.shadowModeSupport = shadowModeSupport;
  b.capabilityMatrix.push(entry);
}

/** Record a per-(endpoint, field) observe-mode note. */
export function noteObserveMode(
  b: V3Builder,
  field: string,
  support: ObserveModeSupport,
  message: string
): void {
  b.observeModeNotes.push({ endpoint_id: b.eid, field, support, message });
}

export function isRuleRef(v: unknown): v is { ref: string } {
  return !!v && typeof v === 'object' && typeof (v as { ref?: unknown }).ref === 'string';
}
