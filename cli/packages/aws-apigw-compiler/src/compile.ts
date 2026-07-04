import { createHash } from 'node:crypto';
import type { SpecIR } from '@writ/core';
import {
  and,
  methodEquals,
  uriPathExact
} from './statements.js';
import { endpointHash, endpointId, endpointNameSegment } from './endpoint.js';
import { compileV2, type V2Builder } from './v2.js';
import { compileV3, type V3Builder } from './v3.js';
import type {
  ApiGatewayPolicyFragment,
  AwsCompileOptions,
  AwsCompileOutput,
  CapabilityEntry,
  CloudFrontCachePolicySpec,
  CompileError,
  CompileWarning,
  DeployMode,
  GatewayResponseSpec,
  IntegrationResponseMappingSpec,
  IPSetSpec,
  LambdaAuthorizerSpec,
  ObserveModeNote,
  RegexPatternSetSpec,
  RequestValidatorSpec,
  UnsupportedDirective,
  UsagePlanSpec,
  WafV2Rule,
  WebSocketRouteSpec
} from './types.js';
import { isObserveMode } from './shared.js';

const SCHEMA_VERSION_DEFAULT = '0.3.0';

/**
 * Pure function: compile a normalized OpenAPI spec into AWS WAFv2 rules +
 * API Gateway resource-policy fragments + Usage Plans + v0.3 artifacts
 * (request validators, gateway responses, Lambda authorizer configs,
 * CloudFront cache policies, integration responses, WebSocket routes).
 *
 * Deterministic — same input always yields byte-identical output.
 *
 * Output is plain JSON. The compiler does not call AWS — that is the
 * connector's job.
 */
export function compile(spec: SpecIR, options: AwsCompileOptions = {}): AwsCompileOutput {
  // Default per the rev 3 rollout plan: newly generated policies ship in observe.
  const mode: DeployMode = options.mode ?? 'observe';
  const scope = options.scope ?? 'REGIONAL';
  const schemaVersion = options.schemaVersion ?? SCHEMA_VERSION_DEFAULT;
  const defaultPrefix =
    mode === 'enforce'
      ? 'writ'
      : mode === 'shadow'
        ? 'writ-shadow'    // back-compat for legacy callers.
        : 'writ-observe';
  const prefix = options.namePrefix ?? defaultPrefix;
  const enableManagedBotControl = options.enableManagedBotControl ?? false;
  const basePriority = options.basePriority ?? 0;

  const warnings: CompileWarning[] = [];
  const unsupported: UnsupportedDirective[] = [];
  const errors: CompileError[] = [];
  const rules: WafV2Rule[] = [];
  const ipSets: IPSetSpec[] = [];
  const regexSets: RegexPatternSetSpec[] = [];
  const apigwPolicies: ApiGatewayPolicyFragment[] = [];
  const usagePlans: UsagePlanSpec[] = [];
  const requestValidators: RequestValidatorSpec[] = [];
  const gatewayResponses: GatewayResponseSpec[] = [];
  const lambdaAuthorizers: LambdaAuthorizerSpec[] = [];
  const cloudFrontCachePolicies: CloudFrontCachePolicySpec[] = [];
  const integrationResponses: IntegrationResponseMappingSpec[] = [];
  const webSocketRoutes: WebSocketRouteSpec[] = [];
  const capabilityMatrix: CapabilityEntry[] = [];
  const observeModeNotes: ObserveModeNote[] = [];

  const priorityCursor = { value: basePriority };

  const ordered = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );

  for (const ep of ordered) {
    const ehash = endpointHash(ep.method, ep.path);
    const eid = endpointId(ep.method, ep.path);
    const ename = endpointNameSegment(ep.method, ep.path);
    const baseMatch = and(methodEquals(ep.method), uriPathExact(ep.path));
    const policy = ep.policy ?? {};

    // v0.3 hard-error pre-check: bearer-jwt MUST have allowedAlgorithms. Per
    // the design doc, refuse to emit ANY gateway config for the endpoint if
    // missing.
    if (
      policy.authentication?.type === 'bearer-jwt' &&
      (!policy.authentication.allowedAlgorithms || policy.authentication.allowedAlgorithms.length === 0)
    ) {
      errors.push({
        endpoint_id: eid,
        field: 'authentication.allowedAlgorithms',
        message:
          "authentication.type 'bearer-jwt' REQUIRES allowedAlgorithms (asymmetric algs only — RS*/ES*/PS*/EdDSA). " +
          'Refusing to emit gateway config for this endpoint to avoid JWT-algorithm-confusion class bugs.'
      });
      continue;
    }

    const v2b: V2Builder = {
      endpoint: ep,
      ehash, eid, ename,
      mode, scope, schemaVersion, prefix,
      enableManagedBotControl,
      warnings, unsupported, errors,
      rules, ipSets, regexSets, apigwPolicies, usagePlans,
      priorityCursor
    };
    compileV2(v2b, baseMatch);

    const v3b: V3Builder = {
      endpoint: ep,
      ehash, eid, ename,
      mode, scope, schemaVersion, prefix,
      warnings, unsupported, errors,
      rules, regexSets,
      requestValidators,
      gatewayResponses,
      lambdaAuthorizers,
      cloudFrontCachePolicies,
      integrationResponses,
      webSocketRoutes,
      capabilityMatrix,
      observeModeNotes,
      priorityCursor
    };
    compileV3(v3b, baseMatch);
  }

  // Deterministic ordering for observe-mode notes so contentHash is stable.
  observeModeNotes.sort((a, b) =>
    (a.endpoint_id ?? '').localeCompare(b.endpoint_id ?? '') ||
    a.field.localeCompare(b.field) ||
    a.message.localeCompare(b.message)
  );

  const contentHash = hashContent({
    rules,
    ipSets,
    regexSets,
    apigwPolicies,
    usagePlans,
    requestValidators,
    gatewayResponses,
    lambdaAuthorizers,
    cloudFrontCachePolicies,
    integrationResponses,
    webSocketRoutes,
    capabilityMatrix,
    observeModeNotes,
    unsupported,
    errors
  });

  return {
    webAclRules: rules,
    ipSets,
    regexPatternSets: regexSets,
    apiGatewayResourcePolicies: apigwPolicies,
    usagePlans,
    requestValidators,
    gatewayResponses,
    lambdaAuthorizers,
    cloudFrontCachePolicies,
    integrationResponses,
    webSocketRoutes,
    capabilityMatrix,
    observeModeNotes,
    warnings,
    unsupportedDirectives: unsupported,
    errors,
    contentHash
  };
}

function hashContent(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

/** Deterministic JSON stringify — object keys sorted recursively. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map(k => JSON.stringify(k) + ':' + stableStringify((value as Record<string, unknown>)[k]));
  return '{' + parts.join(',') + '}';
}
