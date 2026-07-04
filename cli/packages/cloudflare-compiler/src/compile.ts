import { createHash } from 'node:crypto';
import type { EndpointIR, SpecIR } from '@writ/core';
import type {
  Authentication,
  Cors,
  IpPolicy,
  RequestPolicy,
  XSecurityPolicy
} from '@writ/schema';
import {
  endpointHash,
  endpointId,
  methodMatchExpression,
  pathMatchExpression
} from './endpoint.js';
import {
  and,
  bodySizeGt,
  contentTypeNotIn,
  hasHeader,
  headerMatches,
  inCidrAny,
  missingHeader,
  not,
  or,
  parseByteSize
} from './expressions.js';
import { compileEndpointRateLimit as compileEndpointRateLimitImpl } from './ratelimit.js';
import { compileLegacyBotProtection, compileLegacyResponseHeaders } from './legacy.js';
import type {
  CfPlanTier,
  CompileOptions,
  CompileResult,
  CompileWarning,
  CompiledRule,
  CompiledRuleset,
  Confidence,
  DeployMode,
  ManagedRulesetSelection,
  ObserveModeNote,
  ProvenanceNote,
  RuleAction,
  RulesetPhase,
  WorkerArtifact
} from './types.js';
import { compileV3Request } from './v3-request.js';
import { compileV3Response } from './v3-response.js';
import { compileV3Protocol } from './v3-protocol.js';
import { assertJwtAlgorithms, compileV3Authorization, noteJwtAlgorithms } from './v3-authz.js';
import { isObserveMode, modePrefix, type V3Builder } from './v3-shared.js';

const SCHEMA_VERSION_DEFAULT = '0.2.0';

// RuleBuilder is structurally compatible with V3Builder so the per-concern v3
// modules can share the same accumulator. Keeping the alias prevents a type
// fan-out: every v3 helper takes V3Builder and works against this struct too.
type RuleBuilder = V3Builder;

/**
 * Pure function: compile a parsed/normalized OpenAPI spec into Cloudflare
 * Rulesets API JSON. Deterministic — same input always yields byte-identical
 * output (rules ordered by endpoint, then by rule_type, then by index).
 */
export function compile(spec: SpecIR, options: CompileOptions = {}): CompileResult {
  // Default per the rev 3 rollout plan: new policies ship in observe mode.
  const mode: DeployMode = options.mode ?? 'observe';
  const schemaVersion = options.schemaVersion ?? SCHEMA_VERSION_DEFAULT;
  const version = options.version ?? 1;
  const defaultPrefix =
    mode === 'enforce' ? 'writ'
    : mode === 'shadow' ? 'writ-shadow'
    : 'writ-observe';
  const prefix = options.namePrefix ?? defaultPrefix;
  const planTier = options.planTier ?? 'free';
  const managedRulesAllowed = planTier === 'business' || planTier === 'enterprise';

  const customRules: CompiledRule[] = [];
  const rateLimitRules: CompiledRule[] = [];
  const reqTransformRules: CompiledRule[] = [];
  const respTransformRules: CompiledRule[] = [];
  const managed: ManagedRulesetSelection[] = [];
  const warnings: CompileWarning[] = [];
  const provenance: ProvenanceNote[] = [];
  const observeModeNotes: ObserveModeNote[] = [];
  const workerArtifacts: WorkerArtifact[] = [];

  // Sort endpoints for deterministic output: method, path
  const ordered = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );

  for (const ep of ordered) {
    const eid = endpointId(ep.method, ep.path);
    // Hard schema-level requirement: bearer-jwt must declare allowedAlgorithms.
    // Bypassing this would re-open the alg:none / HS-vs-RS confusion class —
    // exactly what v0.3 is designed to close. Hard error, not a warning.
    assertJwtAlgorithms(ep.policy ?? {}, eid);

    const cfOverrides = ((ep.policy?.targetOverrides as Record<string, unknown> | undefined)?.cloudflare ?? {}) as Record<string, unknown>;

    const builder: RuleBuilder = {
      endpoint: ep,
      ehash: endpointHash(ep.method, ep.path),
      eid,
      mode,
      schemaVersion,
      planTier,
      warnings,
      provenance,
      observeModeNotes,
      workerArtifacts,
      custom: [],
      rateLimit: [],
      reqTransform: [],
      respTransform: [],
      managed,
      overrides: cfOverrides
    };
    compileEndpoint(builder);
    customRules.push(...builder.custom);
    rateLimitRules.push(...builder.rateLimit);
    reqTransformRules.push(...builder.reqTransform);
    respTransformRules.push(...builder.respTransform);
  }

  // OWASP CRS managed ruleset requires Business+ Cloudflare plan. On free/pro
  // accounts, attempting to deploy it returns 403. Emit it only when the
  // customer's plan supports it; otherwise warn and skip.
  if (managed.length === 0) {
    if (managedRulesAllowed) {
      managed.push({
        ruleset_id: 'efb7b8c949ac4650a09736fc376e9aee', // CF Managed Rules — OWASP Core Ruleset
        description: 'OWASP Core Ruleset (paranoia 1, default thresholds)'
      });
    } else {
      warnings.push({
        field: 'managedRulesets.owaspCrs',
        message: `OWASP CRS managed ruleset requires Cloudflare Business or Enterprise plan; skipped on '${planTier}' tier.`,
        severity: 'info'
      });
    }
  }

  // Free plans support only 1 rate-limit rule per zone; Cloudflare silently
  // truncates additional rules. Warn so the customer can consolidate.
  if (planTier === 'free' && rateLimitRules.length > 1) {
    warnings.push({
      field: 'rateLimit.count',
      message: `Compiled ${rateLimitRules.length} rate-limit rules but free Cloudflare plans support only 1 per zone; Cloudflare will reject or truncate the rest. Consolidate endpoints or upgrade to Business+.`,
      severity: 'warn'
    });
  }

  const rulesets: CompiledRuleset[] = [];
  pushRulesetIfNonEmpty(rulesets, {
    name: `${prefix}-custom-v${version}`,
    description: 'Writ Custom Rules (auth/cors/body/idor)',
    kind: 'zone',
    phase: 'http_request_firewall_custom',
    rules: customRules
  });
  pushRulesetIfNonEmpty(rulesets, {
    name: `${prefix}-ratelimit-v${version}`,
    description: 'Writ Rate Limit Rules',
    kind: 'zone',
    phase: 'http_ratelimit',
    rules: rateLimitRules
  });
  pushRulesetIfNonEmpty(rulesets, {
    name: `${prefix}-req-transform-v${version}`,
    description: 'Writ Request Transform Rules',
    kind: 'zone',
    phase: 'http_request_late_transform',
    rules: reqTransformRules
  });
  pushRulesetIfNonEmpty(rulesets, {
    name: `${prefix}-resp-transform-v${version}`,
    description: 'Writ Response Header Transform Rules',
    kind: 'zone',
    phase: 'http_response_headers_transform',
    rules: respTransformRules
  });

  // Deterministic ordering for provenance + worker artifacts so contentHash is stable.
  provenance.sort((a, b) =>
    (a.endpoint_id ?? '').localeCompare(b.endpoint_id ?? '') ||
    a.field.localeCompare(b.field) ||
    a.message.localeCompare(b.message)
  );
  observeModeNotes.sort((a, b) =>
    (a.endpoint_id ?? '').localeCompare(b.endpoint_id ?? '') ||
    a.field.localeCompare(b.field) ||
    a.message.localeCompare(b.message)
  );
  workerArtifacts.sort((a, b) =>
    a.endpoint_id.localeCompare(b.endpoint_id) ||
    a.field.localeCompare(b.field) ||
    a.kind.localeCompare(b.kind)
  );

  const contentHash = hashContent({ rulesets, managedRulesets: managed, provenance, observeModeNotes, workerArtifacts });

  return { rulesets, managedRulesets: managed, warnings, provenance, observeModeNotes, workerArtifacts, contentHash };
}

function pushRulesetIfNonEmpty(out: CompiledRuleset[], rs: CompiledRuleset): void {
  if (rs.rules.length > 0) out.push(rs);
}

function compileEndpoint(b: RuleBuilder): void {
  const policy = b.endpoint.policy ?? {};
  const baseMatch = and(methodMatchExpression(b.endpoint.method), pathMatchExpression(b.endpoint.path));

  compileAuth(b, policy, baseMatch);
  noteJwtAlgorithms(b, policy);
  compileIpPolicy(b, policy.ipPolicy, baseMatch);
  compileCors(b, policy.cors, baseMatch);
  compileRequest(b, policy.request, baseMatch);
  compileEndpointRateLimit(b, baseMatch);
  compileIdorTripwire(b, policy, baseMatch);

  // v0.3 lowering. The legacy response-header injection below is suppressed
  // when policy.response.headers is set ("absence means do not emit" per the
  // v0.3 design doc).
  compileV3Authorization(b, policy, baseMatch);
  compileV3Request(b, policy, baseMatch);
  compileV3Response(b, policy, baseMatch);
  compileV3Protocol(b, policy, baseMatch);

  if (!policy.response?.headers) compileLegacyResponseHeaders(b, policy, baseMatch);
  // The legacy `botProtection: true` toggle remains supported. v3-protocol's
  // compileBotProtectionV3 owns the typed-object shape; the function below
  // is a no-op when `botProtection !== true`, so the call is safe regardless.
  compileLegacyBotProtection(b, policy, baseMatch);
}

function compileIdorTripwire(b: RuleBuilder, policy: XSecurityPolicy, baseMatch: string): void {
  // Tripwire — fires only when path has an {id}-style param AND authorization
  // policy hints at per-user/owner/tenant scoping. Catches unauthenticated
  // IDOR scans even if the app's auth is misconfigured.
  const hasIdParam = /\{[^}]*id[^}]*\}/i.test(b.endpoint.path);
  const isOwnershipAuthz = policy.authorization?.rules?.some(r =>
    /user|owner|tenant/i.test(r.field)
  ) ?? false;
  if (!hasIdParam || !isOwnershipAuthz) return;
  b.custom.push(buildRule(b, {
    kind: 'idor-tripwire',
    description: 'IDOR tripwire: log requests to ownership-scoped resource without auth header',
    expression: and(baseMatch, missingHeader('authorization')),
    action: 'log',
    sourceField: 'authorization.rules[ownership]',
    confidence: 'LOW',
    forceLog: true
  }));
}

function compileAuth(b: RuleBuilder, policy: XSecurityPolicy, baseMatch: string): void {
  const auth = policy.authentication;
  if (!auth || auth.type === 'none') return;

  let condition: string;
  let confidence: Confidence = 'HIGH';
  let action: RuleAction = 'block';
  let field = 'authentication';

  switch (auth.type) {
    case 'bearer-jwt': {
      const hdr = auth.headerName ?? 'authorization';
      condition = or(
        missingHeader(hdr),
        not(headerMatches(hdr, '^(Bearer|bearer) [A-Za-z0-9._~+/=-]+$'))
      );
      break;
    }
    case 'api-key': {
      const hdr = auth.headerName ?? 'x-api-key';
      condition = missingHeader(hdr);
      break;
    }
    case 'oauth2': {
      const hdr = auth.headerName ?? 'authorization';
      condition = or(missingHeader(hdr), not(headerMatches(hdr, '^(Bearer|bearer) .+$')));
      break;
    }
    case 'basic': {
      condition = or(missingHeader('authorization'), not(headerMatches('authorization', '^(Basic|basic) .+$')));
      break;
    }
    case 'mtls': {
      // CF mTLS validation surfaces via cf.tls_client_auth.cert_verified
      condition = 'cf.tls_client_auth.cert_verified eq false';
      confidence = 'MEDIUM';
      action = 'challenge';
      break;
    }
    default:
      b.warnings.push({
        endpoint_id: b.eid,
        field: `authentication.type=${(auth as Authentication).type}`,
        message: 'Unsupported authentication type for Cloudflare Custom Rules',
        severity: 'warn'
      });
      return;
  }

  b.custom.push(buildRule(b, {
    kind: 'auth',
    description: `Auth required (${auth.type}) for ${b.endpoint.method} ${b.endpoint.path}`,
    expression: and(baseMatch, condition),
    action,
    sourceField: `authentication.${auth.type}`,
    confidence,
    fieldLabel: field
  }));
}

function compileIpPolicy(b: RuleBuilder, ip: IpPolicy | undefined, baseMatch: string): void {
  if (!ip) return;
  // We only handle inline CIDR arrays — VarRefs are deferred (compiler is pure).
  if (Array.isArray(ip.allow) && ip.allow.length > 0) {
    b.custom.push(buildRule(b, {
      kind: 'ip-allow',
      description: `IP allowlist: deny non-${ip.allow.length}-CIDR clients`,
      expression: and(baseMatch, not(inCidrAny(ip.allow))),
      action: 'block',
      sourceField: 'ipPolicy.allow',
      confidence: 'HIGH'
    }));
  } else if (typeof ip.allow === 'string') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'ipPolicy.allow',
      message: 'VarRef in ipPolicy.allow — resolve at deploy time, skipped during compile',
      severity: 'info'
    });
  }
  if (Array.isArray(ip.deny) && ip.deny.length > 0) {
    b.custom.push(buildRule(b, {
      kind: 'ip-deny',
      description: `IP denylist (${ip.deny.length} CIDRs)`,
      expression: and(baseMatch, inCidrAny(ip.deny)),
      action: 'block',
      sourceField: 'ipPolicy.deny',
      confidence: 'HIGH'
    }));
  } else if (typeof ip.deny === 'string') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'ipPolicy.deny',
      message: 'VarRef in ipPolicy.deny — resolve at deploy time, skipped during compile',
      severity: 'info'
    });
  }
}

function compileCors(b: RuleBuilder, cors: Cors | undefined, baseMatch: string): void {
  if (!cors) return;
  const origins = cors.allowedOrigins ?? [];
  // If origin is restricted (no "*"), block requests with disallowed Origin header.
  if (origins.length > 0 && !origins.includes('*')) {
    const allowed = origins.map(o => `"${o.replace(/"/g, '\\"')}"`).join(' ');
    const cond = and(
      hasHeader('origin'),
      `not (http.request.headers["origin"][0] in {${allowed}})`
    );
    b.custom.push(buildRule(b, {
      kind: 'cors-origin',
      description: `CORS: block requests with disallowed Origin (allowed: ${origins.join(', ')})`,
      expression: and(baseMatch, cond),
      action: 'block',
      sourceField: 'cors.allowedOrigins',
      confidence: 'MEDIUM'
    }));
  }

  // Response-header injection for permitted origins is handled by Transform Rules
  if (cors.allowedMethods && cors.allowedMethods.length > 0) {
    b.respTransform.push(buildRule(b, {
      kind: 'cors-headers',
      description: 'Set Access-Control-Allow-Methods response header',
      expression: baseMatch,
      action: 'rewrite',
      actionParameters: {
        headers: {
          'Access-Control-Allow-Methods': { operation: 'set', value: cors.allowedMethods.join(', ') }
        }
      },
      sourceField: 'cors.allowedMethods',
      confidence: 'HIGH'
    }));
  }
}

function compileRequest(b: RuleBuilder, req: RequestPolicy | undefined, baseMatch: string): void {
  if (!req) return;

  if (req.maxBodySize) {
    let bytes: number;
    try {
      bytes = parseByteSize(req.maxBodySize);
    } catch (e) {
      b.warnings.push({
        endpoint_id: b.eid,
        field: 'request.maxBodySize',
        message: `Invalid byte size: ${req.maxBodySize}`,
        severity: 'warn'
      });
      return;
    }
    b.custom.push(buildRule(b, {
      kind: 'body-size',
      description: `Reject requests with body > ${req.maxBodySize}`,
      expression: and(baseMatch, bodySizeGt(bytes)),
      action: 'block',
      sourceField: 'request.maxBodySize',
      confidence: 'HIGH'
    }));
  }

  if (req.contentType && req.contentType.length > 0) {
    b.custom.push(buildRule(b, {
      kind: 'content-type',
      description: `Reject content-type not in [${req.contentType.join(', ')}]`,
      expression: and(baseMatch, contentTypeNotIn(req.contentType)),
      action: 'block',
      sourceField: 'request.contentType',
      confidence: 'HIGH'
    }));
  }

}

function compileEndpointRateLimit(b: RuleBuilder, baseMatch: string): void {
  compileEndpointRateLimitImpl(b, (args) => buildRule(b, args), baseMatch);
}

interface BuildRuleArgs {
  kind: string;
  description: string;
  expression: string;
  action: RuleAction;
  actionParameters?: Record<string, unknown>;
  ratelimit?: CompiledRule['ratelimit'];
  sourceField: string;
  confidence: Confidence;
  fieldLabel?: string;
  /** If true, rule stays in `log` even in enforce mode (tripwires). */
  forceLog?: boolean;
}

function buildRule(b: RuleBuilder, args: BuildRuleArgs): CompiledRule {
  // Rewrite (transform) rules don't block traffic, so they're safe in observe mode.
  const isNonBlocking = args.action === 'rewrite';
  const forceLog = args.forceLog === true || (isObserveMode(b.mode) && !isNonBlocking);
  const action: RuleAction = forceLog ? 'log' : args.action;
  const id = `writ-${modePrefix(b.mode)}-${b.ehash}-${args.kind}`;
  const rule: CompiledRule = {
    id,
    description: `[writ] ${args.description}`,
    expression: args.expression,
    action,
    enabled: true,
    mode: b.mode,
    writ: {
      endpoint_id: b.eid,
      rule_type: args.kind,
      source_field: args.sourceField,
      confidence: args.confidence,
      schema_version: b.schemaVersion
    }
  };
  if (args.actionParameters !== undefined) {
    rule.action_parameters = args.actionParameters as NonNullable<CompiledRule['action_parameters']>;
  }
  if (args.ratelimit !== undefined) {
    rule.ratelimit = args.ratelimit;
  }
  return rule;
}

function hashContent(value: unknown): string {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

/** Deterministic JSON stringify: object keys sorted recursively. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const parts = keys.map(k => JSON.stringify(k) + ':' + stableStringify((value as Record<string, unknown>)[k]));
  return '{' + parts.join(',') + '}';
}
