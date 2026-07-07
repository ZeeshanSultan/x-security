import type {
  Authentication,
  Cors,
  IpPolicy,
  RateLimit,
  RequestPolicy,
  XSecurityPolicy
} from '@x-security/schema';
import {
  and,
  bodySizeGt,
  headerEquals,
  headerMissing,
  headerStartsWith,
  not,
  or,
  parseByteSize,
  parseDurationSeconds,
  LOWERCASE_TRANSFORM,
  NO_TRANSFORM
} from './statements.js';
import { pushRule } from './shared.js';
import {
  compileBotProtectionLegacy,
  compileIdorMitigation,
  compileOwaspInjections
} from './v2-extras.js';
import type { V2Builder } from './v2-builder.js';
import type { Confidence, WafStatement } from './types.js';

export type { V2Builder } from './v2-builder.js';

export function compileV2(b: V2Builder, baseMatch: WafStatement): void {
  const policy = b.endpoint.policy ?? {};
  compileAuth(b, policy, baseMatch);
  compileIpPolicy(b, policy.ipPolicy, baseMatch);
  compileCors(b, policy.cors, baseMatch);
  compileRequest(b, policy.request, baseMatch);
  compileRateLimit(b, policy.rateLimit, baseMatch);
  compileIdorMitigation(b, policy);
  compileOwaspInjections(b, policy, baseMatch);
  compileBotProtectionLegacy(b, policy);
}

function compileAuth(b: V2Builder, policy: XSecurityPolicy, baseMatch: WafStatement): void {
  const auth = policy.authentication;
  if (!auth || auth.type === 'none') return;

  let condition: WafStatement;
  const confidence: Confidence = 'HIGH';
  const action: 'Block' | 'Challenge' = 'Block';

  switch (auth.type) {
    case 'bearer-jwt': {
      const hdr = auth.headerName ?? 'authorization';
      condition = or(headerMissing(hdr), not(headerStartsWith(hdr, 'Bearer ')));
      b.warnings.push({
        endpoint_id: b.eid,
        field: 'authentication.bearer-jwt',
        message:
          'AWS WAF can enforce presence of a Bearer header only; configure a Cognito or Lambda authorizer on the API Gateway route for signature/issuer/audience validation.',
        severity: 'info'
      });
      break;
    }
    case 'api-key': {
      const hdr = auth.headerName ?? 'x-api-key';
      condition = headerMissing(hdr);
      b.warnings.push({
        endpoint_id: b.eid,
        field: 'authentication.api-key',
        message:
          'Consider enabling apiKeyRequired=true on the API Gateway method and attaching an API key to a Usage Plan. The WAF rule is a defense-in-depth fallback.',
        severity: 'info'
      });
      break;
    }
    case 'oauth2': {
      const hdr = auth.headerName ?? 'authorization';
      condition = or(headerMissing(hdr), not(headerStartsWith(hdr, 'Bearer ')));
      break;
    }
    case 'basic': {
      condition = or(headerMissing('authorization'), not(headerStartsWith('authorization', 'Basic ')));
      break;
    }
    case 'mtls': {
      b.unsupported.push({
        endpoint_id: b.eid,
        directive: 'authentication.mtls',
        reason:
          'mTLS is configured at the API Gateway custom domain level (DisableExecuteApiEndpoint + truststore), not via AWS WAF rules.'
      });
      return;
    }
    default: {
      b.unsupported.push({
        endpoint_id: b.eid,
        directive: `authentication.${(auth as Authentication).type}`,
        reason: 'Unsupported authentication type for AWS WAFv2'
      });
      return;
    }
  }

  pushRule(b, {
    kind: 'auth',
    statement: and(baseMatch, condition),
    actionKind: action,
    sourceField: `authentication.${auth.type}`,
    confidence
  });
}

function compileIpPolicy(b: V2Builder, ip: IpPolicy | undefined, baseMatch: WafStatement): void {
  if (!ip) return;

  if (Array.isArray(ip.allow) && ip.allow.length > 0) {
    const setName = `${b.prefix}-${b.ename}-allow`.slice(0, 128);
    b.ipSets.push({
      Name: setName,
      Description: `Allow CIDRs for ${b.endpoint.method} ${b.endpoint.path}`,
      Scope: b.scope,
      IPAddressVersion: detectIpv(ip.allow),
      Addresses: [...ip.allow]
    });
    pushRule(b, {
      kind: 'ip-allow',
      statement: and(baseMatch, not({ IPSetReferenceStatement: { ARN: `arn:x-security:ipset:${setName}` } })),
      actionKind: 'Block',
      sourceField: 'ipPolicy.allow',
      confidence: 'HIGH'
    });
  } else if (typeof ip.allow === 'string') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'ipPolicy.allow',
      message: 'VarRef in ipPolicy.allow — resolve at deploy time, skipped during compile',
      severity: 'info'
    });
  }

  if (Array.isArray(ip.deny) && ip.deny.length > 0) {
    const setName = `${b.prefix}-${b.ename}-deny`.slice(0, 128);
    b.ipSets.push({
      Name: setName,
      Description: `Deny CIDRs for ${b.endpoint.method} ${b.endpoint.path}`,
      Scope: b.scope,
      IPAddressVersion: detectIpv(ip.deny),
      Addresses: [...ip.deny]
    });
    pushRule(b, {
      kind: 'ip-deny',
      statement: and(baseMatch, { IPSetReferenceStatement: { ARN: `arn:x-security:ipset:${setName}` } }),
      actionKind: 'Block',
      sourceField: 'ipPolicy.deny',
      confidence: 'HIGH'
    });
  } else if (typeof ip.deny === 'string') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'ipPolicy.deny',
      message: 'VarRef in ipPolicy.deny — resolve at deploy time, skipped during compile',
      severity: 'info'
    });
  }
}

function detectIpv(cidrs: string[]): 'IPV4' | 'IPV6' {
  return cidrs.some(c => c.includes(':')) && !cidrs.some(c => /\d+\.\d+\.\d+\.\d+/.test(c)) ? 'IPV6' : 'IPV4';
}

function compileCors(b: V2Builder, cors: Cors | undefined, baseMatch: WafStatement): void {
  if (!cors) return;
  const origins = cors.allowedOrigins ?? [];

  if (origins.length > 0 && !origins.includes('*')) {
    const allowedOrigin = origins.length === 1
      ? headerEquals('origin', origins[0]!)
      : or(...origins.map(o => headerEquals('origin', o)));
    pushRule(b, {
      kind: 'cors-origin',
      statement: and(baseMatch, { ByteMatchStatement: {
        SearchString: 'http',
        FieldToMatch: { SingleHeader: { Name: 'origin' } },
        TextTransformations: NO_TRANSFORM,
        PositionalConstraint: 'STARTS_WITH'
      }}, not(allowedOrigin)),
      actionKind: 'Block',
      sourceField: 'cors.allowedOrigins',
      confidence: 'MEDIUM'
    });
  }

  if (cors.allowedMethods && cors.allowedMethods.length > 0) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'cors.allowedMethods',
      message:
        'Configure CORS response headers (Access-Control-Allow-Methods/Headers) on the API Gateway method, not WAF. AWS WAF does not modify responses.',
      severity: 'info'
    });
  }
}

function compileRequest(b: V2Builder, req: RequestPolicy | undefined, baseMatch: WafStatement): void {
  if (!req) return;

  if (req.maxBodySize) {
    let bytes: number;
    try {
      bytes = parseByteSize(req.maxBodySize);
    } catch {
      b.warnings.push({
        endpoint_id: b.eid,
        field: 'request.maxBodySize',
        message: `Invalid byte size: ${req.maxBodySize}`,
        severity: 'warn'
      });
      return;
    }
    pushRule(b, {
      kind: 'body-size',
      statement: and(baseMatch, bodySizeGt(bytes)),
      actionKind: 'Block',
      sourceField: 'request.maxBodySize',
      confidence: 'HIGH'
    });
  }

  if (req.contentType && req.contentType.length > 0) {
    const allowedCt = req.contentType.length === 1
      ? { ByteMatchStatement: {
          SearchString: req.contentType[0]!,
          FieldToMatch: { SingleHeader: { Name: 'content-type' } },
          TextTransformations: LOWERCASE_TRANSFORM,
          PositionalConstraint: 'STARTS_WITH' as const
        }}
      : or(...req.contentType.map(ct => ({ ByteMatchStatement: {
          SearchString: ct,
          FieldToMatch: { SingleHeader: { Name: 'content-type' } },
          TextTransformations: LOWERCASE_TRANSFORM,
          PositionalConstraint: 'STARTS_WITH' as const
        }})));
    pushRule(b, {
      kind: 'content-type',
      statement: and(baseMatch, not(allowedCt)),
      actionKind: 'Block',
      sourceField: 'request.contentType',
      confidence: 'HIGH'
    });
  }

  // When denyUnknownFields=true, v0.3 compileV3 emits an API Gateway model +
  // request validator. Only surface as unsupported when a schema is set
  // WITHOUT opting into denyUnknownFields.
  if (req.schema && Object.keys(req.schema).length > 0 && !req.denyUnknownFields) {
    b.unsupported.push({
      endpoint_id: b.eid,
      directive: 'request.schema',
      reason:
        'Per-field JSON path constraints are not natively expressible in AWS WAFv2. Set request.denyUnknownFields=true to emit an API Gateway model + request validator, or attach a Lambda authorizer for deep validation.'
    });
  }
}

function compileRateLimit(
  b: V2Builder,
  rl: RateLimit | RateLimit[] | undefined,
  baseMatch: WafStatement
): void {
  if (!rl) return;
  const list = Array.isArray(rl) ? rl : [rl];
  list.forEach((r, idx) => emitRateLimit(b, r, baseMatch, idx));
}

const AWS_WAF_RATE_WINDOWS = [60, 120, 300, 600] as const;

function emitRateLimit(b: V2Builder, r: RateLimit, baseMatch: WafStatement, idx: number): void {
  let seconds: number;
  try {
    seconds = parseDurationSeconds(r.window);
  } catch {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'rateLimit.window',
      message: `Invalid window: ${r.window}`,
      severity: 'warn'
    });
    return;
  }

  const useUsagePlan = r.identifier === 'api-key';

  if (useUsagePlan) {
    const rate = Math.max(1, Math.floor(r.requests / seconds));
    const burst = r.burst ?? Math.max(rate * 2, r.requests);
    b.usagePlans.push({
      Name: `${b.prefix}-${b.ename}-usageplan-${idx}`.slice(0, 64),
      Description: `Throttle ${r.requests} req / ${r.window} per API key for ${b.endpoint.method} ${b.endpoint.path}`,
      Throttle: { RateLimit: rate, BurstLimit: burst },
      Quota: seconds <= 86_400
        ? { Limit: r.requests, Period: 'DAY' }
        : { Limit: r.requests, Period: 'MONTH' },
      xSecurity: { endpoint_id: b.eid, source_field: `rateLimit[${idx}]` }
    });
    return;
  }

  const window = nearestWindow(seconds);
  if (window !== seconds) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'rateLimit.window',
      message: `Window ${r.window} rounded to ${window}s (AWS WAF only allows ${AWS_WAF_RATE_WINDOWS.join('/')}).`,
      severity: 'info'
    });
  }

  const limit = Math.max(100, r.requests);
  if (limit !== r.requests) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'rateLimit.requests',
      message: `AWS WAFv2 minimum rate-based limit is 100; ${r.requests} rounded up to ${limit}.`,
      severity: 'info'
    });
  }

  let scopeDown: WafStatement = baseMatch;
  if (r.when === 'authenticated') {
    scopeDown = and(scopeDown, not(headerMissing('authorization')));
  } else if (r.when === 'unauthenticated') {
    scopeDown = and(scopeDown, headerMissing('authorization'));
  }

  // v0.4 / v0.5 widened RateLimit.identifier to string | string[] | {components, combinator}.
  // WAFv2 RateBasedStatement takes a single aggregate key, so collapse to the first
  // component and emit a warning if any were dropped.
  let idValue: string | undefined;
  let dropped = 0;
  if (typeof r.identifier === 'string') {
    idValue = r.identifier;
  } else if (Array.isArray(r.identifier)) {
    idValue = r.identifier[0];
    dropped = r.identifier.length - 1;
  } else if (r.identifier && typeof r.identifier === 'object' && 'components' in r.identifier) {
    const c = (r.identifier as { components: string[] }).components;
    idValue = c[0];
    dropped = c.length - 1;
  }
  if (dropped > 0) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'rateLimit.identifier',
      message: `AWS WAFv2 does not support composite rate-limit keys; using '${idValue}' and dropping ${dropped} other(s).`,
      severity: 'info'
    });
  }
  const aggregateKey = identifierToAggregateKey(idValue);

  pushRule(b, {
    kind: `ratelimit-${idx}`,
    statement: {
      RateBasedStatement: {
        Limit: limit,
        AggregateKeyType: aggregateKey.type,
        EvaluationWindowSec: window as 60 | 120 | 300 | 600,
        ScopeDownStatement: scopeDown,
        ...(aggregateKey.forwardedConfig ? { ForwardedIPConfig: aggregateKey.forwardedConfig } : {})
      }
    },
    actionKind: 'Block',
    sourceField: `rateLimit[${idx}]`,
    confidence: 'HIGH'
  });
}

function nearestWindow(target: number): number {
  return AWS_WAF_RATE_WINDOWS.reduce((best, cur) =>
    Math.abs(cur - target) < Math.abs(best - target) ? cur : best
  );
}

function identifierToAggregateKey(
  id: string | undefined
): { type: 'IP' | 'FORWARDED_IP' | 'CONSTANT'; forwardedConfig?: { HeaderName: string; FallbackBehavior: 'MATCH' | 'NO_MATCH' } } {
  switch (id) {
    case undefined:
    case 'ip':
      return { type: 'IP' };
    case 'fingerprint':
      return { type: 'FORWARDED_IP', forwardedConfig: { HeaderName: 'X-Forwarded-For', FallbackBehavior: 'MATCH' } };
    case 'user-id':
      return { type: 'IP' };
    default:
      if (id.startsWith('header:')) {
        return { type: 'IP' };
      }
      return { type: 'IP' };
  }
}
