import type {
  Authentication,
  Authorization,
  Csrf,
  ParamSchema,
  RequestPolicy,
  RequestSignature
} from '@x-security/schema';
import {
  and,
  headerEquals,
  not,
  or,
  parseByteSize,
  NO_TRANSFORM
} from './statements.js';
import { isObserveMode, pushRule } from './shared.js';
import {
  isRuleRef,
  noteObserveMode,
  pushAuthorizer,
  pushCapability,
  type V3Builder
} from './v3-shared.js';
import type { ApiGatewayModelSpec, WafStatement } from './types.js';

// ────────────────────────────────────────────────────────────────────────────
// #2 — authentication.allowedAlgorithms (hard policy-load error)
// ────────────────────────────────────────────────────────────────────────────

export function validateAuthAllowedAlgorithms(b: V3Builder, auth: Authentication | undefined): void {
  if (!auth) return;
  if (auth.type !== 'bearer-jwt') return;
  const algs = auth.allowedAlgorithms;
  if (!algs || algs.length === 0) {
    b.errors.push({
      endpoint_id: b.eid,
      field: 'authentication.allowedAlgorithms',
      message:
        "authentication.type 'bearer-jwt' REQUIRES allowedAlgorithms (asymmetric algs only — RS*/ES*/PS*/EdDSA). " +
        "The JWT-algorithm-confusion class (alg:none, HS-vs-RS confusion) is the bug v0.3 was added to eliminate; " +
        'refusing to emit gateway config for this endpoint.'
    });
    return;
  }
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-jwt-alg`,
    Type: 'REQUEST',
    IdentitySource: [`$request.header.${auth.headerName ?? 'authorization'}`],
    AuthorizerResultTtlInSeconds: 300,
    template: {
      kind: 'jwt-alg-allowlist',
      config: {
        algorithms: [...algs],
        jwksUri: auth.jwksUri,
        issuer: auth.issuer,
        audience: auth.audience
      }
    },
    xSecurity: { endpoint_id: b.eid, source_field: 'authentication.allowedAlgorithms' }
  });
  pushCapability(b, 'authentication.allowedAlgorithms', 'full', 'Lambda authorizer',
    'HTTP API JWT authorizers do not gate on alg; Lambda authorizer enforces the allowlist.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #1 + #3 — RuleRef authorization + resourceLookup
// ────────────────────────────────────────────────────────────────────────────

export function compileRuleRefAuthorization(
  b: V3Builder,
  auth: Authentication | undefined,
  authz: Authorization | undefined
): void {
  if (!authz?.rules) return;
  const hasRuleRef = authz.rules.some(r => isRuleRef(r.value));
  if (!hasRuleRef) return;

  const refs = authz.rules
    .filter(r => isRuleRef(r.value))
    .map(r => ({ field: r.field, operator: r.operator, valueRef: (r.value as { ref: string }).ref }));

  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-authz-ruleref`,
    Type: 'REQUEST',
    IdentitySource: [`$request.header.${auth?.headerName ?? 'authorization'}`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: 'jwt-ruleref',
      config: {
        rules: refs,
        authzType: authz.type,
        jwt: auth?.type === 'bearer-jwt'
          ? { jwksUri: auth.jwksUri, algorithms: auth.allowedAlgorithms ?? [], issuer: auth.issuer, audience: auth.audience }
          : null
      }
    },
    xSecurity: { endpoint_id: b.eid, source_field: 'authorization.rules[].value:RuleRef' }
  });
  pushCapability(b, 'authorization.rules[].value(RuleRef)', 'full', 'Lambda authorizer',
    'WAFv2 cannot dereference JWT claims; Lambda authorizer evaluates RuleRef and emits IAM policy.',
    'simulatable');
}

export function compileResourceLookup(b: V3Builder, authz: Authorization | undefined): void {
  if (!authz?.resourceLookup) return;
  const rl = authz.resourceLookup;
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-resource-lookup`,
    Type: 'REQUEST',
    IdentitySource: [`$request.path`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: 'resource-lookup',
      config: {
        endpoint: rl.endpoint,
        identifierFrom: rl.identifierFrom,
        expose: [...rl.expose]
      }
    },
    xSecurity: { endpoint_id: b.eid, source_field: 'authorization.resourceLookup' }
  });
  pushCapability(b, 'authorization.resourceLookup', 'full', 'Lambda authorizer',
    'Authorizer issues sigv4 sub-call (or DynamoDB read), populates resource.* in context.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #4 — csrf
// ────────────────────────────────────────────────────────────────────────────

export function compileCsrf(b: V3Builder, csrf: Csrf | undefined, baseMatch: WafStatement): void {
  if (!csrf) return;
  if (csrf.method === 'origin-check') {
    const origins = csrf.allowedOrigins ?? [];
    if (origins.length === 0) {
      b.warnings.push({
        endpoint_id: b.eid,
        field: 'csrf.allowedOrigins',
        message: 'csrf.method=origin-check requires allowedOrigins; skipping rule emission.',
        severity: 'warn'
      });
      return;
    }
    const allowed = origins.length === 1
      ? headerEquals('origin', origins[0]!)
      : or(...origins.map(o => headerEquals('origin', o)));
    pushRule(b, {
      kind: 'csrf-origin',
      statement: and(baseMatch, not(allowed)),
      actionKind: 'Block',
      sourceField: 'csrf.origin-check',
      confidence: 'HIGH'
    });
    pushCapability(b, 'csrf', 'partial', 'WAFv2 origin allowlist',
      'origin-check enforced via WAFv2; Referer fallback requires Lambda.',
      'simulatable');
    return;
  }
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-csrf`,
    Type: 'REQUEST',
    IdentitySource: csrf.tokenHeader
      ? [`$request.header.${csrf.tokenHeader}`]
      : [`$request.header.cookie`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: csrf.method === 'double-submit' ? 'csrf-double-submit' : 'csrf-custom-header',
      config: {
        tokenHeader: csrf.tokenHeader,
        tokenCookie: csrf.tokenCookie
      }
    },
    xSecurity: { endpoint_id: b.eid, source_field: `csrf.${csrf.method}` }
  });
  pushCapability(b, 'csrf', 'partial', 'Lambda authorizer',
    `${csrf.method} requires Lambda; double-submit compares header vs cookie at the edge.`,
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #6 — request.denyUnknownFields  (KEY WIN — JSON Schema model)
// ────────────────────────────────────────────────────────────────────────────

export function compileDenyUnknownFields(b: V3Builder, req: RequestPolicy | undefined): void {
  if (!req?.denyUnknownFields) return;
  const schema = req.schema ?? {};
  const properties: Record<string, unknown> = {};
  for (const [name, ps] of Object.entries(schema)) {
    properties[name] = paramSchemaToJsonSchema(ps);
  }
  const modelName = `${b.prefix}-${b.ehash}-body`.replace(/[^A-Za-z0-9]/g, '');
  const jsonSchema: Record<string, unknown> = {
    $schema: 'http://json-schema.org/draft-04/schema#',
    title: modelName,
    type: 'object',
    additionalProperties: false,
    properties
  };
  const model: ApiGatewayModelSpec = {
    Name: modelName,
    ContentType: 'application/json',
    Schema: jsonSchema,
    xSecurity: { endpoint_id: b.eid, source_field: 'request.denyUnknownFields' }
  };
  b.requestValidators.push({
    Name: `${b.prefix}-${b.ehash}-validator`,
    ValidateRequestBody: true,
    ValidateRequestParameters: true,
    ModelName: modelName,
    Model: model,
    xSecurity: { endpoint_id: b.eid, source_field: 'request.denyUnknownFields' }
  });
  pushCapability(b, 'request.denyUnknownFields', 'full', 'API Gateway request validator + JSON Schema model',
    'additionalProperties:false on the body model gives true field-deny at the gateway tier.',
    'always-applied');
  if (isObserveMode(b.mode)) {
    // API Gateway request validators have no observe knob: they always reject
    // or accept. Surface this so the customer either enables the validator
    // knowingly or runs in enforce mode.
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'request.denyUnknownFields',
      message:
        'API Gateway request validators are always-on: there is no native observe knob. ' +
        'Enabling denyUnknownFields in observe-mode will still reject body fields with additionalProperties violations. ' +
        'Either accept the always-applied behavior, or omit denyUnknownFields until promoting to enforce.',
      severity: 'warn'
    });
    noteObserveMode(b, 'request.denyUnknownFields', 'always-applied',
      'API Gateway request validator has no observe knob; additionalProperties:false rejects always.');
  }
}

function paramSchemaToJsonSchema(ps: ParamSchema): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  switch (ps.type) {
    case 'integer': out['type'] = 'integer'; break;
    case 'float': out['type'] = 'number'; break;
    case 'boolean': out['type'] = 'boolean'; break;
    case 'binary': out['type'] = 'string'; out['format'] = 'binary'; break;
    case 'email': out['type'] = 'string'; out['format'] = 'email'; break;
    case 'url': out['type'] = 'string'; out['format'] = 'uri'; break;
    case 'uuid': out['type'] = 'string'; out['format'] = 'uuid'; break;
    case 'date': out['type'] = 'string'; out['format'] = 'date'; break;
    case 'datetime': out['type'] = 'string'; out['format'] = 'date-time'; break;
    case 'ip-address': out['type'] = 'string'; out['format'] = 'ipv4'; break;
    case undefined:
    case 'string':
    case 'name':
    case 'free-text':
    case 'phone':
    default: out['type'] = 'string';
  }
  if (typeof ps.minLength === 'number') out['minLength'] = ps.minLength;
  if (typeof ps.maxLength === 'number') out['maxLength'] = ps.maxLength;
  if (typeof ps.fixedLength === 'number') {
    out['minLength'] = ps.fixedLength;
    out['maxLength'] = ps.fixedLength;
  }
  if (typeof ps.min === 'number') out['minimum'] = ps.min;
  if (typeof ps.max === 'number') out['maximum'] = ps.max;
  if (ps.pattern) out['pattern'] = ps.pattern;
  return out;
}

// ────────────────────────────────────────────────────────────────────────────
// #7 — request.signature (HMAC / Ed25519 → Lambda authorizer)
// ────────────────────────────────────────────────────────────────────────────

export function compileRequestSignature(b: V3Builder, sig: RequestSignature | undefined): void {
  if (!sig) return;
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-sig`,
    Type: 'REQUEST',
    IdentitySource: [`$request.header.${sig.headerName}`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: 'hmac-signature',
      config: {
        algorithm: sig.algorithm,
        headerName: sig.headerName,
        secretRef: sig.secretRef,
        body: sig.body,
        timestampHeader: sig.timestampHeader,
        timestampToleranceSeconds: sig.timestampToleranceSeconds
      }
    },
    xSecurity: { endpoint_id: b.eid, source_field: 'request.signature' }
  });
  pushCapability(b, 'request.signature', 'full', 'Lambda authorizer (HMAC verify)',
    'API Gateway has no native HMAC primitive; authorizer verifies before invoking the integration.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #8 — request.allowedHosts → WAFv2 host-header rule
// ────────────────────────────────────────────────────────────────────────────

export function compileAllowedHosts(b: V3Builder, hosts: string[] | undefined, baseMatch: WafStatement): void {
  if (!hosts || hosts.length === 0) return;
  const allowed = hosts.length === 1
    ? headerEquals('host', hosts[0]!)
    : or(...hosts.map(h => headerEquals('host', h)));
  pushRule(b, {
    kind: 'allowed-hosts',
    statement: and(baseMatch, not(allowed)),
    actionKind: 'Block',
    sourceField: 'request.allowedHosts',
    confidence: 'HIGH'
  });
  pushCapability(b, 'request.allowedHosts', 'full', 'WAFv2 Host header match',
    'Defense against host-header injection / cache-poisoning.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #9 — request.duplicateParamPolicy
// ────────────────────────────────────────────────────────────────────────────

export function compileDuplicateParamPolicy(b: V3Builder, policy: 'first' | 'last' | 'reject' | undefined): void {
  if (!policy) return;
  pushAuthorizer(b, {
    Name: `${b.prefix}-${b.ehash}-dup-param`,
    Type: 'REQUEST',
    IdentitySource: [`$request.path`],
    AuthorizerResultTtlInSeconds: 0,
    template: {
      kind: 'duplicate-param-policy',
      config: { policy }
    },
    xSecurity: { endpoint_id: b.eid, source_field: 'request.duplicateParamPolicy' }
  });
  pushCapability(b, 'request.duplicateParamPolicy', 'partial', 'Lambda authorizer',
    'API Gateway has no HPP primitive; authorizer normalizes per `policy`.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #10 — request.headerInjectionGuard → WAFv2 regex on header values
// ────────────────────────────────────────────────────────────────────────────

export function compileHeaderInjectionGuard(b: V3Builder, on: boolean | undefined, baseMatch: WafStatement): void {
  if (!on) return;
  const setName = `${b.prefix}-${b.ehash}-hdr-inject`.slice(0, 128);
  b.regexSets.push({
    Name: setName,
    Description: `CR/LF/NUL in header values for ${b.endpoint.method} ${b.endpoint.path}`,
    Scope: b.scope,
    RegularExpressionList: [{ RegexString: '[\\r\\n\\x00]' }]
  });
  pushRule(b, {
    kind: 'header-injection-guard',
    statement: and(baseMatch, {
      RegexPatternSetReferenceStatement: {
        ARN: `arn:x-security:regexset:${setName}`,
        FieldToMatch: {
          Headers: {
            MatchPattern: { All: {} },
            MatchScope: 'VALUE',
            OversizeHandling: 'CONTINUE'
          }
        },
        TextTransformations: NO_TRANSFORM
      }
    }),
    actionKind: 'Block',
    sourceField: 'request.headerInjectionGuard',
    confidence: 'HIGH'
  });
  pushCapability(b, 'request.headerInjectionGuard', 'full', 'WAFv2 regex match on header values',
    'Blocks request-smuggling / response-splitting via CR/LF/NUL.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #11 — request.pathCanonicalization
// ────────────────────────────────────────────────────────────────────────────

export function compilePathCanonicalization(b: V3Builder, on: boolean | undefined): void {
  if (!on) return;
  const setName = `${b.prefix}-${b.ehash}-path-canon`.slice(0, 128);
  b.regexSets.push({
    Name: setName,
    Description: 'Path traversal / double-encoding patterns',
    Scope: b.scope,
    RegularExpressionList: [
      { RegexString: '%2[eE]%2[eE]' },
      { RegexString: '%252[eE]' },
      { RegexString: '\\.\\.;' },
      { RegexString: '//+' }
    ]
  });
  pushRule(b, {
    kind: 'path-canonicalization',
    statement: {
      RegexPatternSetReferenceStatement: {
        ARN: `arn:x-security:regexset:${setName}`,
        FieldToMatch: { UriPath: {} },
        TextTransformations: NO_TRANSFORM
      }
    },
    actionKind: 'Block',
    sourceField: 'request.pathCanonicalization',
    confidence: 'MEDIUM'
  });
  if (b.scope !== 'CLOUDFRONT') {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'request.pathCanonicalization',
      message:
        'API Gateway only single-decodes percent-encoding; full canonicalization (resolving `..`, `..;/`, `//`) ' +
        'requires CloudFront in front. Emitted a best-effort WAFv2 regex rule.',
      severity: 'warn'
    });
  }
  pushCapability(b, 'request.pathCanonicalization',
    b.scope === 'CLOUDFRONT' ? 'full' : 'partial',
    'WAFv2 regex + (optional) CloudFront',
    'CloudFront handles canonicalization; WAFv2 regex catches double-encoding patterns.',
    'simulatable');
}

// ────────────────────────────────────────────────────────────────────────────
// #12 — ParamSchema binary upload hardening
// ────────────────────────────────────────────────────────────────────────────

export function compileBinaryParamHardening(b: V3Builder, req: RequestPolicy | undefined): void {
  if (!req?.schema) return;
  let emitted = false;
  for (const [name, ps] of Object.entries(req.schema)) {
    if (ps.type !== 'binary') continue;
    if (!ps.magicByteCheck && !ps.extensionAllowlist && !ps.denyDoubleExtension) continue;
    emitted = true;
    pushAuthorizer(b, {
      Name: `${b.prefix}-${b.ehash}-binary-${name}`.replace(/[^A-Za-z0-9-]/g, '-').slice(0, 64),
      Type: 'REQUEST',
      IdentitySource: [`$request.header.content-type`],
      AuthorizerResultTtlInSeconds: 0,
      template: {
        kind: 'mime-magic-byte',
        config: {
          field: name,
          allowedMimeTypes: ps.allowedMimeTypes ?? [],
          maxSize: ps.maxSize,
          magicByteCheck: !!ps.magicByteCheck,
          extensionAllowlist: ps.extensionAllowlist ?? [],
          denyDoubleExtension: !!ps.denyDoubleExtension
        }
      },
      xSecurity: { endpoint_id: b.eid, source_field: `request.schema.${name}` }
    });
    if (ps.maxSize) {
      try {
        const bytes = parseByteSize(ps.maxSize);
        if (bytes > 10 * 1024 * 1024) {
          b.warnings.push({
            endpoint_id: b.eid,
            field: `request.schema.${name}.maxSize`,
            message:
              'API Gateway payload limit is 10MB; magicByteCheck via Lambda authorizer cannot ' +
              `sniff bodies larger than this. Configured maxSize ${ps.maxSize} will be capped.`,
            severity: 'warn'
          });
        }
      } catch { /* invalid byte size handled upstream */ }
    }
  }
  if (emitted) {
    pushCapability(b, 'request.schema.<binary>', 'partial', 'Lambda authorizer + extension regex',
      'magic-byte sniffing requires Lambda; extension allowlist also matchable via WAFv2 regex on path.',
      'simulatable');
  }
}
