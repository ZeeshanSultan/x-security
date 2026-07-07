/**
 * OpenAppSec declarative policy builders.
 *
 * Maps XSecurity IR endpoints into OpenAppSec declarative YAML structure:
 *   policies.default + per-endpoint schemaValidation rules, rate-limit
 *   practices, log triggers, and custom responses.
 *
 * Primary focus (per PRD R2.4): request schema annotations → schemaValidation.
 * Secondary: rate limit → rate-limit practices. Other fields (auth, CORS,
 * IP policy) are emitted with comments / capability=partial when applicable.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';
import type {
  ParamSchema,
  RateLimit,
  RequestPolicy,
  XSecurityPolicy,
} from '@x-security/schema';

// SemanticType isn't re-exported from the package index; mirror the literal
// union here. Kept in lockstep with packages/schema/src/types.ts.
type SemanticType = NonNullable<ParamSchema['type']>;

// ---------- Declarative document shape (subset we emit) ----------

/**
 * Real open-appsec local_policy.yaml shape (per upstream `examples/local_policy.yaml`
 * and v1beta2 CRD `specific-rules` variant):
 *
 *   policies.{default,specific-rules}:
 *     - host, mode, practices[], triggers[], custom-response
 *   practices: [ { name, openapi-schema-validation, web-attacks, anti-bot, ... } ]
 *   log-triggers: [ ... ]    # NOT `triggers:`
 *   custom-responses: [ ... ]
 *
 * `apiVersion:` does NOT exist in the flat local-policy format (only in K8s CRDs).
 * Top-level `schemaValidation:` does NOT exist — `openapi-schema-validation` is a
 * sub-block of a practice, accepting `configmap: [string]` or `files: [string]`
 * pointing at an OpenAPI spec, NOT inline property rules. See STATUS.md.
 *
 * `x-security-extended` carries XSecurity's per-endpoint schema details so the
 * intent isn't lost; open-appsec ignores unknown top-level keys without erroring.
 */
export interface OpenAppSecDoc {
  policies: {
    default: OpenAppSecPolicyBinding;
    'specific-rules': OpenAppSecSpecificRule[];
  };
  practices: OpenAppSecPractice[];
  'log-triggers': OpenAppSecTrigger[];
  'custom-responses': OpenAppSecCustomResponse[];
  'x-security-extended'?: {
    'schema-validation': OpenAppSecSchemaValidation[];
  };
}

export interface OpenAppSecPolicyBinding {
  mode: 'prevent-learn' | 'detect-learn' | 'prevent' | 'detect' | 'inactive';
  practices: string[];
  triggers: string[];
  'custom-response': string;
  'source-identifiers'?: string;
  'trusted-sources'?: string;
  exceptions?: string[];
}

export interface OpenAppSecSpecificRule {
  name?: string;
  host: string;
  triggers: string[];
  mode: 'prevent-learn' | 'detect-learn' | 'prevent' | 'detect' | 'inactive';
  'custom-response': string;
  practices: string[];
  'source-identifiers'?: string;
  'trusted-sources'?: string;
  exceptions?: string[];
}

/**
 * `type:` is a XSecurity-internal hint used by buildDoc to group; open-appsec
 * does not consume it. Real local_policy.yaml practices are tagged by which
 * sub-block they carry (web-attacks vs rate-limit vs openapi-schema-validation).
 */
export interface OpenAppSecPractice {
  name: string;
  type?: 'threat-prevention' | 'access-control' | 'rate-limit';
  'web-attacks'?: {
    'minimum-confidence': 'critical' | 'high' | 'medium' | 'low';
    'max-url-size-bytes'?: number;
    'max-body-size-kb'?: number;
    'override-mode': 'prevent-learn' | 'detect-learn' | 'prevent' | 'detect' | 'inactive';
  };
  'anti-bot'?: {
    'injected-URIs': string[];
    'validated-URIs': string[];
    'override-mode': 'prevent-learn' | 'detect-learn' | 'prevent' | 'detect' | 'inactive';
  };
  'snort-signatures'?: { configmap: string[]; 'override-mode': string };
  'openapi-schema-validation'?: {
    configmap?: string[];
    files?: string[];
    'override-mode': 'prevent-learn' | 'detect-learn' | 'prevent' | 'detect' | 'inactive';
  };
  'rate-limit'?: {
    'overall-settings-mode': 'according-to-practice' | 'detect' | 'prevent' | 'inactive';
    rules: Array<{
      action: 'detect' | 'prevent' | 'inactive';
      uri: string;
      unit: 'minute' | 'second';
      limit: number;
    }>;
  };
}

export interface OpenAppSecTrigger {
  name: string;
  'access-control-logging': { 'allow-events': boolean; 'drop-events': boolean };
  'additional-suspicious-events-logging'?: {
    enabled: boolean;
    'minimum-severity': 'high' | 'medium' | 'low' | 'critical';
    'response-body': boolean;
  };
  'appsec-logging': {
    'detect-events': boolean;
    'prevent-events': boolean;
    'all-web-requests': boolean;
  };
  'extended-logging': {
    'url-path': boolean;
    'url-query': boolean;
    'http-headers': boolean;
    'request-body': boolean;
  };
  'log-destination': {
    cef?: { 'cef-server-udp-port': number; 'cef-server-ip': string };
    cloud: boolean;
    stdout: { format: 'json' | 'json-formatted' };
    syslog?: { 'syslog-server-udp-port': number; 'syslog-server-ip': string };
  };
}

export interface OpenAppSecCustomResponse {
  name: string;
  mode: 'block-page' | 'response-code-only' | 'redirect';
  'message-title'?: string;
  'message-body'?: string;
  'http-response-code'?: number;
  'redirect-url'?: string;
}

export interface OpenAppSecSchemaValidation {
  name: string;
  enforcementLevel: 'strict' | 'lax';
  overrideMode: 'prevent' | 'detect' | 'inactive';
  schemas: {
    request: {
      contentType?: string[];
      maxBodySizeBytes?: number;
      properties: Record<string, OpenAppSecPropertyRule>;
      required: string[];
    };
    response?: {
      contentType?: string[];
      properties: Record<string, OpenAppSecPropertyRule>;
      stripUnknownFields?: boolean;
    };
  };
  // Endpoint binding
  binding: {
    method: string;
    path: string;
    operationId: string;
  };
}

export interface OpenAppSecPropertyRule {
  type: string;
  format?: string;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  'allowed-mime-types'?: string[];
  'max-size-bytes'?: number;
  'domain-allowlist'?: string[];
  mitigates?: string[];
}

// ---------- Constants / canonical names ----------

const DEFAULT_PRACTICE = 'x-security-threat-prevention';
const DEFAULT_RATE_LIMIT_PRACTICE = 'x-security-rate-limit';
const DEFAULT_TRIGGER = 'x-security-log-trigger';
const DEFAULT_RESPONSE = 'x-security-blocked-response';

// ---------- Helpers ----------

const BYTE_UNITS: Record<string, number> = {
  B: 1,
  KB: 1024,
  MB: 1024 * 1024,
  GB: 1024 * 1024 * 1024,
};

export function parseByteSize(s: string | undefined): number | undefined {
  if (!s) return undefined;
  const m = /^(\d+(?:\.\d+)?)\s*([KMGB]?B)?$/i.exec(s.trim());
  if (!m) return undefined;
  const n = Number(m[1]);
  const unit = (m[2] ?? 'B').toUpperCase();
  const mult = BYTE_UNITS[unit] ?? 1;
  return Math.round(n * mult);
}

const DURATION_TO_UNIT: Record<string, 'minute' | 'second'> = {
  s: 'second',
  m: 'minute',
};

export function durationToUnit(window: string): { unit: 'minute' | 'second'; factor: number } {
  // Returns the OpenAppSec unit and a factor (how many such units the window represents).
  const m = /^(\d+)\s*([smhd])$/i.exec(window.trim());
  if (!m) return { unit: 'minute', factor: 1 };
  const n = Number(m[1]);
  const u = (m[2] ?? 'm').toLowerCase();
  if (u === 's') return { unit: 'second', factor: n };
  if (u === 'm') return { unit: 'minute', factor: n };
  // Hours/days collapse to minutes
  if (u === 'h') return { unit: 'minute', factor: n * 60 };
  return { unit: 'minute', factor: n * 60 * 24 };
}

export function sanitizeName(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || 'endpoint';
}

function semanticToOpenAppSec(t: SemanticType | undefined): { type: string; format?: string } {
  switch (t) {
    case 'integer': return { type: 'integer' };
    case 'float': return { type: 'number' };
    case 'boolean': return { type: 'boolean' };
    case 'email': return { type: 'string', format: 'email' };
    case 'phone': return { type: 'string', format: 'phone' };
    case 'url': return { type: 'string', format: 'uri' };
    case 'date': return { type: 'string', format: 'date' };
    case 'datetime': return { type: 'string', format: 'date-time' };
    case 'uuid': return { type: 'string', format: 'uuid' };
    case 'ip-address': return { type: 'string', format: 'ipv4' };
    case 'binary': return { type: 'string', format: 'binary' };
    case 'name':
    case 'free-text':
    case 'string':
    default: return { type: 'string' };
  }
}

function paramSchemaToProperty(p: ParamSchema): OpenAppSecPropertyRule {
  const base = semanticToOpenAppSec(p.type);
  const rule: OpenAppSecPropertyRule = { type: base.type };
  if (base.format !== undefined) rule.format = base.format;
  if (p.minLength !== undefined) rule.minLength = p.minLength;
  if (p.fixedLength !== undefined) {
    rule.minLength = p.fixedLength;
    rule.maxLength = p.fixedLength;
  }
  if (p.maxLength !== undefined) rule.maxLength = p.maxLength;
  if (p.pattern !== undefined) rule.pattern = p.pattern;
  if (p.min !== undefined) rule.minimum = p.min;
  if (p.max !== undefined) rule.maximum = p.max;
  if (p.allowedMimeTypes !== undefined) rule['allowed-mime-types'] = [...p.allowedMimeTypes];
  if (p.maxSize !== undefined) {
    const bytes = parseByteSize(p.maxSize);
    if (bytes !== undefined) rule['max-size-bytes'] = bytes;
  }
  if (p.domainAllowlist !== undefined) rule['domain-allowlist'] = [...p.domainAllowlist];
  if (p.mitigates !== undefined && p.mitigates.length > 0) rule.mitigates = [...p.mitigates];
  return rule;
}

// ---------- Builders ----------

export function buildDefaultTrigger(): OpenAppSecTrigger {
  return {
    name: DEFAULT_TRIGGER,
    'access-control-logging': { 'allow-events': false, 'drop-events': true },
    'additional-suspicious-events-logging': {
      enabled: true,
      'minimum-severity': 'high',
      'response-body': false,
    },
    'appsec-logging': {
      'detect-events': true,
      'prevent-events': true,
      'all-web-requests': false,
    },
    'extended-logging': {
      'url-path': true,
      'url-query': true,
      'http-headers': true,
      'request-body': false,
    },
    'log-destination': {
      cloud: false,
      stdout: { format: 'json' },
    },
  };
}

export function buildDefaultResponse(): OpenAppSecCustomResponse {
  return {
    name: DEFAULT_RESPONSE,
    mode: 'response-code-only',
    'http-response-code': 403,
  };
}

/**
 * Path inside the open-appsec agent container where the XSecurity OpenAPI
 * schema fragment is mounted. The chain compose mounts the generator out dir
 * at /ext/appsec/, so policy.yaml lands at /ext/appsec/local_policy.yaml and
 * the schema fragment at /ext/appsec/openapi-schema.yaml. Operators deploying
 * elsewhere should bind their mount to match (documented in STATUS.md).
 */
export const SCHEMA_FILE_PATH = '/ext/appsec/openapi-schema.yaml';

export function buildThreatPreventionPractice(opts: { schemaFile?: string } = {}): OpenAppSecPractice {
  const practice: OpenAppSecPractice = {
    name: DEFAULT_PRACTICE,
    type: 'threat-prevention',
    'web-attacks': {
      'minimum-confidence': 'high',
      'override-mode': 'prevent-learn',
    },
    'openapi-schema-validation': {
      // `files:` is the standalone-Docker form; `configmap:` is the k8s form.
      // open-appsec accepts either; we emit files: keyed to the mount path.
      files: opts.schemaFile ? [opts.schemaFile] : [],
      'override-mode': 'prevent-learn',
    },
    'anti-bot': {
      'injected-URIs': [],
      'validated-URIs': [],
      'override-mode': 'prevent-learn',
    },
  };
  return practice;
}

export function buildRateLimitPractice(rules: RateLimitRule[]): OpenAppSecPractice | undefined {
  if (rules.length === 0) return undefined;
  return {
    name: DEFAULT_RATE_LIMIT_PRACTICE,
    type: 'rate-limit',
    'rate-limit': {
      'overall-settings-mode': 'according-to-practice',
      rules: rules.map((r) => ({
        action: 'prevent',
        uri: r.uri,
        unit: r.unit,
        limit: r.limit,
      })),
    },
  };
}

export interface RateLimitRule {
  uri: string;
  unit: 'minute' | 'second';
  limit: number;
}

function rateLimitToRules(uri: string, rl: RateLimit | RateLimit[] | undefined): RateLimitRule[] {
  if (rl === undefined) return [];
  const list = Array.isArray(rl) ? rl : [rl];
  return list.map((r) => {
    const { unit, factor } = durationToUnit(r.window);
    // Normalize: limit per single base unit (minute or second).
    const normalizedLimit = factor > 0 ? Math.max(1, Math.round(r.requests / factor)) : r.requests;
    return { uri, unit, limit: normalizedLimit };
  });
}

export function buildSchemaValidation(ep: EndpointIR): OpenAppSecSchemaValidation | undefined {
  const policy: XSecurityPolicy = ep.policy;
  const req: RequestPolicy | undefined = policy.request;
  const res = policy.response;

  // Only emit when there's something to validate.
  if (!req && !res) return undefined;

  const requestBlock: OpenAppSecSchemaValidation['schemas']['request'] = {
    properties: {},
    required: [],
  };
  if (req?.contentType) requestBlock.contentType = [...req.contentType];
  if (req?.maxBodySize) {
    const bytes = parseByteSize(req.maxBodySize);
    if (bytes !== undefined) requestBlock.maxBodySizeBytes = bytes;
  }
  if (req?.schema) {
    for (const [name, p] of Object.entries(req.schema)) {
      requestBlock.properties[name] = paramSchemaToProperty(p);
    }
  }

  // Mark required parameters from IR (body fields whose `required` is true).
  for (const param of ep.parameters) {
    if (param.in === 'body' && param.required && requestBlock.properties[param.name]) {
      requestBlock.required.push(param.name);
    }
  }

  const out: OpenAppSecSchemaValidation = {
    name: sanitizeName(`${ep.method}-${ep.operationId}`),
    enforcementLevel: 'strict',
    overrideMode: 'prevent',
    schemas: {
      request: requestBlock,
    },
    binding: {
      method: ep.method,
      path: ep.path,
      operationId: ep.operationId,
    },
  };

  if (res) {
    const responseBlock: NonNullable<OpenAppSecSchemaValidation['schemas']['response']> = {
      properties: {},
    };
    if (res.contentType) responseBlock.contentType = [...res.contentType];
    if (res.schema) {
      for (const [name, p] of Object.entries(res.schema)) {
        responseBlock.properties[name] = paramSchemaToProperty(p);
      }
    }
    if (res.stripUnknownFields !== undefined) responseBlock.stripUnknownFields = res.stripUnknownFields;
    out.schemas.response = responseBlock;
  }

  return out;
}

/**
 * Extract the hostname (no scheme, no path, no port unless explicit) from a
 * server URL. open-appsec's `host:` is compared against the request's `Host:`
 * header — it must be a bare hostname, NOT a host+path concatenation.
 *
 * Examples:
 *   https://api.example.com/v1   →  api.example.com
 *   http://vapi:80               →  vapi   (default port stripped)
 *   http://vapi:8080             →  vapi:8080
 *
 * Wave-8: replaces the wave-7 `${host}${path}` concatenation that caused
 * every request to fall through to the `assetName: Any` default policy.
 */
export function extractHost(serverUrl: string | undefined): string {
  if (!serverUrl) return '*';
  try {
    const u = new URL(serverUrl);
    const hostname = u.hostname;
    if (!hostname) return '*';
    const port = u.port;
    const proto = u.protocol;
    const isDefaultPort =
      port === '' ||
      (proto === 'http:' && port === '80') ||
      (proto === 'https:' && port === '443');
    return isDefaultPort ? hostname : `${hostname}:${port}`;
  } catch {
    return '*';
  }
}

export interface BuildDocOptions {
  schemaFile?: string;
}

export function buildDoc(spec: SpecIR, opts: BuildDocOptions = {}): OpenAppSecDoc {
  const schemaValidations: OpenAppSecSchemaValidation[] = [];
  const rateLimitRules: RateLimitRule[] = [];

  for (const ep of spec.endpoints) {
    const sv = buildSchemaValidation(ep);
    if (sv) schemaValidations.push(sv);
    rateLimitRules.push(...rateLimitToRules(ep.path, ep.policy.rateLimit));
  }

  const schemaFile = opts.schemaFile ?? (schemaValidations.length > 0 ? SCHEMA_FILE_PATH : undefined);

  const practices: OpenAppSecPractice[] = [
    buildThreatPreventionPractice(schemaFile ? { schemaFile } : {}),
  ];
  const rlPractice = buildRateLimitPractice(rateLimitRules);
  if (rlPractice) practices.push(rlPractice);

  const allPracticeNames = [DEFAULT_PRACTICE, ...(rlPractice ? [DEFAULT_RATE_LIMIT_PRACTICE] : [])];

  // open-appsec matches `host:` against the request's `Host:` header. It MUST
  // be a bare hostname (optionally with port if non-default). The wave-7 bug
  // was concatenating the path: `host: api.example.com/api/auth/login` never
  // matched a real `Host: api.example.com` header → every request fell
  // through to the default `assetName: Any` policy.
  //
  // Wave-8: emit ONE specific-rule per unique host, attaching x-security's
  // practices. Per-path enforcement comes from the per-host openapi-schema
  // file (the OpenAPI fragment carries the per-path schemas the agent walks
  // when classifying inbound requests).
  const hosts = new Set<string>();
  for (const server of spec.servers) {
    hosts.add(extractHost(server.url));
  }
  if (hosts.size === 0) hosts.add('*');

  const specificRules: OpenAppSecSpecificRule[] = Array.from(hosts).map((host) => ({
    name: `x-security-asset-${sanitizeName(host) || 'default'}`,
    host,
    triggers: [DEFAULT_TRIGGER],
    mode: 'prevent-learn',
    'custom-response': DEFAULT_RESPONSE,
    practices: allPracticeNames,
  }));

  return {
    policies: {
      default: {
        mode: 'prevent-learn',
        practices: allPracticeNames,
        triggers: [DEFAULT_TRIGGER],
        'custom-response': DEFAULT_RESPONSE,
      },
      'specific-rules': specificRules,
    },
    practices,
    'log-triggers': [buildDefaultTrigger()],
    'custom-responses': [buildDefaultResponse()],
    'x-security-extended': {
      'schema-validation': schemaValidations,
    },
  };
}

// ---------- OpenAPI fragment builder ----------

/**
 * Build a minimal OpenAPI 3.0 document containing only the route shape +
 * parameter/body schemas the agent needs for schema validation. Drops `info`,
 * `security`, `tags`, etc. — open-appsec's `openapi-schema-validation` parser
 * only walks `paths.*` and the inline schemas.
 *
 * This is the artifact `practices[].openapi-schema-validation.files:` points
 * at. x-security writes it as a sibling to local_policy.yaml.
 */
export interface OpenApiFragment {
  openapi: string;
  info: { title: string; version: string };
  paths: Record<string, Record<string, unknown>>;
}

export function buildOpenApiFragment(spec: SpecIR): OpenApiFragment {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const ep of spec.endpoints) {
    const pathKey = ep.path;
    const methodKey = ep.method.toLowerCase();
    const pathItem = paths[pathKey] ?? {};
    // ep.raw is the original OperationObject — already minimal-enough for
    // schema validation. Reuse it verbatim. The agent walks request body
    // schemas + parameter schemas; both are preserved.
    pathItem[methodKey] = ep.raw as unknown;
    paths[pathKey] = pathItem;
  }

  return {
    openapi: '3.0.3',
    info: {
      title: spec.info.title,
      version: spec.info.version,
    },
    paths,
  };
}
