// Kong OSS 3.x generator — emits a single kong.yml declarative-config artifact.
//
// Maps each EndpointIR onto a Kong service + route with attached plugins built
// from XSecurityPolicy fields. See plugins.ts for per-field mapping and the
// capabilities matrix below for honesty about what we can/can't do in OSS.

import { createHash } from 'node:crypto';
import { dump as yamlDump } from 'js-yaml';
import type {
  Generator,
  CapabilityMatrix,
  ConfigArtifact,
  SpecIR,
  EndpointIR
} from '@x-security/core';
import type {
  KongDeclarativeConfig,
  KongPlugin,
  KongRoute,
  KongService,
  KongDeployment,
  XSecurityWarning
} from './types.js';
import { collectSsrfPolicyWarnings } from '../ssrf-policy-check.js';
import {
  buildAuthPlugins,
  buildAuthzPlugins,
  buildRuleBasedAuthzPlugins,
  buildCachePlugins,
  buildCorsPlugin,
  buildIpRestrictionPlugin,
  buildRateLimitPlugins,
  buildRequestValidatorPlugin,
  buildResponsePlugins,
  buildSignaturePlugin,
  buildSsrfPreFunctionPlugins,
  buildMassAssignPreFunctionPlugins,
  buildSqliPreFunctionPlugins,
  buildDeprecatedEndpointPlugins,
  applyTargetOverrides,
  kongEditionFor,
  isLoginLikeEndpoint,
  type KongEdition,
  type WarningSink
} from './plugins.js';
import {
  buildResponseStripUnknownPlugins,
  buildResponseStripTracesPlugins,
  buildResponseGenericErrorPlugins,
  buildResponseContentTypeAssertPlugins,
  buildResponseMaxLengthPlugins,
  buildRateLimitFingerprintPlugins,
  buildBotProtectionPlugins
} from './plugins-w26.js';
import {
  buildLoggingPlugins,
  buildPasswordPolicyPlugins,
  buildForbidArrayRootPlugins,
  buildIdempotencyKeyPlugins,
  buildAccountLockoutPlugins
} from './v07-plugins.js';
import { buildConsumers } from './consumers.js';

export interface KongGeneratorOptions {
  /** Emit `consumers:` + per-plugin credentials so OSS Kong's jwt/key-auth/acl
   *  plugins actually authenticate requests instead of wholesale-401ing
   *  every request. Default ON. Set to false for spec-only output. */
  withConsumers?: boolean;
  /** Deployment topology. Controls upstream URL rewriting:
   *  - `standalone` (default): services use spec.servers[0].url.
   *  - `with-coraza`: services point at http://coraza:8080 (eliminates the
   *    manual sed patch the chain demo previously required).
   *  - `behind-proxy`: services use spec.servers[0].url BUT also emit
   *    `trusted_ips` so X-Forwarded-For is honored for rate-limit=ip.
   *  - `with-istio`: services point at http://localhost:15001 (Envoy
   *    sidecar inbound port). */
  deployment?: KongDeployment;
  /** Kong edition. `enterprise` swaps the bearer-jwt OSS plugin for the
   *  `openid-connect` plugin (real JWKS fetch + RS256) and skips the HS256
   *  jwt_secrets downgrade. `oss` (default) keeps the existing behavior. */
  edition?: KongEdition;
  /** W15-C: deployment runs in DB-less mode (`KONG_DATABASE=off`). When set,
   *  per-identity rate-limit buckets fall back to `policy: local` with a
   *  structured warning instead of `policy: cluster` (which requires a DB).
   *  Default false. */
  dbless?: boolean;
  /** W21-C: explicit rate-limit policy. Defaults to `local` (safe for Kong OSS
   *  DB-less, which is the OSS quickstart default — `policy: cluster` causes
   *  Kong to refuse to load there). Set to `cluster` to restore W15-C
   *  cross-instance per-identity buckets — operator confirms Kong is running
   *  in database mode. `dbless: true` hard-overrides cluster back to local
   *  with a warning. */
  policy?: 'local' | 'cluster';
}

// Stable v5-style UUID derived from a namespace + name. Kong uses plugin `id`
// as the primary key — two plugins with the same config produce the same
// computed uuid and Kong rejects the second one as a "uniqueness violation".
// We make the id deterministic from route+plugin+index so the same input
// always yields the same kong.yml (x-security diff depends on it).
const X_SECURITY_KONG_NAMESPACE = 'a4f7e8c2-1b3d-4e5f-9a8b-7c6d5e4f3a2b';

function uuidv5(name: string, namespace: string = X_SECURITY_KONG_NAMESPACE): string {
  const nsBytes = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const hash = createHash('sha1').update(nsBytes).update(name).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const h = bytes.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const KONG_FORMAT_VERSION = '3.0';

// Deployment-specific upstream URL. with-coraza/with-istio rewrite the URL
// regardless of what the spec declares — operators are explicitly opting
// into that topology via the flag.
function deploymentUpstreamUrl(spec: SpecIR, deployment: KongDeployment): string {
  switch (deployment) {
    case 'with-coraza':
      return 'http://coraza:8080';
    case 'with-istio':
      return 'http://localhost:15001';
    case 'standalone':
    case 'behind-proxy':
    default: {
      const first = spec.servers[0]?.url;
      return first && first.length > 0 ? first : 'http://upstream.invalid';
    }
  }
}

function serviceNameFor(ep: EndpointIR): string {
  return `svc_${ep.operationId}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 80);
}

function routeNameFor(ep: EndpointIR): string {
  return `route_${ep.operationId}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 80);
}

// Convert OpenAPI-style path templates (`/api/users/{id}`) to Kong regex paths
// (`~/api/users/[^/]+`) so path params match at runtime.
function kongPath(openapiPath: string): string {
  if (!openapiPath.includes('{')) return openapiPath;
  return '~' + openapiPath.replace(/\{[^}]+\}/g, '[^/]+');
}

interface BuildContext {
  edition: KongEdition;
  warn: WarningSink;
  dbless: boolean;
  policy: 'local' | 'cluster' | undefined;
}

function buildEndpointPlugins(ep: EndpointIR, ctx: BuildContext): KongPlugin[] {
  const p = ep.policy;
  // Per-endpoint edition can override the spec-default via targetOverrides.
  const epEdition = kongEditionFor(p) === 'enterprise' ? 'enterprise' : ctx.edition;

  const auth = p.authentication;
  const unauthenticated = !auth || auth.type === 'none';
  const loginLike = isLoginLikeEndpoint(ep);

  // Surface enterprise-only targetOverrides on an OSS run so operators
  // know what got dropped.
  const overrides = p.targetOverrides?.kong as
    | { edition?: string; plugins?: KongPlugin[] }
    | undefined;
  if (overrides?.edition === 'enterprise' && ctx.edition === 'oss') {
    ctx.warn({
      field: 'targetOverrides.kong.edition',
      endpoint: ep.operationId,
      declared: 'enterprise',
      emitted: 'oss',
      reason:
        'endpoint requested enterprise features but generator run is --kong-edition=oss; ' +
        'enterprise-only plugins (request-validator body_schema, openid-connect) are suppressed.'
    });
  }

  const plugins: KongPlugin[] = [
    // K-5: deprecated-endpoint block runs FIRST so the 410 short-circuits
    // every request before rate-limit/auth fire (otherwise the scorer would
    // attribute the block as wholesale-rate-limit instead of deprecated).
    ...buildDeprecatedEndpointPlugins(p, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildAuthPlugins(p.authentication, epEdition),
    // v0.7 authentication.passwordPolicy — access-phase pre-function validates
    // the password body field (length/charset/blocklist) → 422 (FULL).
    ...buildPasswordPolicyPlugins(p.authentication, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    // v0.7 authentication.accountLockout — per-credential rate-limit throttle
    // (PARTIAL — not a true failed-attempt lockout; see _x_security_warnings).
    ...buildAccountLockoutPlugins(p.authentication, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    ...buildAuthzPlugins(p.authorization),
    ...buildRuleBasedAuthzPlugins(p.authorization, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    ...buildRateLimitPlugins(p.rateLimit, {
      unauthenticated,
      loginLike,
      dbless: ctx.dbless,
      ...(ctx.policy !== undefined ? { policy: ctx.policy } : {}),
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    ...buildCorsPlugin(p.cors),
    ...buildIpRestrictionPlugin(p.ipPolicy),
    ...buildCachePlugins(p.cacheable),
    ...buildRequestValidatorPlugin(p.request, epEdition),
    ...buildSignaturePlugin(p.request?.signature, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    // W26: rate-limit fingerprint composite key (ip+ua hash) — runs before
    // request-side checks so the X-XSecurity-Fingerprint header is set
    // before any plugin (or upstream) might consume it.
    ...buildRateLimitFingerprintPlugins(p.rateLimit, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    // W26: botProtection — UA blocklist + JS-challenge cookie gate. Runs
    // before request-validator/SSRF/etc so bot UAs short-circuit early.
    ...buildBotProtectionPlugins(p.botProtection, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildSsrfPreFunctionPlugins(p.request, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      params: ep.parameters,
      warn: ctx.warn
    }),
    // K-3: mass-assignment unknown-field rejection (gated on denyUnknownFields
    // or allowedFields). API6 vAPI gap.
    ...buildMassAssignPreFunctionPlugins(p.request, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    // K-4: body SQLi heuristic (gated on contentType=json + schema present).
    // API8 vAPI gap — Kong OSS has no native SQLi plugin.
    ...buildSqliPreFunctionPlugins(p.request, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    // v0.7 request.idempotencyKey — best-effort shared_dict replay suppression
    // (PARTIAL — not atomic idempotency; see _x_security_warnings).
    ...buildIdempotencyKeyPlugins(p.request, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    // v0.7 logging (SSEC-AUDIT) — native Kong log plugin matching logging.sink
    // with declared-event custom fields + piiRedaction nil-set (FULL).
    ...buildLoggingPlugins(p, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {}),
      warn: ctx.warn
    }),
    ...buildResponsePlugins(p.response),
    // v0.7 response.forbidArrayRoot — body_filter post-function blocks a bare
    // top-level array response → 502 (FULL, API3 JSON-hijacking defense).
    ...buildForbidArrayRootPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    // W26 response-side post-function plugins. Order: maxLength (truncate
    // oversized fields) before strip-unknown (drop keys outside schema), then
    // strip-traces and generic-error (which operates on error bodies only).
    ...buildResponseMaxLengthPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildResponseStripUnknownPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildResponseStripTracesPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildResponseGenericErrorPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    }),
    ...buildResponseContentTypeAssertPlugins(p.response, {
      ...(ep.operationId ? { endpoint: ep.operationId } : {})
    })
  ];
  return applyTargetOverrides(p, plugins);
}

// Assign a deterministic plugin id so two plugins with identical config on
// different routes don't collide on Kong's computed primary key.
function assignPluginIds(routeName: string, plugins: KongPlugin[]): KongPlugin[] {
  return plugins.map((plugin, idx) => ({
    ...plugin,
    id: plugin.id ?? uuidv5(`${routeName}|${plugin.name}|${idx}`)
  }));
}

function buildService(spec: SpecIR, ep: EndpointIR, ctx: BuildContext, deployment: KongDeployment): KongService {
  const routeName = routeNameFor(ep);
  const route: KongRoute = {
    name: routeName,
    paths: [kongPath(ep.path)],
    methods: [ep.method],
    strip_path: false,
    preserve_host: true,
    plugins: assignPluginIds(routeName, buildEndpointPlugins(ep, ctx))
  };

  const service: KongService = {
    name: serviceNameFor(ep),
    url: deploymentUpstreamUrl(spec, deployment),
    routes: [route]
  };

  const t = ep.policy.timeout;
  if (t?.connect !== undefined) service.connect_timeout = t.connect;
  if (t?.read !== undefined) service.read_timeout = t.read;
  if (t?.write !== undefined) service.write_timeout = t.write;

  if (route.plugins && route.plugins.length === 0) {
    delete route.plugins;
  }

  return service;
}

// Detect whether the spec has any bearer-jwt endpoints whose effective edition
// is enterprise. Used to decide whether to skip jwt_secrets emission (the
// openid-connect plugin handles JWT validation in enterprise mode).
function specHasEnterpriseJwt(spec: SpecIR, runEdition: KongEdition): boolean {
  if (runEdition === 'enterprise') {
    return spec.endpoints.some((ep) => ep.policy.authentication?.type === 'bearer-jwt');
  }
  return spec.endpoints.some(
    (ep) =>
      ep.policy.authentication?.type === 'bearer-jwt' &&
      kongEditionFor(ep.policy) === 'enterprise'
  );
}

export interface KongGenerator extends Generator {
  /** Reconfigure the singleton in place. The CLI calls this after parsing
   *  flags; tests call it to opt back into the legacy empty-consumers mode. */
  configure(opts: KongGeneratorOptions): void;
  /** Warnings produced by the most recent generate() call. The CLI reads
   *  these and emits them on stderr so the operator sees the HS256 downgrade. */
  readonly lastWarnings: readonly string[];
  /** Structured warnings from the most recent generate() call. Same content
   *  as the kong.yml's `_x_security_warnings` block. */
  readonly lastStructuredWarnings: readonly XSecurityWarning[];
}

export function createKongGenerator(opts: KongGeneratorOptions = {}): KongGenerator {
  let withConsumers = opts.withConsumers ?? true;
  let deployment: KongDeployment = opts.deployment ?? 'standalone';
  let edition: KongEdition = opts.edition ?? 'oss';
  let dbless: boolean = opts.dbless ?? false;
  let policy: 'local' | 'cluster' | undefined = opts.policy;
  let lastWarnings: string[] = [];
  let lastStructuredWarnings: XSecurityWarning[] = [];

  const gen: KongGenerator = {
    name: 'kong',
    targets: ['kong-oss-3'],

    configure(o: KongGeneratorOptions): void {
      if (o.withConsumers !== undefined) withConsumers = o.withConsumers;
      if (o.deployment !== undefined) deployment = o.deployment;
      if (o.edition !== undefined) edition = o.edition;
      if (o.dbless !== undefined) dbless = o.dbless;
      if (o.policy !== undefined) policy = o.policy;
    },

    get lastWarnings(): readonly string[] {
      return lastWarnings;
    },

    get lastStructuredWarnings(): readonly XSecurityWarning[] {
      return lastStructuredWarnings;
    },

    generate(spec: SpecIR): ConfigArtifact[] {
      lastWarnings = [];
      lastStructuredWarnings = [];
      const structured: XSecurityWarning[] = [];
      const warn: WarningSink = (w) => structured.push(w);

      const ctx: BuildContext = { edition, warn, dbless, policy };
      const services = spec.endpoints.map((ep) => buildService(spec, ep, ctx, deployment));

      const config: KongDeclarativeConfig = {
        _format_version: KONG_FORMAT_VERSION,
        _transform: true,
        services
      };

      if (withConsumers) {
        const bundle = buildConsumers(spec, {
          enterpriseJwtRoutes: specHasEnterpriseJwt(spec, edition),
          onWarning: warn
        });
        if (bundle.consumers.length) config.consumers = bundle.consumers;
        if (bundle.jwt_secrets.length) config.jwt_secrets = bundle.jwt_secrets;
        if (bundle.keyauth_credentials.length) config.keyauth_credentials = bundle.keyauth_credentials;
        if (bundle.hmacauth_credentials.length) config.hmacauth_credentials = bundle.hmacauth_credentials;
        if (bundle.acls.length) config.acls = bundle.acls;
        lastWarnings = bundle.warnings;
      }

      // behind-proxy: warn that trusted_ips must be set at the Kong-server
      // level (kong.conf / KONG_TRUSTED_IPS env var). Declarative-config
      // can't set top-level Kong server settings — record the gap so
      // operators don't assume X-Forwarded-For is already honored.
      if (deployment === 'behind-proxy') {
        warn({
          field: 'deployment.trusted_ips',
          declared: 'behind-proxy',
          emitted: 'X-Forwarded-For honored only if KONG_TRUSTED_IPS is set at the Kong-server level',
          reason:
            'declarative-config cannot configure kong.conf-level trusted_ips. ' +
            'Set KONG_TRUSTED_IPS="0.0.0.0/0,::/0" (or the specific proxy CIDR) ' +
            'on the Kong container so rate-limit limit_by=ip uses the real client IP.'
        });
      }

      // Spec-hygiene: warn on url-typed params that lack SSRF policy. Operators
      // may legitimately omit it (internal endpoints), so warn — don't fail.
      const ssrfWarnings = collectSsrfPolicyWarnings(spec, 'kong');
      if (ssrfWarnings.length > 0) {
        lastWarnings = [...lastWarnings, ...ssrfWarnings.map((w) => w.message)];
      }

      // request.schema.injectionGuard is UNSUPPORTED on Kong OSS. There is no
      // libinjection/detectSQLi primitive in OSS Kong; a pre-function regex
      // would be a fragile fake (Rule D-1: no shortcuts that mask the gap), so
      // we honestly abstain and surface a spec→runtime divergence per declaring
      // param — same pattern as ssrf-policy-missing. coraza/bunkerweb carry
      // SSEC-INJECTION; kong does not, preserving the cross-target rollup.
      for (const w of collectInjectionGuardWarnings(spec)) warn(w);

      lastStructuredWarnings = [...structured];

      const body = yamlDump(config, {
        noRefs: true,
        lineWidth: 120,
        sortKeys: false
      });

      // Kong rejects unknown top-level keys (`unknown field: ...`), so we
      // CAN'T put `_x_security_warnings:` directly in the declarative
      // config. Instead we emit a comment header at the top of the file
      // with two grep targets:
      //   1) `# WARNING:` lines — one per divergence, human-readable.
      //   2) A YAML-commented `# _x_security_warnings:` block — structured
      //      data that uncomments cleanly into a valid YAML array (so
      //      `sed 's/^# _x_security_warnings/_x_security_warnings/; s/^#   //' kong.yml | yq` works for tooling).
      // Both forms cover `grep _x_security_warnings kong.yml` and
      // `grep '^# WARNING' kong.yml` per the workstream contract.
      const header = renderWarningsHeader(structured, deployment, edition);

      return [
        {
          path: 'kong.yml',
          content: header + body,
          format: 'yaml'
        }
      ];
    },

    capabilities(): CapabilityMatrix {
      return {
        fields: {
          'authentication.bearer-jwt': 'partial',          // OSS jwt needs preconfigured consumers
          'authentication.api-key': 'full',
          'authentication.oauth2': 'partial',              // OSS oauth2 has no JWKS introspection
          'authentication.mtls': 'override-only',          // mtls-auth is enterprise
          'authentication.basic': 'unsupported',
          'authentication.none': 'full',
          'authorization.rbac': 'full',                    // via acl plugin
          'authorization.rule-based': 'full',              // K-1: pre-function Lua + resourceLookup
          'authorization.abac': 'unsupported',
          'rateLimit': 'full',
          'timeout.connect': 'full',
          'timeout.read': 'full',
          'timeout.write': 'full',
          'cacheable': 'full',                             // proxy-cache or no-store header
          'cors': 'full',
          'ipPolicy': 'full',
          'request.contentType': 'full',
          'request.maxBodySize': 'full',                   // via request-size-limiting
          'request.schema': 'partial',                     // request-validator is enterprise-only for body_schema; OSS users see degraded enforcement (mass-assign + sqli pre-functions partially cover)
          'request.schema.injectionGuard': 'unsupported',  // HONEST: Kong OSS has no libinjection/@detectSQLi; a pre-function regex would be a fragile fake (Rule D-1). Abstain + _x_security_warnings divergence note; front with coraza/bunkerweb which carry SSEC-INJECTION.
          'request.denyUnknownFields': 'full',             // K-3: pre-function rejects unknown top-level body fields with x-security-mass-assign-403
          'request.allowedFields': 'full',                 // K-3: pre-function allowlist enforcement
          'request.signature': 'partial',                  // hmac-auth: full for hmac-sha* + Authorization header; ed25519/custom-header degrade with stderr warning
          'response.contentType': 'full',                  // post-function header_filter asserts 2xx Content-Type against allowlist, fail-closed 502
          'response.schema': 'full',                       // W31: post-function cjson-decodes body and enforces ALL typed constraints on parsed values (type/format/min/max/lengths/pattern). ParamSchema is flat (no nested properties/items) so top-level = full coverage of what the DSL can express.
          'response.stripUnknownFields': 'full',           // W26: post-function drops keys outside response.schema
          'response.errorScrubbing.stripStackTraces': 'full',  // W26: post-function body_filter scrub on 4xx/5xx
          'response.errorScrubbing.genericMessages': 'full',   // W26: post-function rewrites 5xx body
          'response.schema.type': 'full',                  // W31: Lua type-check + format (email/uuid/url/date/datetime/ip/phone/integer/float/boolean) on decoded value; drop on mismatch
          'response.schema.min': 'full',                   // W31: numeric compare on decoded number; drop on violation
          'response.schema.max': 'full',                   // W31: numeric compare on decoded number; drop on violation
          'response.schema.minLength': 'full',             // W31: #decoded-string compare; drop on violation
          'response.schema.maxLength': 'full',             // W26/W31: truncate decoded string to limit
          'response.schema.fixedLength': 'full',           // W31: truncate-over then exact-#-or-drop on decoded string
          'response.schema.pattern': 'full',               // W31: ngx.re.match applied to PARSED STRING value (never raw body)
          'rateLimit.identifier.fingerprint': 'full',      // W26: pre-function builds ip+ua composite key
          'botProtection': 'full',                         // W26: pre-function UA-blocklist + JS-challenge cookie gate
          'mtls': 'override-only',
          // v0.8 deferred-residuals — Kong OSS enforces NONE of these (plan.generatorTasks=[] for kong). Honest unsupported cells so the published capability matrix is complete and --strict-fidelity fires instead of silently passing (Rule D-1).
          'graphql.operations.authz': 'unsupported',       // per-resolver BOLA/BFLA (API1/API5:2023) needs an operator-supplied GraphQL-aware processor; Kong OSS has no ext_proc-style hook to host one (cf. envoy override-only). No scaffolding plugin can run a resolver-level authz check, so emitting one would be a fake (Rule D-1).
          'graphql.staticLimits': 'unsupported',           // coarse depth/complexity/alias/introspection limits (API4:2023) require parsing the GraphQL document; Kong OSS has no GraphQL parser and a pre-function regex over the POST body would be a fragile fake. Abstain.
          'request.serializeBy': 'unsupported',            // API6:2023 request serialization — Kong OSS has no per-key edge mutex; emitting nothing is honest (cf. coraza/bunkerweb partial, envoy override-only).
          'request.concurrencyLimit': 'unsupported',       // same family as serializeBy — no in-flight concurrency gate in Kong OSS.
          'request.dataAtRest': 'unsupported',             // SSEC-STORAGE — advisory-only field; NOT gateway-enforceable on ANY target. Kong compiles nothing; drives an out-of-band SSEC-STORAGE finding, never a gateway claim.
          // v0.7 SSEC-AUDIT / API3 / API6 fields (previously bunkerweb-only).
          'logging': 'full',                               // v0.7: native Kong log plugin per logging.sink (http-log/file-log/tcp-log/syslog) with declared-event custom fields; piiRedaction nil-sets declared pii field names out of the serialized entry. Real native plugins → full.
          'authentication.passwordPolicy': 'full',         // v0.7: access pre-function validates the password body field (minLength/uppercase/digit/symbol/blocklist) and exits 422 before upstream. Genuine edge enforcement → full.
          'response.forbidArrayRoot': 'full',              // v0.7 API3: body_filter post-function cjson-decodes the body and rewrites a bare top-level array response to 502. Decoded-value check (not raw regex) → full.
          'request.idempotencyKey': 'partial',             // v0.7 API6: HONEST — Kong OSS has no native idempotency. pre-function shared_dict dedupe is best-effort (per-instance, non-atomic check-and-set); suppresses sequential replays but races on concurrent first-requests. _x_security_warnings divergence note. Never full.
          'authentication.accountLockout': 'partial',      // v0.7: HONEST — no native per-credential lockout. rate-limiting limit_by=header throttles per-credential attempts (blunts brute-force) but is NOT a fixed-duration lockout and counts all attempts (gateway can't see the auth verdict). Body-field identifiers degrade to unsupported+warning. _x_security_warnings note. Never full.
          'deprecated': 'full',                            // K-5: pre-function returns 410 with x-security-deprecated-endpoint-block
          'sunsetDate': 'full',                             // K-5: 410 + RFC 8594 Deprecation: true & Sunset: <date> response headers
          'replacementEndpoint': 'partial',                 // K-5: surfaced in 410 response body, no Link: rel=successor-version header
          'targetOverrides.kong': 'full'
        }
      };
    }
  };

  return gen;
}

// Build a `# WARNING:` comment header that precedes the YAML body. Operators
// can `grep '^# WARNING'` or `grep _x_security_warnings` and see the same
// content rendered two ways. Empty warnings → empty header.
function renderWarningsHeader(
  warnings: XSecurityWarning[],
  deployment: KongDeployment,
  edition: KongEdition
): string {
  const lines: string[] = [];
  lines.push(`# XSecurity Kong generator — deployment=${deployment} edition=${edition}`);
  if (!warnings.length) {
    lines.push('# _x_security_warnings: []  (no spec→runtime divergences detected)');
    lines.push('');
    return lines.join('\n');
  }
  lines.push(`# ${warnings.length} spec→runtime divergence(s) recorded below.`);
  for (const w of warnings) {
    const ep = w.endpoint ? ` (endpoint=${w.endpoint})` : '';
    lines.push(`# WARNING: ${w.field}${ep}: declared="${w.declared}" emitted="${w.emitted}" — ${w.reason}`);
  }
  // Commented YAML block — Kong ignores it (it's all comments), but it
  // remains grep-able via `grep _x_security_warnings kong.yml` and round-
  // trips back to valid YAML if a tool strips the leading `# `.
  lines.push('# _x_security_warnings:');
  for (const w of warnings) {
    lines.push(`#   - field: ${yamlScalar(w.field)}`);
    if (w.endpoint) lines.push(`#     endpoint: ${yamlScalar(w.endpoint)}`);
    lines.push(`#     declared: ${yamlScalar(w.declared)}`);
    lines.push(`#     emitted: ${yamlScalar(w.emitted)}`);
    lines.push(`#     reason: ${yamlScalar(w.reason)}`);
  }
  lines.push('');
  return lines.join('\n');
}

// Quote a scalar so it round-trips cleanly when a tool uncomments the
// header block. We keep it conservative: any character outside the
// safe-plain set forces double-quoting with backslash escapes.
function yamlScalar(s: string): string {
  if (/^[A-Za-z0-9_./:=@+\- ]+$/.test(s) && !s.startsWith(' ') && !s.endsWith(' ')) {
    return s;
  }
  return JSON.stringify(s);
}

// Spec-hygiene: one structured warning per param that declares
// request.schema.<field>.injectionGuard. Kong OSS cannot enforce it (no
// libinjection / @detectSQLi primitive; a pre-function regex would be a
// fragile fake — Rule D-1), so we abstain honestly rather than emit a plugin.
function collectInjectionGuardWarnings(spec: SpecIR): XSecurityWarning[] {
  const out: XSecurityWarning[] = [];
  for (const ep of spec.endpoints) {
    const schema = ep.policy.request?.schema;
    if (!schema) continue;
    for (const [paramName, ps] of Object.entries(schema)) {
      const guards = ps?.injectionGuard;
      if (!Array.isArray(guards) || guards.length === 0) continue;
      out.push({
        field: `request.schema.${paramName}.injectionGuard`,
        ...(ep.operationId ? { endpoint: ep.operationId } : {}),
        declared: guards.join(','),
        emitted: 'unsupported (no rule emitted)',
        reason:
          'Kong OSS has no libinjection/@detectSQLi primitive; a pre-function regex ' +
          'would be a fragile fake that masks the gap. SSEC-INJECTION is NOT enforced ' +
          'at the Kong layer — front Kong with coraza/bunkerweb (which carry the ' +
          'ModSecurity injection rulesets) for this endpoint, or treat injection ' +
          'defense as the upstream application\'s responsibility.'
      });
    }
  }
  return out;
}

// Module-level singleton. `--with-consumers` defaults ON so the kong.yml
// is operable out of the box; CLI calls .configure() to flip it off.
export const kongGenerator: KongGenerator = createKongGenerator();

export default kongGenerator;
