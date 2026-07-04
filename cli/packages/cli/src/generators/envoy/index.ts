/**
 * Envoy generator (wave-9 native-filter refactor).
 *
 * Emits a **full runnable Envoy v3 bootstrap** plus a residual Lua module:
 *
 *   - `envoy.yaml`     Full bootstrap: admin block, listener, route_config
 *                      with typed_per_filter_config overrides, native filter
 *                      chain (jwt_authn → rbac → local_ratelimit → cors →
 *                      lua → router), and the upstream + JWKS clusters.
 *   - `writ.lua` Residual Lua. Only emitted when at least one endpoint
 *                      uses a field with no native filter equivalent
 *                      (request.contentType, maxBodySize, headerInjectionGuard,
 *                      duplicateParamPolicy, request.signature). Contains the
 *                      `-- writ:<METHOD>:<path>:*` sentinel markers the
 *                      drift detector and verify reader key off.
 *
 * Field-coverage migration (wave-7 → wave-9):
 *   authentication.bearer-jwt    partial → full   (native jwt_authn, real JWKS+RS256)
 *   authorization.rbac           partial → full   (native rbac filter)
 *   authorization.rule-based     unsupported → full (wave-10: ext_authz filter + OPA sidecar; emits opa/policy.rego)
 *   rateLimit                    full   → full   (native local_ratelimit, stats-attributed)
 *   cors                         unsup. → full   (native cors filter)
 *
 * Lua fallback still owns: contentType, maxBodySize, duplicateParamPolicy,
 * headerInjectionGuard, signature, method-allowlist (405).
 */

import type { ConfigArtifact, EndpointIR, Generator, SpecIR, CapabilityMatrix } from '@writ/core';
import { buildEnvoyYaml, smallestBodyLimit } from './templates/envoy-yaml.js';
import {
  buildEndpointBlock,
  buildLuaModule,
  endpointNeedsLua,
  envoyPathPattern,
  type MethodAllowlistEntry
} from './templates/lua.js';
import { collectSsrfPolicyWarnings } from '../ssrf-policy-check.js';
import {
  buildRegoPolicy,
  collectRuleBased,
  collectBflaAdmin,
  collectInputValidation,
  collectSsrfPolicy,
  collectAbac,
  needsOpa
} from './templates/extauthz.js';
import {
  buildResponseSchemaConfig,
  collectResponseSchema,
  needsExtProc
} from './templates/ext_proc.js';

export interface EnvoyGenerator extends Generator {
  readonly lastWarnings: readonly string[];
}

const VERSION = '0.3.0';
const ENVOY_PATH = 'envoy.yaml';
const LUA_PATH = 'writ.lua';
const OPA_POLICY_PATH = 'opa/policy.rego';
const RESPONSE_SCHEMA_PATH = 'ext_proc/response-schema.json';

function buildMethodAllowlist(endpoints: EndpointIR[]): MethodAllowlistEntry[] {
  const byPath = new Map<string, Set<string>>();
  for (const ep of endpoints) {
    const set = byPath.get(ep.path) ?? new Set<string>();
    set.add(ep.method);
    byPath.set(ep.path, set);
  }
  const out: MethodAllowlistEntry[] = [];
  for (const [path, methods] of byPath.entries()) {
    out.push({
      path,
      pattern: envoyPathPattern(path),
      methods: [...methods]
    });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Build the residual Lua source. Returns null when no endpoint declares a
 * Lua-requiring field — in that case the generator omits the Lua filter and
 * the `writ.lua` artifact entirely.
 */
function buildLuaSource(spec: SpecIR): string | null {
  const anyLua = spec.endpoints.some(endpointNeedsLua);
  if (!anyLua) return null;

  const sorted = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );
  const blocks: string[] = [];
  for (const ep of sorted) {
    const b = buildEndpointBlock({ endpoint: ep });
    if (b) blocks.push(b);
  }
  const methodMap = buildMethodAllowlist(spec.endpoints);
  return buildLuaModule(spec.info.title, spec.info.version, blocks, methodMap);
}

/**
 * Spec-hygiene: `request.dataAtRest` is advisory-only and compiles to NOTHING
 * enforcing on an L7 proxy (storage-layer encryption is out of band for Envoy).
 * The capability matrix pins it `unsupported`; this warning makes the no-op
 * explicit at generation time so an operator does not assume the gateway is
 * protecting data at rest. Drives the out-of-band SSEC-STORAGE finding.
 */
function collectDataAtRestWarnings(spec: SpecIR): string[] {
  const out: string[] = [];
  for (const ep of spec.endpoints) {
    const dar = ep.policy.request?.dataAtRest;
    if (!dar || !Array.isArray(dar.fields) || dar.fields.length === 0) continue;
    out.push(
      `[envoy:data-at-rest-advisory] ${ep.method} ${ep.path}: request.dataAtRest ` +
        `(${dar.protection} on ${dar.fields.join(', ')}) is NOT gateway-enforced. ` +
        `Envoy is an L7 proxy and emits no config for storage-layer protection; ` +
        `enforce ${dar.protection} in the backend/datastore. Tracked as SSEC-STORAGE.`
    );
  }
  return out;
}

let envoyLastWarnings: string[] = [];

export const envoyGenerator: EnvoyGenerator = {
  name: 'envoy',
  targets: ['envoy', 'envoy-proxy'],

  get lastWarnings(): readonly string[] {
    return envoyLastWarnings;
  },

  generate(spec: SpecIR): ConfigArtifact[] {
    const luaSource = buildLuaSource(spec);
    const yamlContent = buildEnvoyYaml({ spec, luaSource });

    // Keep the body-cap helper alive in the export graph for downstream consumers.
    void smallestBodyLimit;

    // Spec-hygiene: warn on url-typed params missing SSRF policy. Wave-10 W10-9.
    const ssrfWarnings = collectSsrfPolicyWarnings(spec, 'envoy');
    // Spec-hygiene: request.dataAtRest is advisory-only on an L7 proxy — surface
    // the no-op so it is never mistaken for gateway-enforced storage protection.
    envoyLastWarnings = [
      ...ssrfWarnings.map((w) => w.message),
      ...collectDataAtRestWarnings(spec)
    ];

    const artifacts: ConfigArtifact[] = [
      { path: ENVOY_PATH, content: yamlContent, format: 'yaml' }
    ];
    if (luaSource !== null) {
      artifacts.push({ path: LUA_PATH, content: luaSource, format: 'text' });
    }
    // Wave-10 E-3 + Wave-18 W18-A: emit OPA policy bundle when any endpoint
    // declares rule-based authz, rbac admin-only authz, or strict request-body
    // validation (denyUnknownFields / allowedFields).
    if (needsOpa(spec)) {
      const rego = buildRegoPolicy({
        ruleBased: collectRuleBased(spec),
        bflaAdmin: collectBflaAdmin(spec),
        inputValidation: collectInputValidation(spec),
        ssrfPolicy: collectSsrfPolicy(spec),
        abac: collectAbac(spec),
        specTitle: spec.info.title,
        specVersion: spec.info.version
      });
      artifacts.push({ path: OPA_POLICY_PATH, content: rego, format: 'text' });
    }
    // response.schema / response.stripUnknownFields → ext_proc scaffolding.
    // The filter + cluster are emitted into envoy.yaml; this JSON is the typed
    // per-route constraint contract the operator-supplied processor consumes.
    // Status is override-only: Writ does not ship the processor, so this
    // config does not enforce on its own (Rule D-1 — no false 'full').
    if (needsExtProc(spec)) {
      const respSchema = buildResponseSchemaConfig(
        collectResponseSchema(spec),
        spec.info.title,
        spec.info.version
      );
      artifacts.push({ path: RESPONSE_SCHEMA_PATH, content: respSchema, format: 'json' });
    }
    return artifacts;
  },

  capabilities(): CapabilityMatrix {
    return {
      fields: {
        // Native filters (wave-9 upgrade)
        'authentication.type':         'full',        // jwt_authn / api-key still partial
        'authentication.jwksUri':      'full',        // remote_jwks via jwks_cluster
        'authentication.scopes':       'partial',     // requires custom claims matcher; partial via audiences
        'authentication.issuer':       'full',
        'authentication.audience':     'full',
        'authentication.allowedAlgorithms': 'full',
        'authentication.bannedAlgorithms':  'partial',  // jwt_authn lacks explicit deny; allowedAlgorithms is the effective allowlist
        // v0.7 (API2): authentication.accountLockout — stateful per-credential
        // failed-login counting. Envoy has NO native per-credential lockout
        // primitive, and the OPA ext_authz sidecar this generator wires is
        // STATELESS Rego — it cannot count attempts across requests without
        // operator-supplied storage. An operator CAN front a stateful ext_authz/
        // sidecar that owns the counter, so the honest status is override-only,
        // NEVER full/partial. No scaffolding is emitted this wave (the matrix is
        // honest, so --strict-fidelity/--feasible flag the gap — same matrix-
        // honest pattern as graphql.operations.authz / request.serializeBy).
        'authentication.accountLockout':    'override-only',
        // v0.7 (API2): authentication.passwordPolicy — password complexity
        // (minLength / uppercase / digit / symbol / blocklist) on a body-carried
        // password. Envoy's L7 filter chain cannot validate it natively: the
        // password lives in the request BODY, and a Lua/OPA regex over raw body
        // bytes to score complexity is exactly the masked-quality shortcut Rule
        // D-1 bans (consistent with request.schema.* staying unsupported on
        // Envoy). Honestly unsupported — do not fake.
        'authentication.passwordPolicy':    'unsupported',
        'authorization':               'full',        // rbac=full (native), rule-based=full (ext_authz + OPA sidecar)
        'authorization.abac':          'full',        // OPP-3: ext_authz + OPA Rego attribute-predicate conjunction (opa-abac-403); caps API5/BFLA
        'rateLimit':                   'full',        // per-route local_ratelimit, stat_prefix attribution
        'cors':                        'full',        // native cors filter

        // Lua fallback (unchanged from wave-7)
        'request.contentType':         'full',
        'request.maxBodySize':         'full',
        'request.denyUnknownFields':   'full',        // OPP-3: ext_authz + OPA body-key allowlist (opa-input-validation-403) for EVERY declaring endpoint; empty schema → reject-all; caps API6
        'request.duplicateParamPolicy':'partial',     // query-string only; body-form HPP needs body filter
        'request.headerInjectionGuard':'full',
        'request.signature':           'unsupported', // needs body-filter callback (wave-10)
        // v0.7 (API6): request.idempotencyKey — replay / double-submit defense
        // keyed on a client idempotency header. Real enforcement needs a STATEFUL
        // dedupe store (a key seen within ttl is a replay). Envoy has no native
        // request-dedup primitive, and the OPA ext_authz sidecar is stateless
        // Rego — neither can remember a prior key. An operator CAN front a
        // stateful ext_authz/ext_proc dedup service, so the honest status is
        // override-only, never full/partial. A Lua in-memory table would be
        // per-worker, non-durable, and racy — not real dedup (Rule D-1). No
        // scaffolding emitted this wave; matrix-honest so the gap is flagged.
        'request.idempotencyKey':      'override-only',

        // Out of scope for Envoy L7 generator
        'request.schema.minLength':    'unsupported',
        'request.schema.maxLength':    'unsupported',
        'request.schema.fixedLength':  'unsupported',
        'request.schema.min':          'unsupported',
        'request.schema.max':          'unsupported',
        'request.schema.pattern':      'unsupported',
        'request.schema.type':         'unsupported',
        // SSEC-INJECTION sink-hardening (sql/nosql/os-command/xpath/ldap/code-eval).
        // Envoy's L7 filter chain has no libinjection / @detectSQLi-equivalent —
        // there is no native metacharacter/payload inspector. The OPA sidecar only
        // does a body-KEY allowlist (opa-input-validation-403), which is structural
        // field gating, NOT injection-payload detection. Faking it via a Lua regex
        // over raw request bytes would be exactly the masked-quality shortcut Rule
        // D-1 bans, so this stays honestly unsupported (consistent with the rest of
        // request.schema.* on Envoy).
        'request.schema.injectionGuard': 'unsupported',
        'request.schema.allowedMimeTypes': 'unsupported',
        'request.schema.domainAllowlist':  'full',         // W19-A: OPA opa-ssrf-403
        'response':                            'unsupported', // wave-22: per-header support below
        // ext_proc scaffolding: envoy.filters.http.ext_proc + processing
        // cluster + ext_proc/response-schema.json (typed per-field constraints,
        // stripUnknownFields). The body IS delivered to a processor that does a
        // real JSON.parse — NO regex over raw bytes. But Writ does not
        // ship the processor (the opa_grpc sidecar is ext_authz-only; ext_proc
        // is an unmerged upstream PR on a different port). Enforcement depends
        // on an operator-supplied gRPC ExternalProcessor, so the honest status
        // is override-only — NOT 'full'. A false 'full' here is the DVAPI trap.
        'response.schema':                     'override-only',
        'response.stripUnknownFields':         'override-only',
        // v0.7 (API3): response.forbidArrayRoot — reject a bare top-level JSON
        // array response body (JSON-hijacking defense). This is a RESPONSE-BODY
        // SHAPE check, the same class as response.schema: it requires a real
        // JSON.parse to know the root is an array. It rides the SAME ext_proc
        // scaffolding (the filter + cluster + ext_proc/response-schema.json now
        // carry a per-route `forbidArrayRoot` flag the operator processor reads).
        // Envoy ships no native response-body shape inspector and a Lua regex for
        // a leading '[' over raw bytes is the Rule D-1 masked-quality shortcut.
        // Writ does NOT ship the processor → override-only, never full.
        'response.forbidArrayRoot':            'override-only',
        'response.headers.csp':                'full',         // wave-22: per-route response_headers_to_add
        'response.headers.hsts':               'full',
        'response.headers.frameOptions':       'full',
        'response.headers.contentTypeOptions': 'full',
        'response.headers.referrerPolicy':     'full',
        'response.headers.permissionsPolicy':  'full',

        // ── deferred-residuals wave (schema v0.8) ──────────────────────────
        // GraphQL per-operation authz (API1/API5 per-resolver BOLA/BFLA).
        // Envoy parses HTTP, not GraphQL: it has no resolver-graph model, so it
        // cannot evaluate per-operation/per-resolver authorization. The only
        // honest path is the same ext_proc handoff as response.schema — stream
        // the GraphQL POST body to an operator-supplied GraphQL-aware processor
        // that parses the query and enforces authz. Writ ships NO such
        // processor, so this is override-only, NEVER full. (Schema pins this
        // override-only on every target.) No scaffolding is emitted this wave —
        // the matrix is honest so --strict-fidelity/--feasible flag the gap.
        'graphql.operations.authz':    'override-only',
        // GraphQL coarse static limits (API4): depth/complexity/aliases/batch/
        // introspection/allowed-operations. Every one of these requires PARSING
        // the GraphQL query to count depth/aliases or read operation names.
        // Envoy's filter chain has no GraphQL parser (Lua has no GraphQL AST,
        // and a regex over the raw query body to "count braces" is exactly the
        // Rule D-1 masked-quality shortcut — it does not survive aliasing,
        // fragments, or whitespace). So even the crude limits are not genuinely
        // enforceable without the operator processor: override-only, not partial.
        'graphql.staticLimits':        'override-only',
        // request.serializeBy / concurrencyLimit (API6): per-identifier request
        // serialization. Envoy has local_ratelimit (rate over time) but no
        // mutual-exclusion / single-flight primitive keyed on an identifier, and
        // edge serialization could not provide in-handler transaction atomicity
        // anyway (schema disclaimer). An operator could front a serializing
        // ext_proc/sidecar, so the honest status is override-only (schema pins
        // envoy=override-only), never full/partial.
        'request.serializeBy':         'override-only',
        'request.concurrencyLimit':    'override-only',
        // request.dataAtRest (SSEC-STORAGE): storage-layer field encryption/
        // hashing/tokenization. This is advisory-only and compiles to NOTHING
        // enforcing — an L7 proxy has zero relationship to how the backend
        // persists data at rest, and there is no processor handoff that changes
        // that. Hard-pinned unsupported (schema: override-only/unsupported on
        // every target, never full/partial). Drives an out-of-band SSEC-STORAGE
        // finding; the generator emits a hygiene warning, not config.
        'request.dataAtRest':          'unsupported',

        // v0.7 (SSEC-AUDIT): logging — declarative audit/access logging policy.
        // The gateway IS the log point, and Envoy ships first-class access
        // loggers that cover the WHOLE Logging contract NATIVELY:
        //   - events → one access_log entry per status-coded event class
        //     (auth-failure→401, authz-deny→403, rate-limit-trip→429) via native
        //     status_code_filter; request/response/injection-block ride the
        //     always-on base logger.
        //   - sink → the logger TYPE: file/stdout/syslog → FileAccessLog (syslog
        //     pipes /dev/stdout with an operator note — Envoy has no native
        //     syslog logger), http-collector → HttpGrpcAccessLog over a gRPC ALS
        //     cluster (the collector is operator-run LOG infra, like any upstream
        //     — NOT a missing enforcement processor, so this stays full).
        //   - piiRedaction → the JSON format omits the declared fingerprinting
        //     field (User-Agent); field-level omission is natively expressible.
        // Unlike libmodsec3 (partial — cannot route per-event or redact), Envoy
        // does all three natively → full. Emitted by templates/access_log.ts.
        'logging':                     'full',
        'csrf':                        'partial',     // native csrf filter handles origin-check; double-submit/custom-header still need Lua
        'timeout':                     'unsupported', // belongs on cluster, not L7 filter
        'cacheable':                   'full',        // envoy.filters.http.cache per-route enable/disable
        'mtls':                        'unsupported',
        'ipPolicy.allow':              'full',        // envoy.filters.http.rbac.ip ALLOW with source_ip
        'ipPolicy.deny':               'full',        // envoy.filters.http.rbac.ip DENY with source_ip
        'deprecated':                  'unsupported',
        'sunsetDate':                  'unsupported',
        'replacementEndpoint':         'unsupported'
      }
    };
  }
};

export { VERSION };

export default envoyGenerator;
