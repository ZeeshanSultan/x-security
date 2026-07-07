/**
 * Schema v0.8 (deferred-residuals) emitters for BunkerWeb (libmodsec3 /
 * modsec-nginx). One emitter per residual field; each returns 0..N rule-block
 * strings that the groupByService pipeline appends as additional
 * `CUSTOM_CONF_MODSEC_*` blocks (dedupe + rule-id rebasing handled upstream).
 *
 * HONESTY (Rule D-1 — this wave is the hardest for it). Each emitter's status
 * is pinned to exactly what libmodsec3 can actually enforce, never higher:
 *
 *   - graphql.operations[].authz  → OVERRIDE-ONLY. Per-resolver BOLA/BFLA
 *     (API1/API5) needs an operator-supplied GraphQL-aware processor that
 *     parses the operation and evaluates per-field authz. libmodsec3 has no
 *     GraphQL parser and Rule D-1 bans a regex fake over the query body. We
 *     emit SCAFFOLDING ONLY: a phase:2 tagged marker rule that routes the
 *     /graphql POST to an operator processor sidecar (X-x-security-GraphQL-*
 *     headers) plus a self-describing contract block listing the per-operation
 *     authz the processor must enforce. Enforcement DEPENDS ON that processor.
 *     Status: override-only, NOT full, NOT partial.
 *
 *   - graphql.staticLimits        → PARTIAL. The ONE coarse limit libmodsec3
 *     can enforce honestly without a parser is `disableIntrospection`: an
 *     introspection query MUST contain the `__schema` / `__type` meta-fields,
 *     so a phase:2 `@rx __schema|__type` deny on the body is a real, correct
 *     block. `batchLimit` gets a crude raw-body top-level-array guard. Depth /
 *     complexity / alias limits CANNOT be computed by regex (nesting is not a
 *     regular language) — those are surfaced as an override-only operator note,
 *     not faked. Genuine-but-incomplete → partial.
 *
 *   - request.serializeBy / concurrencyLimit → PARTIAL. nginx `limit_conn`
 *     keyed on the serialize key gives real EDGE serialization (concurrency
 *     cap; 1 == strict serialize). It does NOT make the app handler
 *     transaction atomic — two serialized-but-sequential requests still race
 *     in the datastore. Emitted as a CUSTOM_CONF_HTTP_* limit_conn_zone snippet
 *     (same surfacing path as the per-user rate-limit zones). Status: partial,
 *     never full. Schema disclaimer carried verbatim.
 *
 *   - request.dataAtRest          → UNSUPPORTED. Advisory-only at-rest posture
 *     declaration. The WAF never sees the DB write; it compiles to NOTHING
 *     enforcing. We emit a documentation-only marker (so the policy isn't
 *     silently dropped) and a warning; the capability is hard-pinned
 *     unsupported. Drives an out-of-band SSEC-STORAGE finding, not a control.
 *
 * libmodsec3 capability source: coraza/profiles.ts MODSEC_NGINX_PROFILE.
 */

import type { EndpointIR } from '@x-security/core';
import type { GraphqlOperation } from '@x-security/schema';
import { endpointHash, pathRegex } from '../coraza/rules.js';

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}
function escRx(s: string): string {
  return s.replace(/"/g, '\\"');
}
function header(comment: string): string {
  return comment
    .split('\n')
    .map((l) => `# ${l}`)
    .join('\n');
}

/** libmodsec3 requires every chained child SecRule to carry an actions arg. */
const CHAIN_TERM = ' "t:none"';

// ---------------------------------------------------------------------------
// graphql.operations[].authz (API1:2023 BOLA + API5:2023 BFLA). OVERRIDE-ONLY.
//
// Scaffolding mirrors the response-schema ext_proc handoff: x-security does NOT
// ship a GraphQL-aware processor, so we emit the route-marker rule + a contract
// block describing the per-operation authz the operator's processor must
// enforce. Until the operator supplies that processor, NOTHING evaluates
// per-resolver authz — hence override-only, never full/partial.
//
// Rule IDs: dedicated 420000..420999 range.
// ---------------------------------------------------------------------------
const GRAPHQL_OPS_BASE_ID = 420000;

function operationsWithAuthz(ops: GraphqlOperation[] | undefined): GraphqlOperation[] {
  if (!Array.isArray(ops)) return [];
  return ops.filter((op) => op.authz !== undefined && op.authz !== null);
}

export function buildGraphqlOperationAuthzRules(endpoint: EndpointIR): string[] {
  const ops = operationsWithAuthz(endpoint.policy.graphql?.operations);
  if (ops.length === 0) return [];
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|gqlops`, '');
  const id = GRAPHQL_OPS_BASE_ID + (seed % 999);

  // Contract: what the operator-supplied processor must enforce, per operation.
  const contract = ops.map((op) => {
    const kind = op.operationType ?? 'operation';
    const authzType = op.authz?.type ?? 'unknown';
    return `#   - ${op.name} (${kind}): authz=${authzType}`;
  });

  return [
    [
      header(
        `v0.8 graphql.operations[].authz (API1/API5 per-resolver BOLA/BFLA) for\n` +
          `${endpoint.method} ${endpoint.path}. OVERRIDE-ONLY — libmodsec3 has no\n` +
          `GraphQL parser and Rule D-1 bans a regex fake over the query body. This\n` +
          `block is SCAFFOLDING: it tags the /graphql POST for an operator-supplied\n` +
          `GraphQL-aware processor (sidecar/ext-filter) that parses the operation and\n` +
          `evaluates the per-operation authz below. Enforcement DEPENDS ON that\n` +
          `processor; until it is supplied NOTHING enforces per-resolver authz.\n` +
          `Per-operation authz contract the processor MUST enforce:\n` +
          contract.join('\n')
      ),
      // Route marker: pass-through (NOT a deny) so we never claim enforcement
      // we don't have. The tag lets a downstream ext-filter / sidecar pick up
      // the request; on its own it changes nothing about the response.
      `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${id},phase:2,pass,nolog,msg:'x-security: graphql per-operation authz handoff (override-only)',tag:'${esc(tag)}',tag:'x-security-graphql-ops-authz',tag:'x-security-override-only',chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${CHAIN_TERM}`,
    ].join('\n'),
  ];
}

// ---------------------------------------------------------------------------
// graphql.staticLimits (API4:2023). PARTIAL.
//
// The only coarse GraphQL limit libmodsec3 can enforce WITHOUT parsing:
//   - disableIntrospection → phase:2 @rx deny on `__schema` / `__type` in the
//     raw POST body. An introspection query MUST carry those meta-fields, so
//     this is a real, correct block (not a heuristic guess).
//   - batchLimit           → crude raw-body guard: reject a top-level JSON array
//     body (batched GraphQL is `[{...},{...}]`). This caps batching at "no
//     array batching" — stricter than the numeric limit, honestly partial.
// Depth / complexity / alias limits are NOT regular-language-expressible, so we
// do NOT fake them; they're surfaced as an override-only operator note.
//
// Rule IDs: dedicated 422000..422999 range.
// ---------------------------------------------------------------------------
const GRAPHQL_STATIC_BASE_ID = 422000;

export function buildGraphqlStaticLimitRules(endpoint: EndpointIR): string[] {
  const g = endpoint.policy.graphql;
  if (!g) return [];
  const tag = `x-security/${endpoint.method} ${endpoint.path}`;
  const rx = pathRegex(endpoint.path);
  const seed = endpointHash(`${endpoint.method}|${endpoint.path}|gqlstatic`, '');
  const base = GRAPHQL_STATIC_BASE_ID + ((seed % 498) * 2);
  const out: string[] = [];

  // Override-only note for the limits regex genuinely cannot enforce.
  const unenforceable: string[] = [];
  if (typeof g.maxDepth === 'number') unenforceable.push(`maxDepth=${g.maxDepth}`);
  if (typeof g.maxComplexity === 'number') unenforceable.push(`maxComplexity=${g.maxComplexity}`);
  if (typeof g.maxAliases === 'number') unenforceable.push(`maxAliases=${g.maxAliases}`);

  if (g.disableIntrospection === true) {
    out.push(
      [
        header(
          `v0.8 graphql.staticLimits: disableIntrospection for ${endpoint.method} ${endpoint.path}\n` +
            `(API4:2023). phase:2 @rx deny on __schema / __type in the raw POST body —\n` +
            `an introspection query MUST contain those meta-fields, so this is a real,\n` +
            `non-parsing block (not a heuristic guess).`
        ),
        `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base},phase:2,deny,status:403,log,msg:'x-security: GraphQL introspection disabled (graphql.disableIntrospection)',tag:'${esc(tag)}',tag:'x-security-rule-graphql-introspection',chain"`,
        `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
        `    SecRule REQUEST_BODY "@rx (?i)__(?:schema|type)\\b"${CHAIN_TERM}`,
      ].join('\n')
    );
  }

  if (typeof g.batchLimit === 'number') {
    out.push(
      [
        header(
          `v0.8 graphql.staticLimits: batchLimit=${g.batchLimit} for ${endpoint.method} ${endpoint.path}\n` +
            `(API4:2023). PARTIAL — libmodsec3 cannot count batched operations without a\n` +
            `parser, so we reject any top-level JSON-array body (batched GraphQL is\n` +
            `[{...},{...}]). This caps batching at "none" — stricter than the numeric\n` +
            `limit, not the exact semantics, hence partial.`
        ),
        `SecRule REQUEST_FILENAME "@rx ${escRx(rx)}" "id:${base + 1},phase:2,deny,status:403,log,msg:'x-security: GraphQL request batching rejected (graphql.batchLimit)',tag:'${esc(tag)}',tag:'x-security-rule-graphql-batch',chain"`,
        `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
        `    SecRule REQUEST_BODY "@rx ^[\\s]*\\[" "t:none"`,
      ].join('\n')
    );
  }

  if (unenforceable.length > 0) {
    out.push(
      header(
        `v0.8 graphql.staticLimits OVERRIDE-ONLY note for ${endpoint.method} ${endpoint.path}:\n` +
          `${unenforceable.join(', ')} require GraphQL query-depth/complexity/alias\n` +
          `counting, which is NOT regular-language-expressible — libmodsec3 cannot\n` +
          `enforce it without a parser. Wire a GraphQL-aware processor (the same\n` +
          `sidecar the graphql.operations.authz scaffolding routes to) to enforce\n` +
          `these. x-security does NOT fake them with regex (Rule D-1).`
      )
    );
  }

  return out;
}

// ---------------------------------------------------------------------------
// request.serializeBy / concurrencyLimit (API6:2023). PARTIAL.
//
// Edge serialization via nginx `limit_conn`: a per-key connection-zone caps the
// number of concurrent in-flight requests sharing the serialize key.
// concurrencyLimit==1 (or absent → 1) means strict serialization at the edge.
//
// Why PARTIAL (schema + capabilities note): this serializes requests AT THE
// EDGE but does NOT provide in-handler transaction atomicity — two requests
// admitted sequentially still race in the app's datastore. The schema carries
// this disclaimer verbatim. Never full.
//
// Surfaced as a CUSTOM_CONF_HTTP_* limit_conn_zone snippet (the same path as the
// per-user rate-limit zones). The matching `limit_conn ss_serial_<n> <N>;`
// directive goes in the per-location server block (operator wires it, like the
// rate-limit zone). Returns { httpKey, httpSnippet } rather than a SecRule
// because limit_conn is nginx-native, not a modsec directive.
// ---------------------------------------------------------------------------

export interface SerializeByHttpSnippet {
  httpKey: string;
  httpSnippet: string;
}

/** Map a serializeBy RuleRef-style key to an nginx limit_conn zone key var. */
function serializeKeyToNginxVar(key: string): string {
  const k = key.trim();
  const jwtM = /^jwt\.(.+)$/i.exec(k);
  if (jwtM) return `$http_x_forwarded_user`; // trusted identity header from upstream auth
  const headerM = /^header[.:](.+)$/i.exec(k);
  if (headerM) return `$http_${headerM[1]!.trim().toLowerCase().replace(/-/g, '_')}`;
  const bodyM = /^request\.body\.(.+)$/i.exec(k);
  if (bodyM) return `$arg_${bodyM[1]!.trim()}`; // best-effort: query/form arg
  // Fallback: treat as a header name.
  return `$http_${k.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`;
}

export function buildSerializeByHttpSnippet(
  endpoint: EndpointIR,
  index: number
): SerializeByHttpSnippet | null {
  const ser = endpoint.policy.request?.serializeBy;
  if (!ser) return null;
  const limit = endpoint.policy.request?.concurrencyLimit;
  const conc = typeof limit === 'number' && limit >= 1 ? limit : 1;
  const scope = ser.scope ?? 'per-identifier';
  const keyVar =
    scope === 'global' ? `"x_security_serial_global"` : serializeKeyToNginxVar(ser.key);
  const zoneName = `ss_serial_${index}`;

  const snippet =
    `# v0.8 request.serializeBy (API6:2023) for ${endpoint.method} ${endpoint.path}\n` +
    `# PARTIAL — edge serialization only; does NOT provide in-handler transaction\n` +
    `# atomicity. key='${ser.key}' scope='${scope}' concurrencyLimit=${conc}\n` +
    `# (concurrencyLimit 1 == strict serialize). Paste into the nginx http {} block,\n` +
    `# then add to the per-location server block:\n` +
    `#   limit_conn ${zoneName} ${conc};\n` +
    `limit_conn_zone ${keyVar} zone=${zoneName}:10m;`;

  return { httpKey: `CUSTOM_CONF_HTTP_LIMIT_CONN_SERIAL_${index}`, httpSnippet: snippet };
}

// ---------------------------------------------------------------------------
// request.dataAtRest (SSEC-STORAGE). UNSUPPORTED (advisory-only).
//
// At-rest protection posture for named body fields. The WAF never sees the DB
// write — this compiles to NOTHING enforcing. We emit a documentation-only
// marker so the policy is visibly considered (not silently dropped) and surface
// a warning. Capability is hard-pinned unsupported; it drives an out-of-band
// SSEC-STORAGE scan finding, not a gateway control.
// ---------------------------------------------------------------------------

export function buildDataAtRestRules(endpoint: EndpointIR): string[] {
  const dar = endpoint.policy.request?.dataAtRest;
  if (!dar || !Array.isArray(dar.fields) || dar.fields.length === 0) return [];
  return [
    header(
      `v0.8 request.dataAtRest (SSEC-STORAGE) for ${endpoint.method} ${endpoint.path}:\n` +
        `ADVISORY-ONLY — NOT gateway-enforced. fields=[${dar.fields.join(', ')}] must be\n` +
        `'${dar.protection}' at rest, but the WAF never sees the datastore write, so this\n` +
        `compiles to NOTHING enforcing. Implement at-rest ${dar.protection} in the app's\n` +
        `persistence layer. x-security surfaces this as an out-of-band SSEC-STORAGE\n` +
        `finding, not a control (Rule D-1: no fake 'full' for an unenforceable field).`
    ),
  ];
}

/** Operator-facing warning for an advisory-only dataAtRest declaration. */
export function dataAtRestWarning(endpoint: EndpointIR): string | null {
  const dar = endpoint.policy.request?.dataAtRest;
  if (!dar || !Array.isArray(dar.fields) || dar.fields.length === 0) return null;
  return (
    `[bunkerweb] WARNING: request.dataAtRest on ${endpoint.method} ${endpoint.path} ` +
    `is ADVISORY-ONLY — BunkerWeb cannot enforce at-rest ${dar.protection} for ` +
    `fields [${dar.fields.join(', ')}] (the WAF never sees the datastore write). ` +
    `Implement it in the application's persistence layer; this declaration drives ` +
    `an out-of-band SSEC-STORAGE finding only.`
  );
}
