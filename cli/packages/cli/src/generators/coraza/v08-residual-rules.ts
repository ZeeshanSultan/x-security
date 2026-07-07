/**
 * v0.8 deferred-residuals emitters for the Coraza/ModSecurity generator.
 *
 * This wave attributes four new capability keys (see
 * packages/schema/src/owasp-mapping.json and the feasibility probes in
 * reporters/feasibility.ts). Three are emitted here at their HONEST status;
 * the remaining two are matrix-only (override-only / advisory) and emit no
 * enforcing config by design:
 *
 *   - request.serializeBy + request.concurrencyLimit  (API6)  → PARTIAL
 *       A crude SecCollection short-window cap keyed on the serialize key.
 *       This is edge serialization only — it bounds how many same-key requests
 *       reach the upstream in a short window; it is NOT an in-handler mutex and
 *       does NOT provide transaction atomicity. We emit the same cross-request /
 *       HA downgrade warnings the rate-limit path emits, plus an explicit
 *       "not in-handler atomicity" disclaimer.  → never 'full'.
 *
 *   - graphql.staticLimits                            (API4)  → PARTIAL
 *       Coarse, NON-PARSING GraphQL guards over the raw request body:
 *         * disableIntrospection → deny when the body references __schema/__type
 *         * maxAliases           → deny when the alias-token count exceeds N
 *         * batchLimit           → deny when the top-level operation array is
 *                                  longer than N
 *       These are genuine enforcing SecRules that need no GraphQL parser, so
 *       'partial' is honest. maxDepth / maxComplexity require a real parse and
 *       are explicitly NOT emitted (a brace-counting heuristic would be a
 *       Rule D-1 masked-quality trap); we surface a skip warning for them.
 *
 *   - graphql.operations.authz                        (API1/API5) → OVERRIDE-ONLY
 *       Per-resolver BOLA/BFLA needs an operator-supplied GraphQL-aware
 *       processor. A WAF cannot evaluate per-operation authz without parsing
 *       and binding the resolver to an identity claim. We emit NO enforcing
 *       SecRule — only a commented scaffolding/contract block documenting what
 *       the operator must wire (mirrors the envoy ext_proc override-only shape).
 *
 *   - request.dataAtRest                              (SSEC-STORAGE) → OVERRIDE-ONLY
 *       Advisory posture declaration. The WAF never sees the DB write, so this
 *       compiles to NOTHING enforcing. Emits a commented advisory block only;
 *       the out-of-band SSEC-STORAGE finding is produced by the reporter.
 *
 * Self-contained helpers (esc/header/chainTerm) mirror csrf-rules.ts so this
 * module does not depend on rules.ts internals.
 *
 * ID range: 286000..289999 (disjoint from every other x-security range:
 * per-endpoint primary 100000-369999, body-allowlist 400000-408999,
 * response-inspect 420000-428999, SQLi 430000+, SSRF 980000+, CSRF 272000-274999,
 * lifecycle/HPP/response-ctype 269000-276000).
 */

import type { EndpointIR } from '@x-security/core';
import type { GraphqlPolicy, SerializeBy } from '@x-security/schema';
import {
  CORAZA_GO_PROFILE,
  type CorazaEngineProfile,
  type EngineWarning,
} from './profiles.js';
import { endpointHash, pathRegex } from './rules.js';

const SERIALIZE_BASE_ID = 286000;
const GRAPHQL_BASE_ID = 288000;

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function header(comment: string): string {
  return comment.split('\n').map((l) => `# ${l}`).join('\n');
}

/** libmodsecurity3 needs an actions arg on every chain child; Coraza-Go is bare. */
function chainTerm(profile: CorazaEngineProfile): string {
  return profile.legalCollections.has('user') ? '' : ' "t:none"';
}

function safeVarName(name: string): string {
  return name.replace(/[^A-Za-z0-9_]/g, '_');
}

/**
 * Resolve the SerializeBy.key (a RuleRef-style string like
 * `request.body.account_id`, `request.query.id`, `header.X-Account`, or
 * `jwt.sub`) into a ModSecurity variable expression we can key the counter on.
 *
 * Returns null when the key references material the WAF cannot extract without
 * a processor (notably `jwt.sub` — the JWT is opaque to Coraza). In that case
 * the caller skips emission and records an override-only skip so the matrix
 * stays honest rather than emitting a fake key.
 */
function resolveSerializeKeyExpr(
  key: string
): { expr: string; what: string } | null {
  const k = key.trim();
  // body field → ARGS:<field> (works for form + JSON body once the JSON body
  // processor has populated ARGS, which the content-type path already emits).
  let m = /^request\.body\.(.+)$/.exec(k);
  if (m) return { expr: `%{ARGS.${m[1]}}`, what: `request body field '${m[1]}'` };
  m = /^request\.query\.(.+)$/.exec(k);
  if (m) return { expr: `%{ARGS.${m[1]}}`, what: `query arg '${m[1]}'` };
  m = /^header\.(.+)$/.exec(k);
  if (m) return { expr: `%{REQUEST_HEADERS.${m[1]}}`, what: `header '${m[1]}'` };
  // jwt.sub / claim.* — opaque to the WAF without a JWT processor.
  if (/^(jwt|claim)\./.test(k)) return null;
  // Unknown / unsupported shape — treat as unresolvable (no fake key).
  return null;
}

/**
 * request.serializeBy (+ request.concurrencyLimit). API6 edge serialization.
 *
 * PARTIAL: emits a short-window same-key counter keyed on the serialize key,
 * capped at concurrencyLimit (default 1 — "strict serialize"). This bounds how
 * many same-key requests reach upstream per second; it is NOT an in-handler
 * mutex. We surface the "not in-handler atomicity" disclaimer plus the same
 * cross-request/HA downgrade the rate-limit path uses when the engine only
 * honors TX-collection setvar.
 */
export function buildSerializeByRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const sb: SerializeBy | undefined = endpoint.policy.request?.serializeBy;
  if (!sb || !sb.key) return [];

  const epId = `${endpoint.method} ${endpoint.path}`;
  const resolved = resolveSerializeKeyExpr(sb.key);
  if (!resolved) {
    // override-only: the WAF cannot extract this key without a processor.
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: epId,
      reason: `request.serializeBy.key='${sb.key}': not extractable by the WAF (e.g. jwt.sub requires a JWT processor). Edge serialization not emitted — enforce in the upstream/app. (override-only)`,
      detail: { capKey: 'request.serializeBy', key: sb.key },
    });
    return [];
  }

  // concurrencyLimit is "max in-flight requests for the key"; we approximate it
  // as max same-key requests within a 1s short window (edge cap). 1 == strict.
  const limit = Math.max(1, endpoint.policy.request?.concurrencyLimit ?? 1);
  // per-identifier scope keys the counter by the resolved value; global scope
  // ignores the value and serializes ALL traffic to the endpoint on one counter.
  const scope = sb.scope ?? 'per-identifier';
  const keyExpr = scope === 'global' ? `${endpoint.method}` : resolved.expr;

  const slot = endpointHash(endpoint.method, endpoint.path) % 2000;
  const initId = SERIALIZE_BASE_ID + slot * 2;
  const checkId = SERIALIZE_BASE_ID + slot * 2 + 1;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const varName = `ss_serialize_${safeVarName(endpoint.operationId)}`;

  // Collection: prefer global (process-wide, key isolation via the interpolated
  // var name); coraza-go/spoa only honor TX setvar, so downgrade with a warning.
  const onTxOnly = !profile.legalCollections.has('global') && profile.legalCollections.has('tx');
  const col = onTxOnly ? 'tx' : 'global';
  const initcolArg = onTxOnly ? `tx=${keyExpr}` : `global=${keyExpr}`;

  warnings?.push({
    severity: 'downgrade',
    engine: profile.name,
    endpoint: epId,
    reason: `request.serializeBy (concurrencyLimit=${limit}, scope=${scope}): edge serialization only — a crude SecCollection short-window cap, NOT an in-handler mutex; does NOT provide transaction atomicity. (partial)`,
    detail: { capKey: 'request.serializeBy', mechanism: `${col}-collection-1s-window`, key: sb.key },
  });
  if (onTxOnly) {
    warnings?.push({
      severity: 'downgrade',
      engine: profile.name,
      endpoint: epId,
      reason: `request.serializeBy: ${profile.name} only honors setvar on the TX collection (per-transaction); the same-key counter is not cross-request. Move serialization to the upstream/app for real enforcement.`,
      detail: { from: 'global', to: 'tx', capKey: 'request.serializeBy' },
    });
  }

  return [
    [
      header(
        `request.serializeBy (API6) for ${epId}\n` +
          `key=${esc(sb.key)} (${resolved.what}), scope=${scope}, concurrencyLimit=${limit}.\n` +
          `PARTIAL — edge serialization only: a crude same-key cap in a 1s window,\n` +
          `NOT an in-handler mutex. Does NOT provide transaction atomicity.`
      ),
      // 1. open + increment the same-key counter for a 1s edge window.
      `SecRule REQUEST_URI "@rx ${pathRx}" "id:${initId},phase:1,pass,nolog,tag:'x-security-serialize',initcol:${initcolArg},setvar:${col}.${varName}=+1,expirevar:${col}.${varName}=1,chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}"${term}`,
      // 2. deny when the same-key in-window count exceeds the concurrency cap.
      `SecRule REQUEST_URI "@rx ${pathRx}" "id:${checkId},phase:1,deny,status:429,msg:'x-security: serializeBy concurrency cap (${limit}) exceeded (edge serialization, not in-handler atomicity)',tag:'x-security-serialize',log,chain"`,
      `  SecRule REQUEST_METHOD "@streq ${endpoint.method}" "chain"`,
      `    SecRule ${col.toUpperCase()}:${varName} "@gt ${limit}"${term}`,
    ].join('\n'),
  ];
}

/**
 * graphql.staticLimits (API4). Coarse, NON-PARSING guards over the raw body.
 * PARTIAL — emits only the limits that are genuinely enforceable without a
 * GraphQL parser (disableIntrospection, maxAliases, batchLimit). maxDepth /
 * maxComplexity require a real parse and are skipped with a loud warning rather
 * than faked with a brace-counting heuristic (Rule D-1).
 */
export function buildGraphqlStaticLimitRules(
  endpoint: EndpointIR,
  profile: CorazaEngineProfile = CORAZA_GO_PROFILE,
  warnings?: EngineWarning[]
): string[] {
  const g: GraphqlPolicy | undefined = endpoint.policy.graphql;
  if (!g) return [];

  const epId = `${endpoint.method} ${endpoint.path}`;
  const pathRx = pathRegex(endpoint.path);
  const term = chainTerm(profile);
  const slot = endpointHash(endpoint.method, endpoint.path) % 2000;
  const out: string[] = [];
  let n = 0;
  const nextId = (): number => GRAPHQL_BASE_ID + slot * 4 + n++;

  if (g.disableIntrospection === true) {
    const id = nextId();
    out.push(
      [
        header(
          `graphql.staticLimits: disableIntrospection for ${epId}\n` +
            `PARTIAL — non-parsing guard: deny when the body references the\n` +
            `introspection meta-fields __schema / __type. A WAF cannot fully\n` +
            `validate GraphQL semantics, but the introspection token check is\n` +
            `genuinely enforcing at the byte level.`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: GraphQL introspection disabled',tag:'x-security-graphql',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_BODY|ARGS "@rx (?i)__(?:schema|type)\\b"${term}`,
      ].join('\n')
    );
  }

  if (typeof g.maxAliases === 'number' && g.maxAliases > 0) {
    const id = nextId();
    // Crude alias-count guard: GraphQL aliases take the form `name: field`.
    // We count `<ident>:` tokens in the body; @rx with a bounded `{N,}`
    // quantifier denies when at least maxAliases+1 alias-shaped tokens appear.
    // RE2-safe (no backrefs). Heuristic — it can over/under-count inside string
    // literals — hence PARTIAL, surfaced below.
    const min = g.maxAliases + 1;
    out.push(
      [
        header(
          `graphql.staticLimits: maxAliases=${g.maxAliases} for ${epId}\n` +
            `PARTIAL — crude non-parsing alias-token count (heuristic): deny when\n` +
            `>${g.maxAliases} alias-shaped '<ident>:' tokens appear in the body.`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: GraphQL alias cap (${g.maxAliases}) exceeded',tag:'x-security-graphql',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_BODY "@rx (?s)(?:[A-Za-z_][A-Za-z0-9_]*\\s*:\\s*[A-Za-z_][A-Za-z0-9_]*[^:]*){${min},}"${term}`,
      ].join('\n')
    );
    warnings?.push({
      severity: 'downgrade',
      engine: profile.name,
      endpoint: epId,
      reason: `graphql.staticLimits.maxAliases: emitted as a crude non-parsing alias-token count; it can over/under-count tokens inside string literals. PARTIAL — not a real GraphQL parse.`,
      detail: { capKey: 'graphql.staticLimits', limit: 'maxAliases' },
    });
  }

  if (typeof g.batchLimit === 'number' && g.batchLimit > 0) {
    const id = nextId();
    // Batched GraphQL = a top-level JSON array of operations. Crude guard:
    // count `"query"` occurrences (one per batched op) and deny above the cap.
    const min = g.batchLimit + 1;
    out.push(
      [
        header(
          `graphql.staticLimits: batchLimit=${g.batchLimit} for ${epId}\n` +
            `PARTIAL — crude non-parsing batch count: deny when >${g.batchLimit}\n` +
            `'"query"' members appear (batched array of operations).`
        ),
        `SecRule REQUEST_METHOD "@streq ${endpoint.method}" "id:${id},phase:2,deny,status:403,msg:'x-security: GraphQL batch cap (${g.batchLimit}) exceeded',tag:'x-security-graphql',chain"`,
        `  SecRule REQUEST_URI "@rx ${pathRx}" "chain"`,
        `    SecRule REQUEST_BODY "@rx (?s)(?:\\x22query\\x22\\s*:[^:]*){${min},}"${term}`,
      ].join('\n')
    );
    warnings?.push({
      severity: 'downgrade',
      engine: profile.name,
      endpoint: epId,
      reason: `graphql.staticLimits.batchLimit: emitted as a crude non-parsing count of '"query"' members; PARTIAL — not a real JSON/GraphQL parse.`,
      detail: { capKey: 'graphql.staticLimits', limit: 'batchLimit' },
    });
  }

  // maxDepth / maxComplexity require a real parse — DO NOT fake them.
  if (typeof g.maxDepth === 'number' && g.maxDepth > 0) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: epId,
      reason: `graphql.staticLimits.maxDepth: NOT emitted — query-depth enforcement requires a real GraphQL parse the WAF cannot perform; a brace-counting heuristic would be a masked-quality fake (Rule D-1). Enforce via an operator-supplied GraphQL-aware processor.`,
      detail: { capKey: 'graphql.staticLimits', limit: 'maxDepth' },
    });
  }
  if (typeof g.maxComplexity === 'number' && g.maxComplexity > 0) {
    warnings?.push({
      severity: 'skip',
      engine: profile.name,
      endpoint: epId,
      reason: `graphql.staticLimits.maxComplexity: NOT emitted — complexity scoring requires a real GraphQL parse + cost model the WAF cannot perform. Enforce via an operator-supplied GraphQL-aware processor.`,
      detail: { capKey: 'graphql.staticLimits', limit: 'maxComplexity' },
    });
  }

  return out;
}

/**
 * graphql.operations[].authz (API1/API5) — OVERRIDE-ONLY scaffolding, and
 * request.dataAtRest (SSEC-STORAGE) — ADVISORY-ONLY scaffolding.
 *
 * Neither compiles to an enforcing SecRule (a WAF cannot evaluate per-resolver
 * authz without a GraphQL processor, and never sees the DB write). We emit
 * commented contract/advisory blocks ONLY — the operator handoff, mirroring the
 * envoy ext_proc override-only shape — so the operator knows exactly what is
 * NOT enforced here. Returns [] when neither field is declared.
 */
export function buildResidualScaffolding(endpoint: EndpointIR): string[] {
  const out: string[] = [];
  const ops = endpoint.policy.graphql?.operations;
  const epId = `${endpoint.method} ${endpoint.path}`;

  if (Array.isArray(ops) && ops.some((op) => op.authz)) {
    const named = ops
      .filter((op) => op.authz)
      .map((op) => `    - ${op.name}${op.operationType ? ` (${op.operationType})` : ''}: ${op.authz?.type ?? 'authz'}`)
      .join('\n');
    out.push(
      header(
        `graphql.operations[].authz (API1 BOLA / API5 BFLA) for ${epId}\n` +
          `OVERRIDE-ONLY — SCAFFOLDING, NOT ENFORCED.\n` +
          `Per-resolver authorization requires an operator-supplied GraphQL-aware\n` +
          `processor: a WAF cannot parse the query, bind the resolved object to an\n` +
          `identity claim, and evaluate ownership/role per operation. x-security\n` +
          `emits NO enforcing SecRule for these. Operator contract — wire each\n` +
          `operation's authz in your GraphQL gateway / resolver middleware:\n` +
          named
      )
    );
  }

  const dar = endpoint.policy.request?.dataAtRest;
  if (dar && Array.isArray(dar.fields) && dar.fields.length > 0) {
    out.push(
      header(
        `request.dataAtRest (SSEC-STORAGE) for ${epId}\n` +
          `ADVISORY-ONLY — NOT GATEWAY-ENFORCED. The WAF never sees the database\n` +
          `write, so this compiles to NOTHING enforcing. It is a posture\n` +
          `declaration that drives an out-of-band SSEC-STORAGE scan finding.\n` +
          `Declared at-rest protection '${esc(dar.protection)}' for fields:\n` +
          dar.fields.map((f) => `    - ${esc(f)}`).join('\n')
      )
    );
  }

  return out;
}
