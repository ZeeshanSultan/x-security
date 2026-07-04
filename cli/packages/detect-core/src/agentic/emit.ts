// PolicyEmission → XSecurityPolicy hydration.
//
// The per-route agent emits ONLY the delta from the profile default. The
// runtime is responsible for merging (profileDefault, agentDelta) into the
// full policy that the v0.3 JSON schema (V1 verifier) validates against.
//
// Rule D-1 alignment: on schema validation failure we return null. The caller
// (passes.ts) is responsible for setting reviewRequired=true and surfacing the
// validation reasons — never a hardcoded fallback that hides the gap.

import type { ParamSchema, XSecurityPolicy } from '@writ/schema';
import { validateXSecurity } from '@writ/schema';
import type { ControlHint, PolicyEmission } from './schema.js';

// Lever 2a — perimeter tightness defaults (flag-gated; default OFF = identity).
//
// An input the handler reads but never bounds IS the vulnerability. When the
// agent emits a param with a real semantic but no tight bound (bare type:string
// / type:integer), the perimeter supplies its OWN defensive default — a size
// cap / numeric range — which is a genuine edge control (rejects oversized /
// out-of-domain input), not a claim about handler validation (D-1 ok; the
// schema's free-text+maxLength is designed for exactly "bounded but unvalidated").
// Without this, such params fail V6 tightness, get stripped, and the policy
// collapses to reviewRequired (emitted=0). Only MISSING bounds are filled; an
// agent-supplied bound is never overridden. url/binary are NOT auto-filled —
// domainAllowlist / allowedMimeTypes are real security decisions, not safe
// defaults, so they stay the agent's / reviewRequired's job.
//
// Defaults are deliberately GENEROUS so legitimate traffic is not false-blocked;
// the corpus legit fixtures are the regression guard.
// Deploy-bound placeholder for an authentication finding's JWKS endpoint. The
// detection (route lacks auth) is real; the JWKS URL is the operator's secret,
// so we emit a named ${var} they bind at deploy rather than fabricate one (D-1).
const AUTH_JWKS_VAR = '${WRIT_AUTH_JWKS_URI}';

// Maps a controlHint authorization `location` to the x-security request segment
// the ownership rule compares against. Without this the rule always targeted
// request.params, so query/body-located object identifiers were inexpressible.
const AUTHZ_LOCATION_SEGMENT: Record<'path' | 'query' | 'body' | 'header', string> = {
  path: 'request.params',
  query: 'request.query',
  body: 'request.body',
  header: 'request.headers',
};

const STRING_MAXLEN_DEFAULT = 8192;
const INT_MIN_DEFAULT = -2_147_483_648;
const INT_MAX_DEFAULT = 2_147_483_647;

export function applyPerimeterTightnessDefaults(
  policy: XSecurityPolicy,
): { policy: XSecurityPolicy; applied: string[] } {
  if (process.env['PRESCRIBE_PERIMETER'] !== '1') {
    return { policy, applied: [] };
  }
  const applied: string[] = [];
  const p = structuredClone(policy);
  const sections: Array<[string, Record<string, ParamSchema> | undefined]> = [
    ['request', p.request?.schema as Record<string, ParamSchema> | undefined],
    ['response', p.response?.schema as Record<string, ParamSchema> | undefined],
  ];
  for (const [sec, schema] of sections) {
    if (!schema) continue;
    for (const [name, ps] of Object.entries(schema)) {
      if (!ps || typeof ps !== 'object') continue;
      const t = (ps as ParamSchema).type;
      if (t === 'string') {
        const hasPattern = typeof ps.pattern === 'string' && ps.pattern.length > 0;
        const hasLen =
          typeof ps.minLength === 'number' && typeof ps.maxLength === 'number';
        if (!hasPattern && !hasLen) {
          if (typeof ps.minLength !== 'number') ps.minLength = 0;
          if (typeof ps.maxLength !== 'number') ps.maxLength = STRING_MAXLEN_DEFAULT;
          applied.push(`${sec}.schema.${name}: perimeter length-cap default`);
        }
      } else if (t === 'integer' || t === 'float') {
        if (typeof ps.min !== 'number' || typeof ps.max !== 'number') {
          if (typeof ps.min !== 'number') ps.min = INT_MIN_DEFAULT;
          if (typeof ps.max !== 'number') ps.max = INT_MAX_DEFAULT;
          applied.push(`${sec}.schema.${name}: perimeter range default`);
        }
      } else if (t === 'email') {
        if (typeof ps.maxLength !== 'number' || ps.maxLength > 254) {
          ps.maxLength = 254;
          applied.push(`${sec}.schema.${name}: email maxLength default`);
        }
      } else if (t === 'free-text') {
        if (typeof ps.maxLength !== 'number') {
          ps.maxLength = STRING_MAXLEN_DEFAULT;
          applied.push(`${sec}.schema.${name}: free-text maxLength default`);
        }
      }
    }
  }
  return { policy: p, applied };
}

// Lever 4 — assumption→control compiler (flag-gated; default OFF = identity).
//
// THE KEY FINDING: the agent's detection is excellent — it produces an
// `assumption` per finding whose `field` already names the exact control
// (e.g. "request.schema.target.injectionGuard"), with a verbatim, byte-matching
// cite of the sink ("exec(\"ping \" . $target)") and high confidence — then
// emits reviewRequired and throws the control away. The detection→control
// conversion is a DETERMINISTIC transform, not an LLM task. This compiler reads
// the agent's own cited assumptions and writes the named control into the
// policy. The LLM detects (its strength, code-agnostic); code emits (reliable).

/** Map an assumption's cited sink to its injectionGuard category. Null when the
 * specific sink can't be determined — never guess a wrong operator. */
function inferSink(quote: string, text: string): string | null {
  const t = `${text} ${quote}`.toLowerCase();
  if (/os[ -]?command|command inject|\bexec\s*\(|\bsystem\s*\(|popen|shell_exec|passthru|proc_open|subprocess|child_process/.test(t)) return 'os-command';
  if (/nosql|\$where|\$ne\b|\$gt\b|mongo/.test(t)) return 'nosql';
  if (/\bsql\b|sql inject|select\s+.*\s+from|->raw\(|\.raw\(|union\s+select/.test(t)) return 'sql';
  if (/cross[- ]site|\bxss\b|innerhtml|dangerouslysetinnerhtml/.test(t)) return 'xss';
  if (/\bldap\b/.test(t)) return 'ldap';
  if (/\bxpath\b/.test(t)) return 'xpath';
  if (/deserial|unserialize|pickle|yaml\.load|node-serialize/.test(t)) return 'deserialization';
  if (/\beval\s*\(|code[- ]?eval|new function|assert\s*\(/.test(t)) return 'code-eval';
  if (/prompt inject|jailbreak|system[- ]prompt/.test(t)) return 'ai-prompt';
  return null;
}

// Schema-mirrored validators for rateLimit config. The identifier MUST match
// the schema pattern (single-component form) or the whole policy fails V1;
// window MUST match the Duration pattern. We validate the model's value and
// fall back to the schema's own safe default ('ip' / '1m') when it doesn't —
// these are non-detection config defaults (D-1 ok), never a detection claim.
const RATE_LIMIT_IDENTIFIER_RE = /^(ip|fingerprint|api-key|user-id|header:[A-Za-z0-9_-]+)$/;
const DURATION_RE = /^\d+(ms|s|m|h|d)$/;

// Build the ParamSchema fields for a paramConstraint hint from ONLY the
// model-supplied structural bounds (param name comes from the hint/field, not
// here). Undefined fields are omitted (exactOptionalPropertyTypes) so the
// perimeter-tightness defaults can fill any missing bound afterwards. No field
// is fabricated — an empty hint yields an empty object, which the tightness
// pass then bounds generically.
function buildParamConstraint(hint: ControlHint): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (hint.paramType !== undefined) out['type'] = hint.paramType;
  if (hint.pattern !== undefined) out['pattern'] = hint.pattern;
  if (hint.maxLength !== undefined) out['maxLength'] = hint.maxLength;
  if (hint.minLength !== undefined) out['minLength'] = hint.minLength;
  if (hint.min !== undefined) out['min'] = hint.min;
  if (hint.max !== undefined) out['max'] = hint.max;
  return out;
}

// Pull the param name out of an assumption's dot-path field, regardless of the
// `in:` location the model used (request.schema.x / request.body.x /
// request.query.x / request.params.x / request.headers.x), tolerating a
// trailing `.injectionGuard`. The emitted policy keys all request params under
// request.schema, so we normalize to that one bucket.
const PARAM_FIELD_RE = /^request\.(?:schema|body|query|params|headers)\.([^.]+)/;
function extractParamName(field: string): string | null {
  const m = PARAM_FIELD_RE.exec(field);
  return m ? m[1]! : null;
}

/**
 * Compile high/medium-confidence assumptions that carry a structured
 * `controlHint` into emitted controls. The model does the DETECTION (tag the
 * assumption); this does the deterministic EMISSION. A reviewRequired route
 * that carries control-bearing assumptions is turned into an emitting one.
 *
 * D-1: the control is sourced from the structured `controlHint`, never scraped
 * from the free-text `assumption`. inferSink is only a backfill for the sink
 * CLASS when the model tagged kind=injectionGuard but omitted `sink`, and it
 * reads from the cited evidence — if it can't resolve a specific sink, the
 * control is dropped (never guess a wrong operator).
 */
export function compileAssumptionsToPolicy(
  emission: PolicyEmission,
): { emission: PolicyEmission; applied: string[] } {
  if (process.env['COMPILE_ASSUMPTIONS'] !== '1') return { emission, applied: [] };
  const applied: string[] = [];
  // Start from the agent's policy if it emitted one, else an empty policy we'll
  // populate purely from its cited assumptions.
  const policy: Record<string, unknown> = emission.policy
    ? (structuredClone(emission.policy) as Record<string, unknown>)
    : {};
  const request = (policy['request'] ??= {}) as Record<string, unknown>;
  const schema = (request['schema'] ??= {}) as Record<string, ParamSchema>;

  for (const a of emission.assumptions) {
    if (a.confidence !== 'high' && a.confidence !== 'medium') continue;
    const hint = a.controlHint;
    if (!hint) continue;

    if (hint.kind === 'injectionGuard') {
      const name = hint.param ?? extractParamName(a.field);
      if (!name) continue;
      const sink = hint.sink ?? inferSink(a.cite?.quote ?? '', a.assumption);
      if (!sink) continue;
      const ps = (schema[name] ??= {} as ParamSchema);
      const guards = new Set(ps.injectionGuard ?? []);
      if (!guards.has(sink as never)) {
        guards.add(sink as never);
        ps.injectionGuard = [...guards] as NonNullable<ParamSchema['injectionGuard']>;
        if (!ps.type) ps.type = 'free-text';
        if (ps.type === 'free-text' && typeof ps.maxLength !== 'number') ps.maxLength = 8192;
        applied.push(`request.schema.${name}.injectionGuard:[${sink}]`);
      }
      continue;
    }

    if (hint.kind === 'authentication') {
      const auth = (policy['authentication'] ?? {}) as { type?: string };
      if (!auth.type || auth.type === 'none') {
        // bearer-jwt requires jwksUri + allowedAlgorithms (schema conditional).
        // We do NOT fabricate the JWKS endpoint — it's a deployment secret — so
        // jwksUri is emitted as an explicit ${var} the user binds at deploy
        // (D-1: a named placeholder, never a made-up URL). allowedAlgorithms
        // defaults to RS256, a safe asymmetric default (HS*/none are excluded),
        // which the user can widen. The detection — "this sensitive route has no
        // auth gate" — is real; only the deploy config is left to the operator.
        policy['authentication'] = {
          type: 'bearer-jwt',
          jwksUri: AUTH_JWKS_VAR,
          allowedAlgorithms: ['RS256'],
        };
        applied.push('authentication:bearer-jwt');
      }
      continue;
    }

    if (hint.kind === 'authorization') {
      // BOLA/BFLA. The ownership comparison is a DETECTION assertion: which
      // request param identifies the object, and which principal claim must own
      // it. Both come from the model — D-1 forbids inventing either. If either
      // is missing, the descriptor is incomplete: drop it (route stays
      // reviewRequired), never fabricate a default ownership field.
      const param = hint.param;
      const principalRef = hint.principalRef;
      if (!param || !principalRef) continue;
      const existing = policy['authorization'];
      if (existing && typeof existing === 'object') continue; // never override
      const operator = hint.operator ?? 'equals';
      // The object identifier can live in the path, query, body, or a header —
      // the model says WHERE (cited). Hardcoding path made query/body-keyed
      // ownership inexpressible: the rule resolved an empty path param, blocking
      // BOTH attacker and legit owner. location defaults to 'path' (the common
      // /resource/:id case) when the model omits it.
      const field = `${AUTHZ_LOCATION_SEGMENT[hint.location ?? 'path']}.${param}`;
      policy['authorization'] = {
        type: 'rule-based',
        rules: [
          {
            field,
            operator,
            value: { ref: principalRef },
          },
        ],
      };
      applied.push(`authorization:rule-based(${field} ${operator} ${principalRef})`);
      continue;
    }

    if (hint.kind === 'denyUnknownFields') {
      // Mass-assignment. Pure structural control — closes the surface where the
      // handler binds arbitrary body keys to a model. No detection param.
      if (request['denyUnknownFields'] !== true) {
        request['denyUnknownFields'] = true;
        applied.push('request.denyUnknownFields:true');
      }
      continue;
    }

    if (hint.kind === 'rateLimit') {
      // Brute-force. The identifier (rate-limit key) is the only field that
      // could assert a detection (it names WHAT to throttle on); the model
      // supplies it. requests/window are non-detection config — safe defaults
      // are allowed, same class as perimeter tightness defaults (D-1 ok). The
      // identifier default 'ip' is the schema's own default (R1.6), not a
      // detection claim. identifier must match the schema pattern or the policy
      // fails V1 — validate before accepting the model's value.
      if (policy['rateLimit'] !== undefined) continue; // never override
      const identifier =
        hint.identifier && RATE_LIMIT_IDENTIFIER_RE.test(hint.identifier)
          ? hint.identifier
          : 'ip';
      const requests = hint.requests ?? 10;
      const window =
        hint.window && DURATION_RE.test(hint.window) ? hint.window : '1m';
      policy['rateLimit'] = { requests, window, identifier };
      applied.push(`rateLimit:${requests}/${window}/${identifier}`);
      continue;
    }

    if (hint.kind === 'paramConstraint') {
      // Perimeter tightness. The param name is detection-sourced (model); the
      // tightness fields are structural bounds, not detection claims. We write
      // the supplied fields verbatim and let applyPerimeterTightnessDefaults
      // (lever 2a, same flag class) fill any missing bound so it survives V3.
      const name = hint.param ?? extractParamName(a.field);
      if (!name) continue;
      const ps = (schema[name] ??= {} as ParamSchema);
      const fields = buildParamConstraint(hint);
      let changed = false;
      for (const [k, v] of Object.entries(fields)) {
        if ((ps as Record<string, unknown>)[k] === undefined) {
          (ps as Record<string, unknown>)[k] = v;
          changed = true;
        }
      }
      if (changed) applied.push(`request.schema.${name}:paramConstraint`);
      continue;
    }

    if (hint.kind === 'contentType') {
      // Restrict the accepted request content-type. application/json is a safe
      // non-detection default (the overwhelmingly common API body type); the
      // model may override with the route's actual set.
      if (request['contentType'] !== undefined) continue;
      const allowed =
        hint.allowed && hint.allowed.length > 0
          ? hint.allowed
          : ['application/json'];
      request['contentType'] = allowed;
      applied.push(`request.contentType:[${allowed.join(',')}]`);
      continue;
    }

    if (hint.kind === 'responseShape') {
      // Excessive-data-exposure. Strip response keys not in the declared schema.
      // Pure structural control — no detection param.
      const response = (policy['response'] ??= {}) as Record<string, unknown>;
      if (response['stripUnknownFields'] !== true) {
        response['stripUnknownFields'] = true;
        applied.push('response.stripUnknownFields:true');
      }
      continue;
    }

    if (hint.kind === 'ssrfGuard') {
      // SSRF (server-side fetch of a user-supplied URL). The url param is
      // detection-sourced (model). The enforceable control is
      // blockPrivateRanges:true — it rejects the cloud-metadata IP, RFC1918,
      // loopback, link-local, and non-http schemes at the perimeter. Unlike an
      // empty domainAllowlist (a banned no-op, D-1), this BITES with no operator
      // config. An optional non-empty domainAllowlist tightens it further; an
      // empty/absent one is NOT written (no theater). blockPrivateRanges
      // defaults true (the whole point of the hint).
      const name = hint.param ?? extractParamName(a.field);
      if (!name) continue;
      const ps = (schema[name] ??= {} as ParamSchema);
      if (ps.type !== undefined && ps.type !== 'url') continue; // never reclassify
      ps.type = 'url';
      const block = hint.blockPrivateRanges !== false;
      let changed = false;
      if (block && ps.blockPrivateRanges !== true) {
        ps.blockPrivateRanges = true;
        changed = true;
      }
      if (
        hint.domains &&
        hint.domains.length > 0 &&
        ps.domainAllowlist === undefined
      ) {
        ps.domainAllowlist = hint.domains;
        changed = true;
      }
      if (changed) {
        const parts = ['type:url'];
        if (ps.blockPrivateRanges) parts.push('blockPrivateRanges:true');
        if (Array.isArray(ps.domainAllowlist) && ps.domainAllowlist.length > 0) {
          parts.push(`domainAllowlist:[${ps.domainAllowlist.join(',')}]`);
        }
        applied.push(`request.schema.${name}.${parts.join('+')}`);
      }
      continue;
    }

    if (hint.kind === 'domainAllowlist') {
      // SSRF / open-redirect. The param flowing into the outbound request /
      // redirect is detection-sourced (model). The allowlist itself is a real
      // security decision: an empty allowlist means "deny all external" — a
      // valid, maximally-strict default the operator widens. (V1-valid; note V3
      // tightness wants a non-empty list, so an empty one stays reviewRequired
      // at the verifier — the control is still recorded, never fabricated.)
      const name = hint.param ?? extractParamName(a.field);
      if (!name) continue;
      const ps = (schema[name] ??= {} as ParamSchema);
      if (ps.type !== undefined && ps.type !== 'url') continue; // never reclassify
      if (ps.domainAllowlist !== undefined) continue; // never override
      ps.type = 'url';
      ps.domainAllowlist = hint.domains ?? [];
      applied.push(`request.schema.${name}.domainAllowlist:[${(hint.domains ?? []).join(',')}]`);
      continue;
    }
  }

  if (applied.length === 0) return { emission, applied: [] };
  // Controls were compiled — this is now an emitting policy, not a punt.
  return {
    emission: { ...emission, policy: policy as XSecurityPolicy, reviewRequired: false },
    applied,
  };
}

/**
 * Recursive merge: object keys merge, arrays are taken from `delta` whole
 * (the agent emits the final array verbatim — sorting happens in canonical.ts).
 * Primitives in `delta` override `base`.
 */
function deepMerge<T>(base: T, delta: unknown): T {
  if (delta === null || delta === undefined) return base;
  if (Array.isArray(delta)) return delta as unknown as T;
  if (typeof delta !== 'object') return delta as T;
  if (typeof base !== 'object' || base === null || Array.isArray(base)) {
    return delta as T;
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const key of Object.keys(delta as Record<string, unknown>)) {
    const dv = (delta as Record<string, unknown>)[key];
    if (key in out) {
      out[key] = deepMerge(out[key], dv);
    } else {
      out[key] = dv;
    }
  }
  return out as T;
}

/**
 * Hydrate a PolicyEmission into a full XSecurityPolicy by merging the agent's
 * delta on top of the profile default and validating the result against the
 * v0.3 schema.
 *
 * Returns `null` when:
 *   - the emission carries `policy: null` (the agent explicitly opted out), or
 *   - the merged policy fails schema validation (D-1: do not invent defaults).
 *
 * On null return, callers should mark the emission `reviewRequired: true` and
 * attach the validation errors to `reviewReasons`.
 */
export function hydratePolicy(
  emission: PolicyEmission,
  profile: Partial<XSecurityPolicy> | null,
): XSecurityPolicy | null {
  if (emission.policy === null || emission.policy === undefined) {
    return null;
  }
  const base: Partial<XSecurityPolicy> = profile ? structuredClone(profile) : {};
  const merged = deepMerge(base, emission.policy) as XSecurityPolicy;
  const result = validateXSecurity(merged);
  if (!result.valid) return null;
  return merged;
}

/**
 * Same as `hydratePolicy` but also returns the validation errors when null is
 * returned. `passes.ts` uses this to populate `reviewReasons`.
 */
export function hydratePolicyWithReasons(
  emission: PolicyEmission,
  profile: Partial<XSecurityPolicy> | null,
): { policy: XSecurityPolicy | null; reasons: string[] } {
  if (emission.policy === null || emission.policy === undefined) {
    return { policy: null, reasons: [] };
  }
  const base: Partial<XSecurityPolicy> = profile ? structuredClone(profile) : {};
  const merged = deepMerge(base, emission.policy) as XSecurityPolicy;
  const result = validateXSecurity(merged);
  if (result.valid) return { policy: merged, reasons: [] };
  const reasons = (result.errors ?? []).map((e) => {
    const path = (e as { instancePath?: string }).instancePath ?? '';
    const msg = (e as { message?: string }).message ?? 'invalid';
    return `${path} ${msg}`.trim();
  });

  // Resilient hydration: a schema-invalid SUB-FIELD must not null the whole
  // policy and over-block the route (a single bad authorization or response
  // field would otherwise drop EVERY defense → reviewRequired → legit traffic
  // blocked). AJV pinpoints each failing path; strip those and re-validate,
  // keeping the largest valid remainder. Only null if nothing valid survives.
  const working = structuredClone(merged) as Record<string, unknown>;
  const dropped: string[] = [];
  for (let iter = 0; iter < 6; iter++) {
    const r = validateXSecurity(working);
    if (r.valid) break;
    const errs = r.errors ?? [];
    let changed = false;
    for (const e of errs) {
      const ip = (e as { instancePath?: string }).instancePath ?? '';
      const kw = (e as { keyword?: string }).keyword;
      const addl = (e as { params?: { additionalProperty?: string } }).params?.additionalProperty;
      const target = kw === 'additionalProperties' && addl ? `${ip}/${addl}` : ip;
      if (target && deleteAtPath(working, target)) {
        dropped.push(target);
        changed = true;
      }
    }
    if (!changed) break;
  }
  const finalOk = validateXSecurity(working).valid;
  if (finalOk && Object.keys(working).length > 0) {
    return {
      policy: working as XSecurityPolicy,
      reasons: [...reasons, `recovered partial policy; dropped schema-invalid: ${dropped.join(', ')}`],
    };
  }
  return { policy: null, reasons };
}

/** Delete a value at an AJV instancePath ("/a/b/0/c"). Returns true if removed. */
function deleteAtPath(root: unknown, instancePath: string): boolean {
  const parts = instancePath.split('/').filter((p) => p.length > 0)
    .map((p) => p.replace(/~1/g, '/').replace(/~0/g, '~'));
  if (parts.length === 0) return false;
  let cur: unknown = root;
  for (let i = 0; i < parts.length - 1; i++) {
    if (cur === null || typeof cur !== 'object') return false;
    cur = (cur as Record<string, unknown>)[parts[i]!];
  }
  if (cur === null || typeof cur !== 'object') return false;
  const leaf = parts[parts.length - 1]!;
  const obj = cur as Record<string, unknown>;
  if (Array.isArray(cur)) {
    const idx = Number(leaf);
    if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return false;
    (cur as unknown[]).splice(idx, 1);
    return true;
  }
  if (!(leaf in obj)) return false;
  delete obj[leaf];
  return true;
}
