// v0.3 authorization-side lowering: RuleRef values, resourceLookup, and the
// hard schema-level requirement that bearer-jwt declares allowedAlgorithms.

import type {
  Authorization,
  AuthorizationRule,
  RuleRef,
  XSecurityPolicy
} from '@x-security/schema';
import { and } from './expressions.js';
import { escapeStr } from './endpoint.js';
import { decorate, emitWorker, getOverride, noteProvenance, type V3Builder } from './v3-shared.js';

const RESOURCE_LOOKUP_WORKER_TEMPLATE = `// x-security: resource lookup + BOLA check (v0.3 authorization.resourceLookup)
export default {
  async fetch(req, env) {
    const id = extractIdentifier(req, PARAMS.identifierFrom);
    const lookupUrl = PARAMS.endpoint.replace('{id}', encodeURIComponent(id));
    const r = await fetch(new URL(lookupUrl, req.url), { headers: req.headers });
    if (!r.ok) return new Response('resource not found', { status: 404 });
    const resource = await r.json();
    const jwt = decodeJwt(req.headers.get('authorization'));
    for (const rule of PARAMS.rules) {
      if (!evaluate(rule, { resource, jwt, request: req })) {
        return new Response('forbidden', { status: 403 });
      }
    }
    return fetch(req);
  }
};`;

/**
 * Hard check: any bearer-jwt policy MUST declare allowedAlgorithms. The schema
 * enforces this at validation time but we re-assert it at compile time so
 * callers that bypass the validator (e.g. CVE proposers building policies in
 * memory) cannot accidentally emit a JWT policy that accepts `alg: none`.
 */
export function assertJwtAlgorithms(policy: XSecurityPolicy, endpointId: string): void {
  const auth = policy.authentication;
  if (!auth || auth.type !== 'bearer-jwt') return;
  const algs = auth.allowedAlgorithms;
  if (!algs || algs.length === 0) {
    throw new CompileError(
      `[${endpointId}] authentication.type='bearer-jwt' requires non-empty allowedAlgorithms; ` +
      `refusing to emit a rule that would accept alg:none or HS-vs-RS algorithm confusion.`
    );
  }
}

export function noteJwtAlgorithms(b: V3Builder, policy: XSecurityPolicy): void {
  const auth = policy.authentication;
  if (!auth || auth.type !== 'bearer-jwt' || !auth.allowedAlgorithms) return;
  noteProvenance(
    b,
    'authentication.allowedAlgorithms',
    `Cloudflare WAF cannot verify JWT signatures; algorithm whitelist [${auth.allowedAlgorithms.join(', ')}] enforced by Cloudflare Access JWT validator (when configured) or a Worker using 'jose' jwtVerify().`,
    'override-only',
    getOverride(b, 'authentication.allowedAlgorithms')
  );
}

export function compileV3Authorization(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const authz = policy.authorization;
  if (!authz) return;
  compileResourceLookup(b, authz);
  compileRuleRefs(b, authz, baseMatch);
}

function compileResourceLookup(b: V3Builder, authz: Authorization): void {
  const lookup = authz.resourceLookup;
  if (!lookup) return;
  emitWorker(b, {
    field: 'authorization.resourceLookup',
    kind: 'resource-lookup',
    description: `Pre-fetch resource via ${lookup.endpoint} (id from ${lookup.identifierFrom}) and expose [${lookup.expose.join(', ')}] under resource.*`,
    template: RESOURCE_LOOKUP_WORKER_TEMPLATE,
    params: {
      endpoint: lookup.endpoint,
      identifierFrom: lookup.identifierFrom,
      expose: lookup.expose,
      rules: (authz.rules ?? []).filter(r => refsResourceNamespace(r))
    }
  });
  noteProvenance(
    b,
    'authorization.resourceLookup',
    'Cloudflare WAF cannot issue subrequests; emitted Worker artifact that pre-fetches the resource and evaluates resource.* rules.',
    'override-only',
    getOverride(b, 'authorization.resourceLookup')
  );
}

function compileRuleRefs(b: V3Builder, authz: Authorization, baseMatch: string): void {
  const rules = authz.rules ?? [];
  for (const r of rules) {
    if (!isRuleRef(r.value)) continue;
    const ref = (r.value as RuleRef).ref;
    if (ref.startsWith('jwt.')) {
      // Wirefilter cannot dereference JWT claims; emit a provenance note and
      // (if a resource lookup is also configured) include this rule in the
      // Worker artifact's rule list. Otherwise the customer must add a
      // Worker themselves.
      noteProvenance(
        b,
        'authorization.rules[].value.ref',
        `Rule '${r.field} ${r.operator} ${ref}' compares against a JWT claim; Cloudflare WAF cannot evaluate this. Requires Cloudflare Access or a Worker.`,
        'partial',
        getOverride(b, 'authorization.rules')
      );
      continue;
    }
    if (ref.startsWith('request.')) {
      // request.headers.x / request.params.id / request.query.foo → Wirefilter.
      const lhs = mapRequestRefToWirefilter(r.field);
      const rhs = mapRequestRefToWirefilter(ref);
      if (!lhs || !rhs) {
        noteProvenance(
          b,
          'authorization.rules[].value.ref',
          `Rule '${r.field} ${r.operator} ${ref}' uses an unsupported ref path; lower via Worker.`,
          'partial'
        );
        continue;
      }
      const op = r.operator === 'equals' ? 'eq' : r.operator === 'not-equals' ? 'ne' : null;
      if (!op) {
        noteProvenance(
          b,
          'authorization.rules[].value.ref',
          `Rule operator '${r.operator}' on RuleRef requires Worker evaluation in Cloudflare.`,
          'partial'
        );
        continue;
      }
      b.custom.push(decorate(b, {
        kind: `authz-ref-${escapeRuleId(r.field)}`,
        description: `authorization: ${r.field} ${r.operator} ${ref}`,
        expression: and(baseMatch, `not (${lhs} ${op} ${rhs})`),
        action: 'block',
        sourceField: `authorization.rules[ref=${ref}]`,
        confidence: 'MEDIUM'
      }));
      continue;
    }
    if (ref.startsWith('resource.')) {
      // Only reachable if resourceLookup is configured (handled in Worker). The
      // Worker artifact above already includes this rule in its params.rules,
      // so we don't emit a WAF rule here.
      continue;
    }
    noteProvenance(
      b,
      'authorization.rules[].value.ref',
      `Unrecognized RuleRef namespace in '${ref}'; expected jwt|request|resource.`,
      'unsupported'
    );
  }
}

function isRuleRef(v: AuthorizationRule['value']): v is RuleRef {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && 'ref' in (v as object);
}

function refsResourceNamespace(r: AuthorizationRule): boolean {
  return r.field.startsWith('resource.') ||
    (isRuleRef(r.value) && (r.value as RuleRef).ref.startsWith('resource.'));
}

function mapRequestRefToWirefilter(path: string): string | null {
  // request.headers.x-foo → http.request.headers["x-foo"][0]
  // request.query.q     → http.request.uri.args["q"][0]
  // request.params.id   → not directly accessible — null (Worker only)
  if (path.startsWith('request.headers.')) {
    const name = path.slice('request.headers.'.length).toLowerCase();
    return `http.request.headers["${escapeStr(name)}"][0]`;
  }
  if (path.startsWith('request.query.')) {
    const name = path.slice('request.query.'.length);
    return `http.request.uri.args["${escapeStr(name)}"][0]`;
  }
  if (path.startsWith('request.cookies.')) {
    const name = path.slice('request.cookies.'.length);
    return `http.request.cookies["${escapeStr(name)}"][0]`;
  }
  return null;
}

function escapeRuleId(s: string): string {
  return s.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 32);
}

export class CompileError extends Error {
  override readonly name = 'CompileError';
}
