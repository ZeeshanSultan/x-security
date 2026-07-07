// Depth-completeness gate. The whole-route precision gate (verify-route V2/V4/V5)
// proves a composed policy does not OVER-block. It says nothing about UNDER-
// detection: a route covered by an empty stub policy (`{request:{schema:{}}}`)
// passes V2/V4/V5 trivially because there is nothing to over-block — yet it
// enforces no control on a handler that reads attacker input. That is how the
// completeness loop gets gamed: the model emits a stub to claim "covered" and
// moves on (vapi BOLA/mass-assign routes, 2/13 by-policy).
//
// This gate refuses the stub. It compares the COMPOSED policy against the
// route's deterministic EvidencePack and flags routes whose policy carries no
// substantive control despite observed handler inputs.
//
// D-1 discipline: we assert ONLY what the evidence rock-solidly supports.
//   - HARD gaps (re-detect the route): a stub policy over a route with observed
//     inputs, and a write method missing the denyUnknownFields profile default.
//     Neither manufactures a control or false-demotes a substantive policy.
//   - SOFT advisories (the host must confirm-or-cite-dismiss, never auto-demote):
//     an attacker-controlled id-shaped param with no authorization rule (BOLA
//     surface — but could be a public read), and an HTML sink with no XSS guard.
//     The EvidencePack cannot prove the id reaches an ownership lookup or the
//     input reaches the render, so demoting on these would false-block legit
//     public reads. We surface them as evidence for the model, not a verdict.

import type { EvidencePack, ObjectIdSurface } from './evidence-pack.js';
import type { XSecurityPolicy, ParamSchema } from '@x-security/schema';

export type DepthGapKind =
  | 'stub-policy'
  | 'missing-deny-unknown-fields'
  | 'unguarded-object-id'
  | 'body-route-no-content-type'
  | 'sensitive-route-no-auth'
  | 'auth-endpoint-no-rate-limit';

export interface DepthGap {
  kind: DepthGapKind;
  detail: string;
  /** Byte-matchable surface cite proving the gap is real (D-3). Present on the
   *  evidence-grounded hard gaps (unguarded-object-id, body-route-no-content-type,
   *  sensitive-route-no-auth); absent on the policy-shape gaps (stub-policy,
   *  missing-deny-unknown-fields) which are proven by the policy itself. */
  surface?: { file: string; line: number; excerpt: string };
}

export interface DepthAdvisory {
  kind: 'unguarded-id-param' | 'html-output-unguarded';
  detail: string;
  evidence?: { file: string; line: number; excerpt: string };
}

export interface DepthAssessment {
  gaps: DepthGap[];
  advisories: DepthAdvisory[];
}

/** A V6-verified citation (file + line) the caller passes so the gate can honor
 *  a cited-dismissal exit: an assumption whose byte-matched cite anchors the
 *  ownership-check / public-route line the static scan couldn't parse. */
export interface DismissalCite {
  file: string;
  lineStart: number;
  lineEnd: number;
  /** The V6 byte-matched source text the cite anchors. Used to CONTENT-check a
   *  dismissal on a high-severity mutate BOLA: clearing the gap there requires the
   *  cited line to be a real principal-vs-id ownership comparison, not just any
   *  line near the surface (#1 dismissal-tightening). */
  quote?: string;
}

// A principal-vs-id OWNERSHIP comparison the edge can actually enforce as an
// authorization rule: a principal token co-occurring with a comparison or an
// ownership-binding fetch. This is the ONLY dismissal that clears a mutate BOLA.
// A ROLE gate (admin-only) is deliberately NOT accepted — it is the rbac ceiling
// the edge can't enforce, so a role-gated route demotes to reviewRequired instead
// of silently clearing (honest: the gateway can't block a non-admin token).
const PRINCIPAL_TOKEN_RE =
  /current_user|req(?:uest)?\.user|jwt\.(?:sub|user|username|id|email)|session\[|g\.user|auth\.user|\bprincipal\b|resp\[['"]sub['"]\]|\$current\w*|@current_user|whoami\(\)/i;
const COMPARE_OR_BIND_RE =
  /[!=]==?|<>|\.equals\(|\bis\s+not\b|\bis\b|\bne\b|filter_by\s*\(|\.filter\s*\(|\bwhere\b|find_by|owner_id|user_id/i;
// A ROLE/permission comparison is NOT object-ownership — it is the rbac ceiling the
// edge cannot enforce. A dismissal that only proves "the handler checks the role"
// must NOT clear a mutate BOLA (the route demotes to reviewRequired instead).
const ROLE_COMPARE_RE =
  /\.role\b|\brole\s*[!=]=|[!=]=\s*['"](?:admin|superuser|root|staff|owner|manager)['"]|is_?admin|is_?staff|is_?superuser|require_?role|has_?role|can\(|@admin_required|@roles?_required/i;

/** Does any dismissal cite COVERING the surface prove a principal-vs-id ownership
 *  check (not a role gate, not an unrelated line)? */
function dismissalProvesOwnership(cites: DismissalCite[] | undefined, surface: { file: string; line: number }): boolean {
  if (!cites) return false;
  const base = surface.file.replace(/^\.\//, '');
  return cites.some((c) => {
    const cf = c.file.replace(/^\.\//, '');
    if (cf !== base && !cf.endsWith('/' + base) && !base.endsWith('/' + cf)) return false;
    if (!(surface.line >= c.lineStart - 1 && surface.line <= c.lineEnd + 1)) return false;
    const q = c.quote ?? '';
    if (ROLE_COMPARE_RE.test(q)) return false; // role gate ≠ object ownership
    return PRINCIPAL_TOKEN_RE.test(q) && COMPARE_OR_BIND_RE.test(q);
  });
}

/** Resolved per-route auth chain (for the sensitive-route-no-auth gap, phase C).
 *  `chain` is the declared middleware chain; `inlineSymbols` are inline auth
 *  calls detected in the handler. Both empty ⇒ no resolved auth. */
export interface RouteAuthChain {
  chain: string[];
  inlineSymbols: string[];
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const ATTACKER_SOURCES = new Set(['path', 'query', 'body']);

// The media type a parsed-body kind corresponds to — so the content-type gate hands
// the model the type the handler ACTUALLY reads, instead of letting it guess (and
// so a present-but-contradicting contentType is caught as an over-block).
const KIND_TO_MEDIA: Record<string, string> = {
  json: 'application/json',
  form: 'application/x-www-form-urlencoded',
  multipart: 'multipart/form-data',
  xml: 'application/xml',
};

// Sensitive path tokens (phase C): a route under these segments is a missing-auth
// candidate when its resolved auth chain is empty (or the policy omits an
// authentication block).
const SENSITIVE_PATH_TOKENS = [
  '/admin', '/internal', '/debug', '/me', '/account', '/users/', '/orders/', '/profile',
];

function isSensitivePath(path: string): boolean {
  const p = path.toLowerCase();
  return SENSITIVE_PATH_TOKENS.some((t) => p.includes(t));
}

// Authentication/credential-endpoint path tokens (phase D, rate-limit guard).
const AUTH_ENDPOINT_PATH_TOKENS = [
  '/login', '/signin', '/token', '/auth', '/register', '/signup', '/reset',
];

function isAuthEndpointPath(path: string): boolean {
  const p = path.toLowerCase();
  return AUTH_ENDPOINT_PATH_TOKENS.some((t) => p.includes(t));
}

// A credential-check tell in the handler body: a `password_verify`/`password_hash`
// call, a passport strategy, or a findOne pulling username+password together.
// Reuses the evidence-pack `auth-check` validator class plus a credential-pair
// snippet probe — the byte-matched line surfaces as the gap's cite (D-3).
const CREDENTIAL_CHECK_RE =
  /password_verify|password_hash|passport|check_password|bcrypt\.compare|verify_password|User\.findOne\s*\(\s*\{[^}]*password|findOne\s*\(\s*\{[^}]*password|where[^;\n]*password/i;

/** Find a credential-check line in the evidence pack: an `auth-check` validator
 *  whose excerpt names a credential primitive, or a handler-snippet line the
 *  CREDENTIAL_CHECK_RE matches. Returns the byte-matched cite, or null. */
function findCredentialCheck(pack: EvidencePack): { file: string; line: number; excerpt: string } | null {
  for (const v of pack.observedValidators ?? []) {
    if (v.kind !== 'auth-check') continue;
    if (CREDENTIAL_CHECK_RE.test(v.excerpt) || CREDENTIAL_CHECK_RE.test(v.name)) {
      return { file: v.file, line: v.line, excerpt: v.excerpt };
    }
  }
  const hs = pack.handlerSnippet;
  if (hs) {
    const lines = hs.snippet.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (CREDENTIAL_CHECK_RE.test(lines[i]!)) {
        return { file: hs.file, line: hs.lineStart + i, excerpt: lines[i]!.trim().slice(0, 200) };
      }
    }
  }
  return null;
}

/** Auth-chain symbol/claim tokens that might double as the principal id, used by
 *  the "id IS the principal" carve-out. Derived purely from the chain symbols. */
function principalClaimTokens(auth: RouteAuthChain | undefined): Set<string> {
  const out = new Set<string>();
  if (!auth) return out;
  for (const s of [...auth.chain, ...auth.inlineSymbols]) {
    const lc = s.toLowerCase();
    if (lc.includes('sub')) out.add('sub');
    if (lc.includes('user')) out.add('user');
  }
  return out;
}

// id-shaped param name: a bare `id`, a `<thing>Id`/`<thing>_id`/`<thing>-id`
// suffix, or a known object-handle token. Deliberately tight — we only want the
// classic BOLA object-handle, not every short field.
function isIdLike(name: string): boolean {
  if (name === '(unnamed)') return false;
  const n = name.toLowerCase();
  if (n === 'id' || n === 'uuid' || n === 'guid' || n === 'pid' || n === 'uid') return true;
  return /(?:_|-)?id$|uuid$|guid$/.test(n);
}

// A user/account/order-shaped resource fetch (FIX 4). An auth-less GET that
// fetches one of these by an attacker-controlled id is a real BOLA — NOT a
// public listing. Detected from the id param name (username/user_id/order_id/
// account/…) or the fetch excerpt (`User.findOne`, `Order.find`, `accounts.get`).
// A public listing keyed by a bare product/post `id` with no owner does NOT match.
const USER_SCOPED_RESOURCE_RE =
  /\b(?:user|users|account|accounts|order|orders|profile|customer|member|tenant|invoice|wallet|card|note|notes)\b/i;

function fetchesUserScopedResource(surface: ObjectIdSurface): boolean {
  const name = surface.param.name.toLowerCase();
  if (/^(?:username|user_?id|account(?:_?id)?|order(?:_?id)?|owner)$/.test(name)) return true;
  return USER_SCOPED_RESOURCE_RE.test(surface.param.excerpt);
}

function paramHasConstraint(ps: ParamSchema | undefined): boolean {
  if (!ps || typeof ps !== 'object') return false;
  return Boolean(
    (ps.injectionGuard && ps.injectionGuard.length > 0) ||
      (ps.domainAllowlist && ps.domainAllowlist.length > 0) ||
      ps.pattern ||
      ps.type ||
      ps.minLength !== undefined ||
      ps.maxLength !== undefined ||
      ps.min !== undefined ||
      ps.max !== undefined ||
      (ps.allowedMimeTypes && ps.allowedMimeTypes.length > 0) ||
      ps.magicByteCheck !== undefined,
  );
}

function rateLimitPresent(rl: XSecurityPolicy['rateLimit']): boolean {
  if (!rl) return false;
  return Array.isArray(rl) ? rl.length > 0 : true;
}

/** Does the policy enforce ANY substantive control (vs. just profile defaults)? */
function hasSubstance(policy: XSecurityPolicy): boolean {
  if (policy.authentication && policy.authentication.type && policy.authentication.type !== 'none') return true;
  const authz = policy.authorization;
  if (authz && ((authz.rules && authz.rules.length > 0) || (authz.roles && authz.roles.length > 0) || authz.resourceLookup)) return true;
  if (rateLimitPresent(policy.rateLimit)) return true;
  if (policy.request?.signature) return true;
  if (policy.csrf || policy.mtls) return true;
  const schema = policy.request?.schema;
  if (schema && Object.values(schema).some(paramHasConstraint)) return true;
  return false;
}

function anyInjectionGuard(policy: XSecurityPolicy, sink?: string): boolean {
  const schema = policy.request?.schema;
  if (!schema) return false;
  return Object.values(schema).some((ps) => {
    const g = ps?.injectionGuard;
    if (!g || g.length === 0) return false;
    return sink ? g.includes(sink as never) : true;
  });
}

function authorizationRefsAnyParam(policy: XSecurityPolicy): boolean {
  const rules = policy.authorization?.rules;
  return Boolean(rules && rules.length > 0);
}

/** Normalize a field/param token to its tail name for loose matching:
 *  `request.query.owner` → `owner`, `query.owner` → `owner`, `owner` → `owner`. */
function tailName(field: string): string {
  const parts = field.split('.');
  return (parts[parts.length - 1] ?? field).toLowerCase();
}

/** Does the policy carry an authorization rule (or resourceLookup) that resolves
 *  the given object-id surface? A rule on the id itself, on the discovered owner
 *  field candidate, or any resourceLookup all clear the BOLA gap. */
function authzResolvesSurface(policy: XSecurityPolicy, surface: ObjectIdSurface): boolean {
  const authz = policy.authorization;
  if (!authz) return false;
  if (authz.resourceLookup) return true;
  const rules = authz.rules ?? [];
  if (rules.length === 0) return false;
  const targets = new Set<string>([surface.param.name.toLowerCase()]);
  if (surface.ownerFieldCandidate) targets.add(surface.ownerFieldCandidate.name.toLowerCase());
  return rules.some((r) => targets.has(tailName(r.field)));
}

// A principal token in the handler indicates the route reads/returns data scoped
// to the authenticated user — a sensitive route even without a sensitive path.
const HANDLER_PRINCIPAL_RE =
  /\breq\.user\b|\bjwt\.|\bsession\b|\bcurrent_user\b|\bcurrentUser\b|Auth::(?:id|user)|\bg\.user\b|\brequest\.user\b/;

/** Does the handler emit principal-scoped output? Conservative: requires BOTH a
 *  response sink (json/html) AND a principal token in the handler snippet, so a
 *  static public view (no principal reference) does not trip it. */
function emitsPrincipalScopedOutput(pack: EvidencePack): boolean {
  const outs = pack.observedOutputs ?? [];
  const hasSink = outs.some((o) => o.kind === 'json' || o.kind === 'html');
  if (!hasSink) return false;
  const snippet = pack.handlerSnippet?.snippet ?? '';
  return HANDLER_PRINCIPAL_RE.test(snippet);
}

/** A cited-dismissal exit: a V6-verified assumption cite that anchors a line
 *  inside (or one line adjacent to) the surface — i.e. the model cited the exact
 *  ownership-check / public-route line the static scan couldn't parse. */
function citedDismissalCovers(
  cites: DismissalCite[] | undefined,
  surface: { file: string; line: number },
): boolean {
  if (!cites || cites.length === 0) return false;
  const base = surface.file.replace(/^\.\//, '');
  return cites.some((c) => {
    const cf = c.file.replace(/^\.\//, '');
    if (cf !== base && !cf.endsWith('/' + base) && !base.endsWith('/' + cf)) return false;
    return surface.line >= c.lineStart - 1 && surface.line <= c.lineEnd + 1;
  });
}

/**
 * Assess whether the composed route policy is DEEP enough for the surface the
 * EvidencePack observed. Pure; no IO. Conservative by design (see header).
 */
export function assessRouteDepth(args: {
  policy: XSecurityPolicy;
  pack: EvidencePack;
  method: string;
  /** Route path — for sensitive-path detection (phase C) and the public-read
   *  carve-out. Optional for backward-compat; older callers pass method+pack. */
  path?: string;
  /** Resolved per-route auth chain (phase C). Empty/absent ⇒ no resolved auth. */
  auth?: RouteAuthChain;
  /** V6-verified cites for the cited-dismissal exit on the hard surface gaps. */
  dismissalCites?: DismissalCite[];
}): DepthAssessment {
  const { policy, pack } = args;
  const method = args.method.toUpperCase();
  const path = args.path ?? '';
  const auth = args.auth;
  const dismissalCites = args.dismissalCites;
  const gaps: DepthGap[] = [];
  const advisories: DepthAdvisory[] = [];

  const inputs = pack.observedInputs ?? [];
  const objectIdParams = pack.objectIdParams ?? [];
  const substance = hasSubstance(policy);

  const authChainResolvedEmpty =
    !auth || (auth.chain.length === 0 && auth.inlineSymbols.length === 0);
  const principalClaimNames = principalClaimTokens(auth);

  // HARD gap 1 — stub policy over a route that reads input. The policy enforces
  // nothing the handler actually consumes; "covered" is a lie. Re-detect.
  if (!substance && inputs.length > 0) {
    gaps.push({
      kind: 'stub-policy',
      detail: `policy enforces no substantive control but the handler reads ${inputs.length} input(s) (e.g. ${inputs
        .slice(0, 3)
        .map((i) => `${i.source}.${i.name}`)
        .join(', ')}); re-detect — emit the real control(s) or settle as reviewRequired with a cited reason, not a stub`,
    });
  }

  // HARD gap 2 — write method missing the denyUnknownFields profile default
  // (mass-assignment surface). Absence on a write is a regression, never the
  // legitimate shape; safe to require.
  if (WRITE_METHODS.has(method) && policy.request?.denyUnknownFields !== true) {
    const readsBody = inputs.some((i) => i.source === 'body');
    if (readsBody || inputs.length === 0) {
      gaps.push({
        kind: 'missing-deny-unknown-fields',
        detail: `${method} route does not set request.denyUnknownFields:true — the mass-assignment defense (profile default for writes). Restore it (and enumerate every handler-read body field so it does not over-block).`,
      });
    }
  }

  // HARD gap 3 (phase A) — unguarded-object-id. PROMOTED from the old
  // `unguarded-id-param` advisory: now that the EvidencePack derives
  // `usedInFetchOrMutate` + `comparedToPrincipal`, we can PROVE the BOLA surface
  // (an attacker-controlled id that reaches a fetch/mutate and is NEVER compared
  // to the principal) rather than merely advising. The gate carries the surface
  // cite (D-3) and clears on an authorization rule (on the id or owner field), a
  // resourceLookup, or a V6-verified cited dismissal.
  //
  // Carve-outs (gate does NOT fire — never force auth on a legit public read):
  //   - genuinely-public read: a GET with NO resolved auth chain THAT fetches a
  //     non-user-scoped resource AND has no owner-field candidate (FIX 4 narrows
  //     the old "any auth-less GET = public" carve-out — it let dvrestaurant
  //     GET /orders/{order_id} and dvapi GET /api/user/:username through);
  //   - the handler already compares the id/record to the principal;
  //   - the id IS the principal (its name is the auth-context's principal claim).
  let bolaFired = false;
  for (const surface of objectIdParams) {
    if (!surface.usedInFetchOrMutate) continue;
    if (surface.comparedToPrincipal) continue; // handler already checks ownership
    const idName = surface.param.name.toLowerCase();
    if (principalClaimNames.has(idName)) continue; // id IS the principal
    // public-read carve-out (NARROWED, FIX 4): an auth-less GET is treated as a
    // deliberately public read ONLY when it neither fetches a user/account/order-
    // shaped resource nor carries a request-visible owner field. A user-scoped
    // fetch or an owner-field candidate makes it a real BOLA even without an auth
    // chain — fire. (A public product/post listing keyed by a bare `id` with no
    // owner stays carved out — fetchesUserScopedResource=false, no ownerField.)
    if (
      method === 'GET' &&
      authChainResolvedEmpty &&
      !fetchesUserScopedResource(surface) &&
      !surface.ownerFieldCandidate
    ) {
      continue;
    }
    if (authzResolvesSurface(policy, surface)) continue; // resolved by a control
    const surfaceCite = { file: surface.param.file, line: surface.param.line, excerpt: surface.param.excerpt };
    if (citedDismissalCovers(dismissalCites, surfaceCite)) {
      // #1 dismissal-tightening: on a MUTATE of a user/account/order-shaped
      // resource there is no legitimate "public mutation of another's object",
      // so a mere cite near the surface must NOT wave the BOLA away. Require the
      // dismissal to be a real principal-vs-id ownership comparison the edge can
      // enforce; a role gate or unrelated line does NOT clear it (→ falls through
      // to fire the gap → reviewRequired). Reads (GET) keep the softer location
      // exit so a genuine public-read dismissal still works.
      const isMutate = method === 'DELETE' || WRITE_METHODS.has(method);
      // An AUTHED user-scoped GET is not a public read — its BOLA must clear on a
      // real ownership cite, not just any control cited near the fetch (a nosql
      // guard on the same line was clearing it, leaking dvapi GET /user/:username).
      // A public (unauthed) read keeps the soft location exit so a genuine
      // public-read dismissal still works; a self-read is already carved out above
      // via comparedToPrincipal.
      const authedRead = !authChainResolvedEmpty;
      const strict = fetchesUserScopedResource(surface) && (isMutate || authedRead);
      if (!strict || dismissalProvesOwnership(dismissalCites, surfaceCite)) continue; // cited away
    }
    bolaFired = true;
    // When a request-visible owner field exists, instruct the precise pin so the
    // model emits `request.<loc>.<ownerField> == jwt.<claim>` (FIX 4b).
    const ownerHint = surface.ownerFieldCandidate
      ? ` Prefer pinning the request-visible owner field: \`request.${surface.ownerFieldCandidate.source}.${surface.ownerFieldCandidate.name} == jwt.<claim>\`.`
      : '';
    gaps.push({
      kind: 'unguarded-object-id',
      detail: `attacker-controlled ${surface.param.source}.${surface.param.name} reaches a fetch/mutate and is NEVER compared to the principal (BOLA). Emit an authorization rule \`request.${surface.param.source}.${surface.param.name} == jwt.<claim>\`, or a resourceLookup (resource.<owner> == jwt.sub).${ownerHint} If the resource is genuinely public/principal-scoped, cite the line that proves it and omit.`,
      surface: surfaceCite,
    });
  }

  // HARD gap 4 (phase B) — body-route-no-content-type. A body-bearing route that
  // parses a request body but carries no request.contentType allowlist accepts
  // any content-type (the dvapi addNote / vampi login miss). The gap carries the
  // body-parse surface cite; it clears on a non-empty contentType or a cited
  // dismissal. V4 already round-trips contentType, so this control is low-risk.
  if (pack.bodyParsed) {
    const b = pack.bodyParsed;
    const mediaType = KIND_TO_MEDIA[b.kind]; // the type the handler ACTUALLY parses
    const ct = policy.request?.contentType;
    const surfaceCite = { file: b.file, line: b.line, excerpt: `parses ${b.kind} body` };
    if (!ct || ct.length === 0) {
      // Missing — accepts any content-type. Hand the model the DETECTED media type
      // so it doesn't guess (the dvna over-block was the model emitting json for a
      // urlencoded-parser route).
      if (!citedDismissalCovers(dismissalCites, surfaceCite)) {
        gaps.push({
          kind: 'body-route-no-content-type',
          detail: `${method} route parses a ${b.kind} request body but the policy has no request.contentType allowlist (any content-type accepted). Emit request.contentType: ['${mediaType}'] — the handler parses ${b.kind}, so this is the type legit requests send. Do NOT emit a different type; it would over-block.`,
          surface: surfaceCite,
        });
      }
    } else if (mediaType && !ct.some((c) => c.toLowerCase().split(';')[0]!.trim() === mediaType)) {
      // Present but CONTRADICTS the parser — the emitted allowlist excludes the type
      // the handler actually reads, so every legit request is rejected (the v5 dvna
      // over-block: contentType=['application/json'] on a urlencoded-parser route).
      // Not dismissable — it is a concrete over-block proven by the parser.
      gaps.push({
        kind: 'body-route-no-content-type',
        detail: `request.contentType ${JSON.stringify(ct)} excludes '${mediaType}', but the handler parses a ${b.kind} body — legit requests send '${mediaType}' and would be BLOCKED. Add '${mediaType}' to (or replace) the allowlist.`,
        surface: surfaceCite,
      });
    }
  }

  // HARD gap 5 (phase C) — sensitive-route-no-auth. A sensitive-path route (or
  // one emitting principal-scoped data) is a missing-auth candidate when:
  //   C1 — its resolved auth chain is EMPTY (no middleware, no inline auth), OR
  //   C2 — the chain is NON-empty but the emitted policy carries no
  //        `authentication` block (the gateway, not app middleware, enforces).
  // Carve-out: confidently public/static routes (no sensitive path AND no
  // principal-scoped output) never fire. Clears on an authentication block or a
  // cited dismissal (a public-routes allowlist line).
  {
    const sensitive = isSensitivePath(path) || emitsPrincipalScopedOutput(pack);
    const hasAuthBlock =
      Boolean(policy.authentication && policy.authentication.type && policy.authentication.type !== 'none');
    const c1 = sensitive && authChainResolvedEmpty && !hasAuthBlock;
    const c2 = sensitive && !authChainResolvedEmpty && !hasAuthBlock;
    if (c1 || c2) {
      // Anchor the gap to the handler (or the first principal-scoped output) so it
      // carries a byte-matchable surface (D-3).
      const anchor =
        (pack.observedOutputs ?? []).find((o) => o.kind === 'json' || o.kind === 'html') ??
        undefined;
      const surfaceCite = anchor
        ? { file: anchor.file, line: anchor.line, excerpt: anchor.excerpt }
        : pack.handlerSnippet
        ? { file: pack.handlerSnippet.file, line: pack.handlerSnippet.lineStart, excerpt: '(handler)' }
        : undefined;
      if (surfaceCite && !citedDismissalCovers(dismissalCites, surfaceCite)) {
        const why = c1
          ? `the resolved auth chain is EMPTY (no middleware, no inline auth call)`
          : `app middleware exists but the emitted policy carries no authentication block (the gateway is the enforcement point, not app middleware)`;
        const gap: DepthGap = {
          kind: 'sensitive-route-no-auth',
          detail: `${method} ${path || '(route)'} is sensitive (path token or principal-scoped output) and ${why}. Emit an authentication block, or cite a public-routes allowlist line proving it is intentionally public.`,
          surface: surfaceCite,
        };
        gaps.push(gap);
      }
    }
  }

  // HARD gap 6 (phase D) — auth-endpoint-no-rate-limit. An authentication/
  // credential endpoint with no `rateLimit` is a brute-force regression (dvapi
  // POST /api/login + vampi POST /users/v1/login dropped rateLimit in v2). Fires
  // when the route is an auth endpoint (path token OR a credential-check tell in
  // the handler) AND the policy carries no rateLimit. Carve-out: non-auth routes
  // never fire. Clears on a rateLimit or a cited dismissal. Low precision risk —
  // rateLimit is scored by static adequacy and never over-blocks a single
  // request. The surface cite is the credential-check line (or the handler).
  {
    const credCheck = findCredentialCheck(pack);
    const isAuthEndpoint = isAuthEndpointPath(path) || credCheck !== null;
    if (isAuthEndpoint && !rateLimitPresent(policy.rateLimit)) {
      const surfaceCite =
        credCheck ??
        (pack.handlerSnippet
          ? {
              file: pack.handlerSnippet.file,
              line: pack.handlerSnippet.lineStart,
              excerpt: '(handler)',
            }
          : undefined);
      if (surfaceCite && !citedDismissalCovers(dismissalCites, surfaceCite)) {
        gaps.push({
          kind: 'auth-endpoint-no-rate-limit',
          detail: `${method} ${path || '(route)'} is an authentication/credential endpoint with no rateLimit — a brute-force surface. Emit a rateLimit (e.g. { requests: 5, window: '1m', identifier: 'ip' }) or cite why it is intentionally unthrottled.`,
          surface: surfaceCite,
        });
      }
    }
  }

  // SOFT advisory 1 — id-shaped param the hard gap did NOT promote (e.g. not
  // proven fetch-bound). Classic BOLA surface, but the pack cannot prove the id
  // reaches an ownership lookup, so this is a prompt to confirm, not a demote.
  if (!bolaFired && !authorizationRefsAnyParam(policy)) {
    const idInput = inputs.find((i) => ATTACKER_SOURCES.has(i.source) && isIdLike(i.name));
    if (idInput) {
      advisories.push({
        kind: 'unguarded-id-param',
        detail: `handler reads attacker-controlled ${idInput.source}.${idInput.name} (id-shaped) and the policy has no authorization rule. If the handler fetches a record by it, this is BOLA — emit an authorization rule tying ${idInput.source}.${idInput.name} to the principal. If the resource is public or principal-scoped, cite why and omit.`,
        evidence: { file: idInput.file, line: idInput.line, excerpt: idInput.excerpt },
      });
    }
  }

  // SOFT advisory 2 — HTML sink with no XSS guard and no observed escaping. The
  // pack cannot prove a specific input reaches the render, so advise, not demote.
  if (!anyInjectionGuard(policy, 'xss')) {
    const htmlOut = (pack.observedOutputs ?? []).find((o) => o.kind === 'html');
    const reflectableInput = inputs.some((i) => i.source === 'query' || i.source === 'body');
    const escaped = (pack.observedValidators ?? []).some((v) => v.kind === 'escape' || v.kind === 'sanitizer');
    if (htmlOut && reflectableInput && !escaped) {
      advisories.push({
        kind: 'html-output-unguarded',
        detail: `handler renders HTML and reads reflectable input with no observed escaping and no xss injectionGuard. If user input reaches the rendered output, emit an injectionGuard:[xss] on that param. If the output is fully escaped, cite the escape and omit.`,
        evidence: { file: htmlOut.file, line: htmlOut.line, excerpt: htmlOut.excerpt },
      });
    }
  }

  return { gaps, advisories };
}
