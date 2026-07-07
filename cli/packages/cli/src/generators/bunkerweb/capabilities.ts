/**
 * BunkerWeb capability matrix.
 *
 * Declares, per XSecurityPolicy field, whether the BunkerWeb generator emits
 * enforcing config ('full'), partial enforcement ('partial'), config-only
 * override ('override-only'), or nothing ('unsupported'). The feasibility
 * reporter (packages/cli/src/reporters/feasibility.ts) reads this matrix to
 * decide whether each OWASP probe can be enforced at runtime.
 *
 * D-1 invariant: a field is 'full' ONLY if the generator emits config that
 * actually enforces it. A false 'full' is the worst outcome (CLAUDE.md DVAPI
 * incident) — leave it 'partial' when coverage is incomplete.
 */

import type { CapabilityMatrix } from '@x-security/core';

export function bunkerwebCapabilities(): CapabilityMatrix {
  return {
    fields: {
      'rateLimit': 'full',
      'ipPolicy.allow': 'full',
      'ipPolicy.deny': 'full',
      'cors': 'full',
      'request.maxBodySize': 'full',
      'request.contentType': 'full',
      // OPP-2: request.schema.allowedMimeTypes now enforced by a phase:1
      // Content-Type 415 SecRule + phase:2 415 SecRule on FILES_TMP_CONTENT/
      // FILES (buildSchemaRules), layered on the ALLOWED_MIME_TYPES BW setting
      // → full request-side MIME allowlist.
      'request.schema.allowedMimeTypes': 'full',
      // OPP-2: typed request.schema constraints emitted as phase:2 SecRules
      // (@lt minLength / @gt maxLength / @lt min / @gt max / !@rx pattern /
      // !@rx type-shape email|uuid|integer). libmodsec3 = PCRE, bundled JSON
      // body processor populates ARGS so body fields are inspectable.
      'request.schema.minLength': 'full',
      'request.schema.maxLength': 'full',
      'request.schema.min': 'full',
      'request.schema.max': 'full',
      'request.schema.pattern': 'full',
      'request.schema.type': 'full',
      'request.schema.domainAllowlist': 'full',         // W19-A: SecRule id:980000+
      // W19 (SSEC-INJECTION): per-arg injectionGuard emits a native libmodsec3
      // operator on the field — 'sql' → @detectSQLi, 'xss' → @detectXSS, the
      // other sinks → tuned metachar/operator-token denylists
      // (nosql/os-command/xpath/ldap/code-eval) — as a phase:2 chain
      // (method → path → ARGS:json.<field>|ARGS:<field>).
      // Real enforcement on the declared field → full. (buildInjectionGuardRules)
      'request.schema.injectionGuard': 'full',
      // S-15: redirectAllowedDomains on url-typed fields emits a phase:1 !@rx
      // host-allowlist 403 (id:460000+), same shape as the SSRF domainAllowlist
      // rule. Real per-field enforcement → full. (buildRedirectAllowlistRules)
      'request.schema.redirectAllowedDomains': 'full',
      'timeout.connect': 'full',
      'timeout.read': 'full',
      'timeout.write': 'full',
      'authentication.type=basic': 'full',
      'authentication.type=mtls': 'partial',
      // Promoted: BW 1.6+ nginx_jwt_module via USE_AUTH_JWT/JWT_JWKS_URI/JWT_ALGORITHMS.
      // The WAF-side header-presence SecRule chain stays as defense-in-depth.
      'authentication.type=bearer-jwt': 'full',
      'authentication.jwksUri': 'full',
      'authentication.allowedAlgorithms': 'full',
      'authentication.type=api-key': 'partial',
      'authentication.type=oauth2': 'full',
      'authentication.type=none': 'full',
      // Promoted: rbac multi-role via SecRule chained on X-Forwarded-Groups.
      'authorization.type=rbac': 'full',
      'authorization': 'partial',
      'cacheable': 'override-only',
      // OPP-2: request.denyUnknownFields now emits a phase:2 403 SecRule
      // rejecting body keys outside the allowlist (ARGS_NAMES !@rx
      // ^json\.(allowlist)$). Sourced from request.allowedFields, else
      // request.schema keys when denyUnknownFields:true (mass-assignment).
      'request.denyUnknownFields': 'full',
      // S-5 XXE: disallowXml emits a phase:1 415 SecRule (id:470000+) rejecting
      // application/xml | text/xml | application/*+xml exactly as the contract
      // states → full. (buildXxeRules)
      'request.disallowXml': 'full',
      // S-5 XXE: disableExternalEntities asks to keep XML but block external
      // entity / DTD resolution. libmodsec3 has NO per-route toggle that
      // disables only entity expansion while still parsing XML, so we enforce
      // it the only honest edge way: reject the XML body entirely (the same
      // 415 rule). That's strictly stronger than the field asks, but it is not
      // the literal "accept XML, drop external entities" behavior — so partial,
      // not full (D-1: don't claim full when the semantics differ).
      'request.disableExternalEntities': 'partial',
      // S-3 pathCanonicalization: emits a phase:1 400 SecRule (id:480000+)
      // denying traversal / double-slash / percent-encoded path separators so
      // the canonical path every later @rx ^/path$ rule matches can't be
      // bypassed. libmodsec3 has no compare-to-normalized operator, so we
      // REJECT non-canonical forms rather than canonicalize-then-continue.
      // Meaningful enforcement, but different semantics from "canonicalize" →
      // partial, not full (D-1). (buildPathCanonicalizationRules)
      'request.pathCanonicalization': 'partial',
      // OPP-4: response.schema emits phase:4 RESPONSE_BODY SecRules for fields
      // carrying maxLength/pattern constraints (data exposure, API3). Type-
      // only response fields (e.g. type:name, type:integer) have no phase:4
      // shape to enforce, so coverage is genuine-but-partial — never claim
      // full when type-only fields pass through unchecked (CLAUDE.md D-1).
      'response.schema': 'partial',
      // Promoted: response PII filter (id:428) + errorScrubbing (id:268)
      // emitted as phase:4 SecRules; stripServerHeaders via REMOVE_HEADERS.
      'response': 'partial',
      'response.errorScrubbing.stripStackTraces': 'full',
      'response.errorScrubbing.stripServerHeaders': 'full',
      'response.errorScrubbing.genericMessages': 'full',
      'request.schema.pii': 'full',
      // Promoted: rateLimit identifier=user-id via CUSTOM_CONF_HTTP limit_req_zone
      // keyed on $http_x_forwarded_user.
      'rateLimit.identifier=user-id': 'full',
      // v0.7 (SSEC-INJECTION + SSEC-PROMPT): the injectionGuard cell already
      // emits a native libmodsec3 operator per declared sink. v0.7 adds two
      // sinks that ride the SAME cell — both are real @rx denylists on the
      // field (deserialization preamble denylist; ai-prompt heuristic denylist,
      // tagged x-security-ssec-prompt) → cell stays 'full'.
      // v0.7 (API2): authentication.passwordPolicy — phase:2 !@rx strength
      // SecRules (minLength/upper/digit/symbol/blocklist) on the body password
      // field. Real per-rule enforcement on a present password → full.
      'authentication.passwordPolicy': 'full',
      // v0.7 (API2): authentication.accountLockout — stateful failed-login
      // counter via libmodsec3 persistent collections (initcol:global +
      // setvar/expirevar + @gt deny), the same pattern the rate-limit emitter
      // uses (MODSEC_NGINX_PROFILE.supportsPersistentCollections=true). The
      // counter is keyed on the lockout identifier (header or body field) and
      // increments on a >=400 auth response → full.
      'authentication.accountLockout': 'full',
      // v0.7 (API3): response.forbidArrayRoot — phase:4 RESPONSE_BODY @rx that
      // denies a bare top-level array body (JSON-hijacking). libmodsec3
      // implements SecResponseBodyAccess → full.
      'response.forbidArrayRoot': 'full',
      // v0.7 (API6): request.idempotencyKey — phase:1 replay dedupe via a
      // persistent-collection seen-count keyed on the idempotency-key header
      // (+ a missing-header 400). Stops cross-request REPLAY but NOT concurrent
      // in-flight races: two requests with the same key in one engine tick can
      // both read count==0 before either writes (no atomic check-and-set at the
      // WAF). The schema itself flags this as partial → partial (D-1: the
      // semantics differ from true idempotency, so never 'full').
      'request.idempotencyKey': 'partial',
      // v0.7 (SSEC-AUDIT): logging — libmodsec3 audit-logs every deny rule that
      // carries log,auditlog (injection-block / authz-deny / rate-limit-trip
      // already do), and we add a phase:5 auditlog opt-in for request/response
      // events. But libmodsec3 CANNOT (a) route per-LoggingEvent to a specific
      // sink, (b) ship to an arbitrary http-collector sinkRef (no HTTP log sink
      // — needs a syslog/fluent-bit sidecar), or (c) apply piiRedaction to the
      // already-recorded raw transaction. Genuine-but-incomplete → partial
      // (D-1: don't claim full when sink routing / redaction are unenforced).
      'logging': 'partial',
      // v0.8 (API1/API5): graphql.operations[].authz — per-resolver BOLA/BFLA.
      // libmodsec3 has no GraphQL parser; Rule D-1 bans a regex fake over the
      // query body. We emit SCAFFOLDING only (a tagged route-marker that hands
      // the /graphql POST to an operator-supplied GraphQL-aware processor + a
      // per-operation authz contract block). Enforcement DEPENDS ON that
      // processor — until supplied, nothing evaluates per-resolver authz →
      // override-only, never full/partial. (buildGraphqlOperationAuthzRules)
      'graphql.operations.authz': 'override-only',
      // v0.8 (API4): graphql.staticLimits — coarse block-level limits. The one
      // limit libmodsec3 enforces honestly without a parser is
      // disableIntrospection (phase:2 @rx deny on __schema/__type — an
      // introspection query MUST contain those meta-fields). batchLimit gets a
      // crude top-level-array reject. Depth/complexity/alias are NOT regular-
      // language-expressible and are surfaced as an override-only note, not
      // faked. Genuine-but-incomplete → partial. (buildGraphqlStaticLimitRules)
      'graphql.staticLimits': 'partial',
      // v0.8 (API6): request.serializeBy / concurrencyLimit — nginx limit_conn
      // edge serialization keyed on the serialize key (concurrencyLimit 1 ==
      // strict serialize). Real EDGE serialization but NOT in-handler
      // transaction atomicity (two sequentially-admitted requests still race in
      // the datastore). Schema disclaimer carried verbatim → partial, never
      // full. Emitted as a CUSTOM_CONF_HTTP_* limit_conn_zone snippet.
      // (buildSerializeByHttpSnippet)
      'request.serializeBy': 'partial',
      // v0.8 (SSEC-STORAGE): request.dataAtRest — ADVISORY-ONLY at-rest posture
      // declaration. The WAF never sees the datastore write, so this compiles to
      // NOTHING enforcing. We emit a documentation-only marker + an operator
      // warning and hard-pin the capability unsupported; it drives an
      // out-of-band SSEC-STORAGE finding, not a gateway control (Rule D-1: no
      // fake 'full'/'partial' for an unenforceable field). (buildDataAtRestRules)
      'request.dataAtRest': 'unsupported',
      'mtls.pinnedCertificates': 'unsupported',
      // Promoted: deprecated emits phase:1 SecRule returning 410 with
      // x-security-deprecated-endpoint-block tag (attribution.py:35).
      'deprecated': 'full',
      'sunsetDate': 'partial'
    }
  };
}
