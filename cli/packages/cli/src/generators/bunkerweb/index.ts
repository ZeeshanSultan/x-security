/**
 * BunkerWeb generator (R2.3, v6 rewrite).
 *
 * Emits plain ModSecurity rule files under `configs/modsec/` for the
 * bw-scheduler to sync into BunkerWeb. The prior shape (`bunkerweb.yml`,
 * `variables.env`, plugin manifest + Lua verifier) was abandoned in wave-6:
 *   - BunkerWeb's libmodsec3 build lacks Lua, so SecRuleScript can't run.
 *   - Plugin-registered rule files don't reach the request pipeline.
 *   - Deployment-level env vars belong in docker-compose, not generator output.
 *
 * What this generator owns: phase-1/phase-2 x-security rules in plain
 * ModSecurity syntax. What it does NOT own: BunkerWeb's settings env-vars
 * (set at the compose level) and JWT signature validation (requires an
 * external OIDC sidecar or Kong+OIDC in front of BunkerWeb).
 */

import type {
  CapabilityMatrix,
  ConfigArtifact,
  EndpointIR,
  Generator,
  SpecIR
} from '@x-security/core';

import {
  buildAuthSettings,
  buildCorsSettings,
  buildEndpointSettings,
  buildIpPolicySettings,
  buildRateLimitSettings,
  buildRequestSettings,
  buildTimeoutSettings,
  mergeSettings,
  type SettingMap,
  type SettingValue
} from './settings.js';
import { buildLifecycleRules } from './lifecycle.js';
import { buildAuthzMultiRoleRules } from './authz.js';
import {
  buildPiiResponseRules,
  buildErrorScrubbingRules,
  buildErrorScrubbingSettings
} from './response-rules.js';
import {
  buildRequestSchemaRules,
  buildJsonBodyProcessorRule,
  buildBodyAllowlistRules,
  buildResponseSchemaRules,
  buildInjectionGuardRules,
  buildRedirectAllowlistRules,
  buildXxeRules,
  buildPathCanonicalizationRules
} from './schema-rules.js';
import {
  buildPasswordPolicyRules,
  buildAccountLockoutRules,
  buildForbidArrayRootRules,
  buildIdempotencyKeyRules,
  buildLoggingRules
} from './v07-rules.js';
import {
  buildGraphqlOperationAuthzRules,
  buildGraphqlStaticLimitRules,
  buildSerializeByHttpSnippet,
  buildDataAtRestRules,
  dataAtRestWarning
} from './v08-rules.js';
import { bunkerwebCapabilities } from './capabilities.js';
import { collectSsrfPolicyWarnings } from '../ssrf-policy-check.js';
import { buildSsrfRules } from '../coraza/rules.js';
import { MODSEC_NGINX_PROFILE } from '../coraza/profiles.js';

interface EndpointSettings {
  endpoint: EndpointIR;
  settings: SettingMap;
}

const MODSEC_BLOCK_MARKER = '# x-security-generated authentication rules';

/**
 * Rebase the rule IDs in a block so two distinct blocks in the same service
 * (e.g. two bearer-jwt configs with different header names) don't collide
 * on id:990000..990013. The original block uses 990000+N; we shift by
 * blockIndex * 100 so block 0 → 990000-base, block 1 → 990100-base, etc.
 */
function rebaseRuleIds(block: string, blockIndex: number): string {
  if (blockIndex === 0) return block;
  const offset = blockIndex * 100;
  return block.replace(/\bid:99(\d{4})\b/g, (_match, rest) => {
    const original = Number(rest);
    return `id:99${String(original + offset).padStart(4, '0')}`;
  });
}

function dedupeModsecBlocks(combined: string): string {
  const parts = combined.split(MODSEC_BLOCK_MARKER);
  const seen = new Set<string>();
  const out: string[] = [];
  if (parts[0] && parts[0].trim()) {
    out.push(parts[0]);
  }
  for (let i = 1; i < parts.length; i++) {
    const block = MODSEC_BLOCK_MARKER + parts[i]!;
    const sig = block.trim();
    if (seen.has(sig)) continue;
    seen.add(sig);
    out.push(block);
  }
  return out.join('');
}

function rebaseAllRuleIds(combined: string): string {
  const parts = combined.split(MODSEC_BLOCK_MARKER);
  const out: string[] = [];
  if (parts[0] && parts[0].trim()) out.push(parts[0]);
  for (let i = 1; i < parts.length; i++) {
    const block = MODSEC_BLOCK_MARKER + parts[i]!;
    out.push(rebaseRuleIds(block, i - 1));
  }
  return out.join('');
}

/**
 * Detect endpoints declaring bearer-jwt/oauth2 — surface as structured warning
 * because BunkerWeb's libmodsec3 lacks Lua support and we cannot verify
 * signatures. We still emit the header-presence chain (some enforcement).
 */
function collectJwtWarnings(spec: SpecIR): string[] {
  const warnings: string[] = [];
  for (const ep of spec.endpoints) {
    const t = ep.policy.authentication?.type;
    if (t === 'bearer-jwt' || t === 'oauth2') {
      warnings.push(
        `[bunkerweb] WARNING: ${t} declared on ${ep.method} ${ep.path} but ` +
        `BunkerWeb's libmodsec3 lacks Lua support; emitting header-presence ` +
        `check only. For real JWT signature validation, place an OIDC sidecar ` +
        `(or Kong with --kong-edition enterprise + OIDC plugin) in front of ` +
        `BunkerWeb.`
      );
    }
  }
  return warnings;
}

function detectMixedJwtAudienceIssuer(per: EndpointSettings[]): string[] {
  const audiences = new Set<string>();
  const issuers = new Set<string>();
  for (const { settings } of per) {
    if (settings.X_SECURITY_AUTH_AUDIENCE !== undefined) audiences.add(String(settings.X_SECURITY_AUTH_AUDIENCE));
    if (settings.X_SECURITY_AUTH_ISSUER !== undefined) issuers.add(String(settings.X_SECURITY_AUTH_ISSUER));
  }
  const errors: string[] = [];
  if (audiences.size > 1) errors.push(`mixed JWT audience values across service: ${Array.from(audiences).join(', ')}`);
  if (issuers.size > 1) errors.push(`mixed JWT issuer values across service: ${Array.from(issuers).join(', ')}`);
  return errors;
}

function rateToReqPerMin(rate: string): number {
  const m = /^(\d+)r\/([sm])$/.exec(rate);
  if (!m) return Number.MAX_SAFE_INTEGER;
  const n = Number(m[1]);
  return m[2] === 's' ? n * 60 : n;
}

function stricterRate(a: string, b: string): string {
  return rateToReqPerMin(a) <= rateToReqPerMin(b) ? a : b;
}

function collapseLimitReqUrlCollisions(s: SettingMap): { collisions: string[] } {
  const urlToIndex = new Map<string, number>();
  const collisions: string[] = [];
  const toDelete: string[] = [];
  for (const [key, val] of Object.entries(s)) {
    const m = /^LIMIT_REQ_URL_(\d+)$/.exec(key);
    if (!m) continue;
    const idx = Number(m[1]);
    const url = String(val);
    const first = urlToIndex.get(url);
    if (first === undefined) {
      urlToIndex.set(url, idx);
      continue;
    }
    const rateKeyA = `LIMIT_REQ_RATE_${first}`;
    const rateKeyB = `LIMIT_REQ_RATE_${idx}`;
    if (s[rateKeyA] !== undefined && s[rateKeyB] !== undefined) {
      s[rateKeyA] = stricterRate(String(s[rateKeyA]), String(s[rateKeyB]));
    }
    toDelete.push(key, rateKeyB);
    collisions.push(`${url} (idx ${idx} -> ${first}, kept stricter rate ${s[rateKeyA]})`);
  }
  for (const k of toDelete) delete s[k];
  return { collisions };
}

function mergeServiceSettings(
  per: EndpointSettings[]
): { settings: SettingMap; provenance: Map<string, string[]> } {
  const mixErrors = detectMixedJwtAudienceIssuer(per);
  if (mixErrors.length > 0) {
    throw new Error(
      `BunkerWeb generator: ${mixErrors.join('; ')}. ` +
      `Split endpoints with different issuer/audience into separate services, ` +
      `or unify the auth policy. (unsupported: mixed-issuer/audience-in-single-service)`
    );
  }

  const merged: SettingMap = {};
  const provenance = new Map<string, string[]>();

  const recordOrigin = (key: string, endpoint: string) => {
    const list = provenance.get(key) ?? [];
    if (!list.includes(endpoint)) list.push(endpoint);
    provenance.set(key, list);
  };

  for (const { endpoint, settings } of per) {
    const opLabel = `${endpoint.method} ${endpoint.path}`;
    for (const [key, val] of Object.entries(settings)) {
      const existing = merged[key];
      if (existing === undefined) {
        merged[key] = val;
        recordOrigin(key, opLabel);
        continue;
      }
      if (/^CUSTOM_CONF_MODSEC_\d+$/.test(key)) {
        const combined = `${String(existing)}${String(val)}`;
        merged[key] = dedupeModsecBlocks(combined);
        recordOrigin(key, opLabel);
        continue;
      }
      if (/^CUSTOM_CONF_HTTP_/.test(key)) {
        // Raw nginx http-context snippets (user-id rate-limit zones).
        // Concat unique snippets; cross-endpoint same-URL collisions are
        // collapsed by the LIMIT_REQ collision pass downstream.
        const a = String(existing);
        const b = String(val);
        merged[key] = a.includes(b) ? a : `${a}${b}`;
        recordOrigin(key, opLabel);
        continue;
      }
      if (key === 'REMOVE_HEADERS') {
        const set = new Set<string>(
          String(existing).split(/\s+/).filter(Boolean).concat(String(val).split(/\s+/).filter(Boolean))
        );
        merged[key] = Array.from(set).join(' ');
        recordOrigin(key, opLabel);
        continue;
      }
      if (/_\d+$/.test(key)) {
        merged[key] = val;
        recordOrigin(key, opLabel);
        continue;
      }
      if (key === 'ALLOWED_METHODS') {
        const set = new Set<string>(
          String(existing).split(/[,\s]+/).filter(Boolean).concat(String(val).split(/[,\s]+/).filter(Boolean))
        );
        merged[key] = Array.from(set).join(' ');
        recordOrigin(key, opLabel);
        continue;
      }
      if (key === 'CORS_ALLOW_METHODS' || key === 'CORS_ALLOW_HEADERS' || key === 'CORS_EXPOSE_HEADERS') {
        const set = new Set<string>(
          String(existing).split(/[,\s]+/).filter(Boolean).concat(String(val).split(/[,\s]+/).filter(Boolean))
        );
        merged[key] = Array.from(set).join(', ');
        recordOrigin(key, opLabel);
        continue;
      }
      if (
        key === 'CORS_ALLOW_ORIGIN' ||
        key === 'ALLOWED_MIME_TYPES' ||
        key === 'WHITELIST_IP' ||
        key === 'BLACKLIST_IP'
      ) {
        const set = new Set<string>(
          String(existing).split(/\s+/).filter(Boolean).concat(String(val).split(/\s+/).filter(Boolean))
        );
        merged[key] = Array.from(set).join(' ');
        recordOrigin(key, opLabel);
        continue;
      }
      if (key === 'MAX_CLIENT_SIZE') {
        merged[key] = maxNginxSize(String(existing), String(val));
        recordOrigin(key, opLabel);
        continue;
      }
      if (existing === 'yes' || val === 'yes') {
        merged[key] = 'yes';
        recordOrigin(key, opLabel);
        continue;
      }
      recordOrigin(key, opLabel);
    }
  }
  return { settings: merged, provenance };
}

function nginxSizeToBytes(s: string): number {
  const m = /^(\d+)\s*([kmg]?)$/i.exec(s.trim());
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = (m[2] ?? '').toLowerCase();
  const mult = unit === 'k' ? 1024 : unit === 'm' ? 1024 * 1024 : unit === 'g' ? 1024 * 1024 * 1024 : 1;
  return n * mult;
}

function maxNginxSize(a: string, b: string): string {
  return nginxSizeToBytes(a) >= nginxSizeToBytes(b) ? a : b;
}

interface ServiceBlock {
  settings: SettingMap;
  provenance: Map<string, string[]>;
}

function groupByService(spec: SpecIR): ServiceBlock {
  const per: EndpointSettings[] = [];
  let rlCounter = 0;
  let serialCounter = 0;
  for (const ep of spec.endpoints) {
    const settings = buildEndpointSettings(ep.policy, ep.path, ep.method, rlCounter);
    rlCounter += Object.keys(settings).filter((k) => /^LIMIT_REQ_URL_\d+$/.test(k)).length;
    // v0.8 (API6): request.serializeBy → nginx limit_conn edge serialization
    // (PARTIAL — edge only, NOT in-handler atomicity). Surfaced as a
    // CUSTOM_CONF_HTTP_* snippet, the same path as the per-user rate-limit zones.
    const serial = buildSerializeByHttpSnippet(ep, serialCounter);
    if (serial) {
      settings[serial.httpKey] = serial.httpSnippet;
      serialCounter += 1;
    }
    // v0.8 (SSEC-STORAGE): request.dataAtRest is advisory-only — warn the operator
    // that it is NOT gateway-enforced (drives an out-of-band finding, not a control).
    const darWarn = dataAtRestWarning(ep);
    if (darWarn) {
      bunkerwebGenerator.lastWarnings = [...(bunkerwebGenerator.lastWarnings ?? []), darWarn];
    }
    // W19-A: append SSRF SecRules (id:980000+) as an additional MODSEC block.
    // Reuses the Coraza emitter under the MODSEC_NGINX profile (libmodsec3).
    // W21-D: emit at phase:1 (not phase:2). BunkerWeb's bundled JWT/auth chain
    // fires at phase:1; if our SSRF rule sits at phase:2 the auth chain returns
    // a wholesale 401 before our rule ever evaluates the URL allowlist. Query-
    // param SSRF policies are inspectable at phase:1 because REQUEST_URI and
    // ARGS (query string) are populated before the auth chain runs. Body-form
    // SSRF policies would still need phase:2 — but for the vAPI test case
    // (?url=... query) phase:1 is the correct placement.
    const ssrfRules = buildSsrfRules(ep, MODSEC_NGINX_PROFILE, 1);
    if (ssrfRules.length > 0) {
      const existingKeys = Object.keys(settings).filter((k) => /^CUSTOM_CONF_MODSEC_\d+$/.test(k));
      const nextIdx = existingKeys.length + 1;
      const block = `${MODSEC_BLOCK_MARKER}\n# W19-A SSRF url-allowlist for ${ep.method} ${ep.path}\n` +
        ssrfRules.join('\n\n') + '\n';
      settings[`CUSTOM_CONF_MODSEC_${nextIdx}`] = block;
    }
    // Drift closures: deprecated lifecycle / multi-role rbac / response PII /
    // errorScrubbing rules. Each emitter returns 0..N SecRule strings; we
    // append them as additional CUSTOM_CONF_MODSEC_* blocks so the existing
    // dedupe + rule-id rebasing pipeline handles cross-endpoint collisions.
    const extraRuleSets: Array<{ label: string; rules: string[] }> = [
      { label: 'lifecycle (deprecated → 410)', rules: buildLifecycleRules(ep) },
      { label: 'authz (rbac multi-role)', rules: buildAuthzMultiRoleRules(ep) },
      { label: 'response PII (id:428)', rules: buildPiiResponseRules(ep) },
      { label: 'response errorScrubbing (id:268)', rules: buildErrorScrubbingRules(ep) },
      // OPP-2: request-body validation (API6 mass-assignment + API8). The JSON
      // body-processor ctl rule must precede the allowlist rule that depends on
      // ARGS_NAMES being populated.
      { label: 'request JSON body processor (ctl)', rules: buildJsonBodyProcessorRule(ep) },
      { label: 'request.schema typed constraints (phase:2 @lt/@gt/@rx)', rules: buildRequestSchemaRules(ep) },
      { label: 'request.denyUnknownFields body-key allowlist (mass-assignment)', rules: buildBodyAllowlistRules(ep) },
      // OPP-4: response-body validation (API3) — phase:4 RESPONSE_BODY SecRules.
      { label: 'response.schema typed constraints (phase:4)', rules: buildResponseSchemaRules(ep) },
      // W19 (SSEC-INJECTION): per-arg injectionGuard — @detectSQLi / metachar
      // denylists keyed on request.schema.<field>.injectionGuard (phase:2).
      { label: 'request.schema.injectionGuard (SSEC-INJECTION)', rules: buildInjectionGuardRules(ep) },
      // S-15 open-redirect: request.schema.<url field>.redirectAllowedDomains (phase:1).
      { label: 'request.schema.redirectAllowedDomains (open-redirect 403)', rules: buildRedirectAllowlistRules(ep) },
      // S-5 XXE: request.disallowXml / request.disableExternalEntities (phase:1 415).
      { label: 'request XXE guard (disallowXml/disableExternalEntities)', rules: buildXxeRules(ep) },
      // S-3 path canonicalization: request.pathCanonicalization (phase:1 400).
      { label: 'request.pathCanonicalization (non-canonical path 400)', rules: buildPathCanonicalizationRules(ep) },
      // v0.7 (API2): authentication.passwordPolicy — phase:2 !@rx strength checks.
      { label: 'authentication.passwordPolicy (password strength 422)', rules: buildPasswordPolicyRules(ep) },
      // v0.7 (API2): authentication.accountLockout — stateful failed-login counter.
      { label: 'authentication.accountLockout (failed-login lockout 429)', rules: buildAccountLockoutRules(ep) },
      // v0.7 (API3): response.forbidArrayRoot — phase:4 bare-array reject.
      { label: 'response.forbidArrayRoot (JSON-hijacking 500)', rules: buildForbidArrayRootRules(ep) },
      // v0.7 (API6): request.idempotencyKey — phase:1 replay dedupe (partial).
      { label: 'request.idempotencyKey (replay 409)', rules: buildIdempotencyKeyRules(ep) },
      // v0.7 (SSEC-AUDIT): logging — auditlog opt-in (partial).
      { label: 'logging (SSEC-AUDIT auditlog)', rules: buildLoggingRules(ep) },
      // v0.8 (API1/API5): graphql.operations[].authz — per-resolver BOLA/BFLA
      // scaffolding handoff to an operator-supplied GraphQL processor (override-only).
      { label: 'graphql.operations.authz (override-only handoff)', rules: buildGraphqlOperationAuthzRules(ep) },
      // v0.8 (API4): graphql.staticLimits — introspection-disable + batch guard
      // (partial; depth/complexity/alias surfaced as override-only note).
      { label: 'graphql.staticLimits (introspection/batch 403)', rules: buildGraphqlStaticLimitRules(ep) },
      // v0.8 (SSEC-STORAGE): request.dataAtRest — advisory-only marker (unsupported).
      { label: 'request.dataAtRest (SSEC-STORAGE advisory)', rules: buildDataAtRestRules(ep) },
    ];
    for (const { label, rules } of extraRuleSets) {
      if (rules.length === 0) continue;
      const existingKeys = Object.keys(settings).filter((k) => /^CUSTOM_CONF_MODSEC_\d+$/.test(k));
      const nextIdx = existingKeys.length + 1;
      const block = `${MODSEC_BLOCK_MARKER}\n# ${label} for ${ep.method} ${ep.path}\n` +
        rules.join('\n\n') + '\n';
      settings[`CUSTOM_CONF_MODSEC_${nextIdx}`] = block;
    }
    // REMOVE_HEADERS for stripServerHeaders (BW-native, not a SecRule).
    for (const [k, v] of Object.entries(buildErrorScrubbingSettings(ep))) {
      settings[k] = v;
    }
    per.push({ endpoint: ep, settings });
  }
  const { settings, provenance } = mergeServiceSettings(per);
  for (const k of Object.keys(settings)) {
    if (/^CUSTOM_CONF_MODSEC_\d+$/.test(k)) {
      settings[k] = rebaseAllRuleIds(String(settings[k]));
    }
  }
  const { collisions } = collapseLimitReqUrlCollisions(settings);
  if (collisions.length > 0) {
    bunkerwebGenerator.lastWarnings = [
      ...(bunkerwebGenerator.lastWarnings ?? []),
      ...collisions.map((c) => `LIMIT_REQ_URL collision collapsed: ${c}`)
    ];
  }
  return { settings, provenance };
}

/**
 * Build the modsec rules file body. Comprises:
 *  - file header
 *  - per-endpoint method-allowlist comments (informational; real method
 *    enforcement should be configured at BunkerWeb's ALLOWED_METHODS env var)
 *  - dedup'd + rebased ModSec auth blocks
 *  - rate-limit/IP/CORS/etc. encoded as comments pointing the operator at
 *    the compose-level env vars (those don't live in .conf files in BW).
 *
 * What ACTUALLY runs as ModSec rules: only the auth-enforcement SecRule
 * directives. Everything else BunkerWeb consumes via env vars.
 */
function serializeModsecConf(
  spec: SpecIR,
  service: ServiceBlock
): string {
  const lines: string[] = [];
  lines.push(`# Generated by x-security from ${spec.info.title} v${spec.info.version}`);
  lines.push('# Phase-1/phase-2 x-security ModSecurity rules.');
  lines.push('# Place this file under bw-scheduler\'s /data/configs/modsec/ volume.');
  lines.push('# Do not edit by hand — regenerate via `lazy generate --target bunkerweb`.');
  lines.push('');

  // Emit the ModSec auth blocks (the only thing libmodsec actually evaluates).
  // W21-D: SSRF blocks (tagged `x-security-rule-ssrf`) must precede the auth
  // header-presence chain. Both fire at phase:1, and ModSec evaluates phase:1
  // rules in declaration order; if an auth rule denies 401 first, the URL-
  // allowlist rule never runs and the scorer mis-attributes the response as
  // wholesale auth deflection. Sort SSRF blocks before non-SSRF blocks while
  // preserving the original ordering within each group.
  const modsecEntries = Object.entries(service.settings).filter(([k]) =>
    /^CUSTOM_CONF_MODSEC_\d+$/.test(k)
  );
  const ssrfBlocks = modsecEntries.filter(([, v]) =>
    String(v).includes('x-security-rule-ssrf')
  );
  const otherBlocks = modsecEntries.filter(
    ([, v]) => !String(v).includes('x-security-rule-ssrf')
  );
  for (const [key, val] of [...ssrfBlocks, ...otherBlocks]) {
    const origins = service.provenance.get(key) ?? [];
    lines.push(`# Source endpoints: ${origins.join(', ')}`);
    const body = String(val).replace(/\n$/, '');
    for (const ln of body.split('\n')) lines.push(ln);
    lines.push('');
  }

  // Operator-facing summary of settings that belong in docker-compose env, not .conf.
  const composeKeys = Object.keys(service.settings)
    .filter((k) => !/^CUSTOM_CONF_MODSEC_\d+$/.test(k))
    .filter((k) => !/^CUSTOM_CONF_HTTP_/.test(k))
    .sort();
  if (composeKeys.length > 0) {
    lines.push('# Settings below are NOT ModSec rules — they belong in your');
    lines.push('# bunkerweb compose env (set per-service via <SERVICE>_<KEY>=<value>).');
    for (const k of composeKeys) {
      const v = service.settings[k];
      const strVal = typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v);
      if (strVal.includes('\n')) continue;
      const origins = service.provenance.get(k) ?? [];
      lines.push(`# ${k}=${strVal}    # from: ${origins.join(', ')}`);
    }
    lines.push('');
  }

  // Raw nginx http-context snippets (CUSTOM_CONF_HTTP_*) — for the per-user-id
  // rate-limit zones. These belong in the nginx http {} block, surfaced here
  // verbatim so the operator can paste them into bw-scheduler's overrides.
  const httpKeys = Object.keys(service.settings)
    .filter((k) => /^CUSTOM_CONF_HTTP_/.test(k))
    .sort();
  if (httpKeys.length > 0) {
    lines.push('# CUSTOM_CONF_HTTP_* — paste into BunkerWeb http-context custom conf');
    lines.push('# (configs/http/*.conf in the bw-scheduler volume).');
    for (const k of httpKeys) {
      const origins = service.provenance.get(k) ?? [];
      lines.push(`# ↓ ${k}    # from: ${origins.join(', ')}`);
      const body = String(service.settings[k]).replace(/\n$/, '');
      for (const ln of body.split('\n')) lines.push(`# ${ln}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

function serializeDeploymentMd(spec: SpecIR, warnings: string[]): string {
  const lines: string[] = [
    '# x-security → BunkerWeb deployment notes',
    '',
    `Generated from ${spec.info.title} v${spec.info.version}.`,
    '',
    '## Mount',
    '',
    'Place the files under `configs/modsec/` (and `configs/modsec-crs/` if present)',
    'into your **bw-scheduler** container\'s `/data/configs/` volume — that volume',
    'must be writable. The scheduler will sync them to BunkerWeb via its admin',
    'API on next reload.',
    '',
    'Example compose volume:',
    '',
    '```yaml',
    '  bw-scheduler:',
    '    volumes:',
    '      - ./configs:/data/configs:rw',
    '```',
    '',
    '## What this generator emits (and what it does not)',
    '',
    '- **Emits**: plain ModSecurity SecRule directives under `configs/modsec/`.',
    '- **Does NOT emit**: `bunkerweb.yml`, `variables.env`, or a plugin manifest.',
    '  Settings like `USE_MODSECURITY`, `ALLOWED_METHODS`, rate-limit thresholds, etc.',
    '  belong in your **docker-compose.yml** as per-service environment variables',
    '  (`<SERVICE>_<KEY>=<value>` in multisite mode). See the comment block at the',
    '  bottom of `configs/modsec/x-security.conf` for the recommended values.',
    '',
    '## JWT signature validation',
    '',
    'BunkerWeb 1.6+ ships `nginx_jwt_module`; x-security now emits the native',
    '`USE_AUTH_JWT`, `JWT_JWKS_URI`, and `JWT_ALGORITHMS` settings for every',
    '`bearer-jwt` / `oauth2` endpoint that declares `jwksUri`. The WAF-side',
    'header-presence SecRule chain (id:990010/990011) stays as defense-in-depth.',
    '',
    'If you front BunkerWeb with an OIDC sidecar (oauth2-proxy / Kong+OIDC),',
    'set `<SERVER>_USE_AUTH_JWT=no` to disable the native chain and consume the',
    'sidecar\'s trust headers (`X-Forwarded-User`, `X-Forwarded-Groups`) directly.',
    'The RBAC multi-role SecRules emitted by this generator already chain on',
    '`X-Forwarded-Groups`, so the sidecar pattern is supported out of the box.',
    '',
    '## Per-user rate limits (rateLimit.identifier=user-id)',
    '',
    'For endpoints declaring `rateLimit.identifier: user-id`, x-security emits a',
    '`CUSTOM_CONF_HTTP_LIMIT_REQ_USER_<n>` snippet that declares a dedicated',
    '`limit_req_zone` keyed on `$http_x_forwarded_user`. Paste the snippet into',
    '`configs/http/x-security-limit-user.conf` in your bw-scheduler volume, then',
    'wire the matching `limit_req zone=lazy_user_<n> burst=<b> nodelay;` into the',
    'per-location server block (BunkerWeb\'s `CUSTOM_CONF_SERVER_*` overrides).',
    '',
    '## Deprecated endpoints',
    '',
    'Endpoints with `deprecated: true` get a phase:1 SecRule returning **410 Gone**',
    'with tag `x-security-deprecated-endpoint-block` (consumed by the scorer\'s',
    'attribution table). `sunsetDate` is surfaced in the deny message; emit a',
    '`Sunset:` response header via `CUSTOM_HEADER_*` if the client needs it.',
    '',
    '## Warnings',
    ''
  ];
  if (warnings.length === 0) {
    lines.push('_None._');
  } else {
    for (const w of warnings) lines.push(`- ${w}`);
  }
  lines.push('');
  return lines.join('\n');
}

interface BunkerwebGenerator extends Generator {
  lastWarnings?: string[];
}

export const bunkerwebGenerator: BunkerwebGenerator = {
  name: 'bunkerweb',
  targets: ['bunkerweb'],
  lastWarnings: [],

  generate(spec: SpecIR): ConfigArtifact[] {
    bunkerwebGenerator.lastWarnings = [];

    // Structured JWT warnings: bearer-jwt/oauth2 declared but BunkerWeb's
    // libmodsec3 can't verify signatures. Surface to stderr and DEPLOYMENT.md.
    const jwtWarnings = collectJwtWarnings(spec);
    for (const w of jwtWarnings) {
      bunkerwebGenerator.lastWarnings!.push(w);
      // Print to stderr so CLI operators see it immediately.
      // eslint-disable-next-line no-console
      console.error(w);
    }

    // Spec-hygiene: SSRF policy missing on url-typed params (wave-10 W10-9).
    for (const w of collectSsrfPolicyWarnings(spec, 'bunkerweb')) {
      bunkerwebGenerator.lastWarnings!.push(w.message);
    }

    const service = groupByService(spec);
    const modsecBody = serializeModsecConf(spec, service);

    const artifacts: ConfigArtifact[] = [
      {
        path: 'configs/modsec/x-security.conf',
        content: modsecBody,
        format: 'conf'
      },
      {
        path: 'DEPLOYMENT.md',
        content: serializeDeploymentMd(spec, bunkerwebGenerator.lastWarnings ?? []),
        format: 'text'
      }
    ];

    return artifacts;
  },

  capabilities(): CapabilityMatrix {
    return bunkerwebCapabilities();
  }
};

// Re-export builders for granular use by other tooling/tests.
export {
  buildAuthSettings,
  buildCorsSettings,
  buildEndpointSettings,
  buildIpPolicySettings,
  buildRateLimitSettings,
  buildRequestSettings,
  buildTimeoutSettings,
  mergeSettings
};
