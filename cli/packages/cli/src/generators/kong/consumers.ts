// Walk the SpecIR and emit Kong consumers + per-plugin credentials so the
// generated kong.yml works without manual operator wiring. Kong OSS's jwt,
// key-auth, acl, and hmac-auth plugins all 401 on every request unless a
// matching Consumer + credential exists in the declarative config.
//
// Strategy: one Consumer per unique `authorization.rbac.roles[]` value across
// the whole spec. Each consumer gets:
//   - an ACL group equal to the role name (so the acl plugin's `allow` matches)
//   - a key-auth credential (used by api-key endpoints)
//   - a jwt_secret with HS256 (RS256 is unavailable in OSS without JWKS fetch)
//   - an hmac-auth credential (used by request.signature endpoints)
//
// Anonymous endpoints (no authorization.rbac) still get a default `role_anon`
// consumer so api-key-only or jwt-only routes have *some* credential to hit;
// otherwise the operator gets a kong.yml that's still half-broken.

import { createHash } from 'node:crypto';
import type { SpecIR, EndpointIR } from '@x-security/core';
import type {
  KongConsumer,
  KongJwtSecret,
  KongKeyAuthCredential,
  KongHmacAuthCredential,
  KongAcl,
  XSecurityWarning
} from './types.js';

export interface BuildConsumersOptions {
  /** Skip jwt_secrets emission for endpoints whose policy declares
   *  Kong Enterprise — the `openid-connect` plugin does real JWKS fetch,
   *  so the HS256 downgrade is unnecessary and misleading. */
  enterpriseJwtRoutes?: boolean;
  /** Structured-warning sink. Receives the HS256 downgrade record so it
   *  shows up in kong.yml's `_x_security_warnings` block (not just stderr). */
  onWarning?: (w: XSecurityWarning) => void;
}

export interface ConsumerBundle {
  consumers: KongConsumer[];
  jwt_secrets: KongJwtSecret[];
  keyauth_credentials: KongKeyAuthCredential[];
  hmacauth_credentials: KongHmacAuthCredential[];
  acls: KongAcl[];
  /** Generator warnings — surfaced to the CLI for stderr output. */
  warnings: string[];
}

const DEFAULT_ROLE = 'anon';

function consumerName(role: string): string {
  return `role_${role}`.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 64);
}

function shortHash(input: string, len = 8): string {
  return createHash('sha1').update(input).digest('hex').slice(0, len);
}

function collectRoles(spec: SpecIR): {
  roles: string[];
  hasApiKey: boolean;
  hasJwt: boolean;
  hasCustomToken: boolean;
  hasHmac: boolean;
} {
  const roles = new Set<string>();
  let hasApiKey = false;
  let hasJwt = false;
  let hasCustomToken = false;
  let hasHmac = false;

  for (const ep of spec.endpoints) {
    const p = ep.policy;
    if (p.authorization?.type === 'rbac' && p.authorization.roles?.length) {
      for (const r of p.authorization.roles) roles.add(r);
    }
    if (p.authentication?.type === 'api-key') hasApiKey = true;
    if (p.authentication?.type === 'bearer-jwt') hasJwt = true;
    if (p.authentication?.type === 'custom-token') hasCustomToken = true;
    if (p.request?.signature?.algorithm?.startsWith('hmac-')) hasHmac = true;
  }

  // Default consumer so credential-only endpoints work even without RBAC roles.
  if (roles.size === 0 && (hasApiKey || hasJwt || hasHmac)) {
    roles.add(DEFAULT_ROLE);
  }

  return { roles: [...roles].sort(), hasApiKey, hasJwt, hasCustomToken, hasHmac };
}

export function buildConsumers(
  spec: SpecIR,
  options: BuildConsumersOptions = {}
): ConsumerBundle {
  const bundle: ConsumerBundle = {
    consumers: [],
    jwt_secrets: [],
    keyauth_credentials: [],
    hmacauth_credentials: [],
    acls: [],
    warnings: []
  };

  const { roles, hasApiKey, hasJwt: hasJwtRaw, hasCustomToken, hasHmac } = collectRoles(spec);
  // Enterprise OIDC mode: the openid-connect plugin does real JWKS fetch,
  // so we MUST NOT emit HS256 jwt_secrets — they'd be inert at best and
  // misleading at worst. The bearer-jwt routes are still gated, just by
  // the OIDC plugin instead of the OSS `jwt` plugin.
  const hasJwt = hasJwtRaw && !options.enterpriseJwtRoutes;

  if (roles.length === 0) return bundle;

  // Pick an issuer key for jwt_secrets that matches the plugin's
  // key_claim_name=iss. Prefer the first bearer-jwt issuer we see, else
  // synthesize a stable per-spec value so the credential is still valid.
  let jwtIssuer: string | undefined;
  for (const ep of spec.endpoints) {
    if (ep.policy.authentication?.type === 'bearer-jwt' && ep.policy.authentication.issuer) {
      jwtIssuer = ep.policy.authentication.issuer;
      break;
    }
  }

  for (const role of roles) {
    const username = consumerName(role);
    bundle.consumers.push({
      username,
      tags: [`x_security_role=${role}`]
    });

    // ACL group: the acl plugin allow-lists the bare role name, so the
    // consumer's group must match exactly (not the prefixed `role_*`).
    bundle.acls.push({ consumer: username, group: role });

    if (hasApiKey) {
      bundle.keyauth_credentials.push({
        consumer: username,
        key: `${role}_test_key_${shortHash(`${(spec.info?.title ?? 'x-security')}|${role}`)}`
      });
    }

    if (hasJwt) {
      const key = jwtIssuer ?? `x-security-${shortHash((spec.info?.title ?? 'x-security') || 'spec', 6)}`;
      bundle.jwt_secrets.push({
        consumer: username,
        // Per-consumer key MUST be unique across the spec (Kong primary key
        // on `key`), so we suffix the role.
        key: `${key}#${role}`,
        algorithm: 'HS256',
        secret: `${role}_jwt_secret_${shortHash(`${(spec.info?.title ?? 'x-security')}|${role}|jwt`, 16)}`
      });
    }

    if (hasHmac) {
      bundle.hmacauth_credentials.push({
        consumer: username,
        username: role,
        secret: `${role}_hmac_secret_${shortHash(`${(spec.info?.title ?? 'x-security')}|${role}|hmac`, 16)}`
      });
    }
  }

  if (hasJwt) {
    bundle.warnings.push(
      'kong: emitted jwt_secrets with algorithm=HS256. OSS Kong cannot fetch JWKS, ' +
      'so RS256/ES256 (the spec-declared allowedAlgorithms) are downgraded to HS256 ' +
      'with a per-consumer shared secret. This is a STATUS-documented OSS downgrade; ' +
      'use Kong Enterprise + OIDC plugin for true RS256 + JWKS validation.'
    );
    // Capture the same downgrade in structured form so kong.yml's
    // _x_security_warnings block records it (Rule D-1: surface the gap
    // in the artifact, not just on stderr).
    if (options.onWarning) {
      // Pick a representative declared algorithm if the spec declared any.
      let declared = 'RS256';
      for (const ep of spec.endpoints) {
        const a = ep.policy.authentication;
        if (a?.type === 'bearer-jwt' && a.allowedAlgorithms?.length) {
          declared = a.allowedAlgorithms.join('|');
          break;
        }
      }
      options.onWarning({
        field: 'authentication.allowedAlgorithms',
        declared,
        emitted: 'HS256',
        reason:
          'Kong OSS cannot fetch JWKS at runtime; asymmetric-key validation ' +
          'is unavailable. jwt_secrets emitted with a per-role shared secret. ' +
          'Use --kong-edition=enterprise (openid-connect plugin) for real ' +
          'RS256/ES256 + JWKS.'
      });
    }
  }

  if (hasCustomToken) {
    bundle.warnings.push(
      'kong: authentication.custom-token has no OSS plugin. No consumer credential ' +
      'is emitted for custom-token routes; supply a custom plugin via ' +
      'targetOverrides.kong, or downgrade the auth type.'
    );
  }

  return bundle;
}

/** Test helper: which endpoints (by operationId) carry custom-token auth. */
export function customTokenEndpoints(spec: SpecIR): EndpointIR[] {
  return spec.endpoints.filter((e) => e.policy.authentication?.type === 'custom-token');
}
