/**
 * BunkerWeb 1.6.x native JWT settings (closes drift on
 * `authentication.type=bearer-jwt`, `authentication.jwksUri`,
 * `authentication.allowedAlgorithms`).
 *
 * BunkerWeb 1.6+ bundles `nginx_jwt_module` and exposes:
 *   USE_AUTH_JWT      = yes|no   — turn the chain on per-server
 *   JWT_JWKS_URI      = https://... — JWKS endpoint (RSx/ESx/PSx validation)
 *   JWT_ALGORITHMS    = "RS256,ES256" — comma-list of permitted algs
 *   JWT_HEADER        = Authorization (default)
 *   JWT_ISSUER        = (optional)
 *   JWT_AUDIENCE      = (optional)
 *
 * These are emitted as per-server prefixed settings (`<SERVER_NAME>_USE_AUTH_JWT`)
 * by the operator's compose file; the generator surfaces the bare keys in
 * x-security.conf's settings-comment block and the caller prefixes them.
 *
 * When BunkerWeb is fronted by an OIDC sidecar (oauth2-proxy / Kong+OIDC) the
 * native JWT chain should be disabled (`USE_AUTH_JWT=no`) and the sidecar's
 * trust headers consumed instead — DEPLOYMENT.md spells this out.
 */

import type { Authentication, JwtAlgorithm } from '@x-security/schema';
import type { SettingMap } from './settings.js';

/**
 * Algorithm sets that signal a misconfiguration the BW JWT module cannot run
 * safely (HS* requires a shared secret which the WAF doesn't have; 'none'
 * disables verification entirely). The generator-side allowedAlgorithms type
 * is already constrained to asymmetric algs by @x-security/schema, so this
 * is defense-in-depth.
 */
const ASYMMETRIC_ALGS: ReadonlySet<JwtAlgorithm> = new Set([
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
  'EdDSA',
]);

export interface JwtNativeOptions {
  /** If true (default), the generator emits BW JWT settings. False when an OIDC
   *  sidecar is doing the verification — settings.ts callers pass through. */
  enableNativeJwt?: boolean;
}

/**
 * Build BunkerWeb native JWT settings for a bearer-jwt / oauth2 endpoint.
 * Returns an empty map for non-JWT auth types or when jwksUri is missing
 * (no JWKS → cannot validate signatures → caller falls back to header-presence
 * SecRule chain emitted by buildAuthModSecRules).
 */
export function buildJwtNativeSettings(
  auth: Authentication | undefined,
  opts: JwtNativeOptions = {}
): SettingMap {
  if (!auth) return {};
  if (auth.type !== 'bearer-jwt' && auth.type !== 'oauth2') return {};
  if (opts.enableNativeJwt === false) return {};
  if (!auth.jwksUri) return {};

  const out: SettingMap = {
    USE_AUTH_JWT: 'yes',
    JWT_JWKS_URI: String(auth.jwksUri),
  };

  if (auth.allowedAlgorithms?.length) {
    const safe = auth.allowedAlgorithms.filter((a) => ASYMMETRIC_ALGS.has(a));
    if (safe.length > 0) out.JWT_ALGORITHMS = safe.join(',');
  } else {
    // Sensible default — only asymmetric algs. Closes the "alg=none" attack.
    out.JWT_ALGORITHMS = 'RS256,ES256';
  }

  if (auth.headerName) out.JWT_HEADER = auth.headerName;
  if (auth.issuer) out.JWT_ISSUER = String(auth.issuer);
  if (auth.audience) out.JWT_AUDIENCE = String(auth.audience);

  return out;
}
