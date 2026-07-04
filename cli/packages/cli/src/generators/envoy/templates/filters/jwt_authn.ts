/**
 * envoy.filters.http.jwt_authn — JWKS-backed RS256/ES256/EdDSA validation.
 *
 * Replaces the wave-7 Lua "header presence" check; this is real signature
 * validation. Banned algorithms (HS256, none) require a Lua sidecar — wave-9
 * leans on allowedAlgorithms as the effective allowlist.
 */

import type { EndpointIR, SpecIR } from '@writ/core';
import { JWKS_CLUSTER } from '../clusters.js';
import { asString, pathToSafeRegex, yamlString } from '../yaml-util.js';

export interface JwtProvider {
  providerName: string;
  issuer: string | null;
  audiences: string[];
  jwksUri: string;
  headerName: string;
  endpoints: EndpointIR[];
}

/**
 * Collect endpoints that declare bearer-jwt with a JWKS URI. We bucket them
 * by `(jwksUri, issuer, audience)` so we can emit one provider per unique
 * configuration (Envoy supports multiple providers in one filter).
 *
 * For wave-9 we emit a single canonical provider per spec, named
 * `writ_jwt`. Multi-provider support is a future extension; if the spec
 * spread JWKS URIs across endpoints we'd need to demultiplex.
 */
export function collectJwtEndpoints(spec: SpecIR): JwtProvider | null {
  const jwt: EndpointIR[] = [];
  let jwksUri: string | null = null;
  let issuer: string | null = null;
  const audiences = new Set<string>();
  let headerName: string = 'Authorization';

  for (const ep of spec.endpoints) {
    const auth = ep.policy.authentication;
    if (!auth || auth.type !== 'bearer-jwt') continue;
    if (!auth.jwksUri) continue;
    const uri = asString(auth.jwksUri);
    if (!uri) continue;
    jwt.push(ep);
    if (!jwksUri) jwksUri = uri;
    if (!issuer && auth.issuer) issuer = asString(auth.issuer);
    if (auth.audience) {
      const aud = asString(auth.audience);
      if (aud) audiences.add(aud);
    }
    if (auth.headerName) headerName = auth.headerName;
  }
  if (!jwt.length || !jwksUri) return null;
  return {
    providerName: 'writ_jwt',
    issuer,
    audiences: [...audiences],
    jwksUri,
    headerName,
    endpoints: jwt
  };
}

export function emitJwtAuthnFilter(lines: string[], jwt: JwtProvider | null): void {
  if (!jwt) return;
  lines.push('  - name: envoy.filters.http.jwt_authn');
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication');
  lines.push('      providers:');
  lines.push(`        ${jwt.providerName}:`);
  if (jwt.issuer) lines.push(`          issuer: ${yamlString(jwt.issuer)}`);
  if (jwt.audiences.length) {
    lines.push('          audiences:');
    for (const a of jwt.audiences) lines.push(`            - ${yamlString(a)}`);
  }
  lines.push('          from_headers:');
  lines.push(`            - name: ${yamlString(jwt.headerName)}`);
  lines.push('              value_prefix: "Bearer "');
  lines.push('          forward_payload_header: x-writ-jwt-payload');
  lines.push(`          payload_in_metadata: ${jwt.providerName}`);
  lines.push('          remote_jwks:');
  lines.push('            http_uri:');
  lines.push(`              uri: ${yamlString(jwt.jwksUri)}`);
  lines.push(`              cluster: ${JWKS_CLUSTER}`);
  lines.push('              timeout: 5s');
  lines.push('            cache_duration: 600s');
  lines.push('      rules:');
  for (const ep of jwt.endpoints) {
    lines.push('        - match:');
    lines.push(`            safe_regex:`);
    lines.push(`              regex: ${yamlString(pathToSafeRegex(ep.path))}`);
    lines.push('          requires:');
    lines.push(`            provider_name: ${jwt.providerName}`);
  }
  lines.push('      # NOTE: bannedAlgorithms (e.g. HS256, none) require a Lua sidecar — wave-9');
  lines.push('      # leans on allowedAlgorithms as the effective allowlist.');
}
