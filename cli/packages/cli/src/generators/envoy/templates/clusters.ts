/**
 * Envoy cluster emission (upstream + JWKS).
 *
 * The OPA cluster (`opa_grpc`) lives in extauthz.ts because it is tied to the
 * ext_authz filter; here we only emit clusters owned by the core bootstrap.
 */

import type { JwtProvider } from './filters/jwt_authn.js';
import { urlHostPort, yamlString } from './yaml-util.js';

export const UPSTREAM_CLUSTER = 'writ_upstream';
export const JWKS_CLUSTER = 'jwks_cluster';

export function emitUpstreamCluster(lines: string[], upstreamHost: string, upstreamPort: number): void {
  lines.push(`  - name: ${UPSTREAM_CLUSTER}`);
  lines.push('    type: STRICT_DNS');
  lines.push('    connect_timeout: 5s');
  lines.push('    lb_policy: ROUND_ROBIN');
  lines.push('    load_assignment:');
  lines.push(`      cluster_name: ${UPSTREAM_CLUSTER}`);
  lines.push('      endpoints:');
  lines.push('        - lb_endpoints:');
  lines.push('            - endpoint:');
  lines.push('                address:');
  lines.push(`                  socket_address: { address: ${upstreamHost}, port_value: ${upstreamPort} }`);
}

export function emitJwksCluster(lines: string[], jwt: JwtProvider): void {
  const hp = urlHostPort(jwt.jwksUri);
  if (!hp) return;
  lines.push(`  - name: ${JWKS_CLUSTER}`);
  lines.push('    type: STRICT_DNS');
  lines.push('    connect_timeout: 5s');
  lines.push('    lb_policy: ROUND_ROBIN');
  if (hp.useTls) {
    lines.push('    transport_socket:');
    lines.push('      name: envoy.transport_sockets.tls');
    lines.push('      typed_config:');
    lines.push('        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext');
    lines.push(`        sni: ${yamlString(hp.host)}`);
  }
  lines.push('    load_assignment:');
  lines.push(`      cluster_name: ${JWKS_CLUSTER}`);
  lines.push('      endpoints:');
  lines.push('        - lb_endpoints:');
  lines.push('            - endpoint:');
  lines.push('                address:');
  lines.push(`                  socket_address: { address: ${yamlString(hp.host)}, port_value: ${hp.port} }`);
}
