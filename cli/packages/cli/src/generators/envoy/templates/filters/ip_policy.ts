/**
 * IP allow/deny policy — second envoy.filters.http.rbac instance, named
 * `envoy.filters.http.rbac.ip` to keep it distinct from the role-based RBAC
 * filter emitted by ./rbac.ts. Envoy keys per-route overrides by filter
 * `name:`, so two RBAC filters can coexist.
 *
 * Chain-level shell is default-ALLOW with an empty policy; per-route
 * typed_per_filter_config supplies the actual ALLOW (ipPolicy.allow) or DENY
 * (ipPolicy.deny) policy using source_ip principals. Wave-22 W22-A.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';
import type { Cidr, IpPolicy } from '@x-security/schema';
import { yamlString } from '../yaml-util.js';

export const IP_RBAC_FILTER_NAME = 'envoy.filters.http.rbac.ip';

export interface RouteIpPolicy {
  endpoint: EndpointIR;
  allow: string[];
  deny: string[];
}

function asCidrArray(v: Cidr[] | string | undefined): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter((s): s is string => typeof s === 'string');
  // VarRef (string token like `${IP_ALLOW}`) — leave to operator override; no native emission.
  return [];
}

export function collectIpPolicies(spec: SpecIR): RouteIpPolicy[] {
  const out: RouteIpPolicy[] = [];
  for (const ep of spec.endpoints) {
    const ip = ep.policy.ipPolicy as IpPolicy | undefined;
    if (!ip) continue;
    const allow = asCidrArray(ip.allow);
    const deny = asCidrArray(ip.deny);
    if (allow.length === 0 && deny.length === 0) continue;
    out.push({ endpoint: ep, allow, deny });
  }
  return out;
}

function parseCidr(cidr: string): { addr: string; prefix: number } | null {
  const m = cidr.trim().match(/^([0-9a-fA-F:.]+)(?:\/(\d{1,3}))?$/);
  if (!m || !m[1]) return null;
  const addr = m[1];
  const isV6 = addr.includes(':');
  const prefix = m[2] !== undefined ? parseInt(m[2], 10) : (isV6 ? 128 : 32);
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > (isV6 ? 128 : 32)) return null;
  return { addr, prefix };
}

/** Chain-level shell filter — empty default-ALLOW. The real policy is per-route. */
export function emitIpRbacFilterChain(lines: string[]): void {
  lines.push(`  - name: ${IP_RBAC_FILTER_NAME}`);
  lines.push('    typed_config:');
  lines.push('      "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC');
  lines.push('      rules:');
  lines.push('        action: ALLOW');
  lines.push('        policies: {}');
}

/** Per-route typed_per_filter_config block — emitted by routes.ts under typed_per_filter_config. */
export function emitRouteIpPolicy(lines: string[], pol: RouteIpPolicy): void {
  lines.push(`          ${IP_RBAC_FILTER_NAME}:`);
  lines.push('            "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute');
  lines.push('            rbac:');
  lines.push('              rules:');
  if (pol.deny.length) {
    // DENY takes precedence: a deny match returns 403 before the allow rule runs.
    lines.push('                action: DENY');
    lines.push('                policies:');
    lines.push('                  x-security-ip-deny:');
    lines.push('                    permissions: [{ any: true }]');
    lines.push('                    principals:');
    for (const c of pol.deny) {
      const p = parseCidr(c);
      if (!p) continue;
      lines.push(`                      - remote_ip: { address_prefix: ${yamlString(p.addr)}, prefix_len: ${p.prefix} }`);
    }
  } else {
    lines.push('                action: ALLOW');
    lines.push('                policies:');
    lines.push('                  x-security-ip-allow:');
    lines.push('                    permissions: [{ any: true }]');
    lines.push('                    principals:');
    for (const c of pol.allow) {
      const p = parseCidr(c);
      if (!p) continue;
      lines.push(`                      - remote_ip: { address_prefix: ${yamlString(p.addr)}, prefix_len: ${p.prefix} }`);
    }
  }
}
