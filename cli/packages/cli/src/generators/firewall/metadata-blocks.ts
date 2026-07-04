/**
 * SSRF-protection constants: cloud metadata endpoints and RFC1918 private
 * ranges that MUST be blocked by default from the application's egress path.
 *
 * Used by both iptables and (future) nftables flavors. These are
 * intentionally typed as readonly tuples so callers can't mutate them.
 *
 * Provenance: PRD R2.5 (SSRF protection — host firewall layer).
 */

export interface BlockEntry {
  /** CIDR or single address; family is implied by presence of ':' */
  cidr: string;
  /** Short human label used in the rule comment */
  label: string;
  /** "v4" | "v6" — drives ip6tables vs iptables emission */
  family: 'v4' | 'v6';
}

/**
 * Cloud instance metadata service (IMDS) endpoints. Blocking these prevents
 * the canonical AWS/GCP/Azure/Alibaba SSRF credential-exfiltration pattern.
 */
export const CLOUD_METADATA_BLOCKS: readonly BlockEntry[] = [
  { cidr: '169.254.169.254/32', label: 'AWS/GCP/Azure IMDSv1/v2', family: 'v4' },
  { cidr: '169.254.170.2/32',   label: 'AWS ECS task metadata',  family: 'v4' },
  { cidr: '100.100.100.200/32', label: 'Alibaba Cloud metadata',  family: 'v4' },
  { cidr: 'fd00:ec2::254/128',  label: 'AWS IMDS (IPv6)',         family: 'v6' },
] as const;

/**
 * RFC1918 + link-local + CGNAT + loopback ranges. Blocking these prevents
 * the app from pivoting onto the internal LAN via SSRF. Callers may exempt
 * specific CIDRs via the future `--firewall-allow-internal` flag (not yet
 * implemented — documented in STATUS.md).
 */
export const PRIVATE_RANGE_BLOCKS: readonly BlockEntry[] = [
  { cidr: '10.0.0.0/8',       label: 'RFC1918 10/8',          family: 'v4' },
  { cidr: '172.16.0.0/12',    label: 'RFC1918 172.16/12',     family: 'v4' },
  { cidr: '192.168.0.0/16',   label: 'RFC1918 192.168/16',    family: 'v4' },
  { cidr: '100.64.0.0/10',    label: 'CGNAT (RFC6598)',       family: 'v4' },
  { cidr: '169.254.0.0/16',   label: 'IPv4 link-local',       family: 'v4' },
  { cidr: '127.0.0.0/8',      label: 'IPv4 loopback',         family: 'v4' },
  { cidr: '::1/128',          label: 'IPv6 loopback',         family: 'v6' },
  { cidr: 'fc00::/7',         label: 'IPv6 ULA (RFC4193)',    family: 'v6' },
  { cidr: 'fe80::/10',        label: 'IPv6 link-local',       family: 'v6' },
] as const;
