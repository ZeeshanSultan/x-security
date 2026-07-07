/**
 * iptables OUTPUT-chain rule builders for XSecurity's SSRF protection.
 *
 * We emit `iptables-save` format because that's what `iptables-restore` (and
 * `ip6tables-restore`) consume — it's the only stable contract iptables
 * offers. Every emitted rule is DROP, never REJECT — REJECT would surface a
 * recognizable error to the app and let an SSRF probe distinguish
 * "blocked-by-firewall" from "host-unreachable", leaking information.
 *
 * Resolution of `domainAllowlist` entries from FQDNs to IP literals MUST
 * happen at deploy time via a wrapper script (documented in STATUS.md);
 * iptables itself has no DNS support and resolving at compile time would
 * bake in a stale answer. We emit a placeholder comment + a deferred
 * resolution directive that the wrapper substitutes.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';
import {
  CLOUD_METADATA_BLOCKS,
  PRIVATE_RANGE_BLOCKS,
  type BlockEntry,
} from './metadata-blocks.js';

/** Identifies which app uid the OUTPUT rules apply to. */
export interface FirewallOptions {
  /**
   * Linux uid that runs the application. iptables `-m owner --uid-owner`
   * scopes rules so other system processes (DNS resolver, package manager,
   * SSH) are unaffected. Defaults to a placeholder the deploy wrapper
   * replaces.
   */
  appUid?: string;
}

const DEFAULT_UID = '${X_SECURITY_APP_UID}';

/** Single emitted line plus the comment that precedes it. */
interface Rule {
  comment: string;
  line: string;
  family: 'v4' | 'v6';
}

function provenanceComment(endpoint: string, field: string, label: string): string {
  // Order matters: `# x-security:` prefix is the machine-readable anchor.
  return `# x-security: ${endpoint} ${field} -- ${label}`;
}

function blockRule(
  entry: BlockEntry,
  uid: string,
  endpoint: string,
  field: string
): Rule {
  // `-m comment --comment` is reproduced inline so the comment survives
  // `iptables-save` round-trips (the leading `#` comment is stripped by the
  // kernel). Both forms together give human-readable + machine-readable.
  const inlineComment = `x-security/${endpoint}/${field}`;
  return {
    comment: provenanceComment(endpoint, field, entry.label),
    line: `-A OUTPUT -d ${entry.cidr} -m owner --uid-owner ${uid} -m comment --comment "${inlineComment}" -j DROP`,
    family: entry.family,
  };
}

/**
 * Domain-allowlist rule emission. Because iptables can't resolve names, we
 * emit a deferred-resolution directive — the deploy wrapper greps for
 * `@@X_SECURITY_RESOLVE:<fqdn>@@` and substitutes the current A/AAAA set
 * before invoking `iptables-restore`. The fail-closed default below the
 * directive ensures that if the wrapper is skipped, the rule still drops
 * everything (no resolved hosts === no allowed destinations).
 */
function allowlistRule(
  fqdn: string,
  uid: string,
  endpoint: string,
  field: string
): Rule {
  const inlineComment = `x-security/${endpoint}/${field}/allow=${fqdn}`;
  return {
    comment: provenanceComment(endpoint, field, `allow ${fqdn} (resolved at deploy)`),
    line: `-A OUTPUT @@X_SECURITY_RESOLVE:${fqdn}@@ -m owner --uid-owner ${uid} -m comment --comment "${inlineComment}" -j ACCEPT`,
    family: 'v4',
  };
}

/** Walk every endpoint and collect `(endpoint, field, ParamSchema)` triples
 *  whose schema is a URL with a non-empty domainAllowlist. */
function collectUrlAllowlists(
  spec: SpecIR
): Array<{ endpoint: EndpointIR; field: string; domains: string[] }> {
  const out: Array<{ endpoint: EndpointIR; field: string; domains: string[] }> = [];
  for (const ep of spec.endpoints) {
    const schema = ep.policy.request?.schema;
    if (!schema) continue;
    for (const [field, param] of Object.entries(schema)) {
      if (param?.type !== 'url') continue;
      const domains = param.domainAllowlist;
      if (!domains || domains.length === 0) continue;
      out.push({ endpoint: ep, field, domains });
    }
  }
  return out;
}

function endpointLabel(ep: EndpointIR): string {
  return ep.operationId || `${ep.method} ${ep.path}`;
}

/** Build the v4 ruleset as iptables-save format text. */
export function buildIptablesV4(spec: SpecIR, opts: FirewallOptions = {}): string {
  const uid = opts.appUid ?? DEFAULT_UID;
  const allowlists = collectUrlAllowlists(spec);
  const rules: Rule[] = [];

  // 1. Per-endpoint allow rules (ACCEPT). Order matters in iptables:
  //    ACCEPT must come before DROP for the same destination set, so any
  //    explicit allow wins over the blanket metadata/RFC1918 drop below.
  for (const { endpoint, field, domains } of allowlists) {
    for (const fqdn of domains) {
      rules.push(allowlistRule(fqdn, uid, endpointLabel(endpoint), field));
    }
  }

  // 2. Cloud metadata DROP (always, regardless of allowlist contents).
  for (const entry of CLOUD_METADATA_BLOCKS) {
    if (entry.family !== 'v4') continue;
    rules.push(blockRule(entry, uid, '*', 'ssrf-metadata-block'));
  }

  // 3. RFC1918 / link-local / CGNAT / loopback DROP.
  for (const entry of PRIVATE_RANGE_BLOCKS) {
    if (entry.family !== 'v4') continue;
    rules.push(blockRule(entry, uid, '*', 'ssrf-private-range-block'));
  }

  return renderRuleset(rules, 'v4', uid);
}

/** Build the v6 ruleset as ip6tables-save format text. */
export function buildIptablesV6(spec: SpecIR, opts: FirewallOptions = {}): string {
  const uid = opts.appUid ?? DEFAULT_UID;
  const rules: Rule[] = [];

  for (const entry of CLOUD_METADATA_BLOCKS) {
    if (entry.family !== 'v6') continue;
    rules.push(blockRule(entry, uid, '*', 'ssrf-metadata-block'));
  }
  for (const entry of PRIVATE_RANGE_BLOCKS) {
    if (entry.family !== 'v6') continue;
    rules.push(blockRule(entry, uid, '*', 'ssrf-private-range-block'));
  }

  return renderRuleset(rules, 'v6', uid);
}

function renderRuleset(rules: Rule[], family: 'v4' | 'v6', uid: string): string {
  const filtered = rules.filter((r) => r.family === family);
  const header = [
    `# Generated by XSecurity — DO NOT EDIT.`,
    `# Family: IP${family === 'v4' ? 'v4' : 'v6'}`,
    `# Apply with: ${family === 'v4' ? 'iptables-restore' : 'ip6tables-restore'} < this-file`,
    `# Deploy wrapper must substitute @@X_SECURITY_RESOLVE:<fqdn>@@ tokens`,
    `# and ${'${X_SECURITY_APP_UID}'} before applying.`,
    `*filter`,
    `:INPUT ACCEPT [0:0]`,
    `:FORWARD ACCEPT [0:0]`,
    `:OUTPUT ACCEPT [0:0]`,
  ];

  const body: string[] = [];
  for (const rule of filtered) {
    body.push(rule.comment);
    body.push(rule.line);
  }

  // Final default-deny marker for the app uid. DROP, never REJECT.
  // Placed last so explicit ACCEPTs above take precedence.
  body.push(`# x-security: * default-deny -- fail-closed terminator`);
  body.push(
    `-A OUTPUT -m owner --uid-owner ${uid} -m comment --comment "x-security/default-deny" -j DROP`
  );

  return [...header, ...body, `COMMIT`, ``].join('\n');
}
