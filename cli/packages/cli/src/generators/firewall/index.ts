/**
 * Host-firewall generator (R2.5: SSRF protection at L3/L4).
 *
 * A host firewall is not an L7 device — it can't introspect HTTP request
 * bodies, headers, or paths. The capability matrix below therefore reports
 * `unsupported` for almost every XSecurityPolicy field. The one thing it
 * does well is enforce egress destination restrictions, which is exactly
 * what `request.schema.<field>.domainAllowlist` describes when paired with
 * `type: url`.
 */

import type {
  ConfigArtifact,
  Generator,
  CapabilityMatrix,
  SpecIR,
} from '@writ/core';
import type { EndpointIR } from '@writ/core';
import { buildIptablesV4, buildIptablesV6 } from './iptables.js';
import { loadWrapperScripts } from './scripts-loader.js';
import { collectSsrfPolicyWarnings } from '../ssrf-policy-check.js';

export interface FirewallGenerator extends Generator {
  readonly lastWarnings: readonly string[];
}

let firewallLastWarnings: string[] = [];

interface UrlField {
  endpoint: EndpointIR;
  field: string;
}

function collectUrlFields(spec: SpecIR): UrlField[] {
  const out: UrlField[] = [];
  for (const ep of spec.endpoints) {
    const schema = ep.policy.request?.schema;
    if (!schema) continue;
    for (const [field, param] of Object.entries(schema)) {
      if (param?.type === 'url') out.push({ endpoint: ep, field });
    }
  }
  return out;
}

type ProvenanceEntry = { line: number; endpoint: string; field: string };

function buildProvenance(spec: SpecIR): ProvenanceEntry[] {
  const urls = collectUrlFields(spec);
  return urls.map((u) => ({
    line: 0, // line resolution deferred — single-file ruleset; precise mapping is in inline comments
    endpoint: u.endpoint.operationId || `${u.endpoint.method} ${u.endpoint.path}`,
    field: `request.schema.${u.field}.domainAllowlist`,
  }));
}

export const firewallGenerator: FirewallGenerator = {
  name: 'firewall',
  targets: ['iptables'], // nftables flavor is documented but not yet emitted

  get lastWarnings(): readonly string[] {
    return firewallLastWarnings;
  },

  generate(spec: SpecIR): ConfigArtifact[] {
    // Spec-hygiene: warn on url-typed params missing SSRF policy. Wave-11 W11-B.
    // Firewall is L3/L4 and can only enforce SSRF policy via domainAllowlist
    // (resolved to iptables ALLOW rules at apply-time), so the wording is
    // adapted from the generic helper output.
    firewallLastWarnings = collectSsrfPolicyWarnings(spec, 'firewall').map(
      (w) =>
        `[firewall:ssrf-policy-missing] ${w.method} ${w.path}: parameter "${w.paramName}" ` +
        `declares type=url without domainAllowlist or blockPrivateRanges. Firewall can enforce ` +
        `SSRF policy ONLY when domainAllowlist is declared (resolved to iptables ALLOW rules at ` +
        `apply-time). Without it, this firewall rule set provides no SSRF defense for this endpoint.`
    );

    const provenance = buildProvenance(spec);
    const v4 = buildIptablesV4(spec);
    const v6 = buildIptablesV6(spec);

    // Two artifacts: v4 + v6. They're separate because iptables and
    // ip6tables are separate binaries with separate rule tables on Linux.
    const v4Artifact: ConfigArtifact = {
      path: 'firewall/iptables.rules',
      content: v4,
      format: 'text',
    };
    const v6Artifact: ConfigArtifact = {
      path: 'firewall/ip6tables.rules',
      content: v6,
      format: 'text',
    };
    if (provenance.length > 0) {
      v4Artifact.provenance = provenance;
      v6Artifact.provenance = provenance;
    }

    // Deploy-time DNS wrapper scripts. These are emitted as separate
    // artifacts (one per file) so the deployer can stage them to
    // /usr/local/sbin and /etc/systemd/system independently of the .rules
    // files. Without these, the `@@WRIT_RESOLVE:<fqdn>@@` tokens in
    // the rulesets are inert and the default-deny terminator blocks all
    // egress (fail-closed — intentional).
    const wrappers: ConfigArtifact[] = loadWrapperScripts().map((w) => ({
      path: `firewall/scripts/${w.filename}`,
      content: w.content,
      format: w.format,
    }));

    return [v4Artifact, v6Artifact, ...wrappers];
  },

  capabilities(): CapabilityMatrix {
    // Host firewall is L3/L4 only. The single capability we genuinely
    // implement at this layer is egress destination restriction for URL
    // fields. Everything else is L7 territory.
    return {
      fields: {
        'request.schema.*.domainAllowlist': 'full',

        'authentication': 'unsupported',
        'authorization': 'unsupported',
        'rateLimit': 'unsupported',
        'timeout': 'unsupported',
        'cacheable': 'unsupported',
        'cors': 'unsupported',
        'mtls': 'unsupported',
        'ipPolicy': 'unsupported', // *ingress* IP filtering — different generator
        'request.contentType': 'unsupported',
        'request.maxBodySize': 'unsupported',
        'request.schema.*.type': 'unsupported',
        'request.schema.*.minLength': 'unsupported',
        'request.schema.*.maxLength': 'unsupported',
        'request.schema.*.fixedLength': 'unsupported',
        'request.schema.*.min': 'unsupported',
        'request.schema.*.max': 'unsupported',
        'request.schema.*.pattern': 'unsupported',
        'request.schema.*.allowedMimeTypes': 'unsupported',
        'request.schema.*.maxSize': 'unsupported',
        'response': 'unsupported',
      },
    };
  },
};

export default firewallGenerator;
