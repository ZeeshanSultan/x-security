/**
 * W19-A: SSRF url-allowlist Rego emission for the Envoy ext_authz + OPA path.
 *
 * Split out of extauthz.ts to stay under Rule G-1's 500-line cap. Owns:
 *   - SsrfPolicyEndpoint collector (spec → list of url-typed params + policy)
 *   - private-range pattern list (substring/prefix, no DNS resolution)
 *   - emitSsrfBranches(): builds the Rego decision-chain branches that fire
 *     `opa-ssrf-403` when host ∉ domainAllowlist or matches a private range.
 *
 * extauthz.ts imports these symbols and splices the branches into the larger
 * decision-chain in the canonical order (BFLA → input-validation → SSRF →
 * rule-based → default).
 */

import type { EndpointIR, SpecIR } from '@writ/core';

export interface SsrfPolicyEndpoint {
  endpoint: EndpointIR;
  paramName: string;
  /** Lowercased host allowlist; empty when only blockPrivateRanges is set. */
  domainAllowlist: string[];
  blockPrivateRanges: boolean;
  /** Where the URL value comes from on the wire (query/body). */
  source: 'query' | 'body';
}

/**
 * Any url-typed request.schema parameter with at least one of `domainAllowlist`
 * or `blockPrivateRanges`. Query vs body is determined from the OpenAPI
 * parameter binding — the canonical vAPI /vapi/serversurfer shape is
 * `?url=...`, which lands here with source='query'.
 */
export function collectSsrfPolicy(spec: SpecIR): SsrfPolicyEndpoint[] {
  const out: SsrfPolicyEndpoint[] = [];
  for (const ep of spec.endpoints) {
    const schema = ep.policy.request?.schema;
    if (!schema) continue;
    for (const [paramName, ps] of Object.entries(schema)) {
      if (!ps || ps.type !== 'url') continue;
      const allow = Array.isArray(ps.domainAllowlist)
        ? ps.domainAllowlist.map((d) => d.toLowerCase())
        : [];
      const block = ps.blockPrivateRanges === true;
      if (allow.length === 0 && !block) continue;
      const isQuery = (ep.parameters ?? []).some(
        (p) => p.name === paramName && p.in === 'query'
      );
      out.push({
        endpoint: ep,
        paramName,
        domainAllowlist: allow,
        blockPrivateRanges: block,
        source: isQuery ? 'query' : 'body'
      });
    }
  }
  return out;
}

/**
 * Private/loopback/link-local host prefixes the Rego ssrf branch denies on
 * when blockPrivateRanges:true. Substring/prefix-only; no DNS resolution.
 * Sophisticated bypass (DNS rebinding, decimal-encoded IPs) is documented as
 * a limitation rather than papered over with a partial fix.
 */
export const PRIVATE_HOST_PATTERNS: readonly string[] = [
  '10.',
  '127.',
  '169.254.',
  '172.16.', '172.17.', '172.18.', '172.19.',
  '172.20.', '172.21.', '172.22.', '172.23.',
  '172.24.', '172.25.', '172.26.', '172.27.',
  '172.28.', '172.29.', '172.30.', '172.31.',
  '192.168.',
  'localhost',
  'internal-only',
  '0.0.0.0',
  '[::1]',
  '[fc',
  '[fd',
  '[fe80'
];

export interface SsrfEmitDeps {
  regoString: (s: string) => string;
  pathToRegoRegex: (path: string) => string;
  denyLiteral: (cls: string) => string;
  pushBranch: (body: string[] | null, value: string) => void;
  lines: string[];
}

/** Emit the SSRF deny branches into the shared `lines[]`. */
export function emitSsrfBranches(items: SsrfPolicyEndpoint[], d: SsrfEmitDeps): void {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) return a.endpoint.method.localeCompare(b.endpoint.method);
    if (a.endpoint.path !== b.endpoint.path) return a.endpoint.path.localeCompare(b.endpoint.path);
    return a.paramName.localeCompare(b.paramName);
  });

  for (const item of sorted) {
    const method = item.endpoint.method.toUpperCase();
    const pathRegex = d.pathToRegoRegex(item.endpoint.path);
    // OPA-Envoy puts the query string in `:path` (not in a separate `query`
    // field), so we split on '?' rather than reading request.http.query.
    // Match on the path-prefix (before '?') so the static route regex still
    // anchors. Then strip the query segment for url-param extraction.
    const matchClauses = [
      `    input.attributes.request.http.method == ${d.regoString(method)}`,
      `    full_path := input.attributes.request.http.path`,
      `    path_only := split(full_path, "?")[0]`,
      `    regex.match(${d.regoString(pathRegex)}, path_only)`
    ];
    const allowSet = item.domainAllowlist.length > 0
      ? '{' + item.domainAllowlist.map(d.regoString).join(', ') + '}'
      : '{}';
    const urlExtract = item.source === 'query'
      ? [
          `    qs_parts := split(full_path, "?")`,
          `    count(qs_parts) > 1`,
          `    raw_url := qs_parts[1]`,
          `    contains(raw_url, ${d.regoString(item.paramName + '=')})`,
          `    parts := split(raw_url, ${d.regoString(item.paramName + '=')})`,
          `    tail := parts[1]`,
          `    enc_url := split(tail, "&")[0]`
        ]
      : [
          `    body := json.unmarshal(input.attributes.request.http.body)`,
          `    enc_url := body[${d.regoString(item.paramName)}]`
        ];
    // Strip scheme://, take everything up to '/', '?', '#', ':' — no full
    // URL parser, just enough to expose the host for prefix/set membership.
    const hostExtract = [
      `    scheme_split := split(enc_url, "://")`,
      `    after_scheme := scheme_split[count(scheme_split) - 1]`,
      `    host_and_path := split(after_scheme, "/")[0]`,
      `    host_q := split(host_and_path, "?")[0]`,
      `    host_h := split(host_q, "#")[0]`,
      `    host := lower(split(host_h, ":")[0])`
    ];
    d.lines.push(`# ${item.endpoint.method} ${item.endpoint.path} — SSRF url-allowlist on "${item.paramName}" (W19-A)`);

    if (item.domainAllowlist.length > 0) {
      d.pushBranch(
        [
          ...matchClauses,
          ...urlExtract,
          ...hostExtract,
          `    allowed := ${allowSet}`,
          `    not allowed[host]`
        ],
        d.denyLiteral('ssrf')
      );
    }

    if (item.blockPrivateRanges) {
      for (const pat of PRIVATE_HOST_PATTERNS) {
        d.pushBranch(
          [
            ...matchClauses,
            ...urlExtract,
            ...hostExtract,
            `    startswith(host, ${d.regoString(pat)})`
          ],
          d.denyLiteral('ssrf')
        );
      }
    }
    d.lines.push('');
  }
}
