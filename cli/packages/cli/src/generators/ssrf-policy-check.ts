/**
 * Shared spec-hygiene check: when a request.schema parameter declares
 * `type: url` but neither `domainAllowlist` nor `blockPrivateRanges` is set,
 * generators surface a structured warning. Operators may have legitimate
 * reasons to omit SSRF policy (internal-only endpoints), so we WARN, not fail.
 *
 * The warning format is:
 *   [<target>:ssrf-policy-missing] <METHOD> <PATH>: parameter "<name>" ...
 *
 * Wave-10 (W10-9). Born from the vAPI /vapi/serversurfer gap where Coraza-SPOA
 * silently passed through the file:// SSRF attack because the spec never
 * declared a policy.
 */

import type { SpecIR } from '@x-security/core';

export interface SsrfPolicyWarning {
  method: string;
  path: string;
  paramName: string;
  message: string;
}

export function collectSsrfPolicyWarnings(spec: SpecIR, target: string): SsrfPolicyWarning[] {
  const out: SsrfPolicyWarning[] = [];
  for (const ep of spec.endpoints) {
    const schema = ep.policy.request?.schema;
    if (!schema) continue;
    for (const [paramName, ps] of Object.entries(schema)) {
      if (!ps || ps.type !== 'url') continue;
      const hasAllowlist = Array.isArray(ps.domainAllowlist) && ps.domainAllowlist.length > 0;
      const hasBlockPrivate = ps.blockPrivateRanges === true;
      if (hasAllowlist || hasBlockPrivate) continue;
      const message =
        `[${target}:ssrf-policy-missing] ${ep.method} ${ep.path}: parameter "${paramName}" ` +
        `declares type=url without domainAllowlist or blockPrivateRanges. ` +
        `SSRF defense will not be enforced for this endpoint. ` +
        `Add \`request.schema.${paramName}.blockPrivateRanges: true\` and/or ` +
        `\`domainAllowlist: [...]\`.`;
      out.push({ method: ep.method, path: ep.path, paramName, message });
    }
  }
  return out;
}
