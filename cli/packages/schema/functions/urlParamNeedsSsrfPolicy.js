// W10-9 Spectral function: when a param under request.schema declares
// `type: url`, the spec MUST also declare `domainAllowlist` or
// `blockPrivateRanges` for the SSRF defense to actually be emitted by
// downstream generators (kong, coraza, envoy, ...).
//
// Severity is warn — operators may have legitimate reasons to omit (internal-
// only endpoints) — but the lint output makes the gap visible.
//
// Receives the `x-security.request` object; iterates request.schema entries.
//
// Born from the vAPI /vapi/serversurfer wave-9 incident: Coraza-SPOA silently
// passed through a file:// SSRF attack because the spec lacked
// `blockPrivateRanges`. See REPORT-v10-corrected.

export default function urlParamNeedsSsrfPolicy(targetVal) {
  if (!targetVal || typeof targetVal !== 'object') return;
  const schema = targetVal.schema;
  if (!schema || typeof schema !== 'object') return;
  const errors = [];
  for (const [name, param] of Object.entries(schema)) {
    if (!param || typeof param !== 'object') continue;
    if (param.type !== 'url') continue;
    const hasAllowlist = Array.isArray(param.domainAllowlist) && param.domainAllowlist.length > 0;
    const hasBlockPrivate = param.blockPrivateRanges === true;
    if (hasAllowlist || hasBlockPrivate) continue;
    errors.push({
      message: `request.schema.${name} declares type=url without domainAllowlist or blockPrivateRanges — SSRF defense will not be enforced. Add \`blockPrivateRanges: true\` and/or \`domainAllowlist: [...]\`.`,
      path: ['schema', name]
    });
  }
  return errors.length > 0 ? errors : undefined;
}
