// v0.5 S-15 Spectral function: `redirectAllowedDomains` is only meaningful when
// the param `type` is 'url'. The schema accepts it on any ParamSchema (to keep
// JSON Schema simple), but lint should warn loudly if it appears on a non-url
// param — that means the policy author thinks they have open-redirect defense
// when they don't.

export default function redirectAllowedDomainsRequiresUrl(targetVal) {
  if (!targetVal || typeof targetVal !== 'object') return;
  const errors = [];
  for (const [name, param] of Object.entries(targetVal)) {
    if (!param || typeof param !== 'object') continue;
    if (Array.isArray(param.redirectAllowedDomains) && param.type !== 'url') {
      errors.push({
        message: `request.schema.${name}.redirectAllowedDomains is only meaningful when type === 'url' (current: type="${param.type ?? '<unset>'}")`,
        path: ['schema', name, 'redirectAllowedDomains']
      });
    }
  }
  return errors.length > 0 ? errors : undefined;
}
