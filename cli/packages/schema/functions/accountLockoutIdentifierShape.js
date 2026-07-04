// v0.5 S-12 Spectral function: warn if `accountLockout.identifier` doesn't look
// like a per-username key. The typical mistake is to set it to `ip`, which makes
// the policy a per-IP rate limit, not credential-stuffing defense.
//
// Heuristic: the identifier should reference a header that names a user
// (X-Username, X-User-Id, ...) or a body field (request.body.email, .username).

const USER_HINTS = /(user|username|email|account|login)/i;

export default function accountLockoutIdentifierShape(targetVal) {
  if (!targetVal || typeof targetVal !== 'object') return;
  const id = targetVal.identifier;
  if (typeof id !== 'string') return;

  if (USER_HINTS.test(id)) return; // looks reasonable

  return [
    {
      message: `accountLockout.identifier="${id}" doesn't look like a per-user key. Credential-stuffing defense requires grouping attempts by username/email, not by IP. Consider 'header:X-Username' or 'request.body.email'.`
    }
  ];
}
