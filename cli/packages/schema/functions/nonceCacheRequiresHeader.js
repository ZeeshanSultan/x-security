// v0.5 S-17 Spectral function: `request.signature.nonceCacheTtl` requires
// `nonceHeader` — otherwise the WAF has nowhere to read the nonce from.
// JSON Schema enforces this via if/then; we mirror as a Spectral rule for a
// legible per-endpoint error message.

export default function nonceCacheRequiresHeader(targetVal) {
  if (!targetVal || typeof targetVal !== 'object') return;
  if (targetVal.nonceCacheTtl && !targetVal.nonceHeader) {
    return [
      {
        message: 'request.signature.nonceCacheTtl is set but nonceHeader is missing — the gateway has no place to read the nonce from for replay protection.'
      }
    ];
  }
}
