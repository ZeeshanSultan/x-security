// Embedded Ed25519 public key used by `x-security verify-bundle` when the
// caller does not pass `--public-key <path>`.
//
// TODO(release): Production builds MUST replace this placeholder via
// build-time substitution (e.g. sed/envsubst against the published Ed25519
// signing key). The PEM below is a dev-known-bad value — it is syntactically
// valid SPKI Ed25519 but its private half is publicly known and must never
// be trusted for real release verification. All unit tests bypass this
// constant by passing `--public-key <tmp-path>` with a freshly generated
// keypair.

export const BUNDLE_VERIFY_PUBLIC_KEY: string =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n' +
  '-----END PUBLIC KEY-----\n';
