// Single pino redact config. Every Fastify/worker bootstrap passes
// `redactConfig` to `pino({ redact })` so that any structured field that
// could plausibly carry a secret is replaced before serialisation.
//
// Why centralised: per-service redact lists drift. Audit found the github-app
// had no `redact` at all (`{err}` logs can spill installation tokens via
// nested `err.response.config.headers.authorization`), the notifier-worker
// logged Slack webhook URLs in error paths, and the LLM provider error
// stack-traces could surface API keys. One config closes all three.
//
// Paths use pino's bracket-and-dot syntax. `*` matches one segment;
// `[*]` matches array indices. We err on the side of over-redacting — the
// cost of an extra `[Redacted]` in a log line is tiny vs leaked credentials.

const COMMON_TOKEN_FIELDS: string[] = [
  // Direct token fields
  "*.token",
  "*.apiKey",
  "*.api_key",
  "*.accessToken",
  "*.access_token",
  "*.refreshToken",
  "*.refresh_token",
  "*.installationToken",
  "*.encrypted_token",
  "*.encryptedToken",
  "*.password",
  "*.passwd",
  "*.secret",
  "*.clientSecret",
  "*.client_secret",
  "*.privateKey",
  "*.private_key",
  // Common nested locations
  "token",
  "apiKey",
  "api_key",
  "accessToken",
  "access_token",
  "password",
  "secret",
  "clientSecret",
  "client_secret",
];

const HEADER_FIELDS: string[] = [
  // axios-shaped / undici-shaped error objects
  "*.headers.authorization",
  "*.headers.Authorization",
  "*.headers.cookie",
  "*.headers.Cookie",
  "*.headers['x-api-key']",
  "*.headers['x-auth-token']",
  "*.headers['x-github-token']",
  "*.headers['x-csrf-token']",
  "*.headers['proxy-authorization']",
  "*.headers['set-cookie']",
  // Deep-nested (request → headers, config.headers, response.config.headers)
  "*.request.headers.authorization",
  "*.request.headers.cookie",
  "*.config.headers.authorization",
  "*.config.headers.Authorization",
  "*.config.headers.cookie",
  "*.response.config.headers.authorization",
  "*.response.headers['set-cookie']",
  // Top-level Fastify request shape
  "headers.authorization",
  "headers.cookie",
  "headers['set-cookie']",
  "headers['x-api-key']",
];

const SERVICE_SPECIFIC: string[] = [
  // Slack
  "*.slack_webhook_url",
  "*.slackWebhookUrl",
  "*.webhookUrl",
  // GitHub
  "*.encrypted_token", // github-app's installation-token-at-rest
  // Cloudflare
  "*.cloudflare_api_token",
  "*.cloudflareApiToken",
  "*.api_token_enc",
  "*.apiTokenEnc",
  // AWS
  "*.external_id",
  "*.externalId",
  "*.SecretAccessKey",
  "*.SessionToken",
  // OAuth at rest
  "*.access_token_enc",
  "*.accessTokenEnc",
];

/**
 * Combined paths to redact across Writ services. Pass directly as
 * `pino({ redact: redactConfig })` or as `pino({ redact: { paths: ..., censor: ... } })`.
 */
export const REDACT_PATHS: readonly string[] = Object.freeze([
  ...COMMON_TOKEN_FIELDS,
  ...HEADER_FIELDS,
  ...SERVICE_SPECIFIC,
]);

/** Ready-to-spread pino redact option. */
export const redactConfig = {
  paths: REDACT_PATHS as string[],
  censor: "[Redacted]",
  remove: false,
} as const;

/**
 * Lightweight string scrubber for free-form text (e.g. an error message that
 * embeds a URL like `https://hooks.slack.com/services/T.../B.../xxxxxxxx`).
 * Use this for the rare log message that interpolates secrets into a string
 * that pino's path-based redactor can't see (i.e. inside a `.message` field).
 *
 * Returns a new string with known credential shapes replaced by "[Redacted]".
 */
export function scrubString(s: string): string {
  if (!s) return s;
  return (
    s
      // Slack webhook secret (last path segment of /services/T/B/xxxxxxxxxxxx).
      .replace(
        /\bhttps?:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
        "[Redacted Slack webhook]",
      )
      // Bearer tokens in error strings.
      .replace(/\b(?:Bearer|bearer)\s+[A-Za-z0-9._\-+/=]{12,}/g, "Bearer [Redacted]")
      // GitHub installation/PAT/fine-grained.
      .replace(/\bghs_[A-Za-z0-9]{30,}/g, "[Redacted gh token]")
      .replace(/\bghp_[A-Za-z0-9]{30,}/g, "[Redacted gh token]")
      .replace(/\bgithub_pat_[A-Za-z0-9_]{30,}/g, "[Redacted gh token]")
      // Anthropic + OpenAI prefixed keys.
      .replace(/\bsk-ant-[A-Za-z0-9_\-]{20,}/g, "[Redacted anthropic key]")
      .replace(/\bsk-[A-Za-z0-9]{20,}/g, "[Redacted openai key]")
      // Writ internal key prefix
      .replace(/\bsk_session_[A-Za-z0-9]{20,}/g, "[Redacted session key]")
      .replace(/\bsk_dev_[A-Za-z0-9]{20,}/g, "[Redacted dev key]")
  );
}
