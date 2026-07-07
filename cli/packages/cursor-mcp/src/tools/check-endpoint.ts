// Look up an existing endpoint analysis from the x-security API. Requires an
// API key — if neither the input nor the WRIT_API_KEY env var carries
// one, the tool returns a soft hint instead of failing, so zero-config installs
// still work for the local-only tools.

import { request } from 'undici';
import type { McpTool } from '../server.js';

export interface CheckEndpointInput {
  method?: string;
  path?: string;
  apiKey?: string;
  // SECURITY (Slice 5 Medium): apiUrl is no longer accepted from per-call
  // input. A malicious MCP client could otherwise pass
  // `apiUrl: "https://attacker.com"` and capture the user's
  // WRIT_API_KEY in the Bearer header. The URL is pinned to env or
  // the documented default.
}

const DEFAULT_API_URL = 'https://usewaf.com';

const inputSchema = {
  type: 'object',
  properties: {
    method: { type: 'string', description: 'HTTP method.' },
    path: { type: 'string', description: 'Route path.' },
    apiKey: { type: 'string', description: 'Override WRIT_API_KEY for this call.' }
  },
  required: ['method', 'path']
} as const;

export interface CheckEndpointResult {
  configured: boolean;
  hint?: string;
  status?: number;
  body?: unknown;
  error?: string;
}

// Indirection so tests can mock the HTTP call without spinning a server.
export type Fetcher = (
  url: string,
  init: { headers: Record<string, string> }
) => Promise<{ statusCode: number; body: unknown }>;

const defaultFetcher: Fetcher = async (url, init) => {
  const res = await request(url, { method: 'GET', headers: init.headers });
  const text = await res.body.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // leave as text
  }
  return { statusCode: res.statusCode, body };
};

export async function checkEndpoint(
  input: CheckEndpointInput,
  fetcher: Fetcher = defaultFetcher
): Promise<CheckEndpointResult> {
  const apiKey = input.apiKey ?? process.env.X_SECURITY_API_KEY ?? process.env.WRIT_API_KEY;
  // apiUrl is pinned to env / default (Slice 5 Medium). Caller-supplied
  // override removed to prevent token capture via attacker-controlled URL.
  const apiUrl = process.env.X_SECURITY_API_URL ?? process.env.WRIT_API_URL ?? DEFAULT_API_URL;

  if (!apiKey) {
    return {
      configured: false,
      hint:
        'WRIT_API_KEY not set — propose-annotation and lint-annotation work offline, ' +
        'but check-endpoint needs an org API key. See https://usewaf.com/docs/cursor.'
    };
  }

  if (!input.method || !input.path) {
    return { configured: true, error: 'method and path are required' };
  }

  const url =
    apiUrl.replace(/\/$/, '') +
    `/v1/endpoints?path=${encodeURIComponent(input.path)}&method=${encodeURIComponent(
      input.method.toUpperCase()
    )}`;

  try {
    const res = await fetcher(url, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'User-Agent': '@x-security/cursor-mcp/0.1.0',
        Accept: 'application/json'
      }
    });
    return { configured: true, status: res.statusCode, body: res.body };
  } catch (e) {
    return { configured: true, error: (e as Error).message };
  }
}

export const checkEndpointTool: McpTool = {
  name: 'x-security/check-endpoint',
  description:
    'Look up an endpoint in the x-security scan history. Returns existing analysis ' +
    '(annotations, OWASP coverage, prior findings) if WRIT_API_KEY is configured.',
  inputSchema,
  handler: async (raw) => {
    const input = (raw ?? {}) as CheckEndpointInput;
    const r = await checkEndpoint(input);
    if (!r.configured) return `not-configured: ${r.hint}\n`;
    if (r.error) return `error: ${r.error}\n`;
    if (r.status && r.status >= 400) {
      return `status: ${r.status}\nbody: ${JSON.stringify(r.body)}\n`;
    }
    return `status: ${r.status}\nbody: ${JSON.stringify(r.body, null, 2)}\n`;
  }
};
