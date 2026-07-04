// Rules-based proposer: given a route signature, emit a sensible x-security YAML
// block matching the @writ/schema shape. No LLM calls — this runs on the
// developer's machine in <1ms so the agent can pick it up while diffing.

import type { McpTool } from '../server.js';

export interface ProposeInput {
  method?: string;
  path?: string;
  description?: string;
  bodySchema?: Record<string, unknown>;
}

const inputSchema = {
  type: 'object',
  properties: {
    method: { type: 'string', description: 'HTTP method (GET, POST, ...).' },
    path: { type: 'string', description: 'Route path, e.g. /users/{id}.' },
    description: { type: 'string', description: 'Optional natural-language description.' },
    bodySchema: { type: 'object', description: 'Optional request body JSON schema.' }
  },
  required: ['method', 'path']
} as const;

interface Proposal {
  yaml: string;
  rationale: string[];
}

export function propose(input: ProposeInput): Proposal {
  const method = (input.method ?? 'GET').toUpperCase();
  const path = input.path ?? '/';
  const desc = (input.description ?? '').toLowerCase();
  const lower = path.toLowerCase();
  const rationale: string[] = [];

  // --- Authentication ---------------------------------------------------
  const isAuthEndpoint =
    /\/(login|signin|signup|register|auth|token|password[-_/]?reset|forgot[-_/]?password)\b/.test(
      lower
    ) || desc.includes('login') || desc.includes('sign in') || desc.includes('signup');
  const isAdmin = /\/admin(\/|$)/.test(lower) || desc.includes('admin');
  const isPublicRead = method === 'GET' && /\/(health|status|ping|version|public)\b/.test(lower);

  const auth: Record<string, unknown> = {};
  if (isAuthEndpoint) {
    auth.type = 'none';
    rationale.push('auth endpoint — no bearer required to obtain credentials');
  } else if (isPublicRead) {
    auth.type = 'none';
    rationale.push('public read endpoint — no auth required');
  } else {
    auth.type = 'bearer-jwt';
    rationale.push('non-public endpoint — requires bearer JWT');
    if (isAdmin) {
      auth.scopes = ['admin'];
      rationale.push('path contains /admin — admin scope required');
    }
  }

  // --- Rate limit -------------------------------------------------------
  let rate: { requests: number; window: string; identifier: string };
  if (isAuthEndpoint) {
    rate = { requests: 5, window: '1m', identifier: 'ip' };
    rationale.push('auth endpoint — tight 5/min per-IP rate limit to deter brute force');
  } else if (isAdmin) {
    rate = { requests: 30, window: '1m', identifier: 'user-id' };
    rationale.push('admin endpoint — modest 30/min per-user rate limit');
  } else if (method === 'GET') {
    rate = { requests: 120, window: '1m', identifier: 'user-id' };
    rationale.push('read endpoint — 120/min per-user');
  } else {
    rate = { requests: 60, window: '1m', identifier: 'user-id' };
    rationale.push('write endpoint — 60/min per-user');
  }

  // --- Request size -----------------------------------------------------
  const isUpload = /\/(upload|attach|files?|media|images?)\b/.test(lower) || desc.includes('upload');
  const maxBody = isUpload ? '10MB' : '32KB';
  if (isUpload) rationale.push('upload endpoint — 10MB body cap');

  // --- IDOR hint --------------------------------------------------------
  const hasIdParam = /\{[^}]+\}/.test(path) || /:[A-Za-z_][\w]*/.test(path);
  if (hasIdParam) {
    rationale.push(
      'path has a resource identifier — add authorization rules to prevent IDOR (API1:2023)'
    );
  }

  // --- Build YAML -------------------------------------------------------
  const lines: string[] = ['x-security:'];
  lines.push('  authentication:');
  lines.push(`    type: ${auth.type as string}`);
  if (Array.isArray(auth.scopes)) {
    lines.push(`    scopes: [${(auth.scopes as string[]).map((s) => JSON.stringify(s)).join(', ')}]`);
  }
  if (auth.type !== 'none') {
    lines.push('    mitigates: [API2:2023]');
  }

  if (hasIdParam) {
    lines.push('  authorization:');
    lines.push('    type: rule-based');
    lines.push('    rules:');
    lines.push('      - field: resource.owner_id');
    lines.push('        operator: equals');
    lines.push('        value: ${user.id}');
    lines.push('    mitigates: [API1:2023]');
  }

  lines.push('  rateLimit:');
  lines.push(`    requests: ${rate.requests}`);
  lines.push(`    window: "${rate.window}"`);
  lines.push(`    identifier: ${rate.identifier}`);
  lines.push('    mitigates: [API4:2023]');

  lines.push('  request:');
  lines.push(`    maxBodySize: "${maxBody}"`);
  if (isUpload) {
    lines.push('    contentType: [multipart/form-data]');
  }

  return { yaml: lines.join('\n') + '\n', rationale };
}

export const proposeAnnotationTool: McpTool = {
  name: 'writ/propose-annotation',
  description:
    'Propose an x-security block for a route signature. Pure heuristic; no network calls. ' +
    'Returns YAML the agent can paste under the operation in its OpenAPI spec.',
  inputSchema,
  handler: (raw) => {
    const input = (raw ?? {}) as ProposeInput;
    if (!input.method || !input.path) {
      throw new Error('method and path are required');
    }
    const { yaml, rationale } = propose(input);
    return (
      `# Proposed x-security for ${input.method.toUpperCase()} ${input.path}\n` +
      `# Rationale:\n` +
      rationale.map((r) => `#   - ${r}`).join('\n') +
      `\n\n${yaml}`
    );
  }
};
