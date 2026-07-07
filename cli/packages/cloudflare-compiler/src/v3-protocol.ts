// v0.3 protocol-specific lowering: graphql, websocket, botProtection.

import type { BotProtection, GraphqlPolicy, WebsocketPolicy, XSecurityPolicy } from '@x-security/schema';
import { and, hasHeader, missingHeader, not, or, parseDurationSeconds } from './expressions.js';
import { escapeStr } from './endpoint.js';
import { decorate, emitWorker, getOverride, noteProvenance, type V3Builder } from './v3-shared.js';

const GRAPHQL_WORKER_TEMPLATE = `// x-security: GraphQL abuse limits (v0.3 graphql.*)
// Worker parses the GraphQL document and enforces depth/complexity/alias/batch limits.
// Drop in graphql-armor or hand-roll an AST walker — Cloudflare WAF cannot parse GraphQL.
export default {
  async fetch(req) {
    if (req.method !== 'POST') return fetch(req);
    const body = await req.clone().json().catch(() => null);
    if (!body) return fetch(req);
    const docs = Array.isArray(body) ? body : [body];
    if (docs.length > PARAMS.batchLimit) return new Response('batch too large', { status: 413 });
    for (const d of docs) {
      const violations = checkLimits(d.query, PARAMS);
      if (violations.length) return new Response(violations.join('; '), { status: 400 });
    }
    return fetch(req);
  }
};`;

const WS_DO_WORKER_TEMPLATE = `// x-security: WebSocket controls (v0.3 websocket.*)
// Run as a Durable Object. Handshake-level origin check is enforceable at the WAF
// (see ws-origin-check rule); per-message size/rate/connection caps live here.
export class WSGuard {
  constructor(state, env) { this.state = state; this.connections = new Map(); }
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('not a ws', { status: 400 });
    if (this.connections.size >= PARAMS.maxConnectionsPerIdentifier) {
      return new Response('too many connections', { status: 429 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    server.addEventListener('message', e => {
      if (typeof e.data === 'string' ? e.data.length > PARAMS.maxMessageSize : e.data.byteLength > PARAMS.maxMessageSize) {
        server.close(1009, 'message too large');
      }
    });
    return new Response(null, { status: 101, webSocket: client });
  }
}`;

const RECAPTCHA_WORKER_TEMPLATE = `// x-security: CAPTCHA siteverify (v0.3 botProtection.provider in {recaptcha,hcaptcha})
export default {
  async fetch(req, env) {
    const token = req.headers.get('cf-captcha-token') || (await req.clone().formData()).get('captcha');
    if (!token) return new Response('missing captcha', { status: 401 });
    const verify = await fetch(PARAMS.verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: env[PARAMS.secretBinding], response: token })
    });
    const out = await verify.json();
    if (!out.success || (out.score !== undefined && out.score < PARAMS.threshold)) {
      if (PARAMS.mode === 'enforce') return new Response('captcha failed', { status: 401 });
    }
    return fetch(req);
  }
};`;

export function compileV3Protocol(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  compileGraphql(b, policy);
  compileWebsocket(b, policy, baseMatch);
  compileBotProtectionV3(b, policy, baseMatch);
}

function compileGraphql(b: V3Builder, policy: XSecurityPolicy): void {
  const gql = policy.graphql;
  if (!gql) return;
  emitWorker(b, {
    field: 'graphql',
    kind: 'graphql-limits',
    description: 'GraphQL abuse limits: depth / complexity / alias / batch / introspection / op-allowlist',
    template: GRAPHQL_WORKER_TEMPLATE,
    params: {
      maxDepth: gql.maxDepth ?? null,
      maxComplexity: gql.maxComplexity ?? null,
      maxAliases: gql.maxAliases ?? null,
      batchLimit: gql.batchLimit ?? 1,
      disableIntrospection: gql.disableIntrospection ?? false,
      allowedOperations: gql.allowedOperations ?? ['query', 'mutation', 'subscription']
    } satisfies Record<string, unknown>
  });
  noteProvenance(
    b,
    'graphql',
    'Cloudflare WAF does not parse GraphQL. Emitted Worker artifact (graphql-armor-style AST walk).',
    'override-only',
    getOverride(b, 'graphql')
  );
  if (graphqlHasUnsupportedShape(gql)) {
    // Surface every requested sub-field so the UI can show what landed and what didn't.
    for (const k of GRAPHQL_FIELDS) {
      if (gql[k] === undefined) continue;
      noteProvenance(b, `graphql.${k}`, `Subsumed by graphql Worker artifact.`, 'override-only');
    }
  }
}

const GRAPHQL_FIELDS: (keyof GraphqlPolicy)[] = [
  'maxDepth', 'maxComplexity', 'maxAliases', 'batchLimit', 'disableIntrospection', 'allowedOperations'
];

function graphqlHasUnsupportedShape(g: GraphqlPolicy): boolean {
  return GRAPHQL_FIELDS.some(k => g[k] !== undefined);
}

function compileWebsocket(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const ws = policy.websocket;
  if (!ws) return;
  // Handshake-level origin check — Wirefilter on Upgrade: websocket requests.
  const allowed = ws.allowedOrigins.map(o => `"${escapeStr(o)}"`).join(' ');
  if (allowed) {
    b.custom.push(decorate(b, {
      kind: 'ws-origin-check',
      description: `WebSocket upgrade: reject if Origin not in [${ws.allowedOrigins.join(', ')}]`,
      expression: and(
        baseMatch,
        `http.request.headers["upgrade"][0] eq "websocket"`,
        or(
          missingHeader('origin'),
          not(`http.request.headers["origin"][0] in {${allowed}}`)
        )
      ),
      action: 'block',
      sourceField: 'websocket.allowedOrigins',
      confidence: 'HIGH'
    }));
  }

  // Per-message size / rate / connection-cap — Durable Object only.
  if (ws.maxMessageSize || ws.messageRateLimit || ws.maxConnectionsPerIdentifier || ws.idleTimeout) {
    const params: Record<string, unknown> = {
      allowedOrigins: ws.allowedOrigins,
      maxMessageSize: ws.maxMessageSize ?? null,
      maxConnectionsPerIdentifier: ws.maxConnectionsPerIdentifier ?? null
    };
    if (ws.idleTimeout) {
      try { params.idleTimeoutSeconds = parseDurationSeconds(ws.idleTimeout); }
      catch { params.idleTimeoutSeconds = null; }
    }
    if (ws.messageRateLimit) {
      params.messageRateLimit = {
        messages: ws.messageRateLimit.messages,
        windowSeconds: (() => { try { return parseDurationSeconds(ws.messageRateLimit.window); } catch { return null; } })()
      };
    }
    emitWorker(b, {
      field: 'websocket',
      kind: 'websocket-do-guard',
      description: 'WebSocket per-message size/rate caps + connection cap + idle timeout',
      template: WS_DO_WORKER_TEMPLATE,
      params
    });
    noteProvenance(
      b,
      'websocket',
      'Per-message and per-connection WS limits require a Durable Object; emitted Worker artifact.',
      'partial',
      getOverride(b, 'websocket')
    );
  }
}

function compileBotProtectionV3(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  // v0.3 botProtection (typed object). Distinct from the legacy `botProtection: true`
  // toggle handled in compile.ts. If the policy uses the new typed shape, prefer that.
  const bp = policy.botProtection;
  if (!bp || typeof bp !== 'object' || (bp as unknown) === true) return;
  const typed = bp as BotProtection;
  if (typed.provider === 'turnstile') {
    // Turnstile is native — but the WAF rule depends on the client emitting the
    // cf-turnstile-response cookie/header. Lower as a Wirefilter rule that
    // requires the header for state-changing methods. Full verification of the
    // token happens at Cloudflare's edge automatically when a Turnstile widget
    // is bound to the zone.
    if (typed.mode === 'enforce') {
      b.custom.push(decorate(b, {
        kind: 'bot-turnstile',
        description: 'Turnstile: require cf-turnstile-response header on POST/PUT/PATCH/DELETE',
        expression: and(
          baseMatch,
          '(http.request.method in {"POST" "PUT" "PATCH" "DELETE"})',
          missingHeader('cf-turnstile-response')
        ),
        action: 'managed_challenge',
        sourceField: 'botProtection.provider=turnstile',
        confidence: 'HIGH'
      }));
    }
    noteProvenance(
      b,
      'botProtection',
      `Turnstile native integration emitted (mode=${typed.mode}). Bind your Turnstile site key in the zone settings.`,
      'full',
      getOverride(b, 'botProtection')
    );
    return;
  }
  // recaptcha / hcaptcha → Worker
  const verifyUrl =
    typed.provider === 'recaptcha' ? 'https://www.google.com/recaptcha/api/siteverify' :
    'https://hcaptcha.com/siteverify';
  emitWorker(b, {
    field: 'botProtection',
    kind: `bot-${typed.provider}`,
    description: `${typed.provider} siteverify (mode=${typed.mode}, threshold=${typed.threshold ?? 0.5})`,
    template: RECAPTCHA_WORKER_TEMPLATE,
    params: {
      provider: typed.provider,
      verifyUrl,
      secretBinding: derive(typed.secretRef),
      threshold: typed.threshold ?? 0.5,
      mode: typed.mode
    }
  });
  noteProvenance(
    b,
    'botProtection',
    `${typed.provider} requires Worker-side siteverify; emitted artifact.`,
    'override-only',
    getOverride(b, 'botProtection')
  );
}

function derive(ref: string): string {
  const m = /\$\{([A-Z0-9_]+)\}/.exec(ref);
  if (m) return m[1]!;
  return ref.replace(/^\$vault\./, 'vault_').replace(/[^A-Za-z0-9_]/g, '_').toUpperCase();
}

// `hasHeader` re-export to keep the imports tidy across files that might want it.
export { hasHeader };
