// Minimal Model Context Protocol server.
// Transport-agnostic: callers pump JSON-RPC 2.0 messages in via handleMessage()
// and ship the returned response back over whatever transport they like
// (stdio NDJSON, in our case — see ./transport.ts).
//
// Implements just what Cursor needs: initialize, tools/list, tools/call,
// and the notifications/initialized notification (which expects no response).
// See https://modelcontextprotocol.io/ — but we intentionally don't depend on
// any MCP SDK; the slice we need is tiny.

import { proposeAnnotationTool } from './tools/propose-annotation.js';
import { lintAnnotationTool } from './tools/lint-annotation.js';
import { checkEndpointTool } from './tools/check-endpoint.js';

export const PROTOCOL_VERSION = '2024-11-05';
export const SERVER_NAME = 'writ';
export const SERVER_VERSION = '0.1.0';

// JSON-RPC 2.0 error codes we use.
export const JsonRpcErrors = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603
} as const;

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: number | string | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: number | string | null;
  result: unknown;
}

export interface JsonRpcError {
  jsonrpc: '2.0';
  id: number | string | null;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcError;

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: unknown) => Promise<string> | string;
}

const TOOLS: McpTool[] = [proposeAnnotationTool, lintAnnotationTool, checkEndpointTool];

export function listToolNames(): string[] {
  return TOOLS.map((t) => t.name);
}

function ok(id: number | string | null, result: unknown): JsonRpcSuccess {
  return { jsonrpc: '2.0', id, result };
}

function err(id: number | string | null, code: number, message: string): JsonRpcError {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/**
 * Handle a single decoded JSON-RPC message.
 * Returns `null` for notifications (which have no `id` and expect no reply).
 */
export async function handleMessage(msg: JsonRpcRequest): Promise<JsonRpcResponse | null> {
  // Notification — no `id`, no response.
  const isNotification = msg.id === undefined;
  const id = msg.id ?? null;

  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    if (isNotification) return null;
    return err(id, JsonRpcErrors.InvalidRequest, 'invalid JSON-RPC 2.0 request');
  }

  try {
    switch (msg.method) {
      case 'initialize':
        return ok(id, {
          protocolVersion: PROTOCOL_VERSION,
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          capabilities: { tools: {} }
        });

      case 'notifications/initialized':
      case 'initialized':
        // No reply expected for notifications.
        return null;

      case 'tools/list':
        return ok(id, {
          tools: TOOLS.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema
          }))
        });

      case 'tools/call': {
        const params = (msg.params ?? {}) as { name?: string; arguments?: unknown };
        const tool = TOOLS.find((t) => t.name === params.name);
        if (!tool) {
          return err(id, JsonRpcErrors.MethodNotFound, `unknown tool: ${String(params.name)}`);
        }
        const text = await tool.handler(params.arguments ?? {});
        return ok(id, { content: [{ type: 'text', text }] });
      }

      case 'ping':
        return ok(id, {});

      default:
        if (isNotification) return null;
        return err(id, JsonRpcErrors.MethodNotFound, `unknown method: ${msg.method}`);
    }
  } catch (e) {
    if (isNotification) return null;
    return err(id, JsonRpcErrors.InternalError, (e as Error).message);
  }
}
