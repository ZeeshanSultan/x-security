// NDJSON-over-stdio transport. Cursor (like most MCP hosts) frames each
// JSON-RPC message as a single line of JSON on stdin and expects responses
// the same way on stdout.
//
// Everything user-visible (logs, errors) MUST go to stderr — stdout is
// reserved for the protocol.

import { handleMessage, type JsonRpcRequest, type JsonRpcResponse } from './server.js';

/**
 * Pure function: take one NDJSON line, return the encoded response line
 * (with a trailing newline), or null for notifications / unparseable noise.
 *
 * Exposed for unit tests — keeps the stdio plumbing thin.
 */
export async function handleLine(line: string): Promise<string | null> {
  const trimmed = line.trim();
  if (!trimmed) return null;

  let msg: JsonRpcRequest;
  try {
    msg = JSON.parse(trimmed) as JsonRpcRequest;
  } catch (e) {
    const errResp: JsonRpcResponse = {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: `parse error: ${(e as Error).message}` }
    };
    return JSON.stringify(errResp) + '\n';
  }

  const resp = await handleMessage(msg);
  if (resp === null) return null;
  return JSON.stringify(resp) + '\n';
}

/**
 * Pump stdin → handleLine → stdout. Resolves when stdin closes.
 */
export async function runStdio(
  stdin: NodeJS.ReadableStream = process.stdin,
  stdout: NodeJS.WritableStream = process.stdout
): Promise<void> {
  stdin.setEncoding?.('utf8');

  let buffer = '';

  return new Promise<void>((resolve, reject) => {
    const onData = (chunk: string | Buffer) => {
      buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let nl = buffer.indexOf('\n');
      while (nl !== -1) {
        const line = buffer.slice(0, nl);
        buffer = buffer.slice(nl + 1);
        // Fire-and-await per line to preserve ordering.
        // eslint-disable-next-line @typescript-eslint/no-floating-promises
        handleLine(line)
          .then((out) => {
            if (out !== null) stdout.write(out);
          })
          .catch((e: unknown) => {
            process.stderr.write(`cursor-mcp: handler crashed: ${(e as Error).message}\n`);
          });
        nl = buffer.indexOf('\n');
      }
    };

    stdin.on('data', onData);
    stdin.once('end', () => {
      // Drain any trailing partial line.
      if (buffer.trim()) {
        handleLine(buffer)
          .then((out) => {
            if (out !== null) stdout.write(out);
            resolve();
          })
          .catch(reject);
      } else {
        resolve();
      }
    });
    stdin.once('error', reject);
  });
}
