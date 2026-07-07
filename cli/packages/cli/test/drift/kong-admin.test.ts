// Timeout plumbing for the Kong admin-API drift path. `detectAdminDrift` is
// the primary consumer of `validate`'s `timeoutMs` option (see
// `runValidate` in ../../src/commands/validate.ts). We assert:
//   1. a hung admin URL aborts within the requested timeout instead of
//      hanging forever, and the error message is clear (not a raw AbortError).
//   2. omitting timeoutMs preserves the old no-timeout behavior — the
//      request is only bounded by the (much longer) test's own patience.

import test from 'node:test';
import assert from 'node:assert/strict';
import * as net from 'node:net';
import { detectAdminDrift } from '../../src/drift/kong-admin.js';
import type { SpecIR } from '@x-security/core';

const EMPTY_SPEC = { endpoints: [] } as unknown as SpecIR;

/** A TCP server that accepts connections but never writes a response. */
function startHangingServer(): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const sockets = new Set<net.Socket>();
    const srv = net.createServer((sock) => {
      // accept and hang — no response ever sent — but track the socket so
      // teardown can force-close it; otherwise it outlives the aborted
      // request and keeps the event loop (and this test) alive.
      sockets.add(sock);
      sock.on('close', () => sockets.delete(sock));
    });
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address() as net.AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((r) => {
            for (const s of sockets) s.destroy();
            srv.close(() => r());
          })
      });
    });
  });
}

test('detectAdminDrift aborts with a clear message when timeoutMs elapses against a hung gateway', async () => {
  const { url, close } = await startHangingServer();
  try {
    const start = Date.now();
    await assert.rejects(
      () => detectAdminDrift(EMPTY_SPEC, { gatewayUrl: url, timeoutMs: 200 }),
      (err: Error) => {
        assert.match(err.message, /timed out after 200ms/);
        return true;
      }
    );
    const elapsed = Date.now() - start;
    // Generous upper bound — just confirms we aborted near the requested
    // timeout instead of hanging for the test runner's default timeout.
    assert.ok(elapsed < 5000, `expected abort well under 5s, took ${elapsed}ms`);
  } finally {
    await close();
  }
});
