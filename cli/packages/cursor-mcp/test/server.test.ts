import test from 'node:test';
import assert from 'node:assert/strict';
import {
  handleMessage,
  listToolNames,
  PROTOCOL_VERSION,
  SERVER_NAME,
  SERVER_VERSION
} from '../src/server.js';
import { handleLine } from '../src/transport.js';

test('initialize returns protocol version 2024-11-05 and serverInfo', async () => {
  const resp = await handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize' });
  assert.ok(resp && 'result' in resp);
  const r = resp.result as Record<string, unknown>;
  assert.equal(r.protocolVersion, PROTOCOL_VERSION);
  assert.equal(PROTOCOL_VERSION, '2024-11-05');
  assert.deepEqual(r.serverInfo, { name: SERVER_NAME, version: SERVER_VERSION });
  assert.ok(r.capabilities);
});

test('tools/list advertises exactly the 3 Writ tools', async () => {
  const resp = await handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.ok(resp && 'result' in resp);
  const tools = (resp.result as { tools: { name: string }[] }).tools;
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    'writ/check-endpoint',
    'writ/lint-annotation',
    'writ/propose-annotation'
  ]);
  assert.deepEqual(listToolNames().sort(), names);
  for (const t of tools) {
    assert.ok((t as { description: string }).description.length > 0);
    assert.ok((t as { inputSchema: object }).inputSchema);
  }
});

test('tools/call with unknown tool returns JSON-RPC -32601', async () => {
  const resp = await handleMessage({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'does/not/exist', arguments: {} }
  });
  assert.ok(resp && 'error' in resp);
  assert.equal(resp.error.code, -32601);
  assert.match(resp.error.message, /does\/not\/exist/);
});

test('unknown method returns -32601', async () => {
  const resp = await handleMessage({ jsonrpc: '2.0', id: 4, method: 'nope/nope' });
  assert.ok(resp && 'error' in resp);
  assert.equal(resp.error.code, -32601);
});

test('notifications/initialized returns no response', async () => {
  const resp = await handleMessage({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(resp, null);
});

test('handleLine: garbage input emits parse error response', async () => {
  const line = await handleLine('this is not json');
  assert.ok(line);
  const parsed = JSON.parse(line!);
  assert.equal(parsed.error.code, -32700);
});

test('handleLine: empty line returns null', async () => {
  assert.equal(await handleLine(''), null);
  assert.equal(await handleLine('   \n'), null);
});

test('handleLine: well-formed initialize round-trips', async () => {
  const line = await handleLine(
    JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'initialize' })
  );
  assert.ok(line);
  const parsed = JSON.parse(line!);
  assert.equal(parsed.id, 99);
  assert.equal(parsed.result.protocolVersion, '2024-11-05');
});
