#!/usr/bin/env node
// Binary entry. Cursor invokes this via `npx -y @x-security/cli mcp`, which
// in turn dynamic-imports and calls main(). We also expose main() as the
// default export so the CLI wrapper can run us in-process without forking.

import { runStdio } from './transport.js';

export { handleMessage, listToolNames, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION } from './server.js';
export { handleLine, runStdio } from './transport.js';

export async function main(): Promise<void> {
  await runStdio();
}

export default main;

// When run directly as a binary, kick off stdio immediately.
// import.meta.url comparison is the canonical "is this the entry module" check.
const isDirectRun =
  import.meta.url === `file://${process.argv[1] ?? ''}` ||
  process.argv[1]?.endsWith('cursor-mcp/dist/index.js') === true ||
  process.argv[1]?.endsWith('x-security-cursor-mcp') === true;

if (isDirectRun) {
  main().catch((e: unknown) => {
    process.stderr.write(`cursor-mcp: fatal: ${(e as Error).message}\n`);
    process.exit(1);
  });
}
