// `lazy mcp` — boot the Cursor MCP server in-process.
//
// Cursor's mcp.json points `command: npx`, `args: [-y, @x-security/cli, mcp]`,
// so this subcommand has to take over stdin/stdout and speak the MCP NDJSON
// protocol. We dynamic-import @x-security/cursor-mcp so that other CLI
// subcommands don't pay the load cost.

export interface RunMcpResult {
  exitCode: number;
}

export async function runMcp(): Promise<RunMcpResult> {
  const mod = (await import('@x-security/cursor-mcp')) as { main?: () => Promise<void>; default?: () => Promise<void> };
  const main = mod.main ?? mod.default;
  if (typeof main !== 'function') {
    throw new Error('@x-security/cursor-mcp did not export a main()/default function');
  }
  await main();
  return { exitCode: 0 };
}
