# @x-security/cursor-mcp

A minimal [Model Context Protocol](https://modelcontextprotocol.io/) server
that exposes Writ's annotation, linting, and endpoint-check tools to
Cursor (and any other MCP-compatible IDE).

Transport: stdio NDJSON. JSON-RPC 2.0. No SDK dependency — see
`src/server.ts` and `src/transport.ts`.

## Tools

- `propose-annotation` — propose an `x-security` annotation for a route.
- `lint-annotation` — lint an existing annotation against schema + best practices.
- `check-endpoint` — fetch a route's deployed Writ rule state.

## Configuration

The MCP server reads its API base URL from `WRIT_API_URL` (defaults
to the SaaS endpoint). The API URL is **pinned to the environment** — it
cannot be overridden per-tool-call. See `src/tools/check-endpoint.ts`.

## Security

### Run under an isolated parent process (PR-M8)

Cursor's own MCP runner is the supported deployment target. If you embed
this server under any other parent process, treat the parent as part of
your trust boundary:

- **stdio fd capture**: the MCP transport is plain NDJSON over stdin/stdout.
  Any parent that shares its stdio file descriptors with sibling processes
  (or that runs untrusted plugins in the same process) can read or inject
  MCP traffic — including the Writ API token that this server holds
  in memory once it has authenticated.
- **Process isolation**: spawn the MCP server in its own OS process with
  its own stdio handles. Do not multiplex it with other tooling. On macOS
  / Linux, ensure no `setuid` or shared-mailbox tricks expose the pipes.
- **Token scoping**: the `WRIT_API_URL` is pinned to env. Caller-
  supplied URLs are deliberately rejected (see
  `src/tools/check-endpoint.ts` — Slice 5 Medium) so a compromised
  prompt cannot redirect the token to an attacker-controlled endpoint.
  An isolated parent process is the second half of that defence: pinning
  the URL is moot if a sibling process can read the token off the pipe
  before it is ever sent.
- **No remote MCP**: this server has no built-in network listener. It
  speaks stdio only. Do not wrap it in a TCP/HTTP bridge unless you
  understand the implications above.

If you are deploying this server in CI or in a multi-tenant environment,
prefer one MCP process per tenant, not one shared MCP server with
multiplexed auth.

## Development

```bash
pnpm --filter @x-security/cursor-mcp build
pnpm --filter @x-security/cursor-mcp test
```
