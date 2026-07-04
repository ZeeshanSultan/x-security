// Public API for programmatic use.
export { runGenerate } from './commands/generate.js';
export { runValidate } from './commands/validate.js';
export { runTest } from './commands/test.js';
export { runReport } from './commands/report.js';
export { runDiff } from './commands/diff.js';
export { runInit } from './commands/init.js';
export { runMcp } from './commands/mcp.js';
export { runRoutes } from './commands/detect/routes.js';
export { runVerify } from './commands/detect/verify.js';
export { runCompile } from './commands/detect/compile.js';
export { runAudit } from './commands/detect/audit.js';
export { runEmit } from './commands/detect/emit.js';
export {
  runPush,
  PushError,
  resolveApiUrl,
  resolveToken,
  normalizeRemoteUrl,
  DEFAULT_API_URL,
} from './commands/detect/push.js';
export type { PushPayload, PushResult, PushImportResponse, Poster } from './commands/detect/push.js';
export { persistPolicy } from './commands/detect/store.js';
export { loadGenerator, listAvailableTargets, KNOWN_TARGETS, isKnownTarget } from './registry.js';
export type { TargetName } from './registry.js';
export * from './reporters/types.js';
