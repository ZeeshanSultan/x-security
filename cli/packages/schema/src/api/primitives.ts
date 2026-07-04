// Zod primitives shared by the dashboard API contract.
// Patterns are intentionally strict — see CLAUDE.md Rule D-1 (no soft defaults).
import { z } from 'zod';

export const RuleId = z.string().regex(/^SS-\d{3,4}$/, 'expected SS-NNN or SS-NNNN');

export const OwaspCode = z.enum([
  'API1', 'API2', 'API3', 'API4', 'API5',
  'API6', 'API7', 'API8', 'API9', 'API10',
]);

export const Confidence = z.enum(['HIGH', 'MED', 'LOW']);

export const RuleKind = z.enum([
  'size', 'authz', 'ratelimit', 'cors', 'authn',
  'schema', 'ssrf', 'ip', 'advisory', 'headers',
]);

export const HttpMethod = z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

export const Severity = z.enum(['high', 'med', 'low']);

/** "routes/auth.py:14" — required on every finding (Rule D-3). */
export const FileLine = z
  .string()
  .regex(/^[^\s:]+:\d+$/, 'expected file:line, e.g. routes/auth.py:14');

export const OrgId = z.string().uuid();
export const Iso8601 = z.string().datetime({ offset: true });

export type RuleId = z.infer<typeof RuleId>;
export type OwaspCode = z.infer<typeof OwaspCode>;
export type Confidence = z.infer<typeof Confidence>;
export type RuleKind = z.infer<typeof RuleKind>;
export type HttpMethod = z.infer<typeof HttpMethod>;
export type Severity = z.infer<typeof Severity>;
export type FileLine = z.infer<typeof FileLine>;
export type OrgId = z.infer<typeof OrgId>;
export type Iso8601 = z.infer<typeof Iso8601>;
