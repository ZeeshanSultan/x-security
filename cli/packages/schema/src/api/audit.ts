// Append-only audit events — hash-chained per the page mock (digest field).
// NDJSON wire format = one AuditEvent per line.
import { z } from 'zod';
import { RuleId } from './primitives.js';

export const AuditKind = z.enum(['promote', 'rollback', 'scan', 'deny']);
export type AuditKind = z.infer<typeof AuditKind>;

export const AuditEvent = z.object({
  id: z.string().uuid(),
  ts: z.string().datetime({ offset: true }),
  kind: AuditKind,
  actor: z.string().min(1),
  desc: z.string().min(1),
  repo: z.string().min(1),
  rule_id: z.union([RuleId, z.literal('—')]),
  digest: z.string().regex(/^sha256:[a-f0-9]+/),
});
export type AuditEvent = z.infer<typeof AuditEvent>;
