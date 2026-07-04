// Attack runs + per-finding records. Finding.cite is REQUIRED (Rule D-3).
import { z } from 'zod';
import { FileLine, OwaspCode } from './primitives.js';

export const AttackStatus = z.enum(['pass', 'fail', 'running', 'queued']);
export const FindingState = z.enum(['blocked', 'leaked', 'advisory']);

export const AttackRun = z.object({
  id: z.string().regex(/^AR-\d{4,}$/),
  repo: z.string().min(1),
  suite: z.string().min(1),
  triggered: z.string().min(1),
  started: z.string().min(1),
  duration: z.string().min(1),
  total: z.number().int().nonnegative(),
  blocked: z.number().int().nonnegative(),
  leaked: z.number().int().nonnegative(),
  fail: z.number().int().nonnegative(),
  rate: z.number().min(0).max(100),
  status: AttackStatus,
  statusL: z.string().min(1),
});
export type AttackRun = z.infer<typeof AttackRun>;

export const Finding = z.object({
  ix: OwaspCode,
  title: z.string().min(1),
  state: FindingState,
  note: z.string().min(1),
  // Rule D-3 — every finding must cite file:line. NOT optional.
  cite: FileLine,
});
export type Finding = z.infer<typeof Finding>;
