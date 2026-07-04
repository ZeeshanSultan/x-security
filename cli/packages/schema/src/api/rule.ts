// Rule, Endpoint, OwaspCategory, ScanLogLine.
// Mirrors frontend-design-reference/data.js — every detection metadata field
// is required (Rule D-1: no soft defaults masking missing fields).
import { z } from 'zod';
import {
  Confidence,
  FileLine,
  HttpMethod,
  OwaspCode,
  RuleId,
  RuleKind,
  Severity,
} from './primitives.js';

export const Endpoint = z.object({
  method: HttpMethod,
  path: z.string().min(1),
  file: FileLine,
  flag: z.string().nullable(),
  sev: Severity.nullable(),
});
export type Endpoint = z.infer<typeof Endpoint>;

export const Rule = z.object({
  id: RuleId,
  title: z.string().min(1),
  target: z.string().min(1),
  detail: z.string().min(1),
  conf: Confidence,
  kind: RuleKind,
  owasp: OwaspCode,
  default: z.boolean(),
  advisory: z.boolean().optional(),
});
export type Rule = z.infer<typeof Rule>;

export const OwaspStatus = z.enum(['ok', 'partial', 'gap']);
export const OwaspCategory = z.object({
  code: OwaspCode,
  name: z.string().min(1),
  coverage: z.number().min(0).max(100),
  status: OwaspStatus,
});
export type OwaspCategory = z.infer<typeof OwaspCategory>;

export const ScanLogKind = z.enum(['', 'dim', 'ok', 'warn', 'err']);
export const ScanLogLine = z.object({
  kind: ScanLogKind,
  m: z.string(),
});
export type ScanLogLine = z.infer<typeof ScanLogLine>;

// Versioned manifest history for a rule. Backed by `rule_manifests` table
// (composite PK rule_id+version). `author` is the human/agent that wrote the
// version — denormalized into the row at write time so audit log is still the
// canonical source of attribution, but the modal can render without joins.
export const RuleVersion = z.object({
  ruleId: RuleId,
  version: z.number().int().positive(),
  yaml: z.string().min(1),
  digest: z.string().min(1),
  createdAt: z.string(), // ISO timestamp
  author: z.string().min(1),
});
export type RuleVersion = z.infer<typeof RuleVersion>;
