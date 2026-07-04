// RepoStatus, RepoRule, RepoSummary, RepoDetail.
// Mirrors frontend-design-reference/pages-repos.jsx — every field is required
// (Rule D-1: no soft defaults masking missing detection metadata).
import { z } from 'zod';
import { Confidence, Iso8601, OwaspCode, RuleId } from './primitives.js';

export const RepoStatus = z.enum(['shadow', 'review', 'live']);
export type RepoStatus = z.infer<typeof RepoStatus>;

export const RepoRuleState = z.enum(['draft', 'shadow', 'review', 'live', 'rolled']);
export type RepoRuleState = z.infer<typeof RepoRuleState>;

export const RepoRule = z.object({
  id: RuleId,
  route: z.string().min(1),
  category: OwaspCode,
  confidence: Confidence,
  state: RepoRuleState,
});
export type RepoRule = z.infer<typeof RepoRule>;

export const RepoConnection = z.object({
  source: z.enum(['github-app', 'openapi-upload']),
  repoUrl: z.string().url().optional(),
  openapiPath: z.string().optional(),
  installedAt: Iso8601,
  lastSyncAt: Iso8601.nullable(),
});
export type RepoConnection = z.infer<typeof RepoConnection>;

export const RepoSummary = z.object({
  id: z.string(),
  name: z.string().min(1),
  branch: z.string().min(1),
  status: RepoStatus,
  lastScanScore: z.number().nullable(),
  lastScanAt: Iso8601.nullable(),
  rulesCount: z.number().int().nonnegative(),
});
export type RepoSummary = z.infer<typeof RepoSummary>;

export const RepoDetail = RepoSummary.extend({
  rules: z.array(RepoRule),
  connection: RepoConnection,
});
export type RepoDetail = z.infer<typeof RepoDetail>;
