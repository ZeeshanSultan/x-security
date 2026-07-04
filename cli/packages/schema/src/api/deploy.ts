// Deploy state machine + per-rule manifest.
// Track is a fixed 3-tuple (draft → shadow → block) — encoded as z.tuple.
import { z } from 'zod';
import { OwaspCode, RuleId, RuleKind } from './primitives.js';

export const DeployStatus = z.enum(['draft', 'shadow', 'review', 'live']);
export type DeployStatus = z.infer<typeof DeployStatus>;

export const TrackStepKind = z.enum(['draft', 'shadow', 'block']);
export const TrackStepState = z.enum(['done', 'now', 'todo']);

export const TrackStep = z.object({
  k: TrackStepKind,
  label: z.string().min(1),
  state: TrackStepState,
  t: z.string().min(1),
});
export type TrackStep = z.infer<typeof TrackStep>;

export const Deploy = z.object({
  id: RuleId,
  repo: z.string().min(1),
  title: z.string().min(1),
  status: DeployStatus,
  statusL: z.string().min(1),
  track: z.tuple([TrackStep, TrackStep, TrackStep]),
  p99: z.string().min(1),
  fp: z.string(),
  matched: z.string(),
  ready: z.boolean(),
  rolled: z.boolean().optional(),
  route: z.string().min(1),
  owasp: OwaspCode,
  kind: RuleKind,
  drafted: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
});
export type Deploy = z.infer<typeof Deploy>;

export const RuleManifest = z.object({
  rule_id: RuleId,
  version: z.number().int().nonnegative(),
  yaml: z.string().min(1),
  digest: z.string().min(1),
  created_at: z.string().datetime({ offset: true }),
});
export type RuleManifest = z.infer<typeof RuleManifest>;
