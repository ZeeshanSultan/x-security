// Org-level account: members, API keys, integrations, billing, org row.
import { z } from 'zod';

export const MemberRole = z.enum(['Owner', 'Admin', 'Reviewer', 'Member']);

export const Member = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1),
  email: z.string().email(),
  role: MemberRole,
  joined: z.string().min(1),
  initials: z.string().min(1).max(3),
});
export type Member = z.infer<typeof Member>;

export const ApiKeyScope = z.enum(['read', 'read+promote', 'deploy', 'author', '*']);
export const ApiKey = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  created: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  lastUsed: z.string().min(1),
  scope: ApiKeyScope,
});
export type ApiKey = z.infer<typeof ApiKey>;

export const IntegrationState = z.enum(['connected', 'available', 'error']);
export const Integration = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  kind: z.string().min(1),
  state: IntegrationState,
  desc: z.string().min(1),
  meta: z.string().min(1),
});
export type Integration = z.infer<typeof Integration>;

export const InvoiceStatus = z.enum(['paid', 'open', 'failed', 'void']);
export const Invoice = z.object({
  id: z.string().min(1),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  period: z.string().min(1),
  amount: z.string().regex(/^\$[\d,]+\.\d{2}$/),
  status: InvoiceStatus,
  statusL: z.string().min(1),
});
export type Invoice = z.infer<typeof Invoice>;

export const UsageMeter = z.object({
  label: z.string().min(1),
  sub: z.string().min(1),
  n: z.string().min(1),
  pct: z.number().min(0).max(100),
  kind: z.string(),
});
export type UsageMeter = z.infer<typeof UsageMeter>;

export const Org = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
  slug: z.string().regex(/^[a-z0-9-]+$/),
  plan: z.enum(['free', 'team', 'enterprise']),
  billing_email: z.string().email(),
  default_gateway_id: z.string().min(1).nullable(),
});
export type Org = z.infer<typeof Org>;
