// Sites — gateways the org deploys rules to.
// `mode` is the deployment shape (push vs pull); `modeL` is the page-builder label.
import { z } from 'zod';

export const SiteType = z.enum(['cloudflare', 'aws-apigw', 'nginx', 'envoy']);
export type SiteType = z.infer<typeof SiteType>;

/** saas → control plane pushes; self → fleet pulls a manifest. */
export const SiteMode = z.enum(['saas', 'self']);
export type SiteMode = z.infer<typeof SiteMode>;

export const SiteStatus = z.enum(['live', 'shadow', 'review', 'paused']);

export const Site = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  type: SiteType,
  typeL: z.string().min(1),
  mode: SiteMode,
  modeL: z.enum(['push', 'pull']),
  status: SiteStatus,
  rules: z.number().int().nonnegative(),
  last: z.string().min(1),
  desc: z.string().min(1),
  manifest_url: z.string().url().optional(),
});
export type Site = z.infer<typeof Site>;
