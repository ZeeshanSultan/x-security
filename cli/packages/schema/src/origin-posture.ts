// Zod schemas for the Origin Lockdown Verifier (PRD §9 P0).
//
// This file is intentionally standalone — it is NOT re-exported from
// packages/schema/src/index.ts. Callers import it via a deep path:
//
//   import { OriginPostureSchema } from '@writ/schema/dist/origin-posture.js';
//
// Keeping it off the main barrel avoids forcing zod into the schema
// package's already-loaded surface (ajv + ajv-formats) for every existing
// consumer that doesn't need posture types.
import { z } from 'zod';

export const PostureStatusSchema = z.enum(['green', 'yellow', 'red']);

export const FindingCodeSchema = z.enum([
  'DNS_BYPASS',
  'DNS_UNRESOLVED',
  'ORIGIN_REACHABLE',
  'ORIGIN_REACHABLE_REDIRECT',
  'ORIGIN_PROBE_ERROR',
  'NO_CLOUDFLARE_ALLOWLIST',
  'CHECKS_OK'
]);

export const FindingSchema = z.object({
  code: FindingCodeSchema,
  detail: z.string().min(1),
  severity: z.enum(['info', 'warn', 'critical'])
});

export const HostnamePostureSchema = z.object({
  hostname: z.string().min(1),
  originIp: z.string().min(1),
  status: PostureStatusSchema,
  findings: z.array(FindingSchema),
  resolvedIps: z.array(z.string()),
  allResolvedAreCloudflare: z.boolean(),
  originDirectStatus: z.number().int().optional(),
  remediation: z.array(z.string())
});

export const OriginPostureSchema = z.object({
  zoneId: z.string().min(1),
  status: PostureStatusSchema,
  hostnames: z.array(HostnamePostureSchema),
  hasCloudflareAllowlist: z.boolean(),
  checkedAt: z.string().datetime()
});

/**
 * Input payload for `POST /v1/onboarding/origin-verify`.
 * `origins` is bounded so a tenant can't DOS the verifier by submitting 10k
 * hostnames per request.
 */
export const OriginVerifyRequestSchema = z.object({
  zoneId: z.string().min(1),
  origins: z
    .array(
      z.object({
        hostname: z
          .string()
          .min(1)
          .max(253)
          // RFC-1123 hostname (no scheme, no port).
          .regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/),
        originIp: z.string().min(1).max(253)
      })
    )
    .min(1)
    .max(50)
});

export type PostureStatusT = z.infer<typeof PostureStatusSchema>;
export type FindingT = z.infer<typeof FindingSchema>;
export type HostnamePostureT = z.infer<typeof HostnamePostureSchema>;
export type OriginPostureT = z.infer<typeof OriginPostureSchema>;
export type OriginVerifyRequestT = z.infer<typeof OriginVerifyRequestSchema>;
