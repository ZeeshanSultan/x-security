// @writ/shared — cross-service types and queue/HTTP contracts.
// See docs/ADR-003-service-topology.md.

import { z } from "zod";

// ===== Error envelope =====
export class WritError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly cause?: unknown;
  constructor(code: string, message: string, status = 500, cause?: unknown) {
    super(message);
    this.name = "WritError";
    this.code = code;
    this.status = status;
    if (cause !== undefined) this.cause = cause;
  }
}

export const ERROR_CODES = {
  BAD_REQUEST: "BAD_REQUEST",
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  SCAN_NOT_FOUND: "SCAN_NOT_FOUND",
  DEPLOY_NOT_FOUND: "DEPLOY_NOT_FOUND",
  ATTACK_RUN_NOT_FOUND: "ATTACK_RUN_NOT_FOUND",
  ZONE_NOT_VERIFIED: "ZONE_NOT_VERIFIED",
  ZONE_NOT_FOUND: "ZONE_NOT_FOUND",
  ZONE_OWNED_BY_OTHER_ORG: "ZONE_OWNED_BY_OTHER_ORG",
  INTERNAL: "INTERNAL",
  VALIDATION_FAILED: "VALIDATION_FAILED",
} as const;
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// ===== Domain enums =====
export const ConfidenceLevel = z.enum(["HIGH", "MEDIUM", "LOW"]);
export type ConfidenceLevel = z.infer<typeof ConfidenceLevel>;

export const ScanStatus = z.enum([
  "queued",
  "cloning",
  "extracting",
  "inferring",
  "scanning",
  "compiling",
  "completed",
  "done",
  "failed",
]);
export type ScanStatus = z.infer<typeof ScanStatus>;

/** Stable machine codes for scan-worker error states (recorded in audit_log). */
export const SCAN_ERROR_CODES = {
  CLONE_FAILED: "CLONE_FAILED",
  CLONE_TIMEOUT: "CLONE_TIMEOUT",
  REPO_TOO_LARGE: "REPO_TOO_LARGE",
  EXTRACT_FAILED: "EXTRACT_FAILED",
  LLM_FAILED: "LLM_FAILED",
  COMPILE_FAILED: "COMPILE_FAILED",
  PERSIST_FAILED: "PERSIST_FAILED",
  RATE_LIMITED: "RATE_LIMITED",
  UNKNOWN: "UNKNOWN",
} as const;
export type ScanErrorCode = (typeof SCAN_ERROR_CODES)[keyof typeof SCAN_ERROR_CODES];

export const RuleAction = z.enum(["log", "block", "challenge", "managed_challenge", "rate_limit"]);
export type RuleAction = z.infer<typeof RuleAction>;

export const DeployState = z.enum(["shadow", "enforce", "rolled_back", "drift"]);
export type DeployState = z.infer<typeof DeployState>;

export const AttackRunStatus = z.enum(["queued", "running", "completed", "failed"]);
export type AttackRunStatus = z.infer<typeof AttackRunStatus>;

// ===== Queue job payloads (BullMQ) =====
export const ScanJob = z.object({
  scanId: z.string().uuid(),
  orgId: z.string().uuid().optional(),
  repoId: z.string().uuid().optional(),
  repoUrl: z.string().url(),
  ref: z.string().optional(),
  installationId: z.number().optional(),
  prNumber: z.number().optional(),
  /** Public-scan flag (report card / unauthenticated). Triggers per-IP rate limit. */
  isPublic: z.boolean().optional(),
  /** Source IP for per-IP rate limiting on public scans. */
  sourceIp: z.string().optional(),
  /** PR head SHA, for pull_request-triggered scans (PRD §8 R4.2). */
  prHeadSha: z.string().optional(),
  /** PR base SHA, for route-diff scoping. */
  prBaseSha: z.string().optional(),
  /** True when triggered by a pull_request webhook. */
  isPullRequest: z.boolean().optional(),
  /** Restrict inference to routes that changed in the PR diff (PRD §8 R4.3). */
  routeDiffOnly: z.boolean().optional(),
  /** No scan; only delete shadow rules tagged with this PR (PRD §8 R4.7). */
  cleanupOnly: z.boolean().optional(),
  /** Repo full name (owner/repo) — used by github-app for installation API calls. */
  repoFullName: z.string().optional(),
  requestId: z.string().optional(),
});
export type ScanJob = z.infer<typeof ScanJob>;

export const AttackJob = z.object({
  attackRunId: z.string().uuid(),
  orgId: z.string().uuid(),
  scanId: z.string().uuid(),
  targetMode: z.enum(["staging", "shadow_proxy", "sandbox"]),
  targetHost: z.string(),
  payloadCategories: z.array(z.string()),
  requestId: z.string(),
});
export type AttackJob = z.infer<typeof AttackJob>;

/**
 * Endpoint summary passed into an attack run by the api/scan-worker.
 * Subset of @writ/db Endpoint, denormalised so the runner does not
 * need to query the scan back out of postgres on the hot path.
 */
export const EndpointSummary = z.object({
  method: z.string(),
  path: z.string(),
  /** Expected Cloudflare rule that should block abusive variants, if any. */
  expectedBlockRule: z.string().nullable().optional(),
  /** True if this endpoint requires auth (informs broken-auth payload class). */
  requiresAuth: z.boolean().optional(),
  /** True if path has an owner-scoped id segment (informs BOLA payload class). */
  hasOwnerScopedId: z.boolean().optional(),
});
export type EndpointSummary = z.infer<typeof EndpointSummary>;

/**
 * Richer attack-run job payload used by `@writ/attack-runner`.
 * Carries the per-endpoint expected-block map so the runner can compute
 * verdicts without round-tripping back to the api.
 */
export const AttackRunJob = z.object({
  attackRunId: z.string().uuid(),
  orgId: z.string().uuid(),
  targetHostname: z.string().min(1),
  scope: z.enum(["staging", "sandbox"]),
  deployId: z.string().uuid().optional(),
  authHeaderTemplate: z.string().optional(),
  endpoints: z.array(EndpointSummary).min(1),
  /**
   * Optional per-endpoint id list — set by the rule-change enqueue path
   * (api → validation-scheduler) so the runner can correlate verdicts back
   * to the specific endpoints whose policy actually changed. Manual /
   * cron-triggered jobs omit this; the runner treats absence as
   * "no narrowing — run against `endpoints` as supplied".
   */
  endpointIds: z.array(z.string().uuid()).optional(),
  requestId: z.string().optional(),
});
export type AttackRunJob = z.infer<typeof AttackRunJob>;

/** OWASP API Top 10 payload classes the attack-runner ships out of the box. */
export const ATTACK_CLASSES = [
  "bola",
  "broken_auth",
  "excessive_data",
  "rate_limit",
  "bfla",
  "mass_assignment",
  "ssrf",
  "sql_injection",
  "unrestricted_resource",
  "misconfig",
] as const;
export type AttackClass = (typeof ATTACK_CLASSES)[number];

/** Per-payload verdict emitted by the attack-runner. */
export const ATTACK_VERDICTS = [
  "blocked",
  "allowed",
  "would_have_blocked",
  "expected_block_missed",
  "error",
] as const;
export type AttackVerdict = (typeof ATTACK_VERDICTS)[number];

export const DeployJob = z.object({
  deployId: z.string().uuid(),
  orgId: z.string().uuid(),
  scanId: z.string().uuid(),
  zoneId: z.string().uuid(),
  action: z.enum(["shadow_deploy", "promote", "demote", "rollback"]),
  ruleIds: z.array(z.string()).optional(),
  autoRollbackSeconds: z.number().int().positive().optional(),
  requestId: z.string(),
});
export type DeployJob = z.infer<typeof DeployJob>;

export const PrCommentJob = z.object({
  installationId: z.number(),
  repoFullName: z.string(),
  prNumber: z.number(),
  body: z.string(),
  requestId: z.string(),
});
export type PrCommentJob = z.infer<typeof PrCommentJob>;

/**
 * Install-finalize retry job. Enqueued by the github-app when minting an
 * installation access token fails on the `installation.created` webhook;
 * a background worker retries with exponential backoff (SEC-8).
 */
export const InstallFinalizeJob = z.object({
  installationId: z.number(),
  orgId: z.string().uuid().optional(),
  attempt: z.number().int().nonnegative().default(0),
  requestId: z.string().optional(),
});
export type InstallFinalizeJob = z.infer<typeof InstallFinalizeJob>;

/**
 * Per-shadow-rule summary attached to a ScanCompletedNotification. Lets the
 * PR-bot render an actionable "promote in dashboard" link per rule (per PRD_v2_BUILD_REPORT #13, closed).
 */
export const ScanShadowRuleSummary = z.object({
  ruleId: z.string(),
  intent: z.string(),
  endpoint: z.object({
    method: z.string(),
    path: z.string(),
  }),
});
export type ScanShadowRuleSummary = z.infer<typeof ScanShadowRuleSummary>;

/**
 * Notification payload emitted by the scan-worker to the github-app once a
 * PR scan finishes. Carries enough context to render the sticky comment with
 * per-rule promote links.
 */
export const ScanCompletedNotification = z.object({
  scanId: z.string().uuid(),
  deployId: z.string().uuid().optional(),
  installationId: z.number(),
  repoFullName: z.string(),
  prNumber: z.number().optional(),
  shadowRules: z.array(ScanShadowRuleSummary).default([]),
  requestId: z.string().optional(),
});
export type ScanCompletedNotification = z.infer<typeof ScanCompletedNotification>;

// ===== HTTP DTOs =====
export const CreateScanRequest = z.object({
  repoId: z.string().uuid(),
  ref: z.string().min(1),
  prNumber: z.number().int().positive().optional(),
  trigger: z.enum(["manual", "cli", "webhook", "cron"]).default("manual"),
});
export type CreateScanRequest = z.infer<typeof CreateScanRequest>;

export const CreateDeployRequest = z.object({
  scanId: z.string().uuid(),
  zoneId: z.string().uuid(),
});
export type CreateDeployRequest = z.infer<typeof CreateDeployRequest>;

export const PromoteRequest = z.object({
  ruleIds: z.array(z.string().uuid()).min(1),
  autoRollbackSeconds: z.number().int().min(1).max(3600).default(60),
  reason: z.string().optional(),
});
export type PromoteRequest = z.infer<typeof PromoteRequest>;

export const RollbackRequest = z.object({
  reason: z.string().optional(),
});
export type RollbackRequest = z.infer<typeof RollbackRequest>;

export const CreateAttackRunRequest = z.object({
  scanId: z.string().uuid(),
  targetMode: z.enum(["staging", "shadow_proxy", "sandbox"]),
  targetHost: z.string().min(1),
  payloadCategories: z.array(z.string()).min(1),
});
export type CreateAttackRunRequest = z.infer<typeof CreateAttackRunRequest>;

export const VerifyZoneRequest = z.object({
  zoneId: z.string().uuid(),
  method: z.enum(["dns_txt", "http_file"]),
});
export type VerifyZoneRequest = z.infer<typeof VerifyZoneRequest>;

export const PolicyInferRequest = z.object({
  language: z.string(),
  framework: z.string(),
  handlerSource: z.string(),
  route: z.object({ method: z.string(), path: z.string() }),
});
export type PolicyInferRequest = z.infer<typeof PolicyInferRequest>;

// ===== Queue names =====
export const QUEUE_NAMES = {
  scan: "scan",
  attack: "attack",
  deploy: "deploy",
  prComment: "pr-comment",
  installFinalize: "install-finalize",
  drift: "drift",
  eventTail: "event-tail",
} as const;
export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

// ===== drift-worker repeat-job names (BullMQ repeatable jobs) =====
export const DriftJobName = "drift-scan" as const;
export type DriftJobName = typeof DriftJobName;

export const EventTailJobName = "event-tail" as const;
export type EventTailJobName = typeof EventTailJobName;

// ===== Misc =====
export const REQUEST_ID_HEADER = "x-request-id";

export interface Rule {
  id: string;
  scanId: string;
  endpointHash: string;
  ruleType: "custom" | "rate_limit" | "transform" | "bot";
  action: RuleAction;
  confidence: ConfidenceLevel;
  rationale: string;
  xSecurityField: string;
  owaspCategory: string;
  cloudflareJson: Record<string, unknown>;
}

export interface Endpoint {
  id: string;
  scanId: string;
  method: string;
  path: string;
  handlerFile: string;
  handlerLine: number;
  framework: string;
}

/**
 * `DeployRule` is a **joined view** over `rules × policies × endpoints`,
 * not a 1:1 mirror of the `rules` table.
 *
 * `description / endpointPath / method / confidence` are synthesized by
 * the api's `listPoliciesForRepo` query at read time; they do NOT exist
 * as columns on `rules`. A consumer reading the raw `rules` table via
 * @writ/db will see only the fields in {@link RuleRow}.
 *
 * If you want the projected shape, hit `GET /v1/repos/:id/policies` or
 * `GET /v1/deploys/:id`; if you want the raw row, query the `rules` table
 * directly and join policy/endpoint metadata yourself.
 */
export interface DeployRule {
  id: string;
  description: string;
  endpointPath: string;
  method: string;
  ruleType: "custom" | "rate_limit" | "transform" | "bot";
  action: "log" | "block" | "challenge" | "managed_challenge" | "rate_limit";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  /**
   * Optional human-readable request preview attached by some read paths
   * (e.g. the web client's policy editor). Not present on the raw row.
   */
  requestPreview?: string;
}

/**
 * `RuleRow` mirrors the `rules` table in @writ/db. Use this when
 * working with raw drizzle rows. For the read-API projection, see
 * {@link DeployRule}.
 *
 * Field names match the drizzle TS shape (camelCase); column names in
 * postgres are snake_case via the drizzle column mapping.
 */
export interface RuleRow {
  id: string;
  scanId: string;
  policyId: string;
  ruleType: string;
  action: string;
  xSecurityField: string;
  owaspCategory: string;
  cloudflareId: string | null;
  cloudflareJson: unknown;
}
