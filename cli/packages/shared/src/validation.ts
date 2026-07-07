// @x-security/shared/validation — types & schemas for P2 continuous synthetic validation.
//
// Lives in a separate sub-entry (`@x-security/shared/validation`) so that
// adding these schemas does not touch the canonical `index.ts` exports.
import { z } from "zod";

/** How a validation run was triggered. */
export const VALIDATION_TRIGGERS = ["cron", "rule-change", "manual"] as const;
export type ValidationTrigger = (typeof VALIDATION_TRIGGERS)[number];

/** Cron cadence (off disables the scheduler for the org). */
export const VALIDATION_CADENCES = ["off", "daily", "weekly", "monthly"] as const;
export type ValidationCadence = (typeof VALIDATION_CADENCES)[number];

/** Schema for the `triggeredBy` column of attack_run_history. */
export const ValidationTriggerSchema = z.enum(VALIDATION_TRIGGERS);
export const ValidationCadenceSchema = z.enum(VALIDATION_CADENCES);

/** Per-org cadence + environment toggles. */
export const ValidationConfig = z.object({
  cadence: ValidationCadenceSchema.default("weekly"),
  environments: z.record(z.string(), z.boolean()).default({ staging: true }),
});
export type ValidationConfig = z.infer<typeof ValidationConfig>;

/** Update payload accepted by POST /v1/validation/config. */
export const ValidationConfigPatch = ValidationConfig.partial();
export type ValidationConfigPatch = z.infer<typeof ValidationConfigPatch>;

/** Single attempt persisted on attack_run_history.results (denormalised). */
export const ValidationHistoryAttempt = z.object({
  attackClass: z.string(),
  payloadName: z.string(),
  method: z.string(),
  path: z.string(),
  verdict: z.string(),
  expectedBlockRule: z.string().nullable().optional(),
});
export type ValidationHistoryAttempt = z.infer<typeof ValidationHistoryAttempt>;

/** Endpoint shape stored on attack_run_history.endpoints. */
export const ValidationHistoryEndpoint = z.object({
  method: z.string(),
  path: z.string(),
});
export type ValidationHistoryEndpoint = z.infer<typeof ValidationHistoryEndpoint>;

/** Categorised diff vs. the previous run for the same org. */
export const ValidationRunDiff = z.object({
  newlyFailing: z.array(
    z.object({
      attackClass: z.string(),
      payloadName: z.string(),
      method: z.string(),
      path: z.string(),
      previousVerdict: z.string(),
      currentVerdict: z.string(),
    }),
  ),
  newlyPassing: z.array(
    z.object({
      attackClass: z.string(),
      payloadName: z.string(),
      method: z.string(),
      path: z.string(),
      previousVerdict: z.string(),
      currentVerdict: z.string(),
    }),
  ),
  unchanged: z.number().int().nonnegative(),
  newEndpoints: z.array(ValidationHistoryEndpoint),
  removedEndpoints: z.array(ValidationHistoryEndpoint),
});
export type ValidationRunDiff = z.infer<typeof ValidationRunDiff>;

/** Manual-trigger payload for POST /v1/validation/runs. */
export const TriggerValidationRunRequest = z.object({
  scanId: z.string().uuid(),
  targetMode: z.enum(["staging", "shadow_proxy", "sandbox"]).default("staging"),
  targetHost: z.string().min(1),
});
export type TriggerValidationRunRequest = z.infer<typeof TriggerValidationRunRequest>;

/**
 * Optional per-endpoint narrowing carried on the attack-run job payload when
 * the job was enqueued by the rule-change path. Lives next to the rest of the
 * validation contract so the api + runner agree on the shape without having
 * to cross-import from `@x-security/shared`'s root entry.
 *
 * The canonical Zod schema lives on `AttackRunJob.endpointIds` in `index.ts`
 * (this re-export keeps the validation subpath self-describing).
 */
export const RuleChangeEndpointIds = z.array(z.string().uuid());
export type RuleChangeEndpointIds = z.infer<typeof RuleChangeEndpointIds>;

/** Audit event names introduced by this slice. */
export const VALIDATION_AUDIT_EVENTS = {
  RUN_RECORDED: "validation_run.recorded",
  REGRESSION_DETECTED: "validation_run.regression_detected",
  CONFIG_UPDATED: "validation_config.updated",
} as const;

// ----- Pure diff function -----
// Lives here (not in attack-runner) so api + scheduler + runner can all
// import it without crossing app boundaries.

const PASS_VERDICTS = new Set(["blocked", "would_have_blocked"]);
const FAIL_VERDICTS = new Set(["expected_block_missed"]);

function attemptKey(a: ValidationHistoryAttempt): string {
  return `${a.attackClass}::${a.payloadName}::${a.method.toUpperCase()}::${a.path}`;
}

function endpointKey(e: ValidationHistoryEndpoint): string {
  return `${e.method.toUpperCase()} ${e.path}`;
}

export interface DiffInput {
  previous: {
    endpoints: ValidationHistoryEndpoint[];
    results: ValidationHistoryAttempt[];
  } | null;
  current: {
    endpoints: ValidationHistoryEndpoint[];
    results: ValidationHistoryAttempt[];
  };
}

export function computeDiff(input: DiffInput): ValidationRunDiff {
  const current = input.current;
  if (input.previous === null) {
    return {
      newlyFailing: [],
      newlyPassing: [],
      unchanged: current.results.length,
      newEndpoints: [...current.endpoints],
      removedEndpoints: [],
    };
  }
  const previous = input.previous;
  const prevByKey = new Map<string, ValidationHistoryAttempt>();
  for (const a of previous.results) prevByKey.set(attemptKey(a), a);

  const newlyFailing: ValidationRunDiff["newlyFailing"] = [];
  const newlyPassing: ValidationRunDiff["newlyPassing"] = [];
  let unchanged = 0;

  for (const cur of current.results) {
    const prev = prevByKey.get(attemptKey(cur));
    if (!prev) continue;
    if (prev.verdict === cur.verdict) {
      unchanged += 1;
      continue;
    }
    const prevPassed = PASS_VERDICTS.has(prev.verdict);
    const curPassed = PASS_VERDICTS.has(cur.verdict);
    const prevFailed = FAIL_VERDICTS.has(prev.verdict);
    const curFailed = FAIL_VERDICTS.has(cur.verdict);
    if (prevPassed && curFailed) {
      newlyFailing.push({
        attackClass: cur.attackClass,
        payloadName: cur.payloadName,
        method: cur.method,
        path: cur.path,
        previousVerdict: prev.verdict,
        currentVerdict: cur.verdict,
      });
    } else if (prevFailed && curPassed) {
      newlyPassing.push({
        attackClass: cur.attackClass,
        payloadName: cur.payloadName,
        method: cur.method,
        path: cur.path,
        previousVerdict: prev.verdict,
        currentVerdict: cur.verdict,
      });
    }
  }

  const prevEndpoints = new Map(previous.endpoints.map((e) => [endpointKey(e), e]));
  const curEndpoints = new Map(current.endpoints.map((e) => [endpointKey(e), e]));
  const newEndpoints: ValidationHistoryEndpoint[] = [];
  const removedEndpoints: ValidationHistoryEndpoint[] = [];
  for (const [k, e] of curEndpoints) {
    if (!prevEndpoints.has(k)) newEndpoints.push(e);
  }
  for (const [k, e] of prevEndpoints) {
    if (!curEndpoints.has(k)) removedEndpoints.push(e);
  }

  return { newlyFailing, newlyPassing, unchanged, newEndpoints, removedEndpoints };
}

export function regressionCount(diff: ValidationRunDiff): number {
  return diff.newlyFailing.length;
}
