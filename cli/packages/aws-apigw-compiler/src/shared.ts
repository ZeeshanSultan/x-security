import type {
  Confidence,
  DeployMode,
  WafRuleAction,
  WafStatement,
  WafV2Rule
} from './types.js';

/**
 * Minimum surface a per-endpoint rule builder must expose so v2 and v3
 * modules can share `pushRule`/`makeAction` without coupling to each other.
 */
export interface RuleEmitContext {
  ehash: string;
  eid: string;
  mode: DeployMode;
  schemaVersion: string;
  prefix: string;
  rules: WafV2Rule[];
  priorityCursor: { value: number };
}

export interface PushRuleArgs {
  kind: string;
  statement: WafStatement;
  actionKind: 'Block' | 'Challenge' | 'Allow' | 'CAPTCHA';
  sourceField: string;
  confidence: Confidence;
}

/** True iff the mode treats blocking rules as non-blocking (Count). */
export function isObserveMode(m: DeployMode): boolean {
  return m === 'observe' || m === 'shadow';
}

/** ID prefix segment for an effective mode. Legacy 'shadow' callers still see 'shadow'. */
export function modePrefix(m: DeployMode): 'observe' | 'shadow' | 'enforce' {
  if (m === 'enforce') return 'enforce';
  if (m === 'shadow') return 'shadow';
  return 'observe';
}

export function pushRule(b: RuleEmitContext, args: PushRuleArgs): void {
  const effectiveAction = isObserveMode(b.mode) ? 'Count' : args.actionKind;
  const action: WafRuleAction = makeAction(effectiveAction);
  const name = `${b.prefix}-${b.ehash}-${args.kind}`;
  b.rules.push({
    Name: name,
    Priority: b.priorityCursor.value++,
    Statement: args.statement,
    Action: action,
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: name.replace(/[^A-Za-z0-9]/g, '').slice(0, 128)
    },
    mode: b.mode,
    writ: {
      endpoint_id: b.eid,
      rule_type: args.kind,
      source_field: args.sourceField,
      confidence: args.confidence,
      schema_version: b.schemaVersion
    }
  });
}

export function makeAction(kind: 'Block' | 'Challenge' | 'Allow' | 'Count' | 'CAPTCHA'): WafRuleAction {
  switch (kind) {
    case 'Block': return { Block: {} };
    case 'Allow': return { Allow: {} };
    case 'Count': return { Count: {} };
    case 'Challenge': return { Challenge: {} };
    case 'CAPTCHA': return { CAPTCHA: {} };
  }
}
