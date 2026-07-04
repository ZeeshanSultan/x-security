import type { XSecurityPolicy } from '@writ/schema';
import { and } from './statements.js';
import { isObserveMode, pushRule } from './shared.js';
import type { V2Builder } from './v2-builder.js';
import type { WafStatement } from './types.js';

export function compileIdorMitigation(b: V2Builder, policy: XSecurityPolicy): void {
  const hasIdParam = /\{[^}]*id[^}]*\}/i.test(b.endpoint.path);
  const isOwnershipAuthz = policy.authorization?.rules?.some(r => /user|owner|tenant/i.test(r.field)) ?? false;
  if (!hasIdParam || !isOwnershipAuthz) return;

  b.unsupported.push({
    endpoint_id: b.eid,
    directive: 'authorization.ownership-check (BOLA/IDOR)',
    reason:
      'AWS WAF cannot enforce per-request resource ownership (BOLA/IDOR) — it has no context of authenticated user vs path-parameter. Implement this in an API Gateway Lambda authorizer or the application layer.'
  });
}

export function compileOwaspInjections(b: V2Builder, policy: XSecurityPolicy, baseMatch: WafStatement): void {
  const mitigates = policy.mitigates ?? [];
  const wantsInjectionMitigation = mitigates.some(m => m === 'API8:2023' || m === 'API10:2023');
  if (!wantsInjectionMitigation) return;
  if (!['POST', 'PUT', 'PATCH'].includes(b.endpoint.method)) return;

  pushRule(b, {
    kind: 'sqli-body',
    statement: and(baseMatch, {
      SqliMatchStatement: {
        FieldToMatch: { Body: { OversizeHandling: 'CONTINUE' } },
        TextTransformations: [
          { Priority: 0, Type: 'URL_DECODE' },
          { Priority: 1, Type: 'HTML_ENTITY_DECODE' }
        ]
      }
    }),
    actionKind: 'Block',
    sourceField: 'mitigates.API10',
    confidence: 'MEDIUM'
  });

  pushRule(b, {
    kind: 'xss-body',
    statement: and(baseMatch, {
      XssMatchStatement: {
        FieldToMatch: { Body: { OversizeHandling: 'CONTINUE' } },
        TextTransformations: [{ Priority: 0, Type: 'URL_DECODE' }, { Priority: 1, Type: 'HTML_ENTITY_DECODE' }]
      }
    }),
    actionKind: 'Block',
    sourceField: 'mitigates.API10',
    confidence: 'MEDIUM'
  });
}

/** v0.2 path: `botProtection: true` opts into AWS Managed Bot Control. */
export function compileBotProtectionLegacy(b: V2Builder, policy: XSecurityPolicy): void {
  const raw = policy as Record<string, unknown>;
  if (raw['botProtection'] !== true) return;

  if (!b.enableManagedBotControl) {
    b.warnings.push({
      endpoint_id: b.eid,
      field: 'botProtection',
      message:
        'AWS Managed Bot Control is a paid managed rule group ($10/month + per-request fees). Set `enableManagedBotControl: true` in compile options to opt in.',
      severity: 'warn'
    });
    return;
  }

  b.warnings.push({
    endpoint_id: b.eid,
    field: 'botProtection',
    message:
      'AWS Bot Control adds monthly subscription cost ($10) and $1 per million bot-control requests. Verify pricing before enforce.',
    severity: 'warn'
  });

  b.rules.push({
    Name: `${b.prefix}-${b.ehash}-bot-control`,
    Priority: b.priorityCursor.value++,
    Statement: {
      ManagedRuleGroupStatement: {
        VendorName: 'AWS',
        Name: 'AWSManagedRulesBotControlRuleSet'
      }
    },
    OverrideAction: isObserveMode(b.mode) ? { Count: {} } : { None: {} },
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: `${b.prefix}-${b.ehash}-bot-control`.replace(/[^A-Za-z0-9]/g, '')
    },
    mode: b.mode,
    writ: {
      endpoint_id: b.eid,
      rule_type: 'bot-control',
      source_field: 'botProtection',
      confidence: 'MEDIUM',
      schema_version: b.schemaVersion
    }
  });

  b.warnings.push({
    endpoint_id: b.eid,
    field: 'botProtection',
    message:
      'AWS Bot Control evaluates ALL traffic to the WebACL, not just this endpoint. Per-endpoint scoping requires a custom rule with label-matching.',
    severity: 'info'
  });
}
