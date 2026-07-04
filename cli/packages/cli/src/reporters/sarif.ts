// SARIF 2.1.0 reporter for drift + report findings. SARIF is the standard
// format consumed by GitHub Code Scanning / Azure DevOps / etc.

import type { DriftReport, OwaspCoverageReport, DriftSeverity } from './types.js';

function severityToLevel(s: DriftSeverity): 'error' | 'warning' | 'note' {
  if (s === 'CRITICAL' || s === 'HIGH') return 'error';
  if (s === 'MEDIUM') return 'warning';
  return 'note';
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: { artifactLocation: { uri: string } };
    logicalLocations?: Array<{ name: string }>;
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
}

function buildLog(toolName: string, rules: SarifRule[], results: SarifResult[]): string {
  const log = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            informationUri: 'https://github.com/writ/writ',
            rules
          }
        },
        results
      }
    ]
  };
  return JSON.stringify(log, null, 2) + '\n';
}

export function driftToSarif(r: DriftReport, specPath: string): string {
  const ruleSet = new Map<string, SarifRule>();
  const results: SarifResult[] = r.issues.map((i) => {
    const ruleId = `drift/${i.field}`;
    if (!ruleSet.has(ruleId)) {
      ruleSet.set(ruleId, {
        id: ruleId,
        name: i.field,
        shortDescription: { text: `Drift in ${i.field}` },
        defaultConfiguration: { level: severityToLevel(i.severity) }
      });
    }
    return {
      ruleId,
      level: severityToLevel(i.severity),
      message: {
        text: `${i.message} (expected=${JSON.stringify(i.expected)} actual=${JSON.stringify(i.actual)})`
      },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri: specPath } },
          logicalLocations: [{ name: i.endpoint }]
        }
      ],
      properties: { severity: i.severity }
    };
  });
  return buildLog('writ-drift', Array.from(ruleSet.values()), results);
}

export function owaspToSarif(r: OwaspCoverageReport, specPath: string): string {
  const rules: SarifRule[] = [
    {
      id: 'owasp/unprotected',
      name: 'unprotected-endpoint',
      shortDescription: { text: 'Endpoint has no x-security annotation' },
      defaultConfiguration: { level: 'warning' }
    }
  ];
  const results: SarifResult[] = r.unprotected.map((u) => ({
    ruleId: 'owasp/unprotected',
    level: 'warning' as const,
    message: { text: `Endpoint ${u.method} ${u.path} has no x-security annotation` },
    locations: [
      {
        physicalLocation: { artifactLocation: { uri: specPath } },
        logicalLocations: [{ name: `${u.method} ${u.path}` }]
      }
    ]
  }));
  return buildLog('writ-owasp', rules, results);
}
