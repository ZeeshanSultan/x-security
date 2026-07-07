// Shared drift utilities for Kong: builds an "expected plugin set" from the
// SpecIR and compares it to whatever Kong actually has (live or file).
//
// The model we work in:
//   Map<endpointLabel, Map<pluginName, normalizedConfig>>
//
// `normalizedConfig` is a shallow record — we deliberately don't deeply
// compare nested objects to avoid false positives from Kong's defaults.
// Drift is reported only for fields the spec explicitly sets.

import type { SpecIR, EndpointIR } from '@x-security/core';
import {
  buildAuthPlugins,
  buildAuthzPlugins,
  buildRateLimitPlugins,
  buildCorsPlugin,
  buildIpRestrictionPlugin,
  buildCachePlugins,
  buildRequestValidatorPlugin,
  buildResponsePlugins
} from '../generators/kong/plugins.js';
import type { KongPlugin } from '../generators/kong/types.js';
import type { DriftIssue, DriftSeverity } from '../reporters/types.js';

// Severity ranking for known drift dimensions.
const FIELD_SEVERITY: Record<string, DriftSeverity> = {
  'rateLimit.requests': 'HIGH',
  'rateLimit.bucket': 'HIGH',
  'authentication.type': 'CRITICAL',
  'authorization.roles': 'CRITICAL',
  'cors.allowedOrigins': 'HIGH',
  'ipPolicy.allow': 'HIGH',
  'ipPolicy.deny': 'HIGH',
  'request.maxBodySize': 'MEDIUM',
  'request.contentType': 'MEDIUM',
  'cacheable': 'MEDIUM'
};

export function endpointLabel(e: EndpointIR): string {
  return `${e.method} ${e.path}`;
}

export interface ExpectedEndpoint {
  endpoint: string;
  plugins: Map<string, KongPlugin>;
}

export function buildExpected(spec: SpecIR): ExpectedEndpoint[] {
  return spec.endpoints.map((e) => {
    const plugins: KongPlugin[] = [
      ...buildAuthPlugins(e.policy.authentication),
      ...buildAuthzPlugins(e.policy.authorization),
      ...buildRateLimitPlugins(e.policy.rateLimit),
      ...buildCorsPlugin(e.policy.cors),
      ...buildIpRestrictionPlugin(e.policy.ipPolicy),
      ...buildCachePlugins(e.policy.cacheable),
      ...buildRequestValidatorPlugin(e.policy.request),
      ...buildResponsePlugins(e.policy.response)
    ];
    const map = new Map<string, KongPlugin>();
    for (const p of plugins) map.set(p.name, p);
    return { endpoint: endpointLabel(e), plugins: map };
  });
}

export interface ActualEndpoint {
  endpoint: string;
  plugins: Map<string, KongPlugin>;
}

function severityFor(field: string): DriftSeverity {
  return FIELD_SEVERITY[field] ?? 'LOW';
}

function compareConfig(
  endpoint: string,
  pluginName: string,
  expected: Record<string, unknown> | undefined,
  actual: Record<string, unknown> | undefined,
  issues: DriftIssue[]
): void {
  const exp = expected ?? {};
  const act = actual ?? {};
  for (const [k, v] of Object.entries(exp)) {
    const aVal = act[k];
    if (aVal === undefined) {
      issues.push({
        endpoint,
        field: `${pluginName}.${k}`,
        severity: severityFor(`${pluginName === 'rate-limiting' ? 'rateLimit' : pluginName}.${k}`),
        expected: v,
        actual: undefined,
        message: `${pluginName}: expected ${k}=${JSON.stringify(v)}, gateway has no value`
      });
      continue;
    }
    if (JSON.stringify(aVal) !== JSON.stringify(v)) {
      // Special-case rate-limit weakening: actual > expected = HIGH
      let severity = severityFor(`${pluginName === 'rate-limiting' ? 'rateLimit' : pluginName}.${k}`);
      if (
        pluginName === 'rate-limiting' &&
        (k === 'second' || k === 'minute' || k === 'hour' || k === 'day') &&
        typeof aVal === 'number' &&
        typeof v === 'number' &&
        aVal > v
      ) {
        severity = 'CRITICAL';
      }
      issues.push({
        endpoint,
        field: `${pluginName}.${k}`,
        severity,
        expected: v,
        actual: aVal,
        message: `${pluginName}: ${k} drift (spec=${JSON.stringify(v)} gateway=${JSON.stringify(aVal)})`
      });
    }
  }
}

export function diffExpectedVsActual(
  expectedList: ExpectedEndpoint[],
  actualByEndpoint: Map<string, Map<string, KongPlugin>>
): DriftIssue[] {
  const issues: DriftIssue[] = [];

  for (const exp of expectedList) {
    const actMap = actualByEndpoint.get(exp.endpoint);
    if (!actMap) {
      // Whole endpoint missing on gateway.
      for (const name of exp.plugins.keys()) {
        issues.push({
          endpoint: exp.endpoint,
          field: name,
          severity: 'CRITICAL',
          expected: 'present',
          actual: 'missing',
          message: `Endpoint not configured on gateway (missing plugin "${name}")`
        });
      }
      continue;
    }
    for (const [name, plugin] of exp.plugins.entries()) {
      const actualPlugin = actMap.get(name);
      if (!actualPlugin) {
        issues.push({
          endpoint: exp.endpoint,
          field: name,
          severity: name === 'jwt' || name === 'acl' ? 'CRITICAL' : 'HIGH',
          expected: 'enabled',
          actual: 'absent',
          message: `Plugin "${name}" expected but not present on gateway`
        });
        continue;
      }
      compareConfig(exp.endpoint, name, plugin.config, actualPlugin.config, issues);
    }
  }
  return issues;
}
