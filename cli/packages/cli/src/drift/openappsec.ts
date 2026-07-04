/**
 * OpenAppSec drift detector (file-mode only).
 *
 * Strategy:
 *  1. Parse the deployed `policy.yaml` produced by the openappsec generator.
 *  2. Regenerate the expected document from the SpecIR.
 *  3. Compare:
 *     - `schemaValidation[]` entries, matched by `binding.method` + `binding.path`.
 *       Diff `schemas.request` (contentType, maxBodySizeBytes, properties, required).
 *     - `practices[]`, matched by `name`. The interesting practice is
 *       `writ-rate-limit` — compare its rate-limit rules by URI.
 */
import { readFile } from 'node:fs/promises';
import yaml from 'js-yaml';
import type { SpecIR } from '@writ/core';
import type { DriftIssue, DriftReport, DriftSeverity } from '../reporters/types.js';
import { openappsecGenerator } from '../generators/openappsec/index.js';
import type {
  OpenAppSecDoc,
  OpenAppSecPractice,
  OpenAppSecSchemaValidation
} from '../generators/openappsec/policy.js';

export interface OpenAppSecDriftOptions {
  filePath: string;
  yamlContent?: string;
}

function svKey(sv: OpenAppSecSchemaValidation): string {
  return `${sv.binding.method} ${sv.binding.path}`;
}

function asDoc(raw: unknown): Partial<OpenAppSecDoc> {
  if (raw && typeof raw === 'object') return raw as Partial<OpenAppSecDoc>;
  return {};
}

function severityForSchemaField(field: string, expected: unknown, actual: unknown): DriftSeverity {
  if (field === 'maxBodySizeBytes') {
    const e = typeof expected === 'number' ? expected : null;
    const a = typeof actual === 'number' ? actual : null;
    if (e !== null && a !== null && a > e) return 'HIGH';
    return 'MEDIUM';
  }
  if (field === 'contentType') return 'MEDIUM';
  if (field === 'required') return 'HIGH';
  return 'MEDIUM';
}

function diffRequestBlock(
  endpoint: string,
  expected: OpenAppSecSchemaValidation['schemas']['request'],
  actual: OpenAppSecSchemaValidation['schemas']['request'] | undefined
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  if (!actual) {
    issues.push({
      endpoint,
      field: 'schemaValidation.request',
      severity: 'CRITICAL',
      expected: 'present',
      actual: 'missing',
      message: `OpenAppSec request schema missing for ${endpoint}`
    });
    return issues;
  }
  // contentType
  if (JSON.stringify(expected.contentType ?? []) !== JSON.stringify(actual.contentType ?? [])) {
    issues.push({
      endpoint,
      field: 'request.contentType',
      severity: severityForSchemaField('contentType', expected.contentType, actual.contentType),
      expected: expected.contentType,
      actual: actual.contentType,
      message: `OpenAppSec request.contentType drift on ${endpoint}`
    });
  }
  // maxBodySizeBytes
  if ((expected.maxBodySizeBytes ?? null) !== (actual.maxBodySizeBytes ?? null)) {
    issues.push({
      endpoint,
      field: 'request.maxBodySize',
      severity: severityForSchemaField('maxBodySizeBytes', expected.maxBodySizeBytes, actual.maxBodySizeBytes),
      expected: expected.maxBodySizeBytes,
      actual: actual.maxBodySizeBytes,
      message: `OpenAppSec request.maxBodySize drift on ${endpoint}`
    });
  }
  // required (sorted compare)
  const expReq = [...(expected.required ?? [])].sort();
  const actReq = [...(actual.required ?? [])].sort();
  if (JSON.stringify(expReq) !== JSON.stringify(actReq)) {
    issues.push({
      endpoint,
      field: 'request.required',
      severity: 'HIGH',
      expected: expReq,
      actual: actReq,
      message: `OpenAppSec required-fields drift on ${endpoint}`
    });
  }
  // properties — per-field shallow compare
  const expProps = expected.properties ?? {};
  const actProps = actual.properties ?? {};
  for (const [pname, pdef] of Object.entries(expProps)) {
    const apdef = actProps[pname];
    if (!apdef) {
      issues.push({
        endpoint,
        field: `request.schema.${pname}`,
        severity: 'HIGH',
        expected: pdef,
        actual: undefined,
        message: `OpenAppSec property "${pname}" missing on ${endpoint}`
      });
      continue;
    }
    if (JSON.stringify(pdef) !== JSON.stringify(apdef)) {
      issues.push({
        endpoint,
        field: `request.schema.${pname}`,
        severity: 'MEDIUM',
        expected: pdef,
        actual: apdef,
        message: `OpenAppSec property "${pname}" drift on ${endpoint}`
      });
    }
  }
  for (const pname of Object.keys(actProps)) {
    if (!(pname in expProps)) {
      issues.push({
        endpoint,
        field: `request.schema.${pname}`,
        severity: 'LOW',
        expected: undefined,
        actual: actProps[pname],
        message: `Unknown OpenAppSec property "${pname}" on ${endpoint} (not in spec)`
      });
    }
  }
  return issues;
}

function diffRateLimitPractice(
  expected: OpenAppSecPractice | undefined,
  actual: OpenAppSecPractice | undefined
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  if (!expected) return issues;
  if (!actual) {
    issues.push({
      endpoint: '*',
      field: 'practices.writ-rate-limit',
      severity: 'CRITICAL',
      expected: 'present',
      actual: 'missing',
      message: `OpenAppSec rate-limit practice missing entirely`
    });
    return issues;
  }
  const expRules = expected['rate-limit']?.rules ?? [];
  const actRules = actual['rate-limit']?.rules ?? [];
  const actByUri = new Map(actRules.map((r) => [r.uri, r]));
  for (const er of expRules) {
    const ar = actByUri.get(er.uri);
    if (!ar) {
      issues.push({
        endpoint: er.uri,
        field: 'rateLimit',
        severity: 'CRITICAL',
        expected: er,
        actual: undefined,
        message: `OpenAppSec rate-limit rule missing for ${er.uri}`
      });
      continue;
    }
    // Normalize to per-second when units differ for the weakening check.
    const perSec = (limit: number, unit: 'minute' | 'second') =>
      unit === 'minute' ? limit / 60 : limit;
    const expPS = perSec(er.limit, er.unit);
    const actPS = perSec(ar.limit, ar.unit);
    if (Math.abs(expPS - actPS) > 1e-9) {
      const weakened = actPS > expPS;
      issues.push({
        endpoint: er.uri,
        field: 'rateLimit.requests',
        severity: weakened ? 'CRITICAL' : 'MEDIUM',
        expected: `${er.limit}/${er.unit}`,
        actual: `${ar.limit}/${ar.unit}`,
        message: weakened
          ? `OpenAppSec rate-limit weakened on ${er.uri}: spec=${er.limit}/${er.unit} actual=${ar.limit}/${ar.unit}`
          : `OpenAppSec rate-limit tightened on ${er.uri}: spec=${er.limit}/${er.unit} actual=${ar.limit}/${ar.unit}`
      });
    }
    if (er.action !== ar.action) {
      issues.push({
        endpoint: er.uri,
        field: 'rateLimit.action',
        severity: ar.action === 'inactive' || ar.action === 'detect' ? 'CRITICAL' : 'MEDIUM',
        expected: er.action,
        actual: ar.action,
        message: `OpenAppSec rate-limit action drift on ${er.uri}`
      });
    }
  }
  return issues;
}

export async function detectOpenAppSecDrift(
  spec: SpecIR,
  opts: OpenAppSecDriftOptions
): Promise<DriftReport> {
  const raw = opts.yamlContent ?? (await readFile(opts.filePath, 'utf8'));
  const actualDoc = asDoc(yaml.load(raw));
  const expectedArtifacts = await Promise.resolve(openappsecGenerator.generate(spec));
  const expectedDoc = asDoc(yaml.load(expectedArtifacts[0]?.content ?? ''));

  const issues: DriftIssue[] = [];

  // schemaValidation diff — moved under `writ-extended` in wave-7 because
  // open-appsec's flat policy format does not consume top-level `schemaValidation:`.
  const expSV: OpenAppSecSchemaValidation[] =
    expectedDoc['writ-extended']?.['schema-validation'] ?? [];
  const actSV: OpenAppSecSchemaValidation[] =
    actualDoc['writ-extended']?.['schema-validation'] ?? [];
  const actByKey = new Map(actSV.map((s) => [svKey(s), s]));
  for (const e of expSV) {
    const key = svKey(e);
    const a = actByKey.get(key);
    if (!a) {
      issues.push({
        endpoint: key,
        field: 'schemaValidation',
        severity: 'CRITICAL',
        expected: 'present',
        actual: 'missing',
        message: `OpenAppSec schemaValidation entry missing for ${key}`
      });
      continue;
    }
    issues.push(...diffRequestBlock(key, e.schemas.request, a.schemas.request));
    if (e.overrideMode !== a.overrideMode) {
      issues.push({
        endpoint: key,
        field: 'schemaValidation.overrideMode',
        severity:
          a.overrideMode === 'inactive' || a.overrideMode === 'detect' ? 'CRITICAL' : 'MEDIUM',
        expected: e.overrideMode,
        actual: a.overrideMode,
        message: `OpenAppSec overrideMode drift on ${key}`
      });
    }
  }

  // practices diff (only the rate-limit practice is interesting)
  const expPractices = expectedDoc.practices ?? [];
  const actPractices = actualDoc.practices ?? [];
  const expRL = expPractices.find((p) => p.name === 'writ-rate-limit');
  const actRL = actPractices.find((p) => p.name === 'writ-rate-limit');
  issues.push(...diffRateLimitPractice(expRL, actRL));

  return {
    kind: 'drift',
    target: 'openappsec',
    gatewaySource: opts.filePath,
    issues
  };
}
