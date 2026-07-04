// Shared data shapes consumed by every reporter.

import type { OwaspId } from '@writ/schema';

export type ReportFormat = 'table' | 'json' | 'sarif' | 'csv' | 'html' | 'junit';

export interface OwaspCoverageRow {
  endpoint: string; // "GET /api/users"
  /** Per-OWASP coverage: 'yes' | 'no' | 'partial' */
  coverage: Record<OwaspId, 'yes' | 'no' | 'partial'>;
  /**
   * v0.4 --feasible: per-OWASP downgrade applied after cross-referencing the
   * target capability matrix. 'feasible' = Y, 'partial' = Y*, 'none' = ~.
   * Only populated when --feasible was passed.
   */
  feasibility?: Record<OwaspId, 'feasible' | 'partial' | 'none' | 'na'>;
  /** Per-OWASP footnote messages keyed by id, e.g. "not enforceable by kong: authorization.rule-based = unsupported". */
  feasibilityNotes?: Record<OwaspId, string[]>;
}

export interface OwaspCoverageReport {
  kind: 'owasp';
  spec: { title: string; version: string };
  rows: OwaspCoverageRow[];
  unprotected: Array<{ method: string; path: string }>;
  /** Targets passed to --feasible (in order). Empty/undefined when not used. */
  feasibleTargets?: string[];
}

export interface AnnotationCoverageReport {
  kind: 'coverage';
  spec: { title: string; version: string };
  totalEndpoints: number;
  annotatedEndpoints: number;
  unprotected: Array<{ method: string; path: string }>;
  perEndpoint: Array<{
    endpoint: string;
    fields: string[];
  }>;
}

export type ReportData = OwaspCoverageReport | AnnotationCoverageReport;

export type DriftSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DriftIssue {
  endpoint: string; // "POST /api/auth/login"
  field: string; // dotted policy field, e.g. "rateLimit.requests"
  severity: DriftSeverity;
  expected: unknown;
  actual: unknown;
  message: string;
}

export interface DriftReport {
  kind: 'drift';
  target: string;
  gatewaySource: string;
  issues: DriftIssue[];
}

export type TestVerdict = 'PASS' | 'FAIL' | 'SKIP';

export interface TestCaseResult {
  endpoint: string;
  rule: string; // e.g. "rateLimit", "auth", "cors"
  verdict: TestVerdict;
  message: string;
  durationMs: number;
}

export interface TestReport {
  kind: 'test';
  target: string;
  cases: TestCaseResult[];
}
