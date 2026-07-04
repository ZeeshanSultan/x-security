// Machine-readable JSON reporter — passes through the structured report
// shape as-is. Used by CI integrations and the diff command.

import type { DriftReport, ReportData, TestReport } from './types.js';

export function toJson(data: ReportData | DriftReport | TestReport): string {
  return JSON.stringify(data, null, 2) + '\n';
}
