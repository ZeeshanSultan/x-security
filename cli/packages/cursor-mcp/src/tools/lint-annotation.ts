// Lint a proposed x-security block. Runs the @x-security/schema validator and
// layers a confidence verdict (LOW/MEDIUM/HIGH) on top of structural validity.
// The agent uses the verdict + warnings to decide whether to ship as-is or ask
// the human.

import { validateXSecurity } from '@x-security/schema';
import type { McpTool } from '../server.js';

export interface LintInput {
  annotation?: unknown;
  dialect?: '2020-12' | 'draft-04';
}

const inputSchema = {
  type: 'object',
  properties: {
    annotation: {
      type: 'object',
      description: 'The x-security block to lint (the value, not wrapped in `x-security:`).'
    },
    dialect: {
      type: 'string',
      enum: ['2020-12', 'draft-04'],
      description: 'Schema dialect (OpenAPI 3.1 → 2020-12, OpenAPI 3.0 → draft-04).'
    }
  },
  required: ['annotation']
} as const;

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface LintResult {
  valid: boolean;
  confidence: Confidence;
  warnings: string[];
  errors: string[];
}

export function lint(input: LintInput): LintResult {
  const dialect = input.dialect ?? '2020-12';
  const annotation = input.annotation;
  const warnings: string[] = [];
  const errors: string[] = [];

  if (!annotation || typeof annotation !== 'object') {
    return { valid: false, confidence: 'LOW', warnings: [], errors: ['annotation must be an object'] };
  }

  const v = validateXSecurity(annotation, dialect);
  if (!v.valid) {
    for (const e of v.errors) {
      errors.push(`${e.instancePath || '/'} ${e.message ?? 'invalid'}`);
    }
  }

  const a = annotation as Record<string, unknown>;

  // Soft heuristics — even valid policies can be flimsy.
  const auth = a.authentication as Record<string, unknown> | undefined;
  if (!auth) {
    warnings.push('no authentication block — endpoint is implicitly public');
  } else if (auth.type === 'none') {
    warnings.push("authentication.type is 'none' — confirm this endpoint is genuinely public");
  } else if (auth.type === 'bearer-jwt' && !auth.issuer && !auth.jwksUri) {
    warnings.push('bearer-jwt without issuer or jwksUri — JWT verification will fail');
  }

  if (!a.rateLimit) {
    warnings.push('no rateLimit — vulnerable to brute force / scraping (API4:2023)');
  }

  if (!a.request) {
    warnings.push('no request policy — body size and content-type are unbounded');
  } else {
    const req = a.request as Record<string, unknown>;
    if (!req.maxBodySize) warnings.push('request.maxBodySize unset — body size is unbounded');
  }

  let confidence: Confidence;
  if (errors.length > 0) confidence = 'LOW';
  else if (warnings.length >= 3) confidence = 'LOW';
  else if (warnings.length >= 1) confidence = 'MEDIUM';
  else confidence = 'HIGH';

  return { valid: errors.length === 0, confidence, warnings, errors };
}

export const lintAnnotationTool: McpTool = {
  name: 'x-security/lint-annotation',
  description:
    'Validate an x-security block against the x-security schema and return a ' +
    'LOW/MEDIUM/HIGH confidence verdict plus structural warnings.',
  inputSchema,
  handler: (raw) => {
    const input = (raw ?? {}) as LintInput;
    const r = lint(input);
    const lines: string[] = [];
    lines.push(`confidence: ${r.confidence}`);
    lines.push(`valid: ${r.valid}`);
    if (r.errors.length) {
      lines.push('errors:');
      for (const e of r.errors) lines.push(`  - ${e}`);
    }
    if (r.warnings.length) {
      lines.push('warnings:');
      for (const w of r.warnings) lines.push(`  - ${w}`);
    }
    if (!r.errors.length && !r.warnings.length) {
      lines.push('warnings: []');
    }
    return lines.join('\n') + '\n';
  }
};
