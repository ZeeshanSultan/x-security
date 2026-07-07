// CVE virtual-patch fast-path compiler.
//
// The CVE proposer (packages/cve-watcher/src/proposer.ts) emits one of five
// PATCH SHAPES under `x-security.targetOverrides.firewall.virtualPatch`:
//
//   1. request-uri-denylist     → Custom Rule on http.request.uri.path
//   2. request-header-denylist  → Custom Rule on http.request.headers["<name>"][0]
//   3. request-body-pattern     → Custom Rule on http.request.body.raw (Pro+ plan)
//   4. tighten-body-size        → Custom Rule on http.request.body.size
//   5. tighten-rate-limit       → Rate Limit Rule
//
// This compiler is INTENTIONALLY narrow: it only knows how to lower these five
// shapes. It does NOT accept generic policies — the full OpenAPI compile path
// in `./compile.ts` owns that. Keeping the surface small is the security
// boundary: an LLM-generated patch can only ever turn into one of these five
// rule kinds.
//
// All output rules use the action passed in `opts.mode` ('log' or 'block').
// The CVE accept-handler always passes 'log' on auto-accept; promote-to-block
// goes through the standard `/v1/deploys/:id/promote` path.

import { validateRegex } from '@x-security/shared/regex-grammar';
import type { CompiledRule, RuleAction } from './types.js';

const SCHEMA_VERSION_DEFAULT = '0.2.0';

/** Patch shape emitted by the CVE proposer. */
export interface VirtualPatch {
  /** Discriminator — one of the five known shapes. */
  shape:
    | 'request-uri-denylist'
    | 'request-header-denylist'
    | 'request-body-pattern'
    | 'tighten-body-size'
    | 'tighten-rate-limit';
  /** Human-readable description (auditor-facing). */
  description: string;
  /** Regex pattern for -denylist / -pattern shapes (PCRE-ish). */
  pattern?: string;
  /** Header name (lowercased) for request-header-denylist. */
  headerName?: string;
  /** Byte cap for tighten-body-size. Accepts "8KB" / "1MB" / "1024" / number. */
  maxBodySize?: string | number;
  /** Rate-limit params for tighten-rate-limit. */
  rateLimit?: {
    requests: number;
    /** "1s" / "30s" / "1m" / "5m" / "10m" / "1h" — coerced to nearest CF period. */
    window: string | number;
  };
}

export interface CompileVirtualPatchOptions {
  /** Action for the emitted rule. CVE fast-path ALWAYS uses 'log' on auto-accept. */
  mode: 'log' | 'block';
  /**
   * Cloudflare ruleset rule name. The compiler stamps this into the rule's
   * description as a prefix.
   */
  ruleName: string;
  /** Source CVE ID (e.g. "CVE-2021-44228"). */
  cveId: string;
  /**
   * x-security-side rule ID used as the CF rule `ref`. The CVE accept-handler
   * uses this to round-trip the rule across promote/demote calls.
   */
  xSecurityRuleId: string;
  /** Schema version stamped on the rule. Defaults to 0.2.0. */
  schemaVersion?: string;
}

export type CompileVirtualPatchResult =
  | { type: 'customRule'; rule: CompiledRule; warnings?: string[] }
  | { type: 'rateLimitRule'; rule: CompiledRule; warnings?: string[] };

/** Allowed Cloudflare rate-limit periods (seconds). */
const ALLOWED_RATELIMIT_PERIODS = [10, 60, 120, 300, 600, 3600] as const;

/**
 * Public entrypoint. Pure function — same input → same output, no I/O.
 */
export function compileVirtualPatch(
  patch: VirtualPatch,
  opts: CompileVirtualPatchOptions,
): CompileVirtualPatchResult {
  const schemaVersion = opts.schemaVersion ?? SCHEMA_VERSION_DEFAULT;
  const description = `[${opts.ruleName}] CVE-${opts.cveId}: virtual patch — ${patch.description}`;
  const warnings: string[] = [];

  switch (patch.shape) {
    case 'request-uri-denylist': {
      const pattern = requirePattern(patch.pattern, 'request-uri-denylist');
      return {
        type: 'customRule',
        rule: buildCustomRule({
          ruleType: 'cve-uri-denylist',
          expression: `(http.request.uri.path matches "${escapeQuotes(pattern)}")`,
          action: opts.mode,
          description,
          ref: opts.xSecurityRuleId,
          cveId: opts.cveId,
          sourceField: 'targetOverrides.firewall.virtualPatch.pattern',
          schemaVersion,
        }),
      };
    }

    case 'request-header-denylist': {
      const pattern = requirePattern(patch.pattern, 'request-header-denylist');
      const headerName = (patch.headerName ?? '').toLowerCase().trim();
      if (!headerName) throw new VirtualPatchCompileError('request-header-denylist requires headerName');
      // Header names: only ASCII letters, digits, and hyphen are valid in HTTP.
      if (!/^[a-z0-9-]+$/.test(headerName)) {
        throw new VirtualPatchCompileError(
          `request-header-denylist headerName "${headerName}" contains invalid characters`,
        );
      }
      return {
        type: 'customRule',
        rule: buildCustomRule({
          ruleType: 'cve-header-denylist',
          expression: `(http.request.headers["${headerName}"][0] matches "${escapeQuotes(pattern)}")`,
          action: opts.mode,
          description,
          ref: opts.xSecurityRuleId,
          cveId: opts.cveId,
          sourceField: `targetOverrides.firewall.virtualPatch.headerName=${headerName}`,
          schemaVersion,
        }),
      };
    }

    case 'request-body-pattern': {
      const pattern = requirePattern(patch.pattern, 'request-body-pattern');
      warnings.push(
        'request-body-pattern requires Cloudflare Pro plan or higher; the http.request.body.raw field is not available on Free.',
      );
      return {
        type: 'customRule',
        rule: buildCustomRule({
          ruleType: 'cve-body-pattern',
          expression: `(http.request.body.raw matches "${escapeQuotes(pattern)}")`,
          action: opts.mode,
          description,
          ref: opts.xSecurityRuleId,
          cveId: opts.cveId,
          sourceField: 'targetOverrides.firewall.virtualPatch.bodyPattern',
          schemaVersion,
        }),
        warnings,
      };
    }

    case 'tighten-body-size': {
      const bytes = parseBytes(patch.maxBodySize, 'tighten-body-size');
      return {
        type: 'customRule',
        rule: buildCustomRule({
          ruleType: 'cve-body-size',
          expression: `(http.request.body.size gt ${bytes})`,
          action: opts.mode,
          description,
          ref: opts.xSecurityRuleId,
          cveId: opts.cveId,
          sourceField: 'targetOverrides.firewall.virtualPatch.maxBodySize',
          schemaVersion,
        }),
      };
    }

    case 'tighten-rate-limit': {
      if (!patch.rateLimit) {
        throw new VirtualPatchCompileError('tighten-rate-limit requires a rateLimit object');
      }
      const requests = patch.rateLimit.requests;
      if (!Number.isInteger(requests) || requests <= 0) {
        throw new VirtualPatchCompileError(
          `tighten-rate-limit.requests must be a positive integer, got ${requests}`,
        );
      }
      const periodSec = parseRateLimitWindow(patch.rateLimit.window);
      const cfPeriod = nearestPeriod(periodSec);
      if (cfPeriod !== periodSec) {
        warnings.push(
          `rate-limit window ${patch.rateLimit.window} rounded to ${cfPeriod}s (Cloudflare only allows ${ALLOWED_RATELIMIT_PERIODS.join('/')}).`,
        );
      }
      return {
        type: 'rateLimitRule',
        rule: buildRateLimitRule({
          ruleType: 'cve-rate-limit',
          // Apply the rate-limit to all traffic — narrower scoping is done via
          // characteristics in counting_expression by the CVE LLM if needed.
          expression: 'true',
          action: opts.mode,
          description,
          ref: opts.xSecurityRuleId,
          cveId: opts.cveId,
          sourceField: 'targetOverrides.firewall.virtualPatch.rateLimit',
          schemaVersion,
          period: cfPeriod,
          requests,
        }),
        warnings,
      };
    }

    default: {
      // Exhaustiveness guard — TypeScript will error here if we forget a shape.
      const _: never = patch.shape;
      throw new VirtualPatchCompileError(`unsupported virtualPatch shape: ${String(_)}`);
    }
  }
}

// ---------------- helpers ----------------

export class VirtualPatchCompileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VirtualPatchCompileError';
  }
}

function requirePattern(pattern: string | undefined, shape: string): string {
  if (!pattern || pattern.length === 0) {
    throw new VirtualPatchCompileError(`${shape} requires a non-empty pattern`);
  }
  // Refuse `.*`-only patterns (they would match every request).
  if (/^[.\\*]+$/.test(pattern)) {
    throw new VirtualPatchCompileError(`${shape} pattern "${pattern}" matches all traffic — refused`);
  }
  if (pattern.length > 512) {
    throw new VirtualPatchCompileError(`${shape} pattern exceeds 512 chars`);
  }
  // SECURITY (C-15): refuse to compile any pattern the strict regex grammar
  // doesn't accept. This is the WAF-layer safety net — even if a poisoned
  // LLM output slips past the proposer's pre-check, the compiler refuses
  // to lower it into a deployable rule. Reject shapes:
  //   - nested quantifiers (`(a+)+` → ReDoS)
  //   - backreferences, lookaround, named groups
  //   - shorthand classes (`\w`, `\d`, `\s`) — Unicode foot-guns
  // See @x-security/shared/regex-grammar for the full grammar.
  const grammar = validateRegex(pattern);
  if (!grammar.ok) {
    throw new VirtualPatchCompileError(
      `${shape} pattern rejected by grammar: ${grammar.error} (pos ${grammar.position})`,
    );
  }
  return pattern;
}

function escapeQuotes(s: string): string {
  // CF expressions use double-quoted strings; escape embedded quotes only.
  // Backslashes pass through verbatim — they're regex metacharacters that
  // the CF expression engine forwards to its PCRE-style matcher.
  return s.replace(/"/g, '\\"');
}

function parseBytes(input: string | number | undefined, shape: string): number {
  if (input === undefined || input === null) {
    throw new VirtualPatchCompileError(`${shape} requires maxBodySize`);
  }
  if (typeof input === 'number') {
    if (!Number.isFinite(input) || input <= 0) {
      throw new VirtualPatchCompileError(`${shape} maxBodySize must be positive, got ${input}`);
    }
    return Math.floor(input);
  }
  const trimmed = input.trim();
  const m = trimmed.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?$/i);
  if (!m) {
    throw new VirtualPatchCompileError(`${shape} maxBodySize "${input}" not parseable`);
  }
  const n = parseFloat(m[1]!);
  const unit = (m[2] ?? 'B').toUpperCase();
  const mult = unit === 'GB' ? 1024 ** 3 : unit === 'MB' ? 1024 ** 2 : unit === 'KB' ? 1024 : 1;
  return Math.floor(n * mult);
}

function parseRateLimitWindow(window: string | number): number {
  if (typeof window === 'number') {
    if (!Number.isFinite(window) || window <= 0) {
      throw new VirtualPatchCompileError(`rateLimit.window must be positive, got ${window}`);
    }
    return Math.floor(window);
  }
  const trimmed = window.trim();
  const m = trimmed.match(/^(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hr|hours?)?$/i);
  if (!m) {
    throw new VirtualPatchCompileError(`rateLimit.window "${window}" not parseable`);
  }
  const n = parseInt(m[1]!, 10);
  const unit = (m[2] ?? 's').toLowerCase();
  if (unit.startsWith('h')) return n * 3600;
  if (unit.startsWith('m') && !unit.startsWith('min')) return n * 60; // "m" → minutes
  if (unit.startsWith('min')) return n * 60;
  return n;
}

function nearestPeriod(target: number): number {
  if ((ALLOWED_RATELIMIT_PERIODS as readonly number[]).includes(target)) return target;
  return ALLOWED_RATELIMIT_PERIODS.reduce((best, cur) =>
    Math.abs(cur - target) < Math.abs(best - target) ? cur : best,
  );
}

interface BuildArgs {
  ruleType: string;
  expression: string;
  action: RuleAction;
  description: string;
  ref: string;
  cveId: string;
  sourceField: string;
  schemaVersion: string;
}

function buildCustomRule(args: BuildArgs): CompiledRule {
  return {
    id: args.ref,
    description: args.description,
    expression: args.expression,
    action: args.action,
    enabled: true,
    // Virtual-patch mode mirrors the rule's action: `log` → observe, `block` → enforce.
    mode: args.action === 'block' ? 'enforce' : 'observe',
    xSecurity: {
      endpoint_id: `cve:${args.cveId}`,
      rule_type: args.ruleType,
      source_field: args.sourceField,
      confidence: 'MEDIUM',
      schema_version: args.schemaVersion,
    },
  };
}

interface BuildRateLimitArgs extends BuildArgs {
  period: number;
  requests: number;
}

function buildRateLimitRule(args: BuildRateLimitArgs): CompiledRule {
  return {
    id: args.ref,
    description: args.description,
    expression: args.expression,
    action: args.action,
    enabled: true,
    mode: args.action === 'block' ? 'enforce' : 'observe',
    ratelimit: {
      characteristics: ['ip.src'],
      period: args.period,
      requests_per_period: args.requests,
      mitigation_timeout: args.period,
      requests_to_origin: true,
    },
    xSecurity: {
      endpoint_id: `cve:${args.cveId}`,
      rule_type: args.ruleType,
      source_field: 'targetOverrides.firewall.virtualPatch.rateLimit',
      confidence: 'MEDIUM',
      schema_version: args.schemaVersion,
    },
  };
}
