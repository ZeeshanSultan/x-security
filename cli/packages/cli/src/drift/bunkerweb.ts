/**
 * BunkerWeb drift detector (file-mode only).
 *
 * Strategy (wave-8, after wave-6 reshape):
 *  The bunkerweb generator now emits `configs/modsec/x-security.conf` — a
 *  plain ModSecurity rule file with a trailing block of commented operator
 *  hints (`# KEY=value    # from: <endpoints>`). Those KEY=value comments
 *  carry the env-var settings that previously lived in `variables.env`.
 *
 *  Drift is detected by:
 *   1. Re-generating the expected `.conf` from the SpecIR.
 *   2. Parsing both `.conf` files into a settings map by scanning for
 *      `# KEY=value` comment lines AND active `SecAction`/`SecRule` directives
 *      (so a `SecAction id:990000` is treated as proof the auth block is
 *      present, separately from the commented `# USE_MODSECURITY=yes` hint).
 *   3. Diffing key-by-key with the same severity rules as before
 *      (auth-missing=CRITICAL, rate-limit weakening=CRITICAL, etc.).
 *
 *  Limitation: BunkerWeb settings actually live in the operator's compose
 *  env-vars, not in this `.conf` file. The drift detector here checks that
 *  the deployed `.conf` *advertises* the same intended values; verifying the
 *  live container's env is the verifier's job (see packages/cli/src/verify/).
 */
import { readFile } from 'node:fs/promises';
import type { SpecIR } from '@x-security/core';
import type { DriftIssue, DriftReport, DriftSeverity } from '../reporters/types.js';
import { bunkerwebGenerator } from '../generators/bunkerweb/index.js';

export interface BunkerWebDriftOptions {
  filePath: string;
  yamlContent?: string;
}

const SYNTHETIC_HOST = 'default';

// Rough byte-size conversion for MAX_CLIENT_SIZE / similar nginx-style values.
function nginxSizeToBytes(v: unknown): number | null {
  if (typeof v === 'number') return v;
  if (typeof v !== 'string') return null;
  const m = /^(\d+(?:\.\d+)?)\s*([kmg]?)$/i.exec(v.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? '').toLowerCase();
  const mult = unit === 'g' ? 1024 ** 3 : unit === 'm' ? 1024 ** 2 : unit === 'k' ? 1024 : 1;
  return Math.round(n * mult);
}

// LIMIT_REQ_RATE_<n> values are nginx leaky-bucket strings: e.g. "30r/m".
function rateToPerSecond(v: unknown): number | null {
  if (typeof v !== 'string') return null;
  const m = /^(\d+)\s*r\/(s|m|h)$/i.exec(v.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = (m[2] ?? 's').toLowerCase();
  return unit === 'h' ? n / 3600 : unit === 'm' ? n / 60 : n;
}

function severityForKey(key: string, expected: unknown, actual: unknown): DriftSeverity {
  if (
    (key === 'USE_AUTH_BASIC' ||
      key === 'USE_MODSECURITY' ||
      // Accept legacy WRIT_* keys on pre-rebrand deployments (back-compat).
      key === 'X_SECURITY_AUTH_TYPE' || key === 'WRIT_AUTH_TYPE' ||
      key === 'X_SECURITY_JWKS_URI' || key === 'WRIT_JWKS_URI' ||
      key === 'USE_CLIENT_SSL' ||
      key === 'X_SECURITY_AUTH_HEADER' || key === 'WRIT_AUTH_HEADER' ||
      key === 'MODSECURITY_RULES_FILE') &&
    (actual === undefined || actual === 'no' || actual === '')
  ) {
    return 'CRITICAL';
  }
  if (/^LIMIT_REQ_RATE_\d+$/.test(key)) {
    const e = rateToPerSecond(expected);
    const a = rateToPerSecond(actual);
    if (e !== null && a !== null && a > e) return 'CRITICAL';
    return 'MEDIUM';
  }
  if (key === 'USE_LIMIT_REQ' && (actual === undefined || actual === 'no')) return 'CRITICAL';
  if (
    (key === 'USE_WHITELIST' || key === 'WHITELIST_IP') &&
    (actual === undefined || actual === 'no' || actual === '')
  ) {
    return 'HIGH';
  }
  if (key === 'MAX_CLIENT_SIZE') {
    const e = nginxSizeToBytes(expected);
    const a = nginxSizeToBytes(actual);
    if (e !== null && a !== null && a > e) return 'HIGH';
    return 'MEDIUM';
  }
  if (key === 'CORS_ALLOW_ORIGIN') {
    const expSet = new Set(String(expected ?? '').split(/\s+/).filter(Boolean));
    const actSet = new Set(String(actual ?? '').split(/\s+/).filter(Boolean));
    for (const o of actSet) if (!expSet.has(o)) return 'HIGH';
    return 'MEDIUM';
  }
  if (key === 'USE_CORS' || /^CORS_/.test(key)) return 'HIGH';
  if (/^(CONNECT|SEND|READ)_TIMEOUT$/.test(key)) return 'MEDIUM';
  if (key === 'ALLOWED_METHODS' || key === 'ALLOWED_MIME_TYPES') return 'MEDIUM';
  return 'LOW';
}

/**
 * Parse a x-security-emitted bunkerweb `.conf` file into a flat settings map.
 *
 * Recognized lines:
 *   `# KEY=value    # from: ...`  → settings[KEY] = value
 *   `SecAction "id:990000,...`    → settings[__has_auth_rules] = "yes"
 *
 * Anything else is ignored. Operators can hand-edit values via the
 * KEY=value comment as long as `# from:` provenance is preserved.
 */
function parseConf(raw: string): Record<string, string> {
  const settings: Record<string, string> = {};
  if (raw.trim() === '') return settings;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('SecAction') || trimmed.startsWith('SecRule')) {
      settings.__has_auth_rules = 'yes';
      continue;
    }
    // `# KEY=value    # from: ...` — first `#` then KEY=VALUE, optional second `# from:`.
    const m = /^#\s*([A-Z_][A-Z0-9_]*)=([^#]*?)(?:\s+#.*)?$/.exec(trimmed);
    if (!m) continue;
    const key = m[1]!;
    // Skip lines that aren't real env keys (heuristic: must contain at least one digit/letter value).
    const val = m[2]!.trim();
    if (key.length === 0) continue;
    settings[key] = val;
  }
  return settings;
}

function diffSettings(
  host: string,
  expected: Record<string, string>,
  actual: Record<string, string>
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  const label = `service:${host}`;

  for (const [k, v] of Object.entries(expected)) {
    const a = actual[k];
    if (a === undefined) {
      issues.push({
        endpoint: label,
        field: k,
        severity: severityForKey(k, v, undefined),
        expected: v,
        actual: undefined,
        message: `BunkerWeb setting "${k}" missing on deployed config "${host}"`
      });
      continue;
    }
    if (a !== v) {
      issues.push({
        endpoint: label,
        field: k,
        severity: severityForKey(k, v, a),
        expected: v,
        actual: a,
        message: `BunkerWeb setting "${k}" drift on "${host}" (spec=${JSON.stringify(v)} actual=${JSON.stringify(a)})`
      });
    }
  }
  for (const k of Object.keys(actual)) {
    if (k === '__has_auth_rules') continue;
    if (!(k in expected)) {
      issues.push({
        endpoint: label,
        field: k,
        severity: 'LOW',
        expected: undefined,
        actual: actual[k],
        message: `Unknown BunkerWeb setting "${k}" on deployed config "${host}" (not in spec)`
      });
    }
  }
  return issues;
}

export async function detectBunkerWebDrift(
  spec: SpecIR,
  opts: BunkerWebDriftOptions
): Promise<DriftReport> {
  const raw = opts.yamlContent ?? (await readFile(opts.filePath, 'utf8'));

  const expectedArtifacts = await Promise.resolve(bunkerwebGenerator.generate(spec));
  // The primary artifact is configs/modsec/x-security.conf (artifact[0]).
  const expectedConf = expectedArtifacts[0]?.content ?? '';

  const expected = parseConf(expectedConf);
  const actual = parseConf(raw);

  const issues: DriftIssue[] = [];

  // Treat an empty deployed config (no settings, no SecRules) as a missing service.
  if (Object.keys(actual).length === 0) {
    issues.push({
      endpoint: `service:${SYNTHETIC_HOST}`,
      field: 'service',
      severity: 'CRITICAL',
      expected: 'present',
      actual: 'missing',
      message: `BunkerWeb config "${SYNTHETIC_HOST}" not configured on gateway`
    });
  } else {
    issues.push(...diffSettings(SYNTHETIC_HOST, expected, actual));
  }

  return {
    kind: 'drift',
    target: 'bunkerweb',
    gatewaySource: opts.filePath,
    issues
  };
}
