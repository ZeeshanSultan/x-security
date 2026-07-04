// `lazy migrate <spec> --from 0.4 --to 0.5 [--in-place|--out <path>] [--no-suggestions]`
//
// Pure spec-rewrite tool. The only auto-migration in v0.5 is
// `rateLimit.identifier: [a, b]` → `{components: [a, b], combinator: concat}`.
// Back-compat is preserved (the v0.5 schema still accepts bare arrays); the
// rewrite is cosmetic — it makes the combinator semantics explicit.
//
// Everything else surfaces as a stderr suggestion (no auto-rewrite). See the
// SUGGESTERS table below for the rule set.

import { readFile, writeFile } from 'node:fs/promises';
import * as yaml from 'js-yaml';

export type FromVersion = '0.4';
export type ToVersion = '0.5';

export interface MigrateOptions {
  from: FromVersion;
  to: ToVersion;
  /** Rewrite the input file in place. Mutually exclusive with `out`. */
  inPlace?: boolean;
  /** Write to this path. Mutually exclusive with `inPlace`. Default: <spec>.v0.5.yaml. */
  out?: string;
  /** Silence the stderr suggestion advisories. Auto-migrations still happen. */
  noSuggestions?: boolean;
}

export type Severity = 'info' | 'suggest';

export interface Change {
  severity: Severity;
  /** Dotted JSON-pointer-ish path to the location, e.g. `paths./vapi/x.get.x-security.rateLimit.identifier`. */
  location: string;
  message: string;
}

export interface MigrateResult {
  /** Auto-applied rewrites. */
  applied: Change[];
  /** Suggest-only advisories (no rewrite). Empty if `noSuggestions`. */
  suggestions: Change[];
  /** YAML of the (possibly rewritten) spec. */
  yaml: string;
  /** Resolved output path, or null if the caller asked for in-memory only. */
  writtenTo: string | null;
  /** True if any auto-migration was applied. Used by the bin layer for idempotence exit code. */
  changed: boolean;
}

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] as const;

const SUPPORTED_PAIRS: Array<[FromVersion, ToVersion]> = [['0.4', '0.5']];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// --------------------------------------------------------------------------
// Auto-migration: rateLimit.identifier bare-array → {components, combinator}
// --------------------------------------------------------------------------

interface IdentifierObject {
  components: string[];
  combinator: 'concat';
}

function migrateRateLimitIdentifier(
  xsec: Record<string, unknown>,
  loc: string,
  applied: Change[]
): void {
  const rl = xsec.rateLimit;
  if (!isPlainObject(rl)) return;
  const ident = rl.identifier;
  if (!Array.isArray(ident)) return; // scalar string stays as-is; only bare arrays migrate
  // Confirm it's a string[]; refuse if not (don't silently corrupt structured data).
  if (!ident.every((x) => typeof x === 'string')) {
    return;
  }
  const next: IdentifierObject = { components: ident as string[], combinator: 'concat' };
  rl.identifier = next;
  applied.push({
    severity: 'info',
    location: `${loc}.rateLimit.identifier`,
    message: `expanded bare array ${JSON.stringify(ident)} to {components: [...], combinator: concat}`
  });
}

// --------------------------------------------------------------------------
// Suggestions (stderr advisories — no rewrite)
// --------------------------------------------------------------------------

function suggestPrincipalNamespace(
  xsec: Record<string, unknown>,
  loc: string,
  suggestions: Change[]
): void {
  const authz = xsec.authorization;
  if (!isPlainObject(authz)) return;
  const rules = authz.rules;
  if (!Array.isArray(rules)) return;
  rules.forEach((rule, idx) => {
    if (!isPlainObject(rule)) return;
    const value = rule.value;
    if (!isPlainObject(value)) return;
    const ref = value.ref;
    if (typeof ref !== 'string') return;
    if (/^request\.(user|session)\./.test(ref)) {
      suggestions.push({
        severity: 'suggest',
        location: `${loc}.authorization.rules[${idx}].value.ref`,
        message: `"${ref}" uses request.user.*/request.session.*; consider principal.* namespace (v0.5). Manual review required — semantics may differ if your auth layer doesn't populate principal.`
      });
    }
  });
}

function suggestOutboundCalls(
  pathKey: string,
  opId: string | undefined,
  xsec: Record<string, unknown>,
  loc: string,
  suggestions: Change[]
): void {
  if ('outboundCalls' in xsec) return;
  const haystack = `${pathKey} ${opId ?? ''}`.toLowerCase();
  if (!/serversurfer|proxy|webhook/.test(haystack)) return;
  suggestions.push({
    severity: 'suggest',
    location: `${loc}.outboundCalls`,
    message: `endpoint name suggests outbound calls; consider declaring outboundCalls (v0.5) for upstream trust policy`
  });
}

function suggestJwtAlgorithms(
  xsec: Record<string, unknown>,
  loc: string,
  suggestions: Change[]
): void {
  const auth = xsec.authentication;
  if (!isPlainObject(auth)) return;
  if (auth.type !== 'bearer-jwt') return;
  if ('bannedAlgorithms' in auth || 'allowedAlgorithms' in auth) return;
  suggestions.push({
    severity: 'suggest',
    location: `${loc}.authentication`,
    message: `bearer-jwt without bannedAlgorithms/allowedAlgorithms; consider bannedAlgorithms: [none, HS256, HS384, HS512] to harden against JWT confusion`
  });
}

function suggestXxe(
  xsec: Record<string, unknown>,
  loc: string,
  suggestions: Change[]
): void {
  const req = xsec.request;
  if (!isPlainObject(req)) return;
  const ct = req.contentType;
  if (!Array.isArray(ct)) return;
  const hasXml = ct.some((t) => typeof t === 'string' && t.toLowerCase().includes('application/xml'));
  if (!hasXml) return;
  if ('disableExternalEntities' in req || 'disallowXml' in req) return;
  suggestions.push({
    severity: 'suggest',
    location: `${loc}.request`,
    message: `XML accepted in contentType; consider request.disableExternalEntities: true to defend against XXE`
  });
}

// --------------------------------------------------------------------------
// Walker
// --------------------------------------------------------------------------

function walkOperations(
  doc: unknown,
  noSuggestions: boolean
): { applied: Change[]; suggestions: Change[] } {
  const applied: Change[] = [];
  const suggestions: Change[] = [];
  if (!isPlainObject(doc)) return { applied, suggestions };
  const paths = doc.paths;
  if (!isPlainObject(paths)) return { applied, suggestions };

  for (const [pathKey, pathItem] of Object.entries(paths)) {
    if (!isPlainObject(pathItem)) continue;
    for (const m of METHODS) {
      const op = pathItem[m];
      if (!isPlainObject(op)) continue;
      const xsec = op['x-security'];
      if (!isPlainObject(xsec)) continue;
      const opId = typeof op.operationId === 'string' ? op.operationId : undefined;
      const loc = `paths.${pathKey}.${m}.x-security`;
      migrateRateLimitIdentifier(xsec, loc, applied);
      if (!noSuggestions) {
        suggestPrincipalNamespace(xsec, loc, suggestions);
        suggestOutboundCalls(pathKey, opId, xsec, loc, suggestions);
        suggestJwtAlgorithms(xsec, loc, suggestions);
        suggestXxe(xsec, loc, suggestions);
      }
    }
  }
  return { applied, suggestions };
}

// --------------------------------------------------------------------------
// Entry point
// --------------------------------------------------------------------------

function defaultSidecarPath(specPath: string, to: ToVersion): string {
  // foo.yaml -> foo.v0.5.yaml ; foo.yml -> foo.v0.5.yml ; otherwise append .v0.5.yaml
  const m = /^(.*?)(\.ya?ml)$/i.exec(specPath);
  if (m) return `${m[1]}.v${to}${m[2]}`;
  return `${specPath}.v${to}.yaml`;
}

export async function runMigrate(specPath: string, opts: MigrateOptions): Promise<MigrateResult> {
  const pair: [FromVersion, ToVersion] = [opts.from, opts.to];
  if (!SUPPORTED_PAIRS.some(([f, t]) => f === pair[0] && t === pair[1])) {
    throw new Error(
      `migrate: unsupported version pair --from ${opts.from} --to ${opts.to}. Supported: ${SUPPORTED_PAIRS.map(([f, t]) => `${f}->${t}`).join(', ')}`
    );
  }
  if (opts.inPlace && opts.out !== undefined) {
    throw new Error('migrate: --in-place and --out are mutually exclusive');
  }

  const raw = await readFile(specPath, 'utf8');
  const doc = yaml.load(raw);
  if (!isPlainObject(doc)) {
    throw new Error(`migrate: ${specPath} did not parse to a YAML object`);
  }

  const { applied, suggestions } = walkOperations(doc, opts.noSuggestions === true);
  const changed = applied.length > 0;
  const out = yaml.dump(doc, { lineWidth: 120, noRefs: true });

  let writtenTo: string | null = null;
  if (opts.inPlace) {
    // Idempotence: if nothing changed, do NOT touch the file. The bin layer
    // reports exit 1 on this case so CI can assert "no migration needed".
    if (changed) {
      await writeFile(specPath, out, 'utf8');
      writtenTo = specPath;
    }
  } else {
    const dest = opts.out ?? defaultSidecarPath(specPath, opts.to);
    await writeFile(dest, out, 'utf8');
    writtenTo = dest;
  }

  return { applied, suggestions, yaml: out, writtenTo, changed };
}
