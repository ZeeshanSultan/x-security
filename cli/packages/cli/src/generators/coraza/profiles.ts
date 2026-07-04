/**
 * Coraza engine profiles.
 *
 * Writ's Coraza generator targets four distinct runtimes that all speak
 * a ModSecurity-compatible directive syntax but differ in *which subset* of
 * that syntax they accept and *how* the rules are loaded:
 *
 *   - `modsec-nginx`   ModSecurity-nginx + libmodsecurity3 (3.0.x). Loads via
 *                       `Include /etc/modsecurity.d/...conf`. Bundled with the
 *                       `owasp/modsecurity-crs:nginx` image. Rejects YAML, rejects
 *                       a second `SecDefaultAction` per phase, and only accepts
 *                       `ip` / `global` / `resource` as `initcol` collection names.
 *   - `modsec-apache`  ModSecurity for Apache httpd. Same libmodsecurity3, same
 *                       collection restrictions; loaded via `Include` from
 *                       `mod_security2.conf`.
 *   - `coraza-go`      Coraza WAF v3.x linked into a Go binary. Rules are passed
 *                       as a single directive string via `WithDirectives(...)`,
 *                       supports arbitrary collection names, and is happy to
 *                       re-set engine globals.
 *   - `coraza-spoa`    Coraza-SPOA bridge for HAProxy. Same directive surface
 *                       as `coraza-go` (it embeds the same library).
 *
 * Rule emission is parameterised by {@link CorazaEngineProfile}. Each rule
 * builder takes the profile and either emits the appropriate directive variant
 * or returns `null` plus a structured {@link EngineWarning}. **There is no
 * silent drop path** — if a feature cannot be expressed under the chosen
 * profile, the builder either downgrades (and warns) or skips (and warns
 * loudly). See `rules.ts` for the per-builder behaviour matrix.
 */

export type CorazaEngineName = 'modsec-nginx' | 'modsec-apache' | 'coraza-go' | 'coraza-spoa';

export interface CorazaEngineProfile {
  /** Engine identity; selected via `--coraza-engine`. */
  name: CorazaEngineName;
  /** File extension for the primary emitted artifact. */
  fileExt: 'conf' | 'yml';
  /**
   * Whether to emit `SecRuleEngine On` / `SecRequestBodyAccess On` /
   * `SecDefaultAction` at the top of the file.
   *
   * False for `modsec-nginx` (and `modsec-apache`) because the bundled
   * `crs-setup.conf` already calls `SecDefaultAction` once per phase, and
   * libmodsecurity3 rejects a second call with
   *
   *   "SecDefaultActions can only be placed once per phase and configuration
   *    context".
   *
   * True for the Go-embedded engines, which start from a blank slate.
   */
  emitEngineGlobals: boolean;
  /**
   * Collection names that the engine accepts as the LHS of `initcol:`.
   *
   * libmodsecurity3 (3.0.x) only accepts `ip`, `global`, `resource`. Coraza-Go
   * additionally accepts `user`, `session`, and arbitrary identifiers — see
   * {@link supportsArbitraryCollection}.
   */
  legalCollections: ReadonlySet<string>;
  /**
   * Whether the engine accepts collection names outside `legalCollections`
   * (i.e. arbitrary user-defined collections like `user` or `tenant`).
   *
   * `true` for Coraza-Go; `false` for the libmodsecurity3 engines.
   */
  supportsArbitraryCollection: boolean;
  /**
   * Whether the body-allowlist rule should explicitly toggle the JSON body
   * processor via `ctl:requestBodyProcessor=JSON`.
   *
   * True for the libmodsecurity3 engines: the default body processor is
   * URL-encoded; without this `ctl` directive, JSON keys never end up in
   * `ARGS_NAMES` and the allowlist regex never matches anything. Coraza-Go's
   * built-in JSON content-type sniffing already routes JSON through the JSON
   * parser, so the `ctl` directive is redundant (but harmless).
   */
  jsonBodyProcessorCtl: boolean;
  /**
   * Whether the engine supports persistent (cross-request) collections via
   * `initcol` + `expirevar` for rate-limit counters. All four shipping
   * engines support this — Coraza-Go's documented `setvar`-on-TX restriction
   * (corazawaf/coraza setvar.go) applies to the *setvar action targeting
   * the TX collection* only; `initcol:ip=...` followed by `setvar:ip.X=+1`
   * via the persistent-collection write path is supported on both
   * libmodsecurity3 and Coraza v3.
   *
   * For the Go-embedded engines the in-memory backing is per-process — see
   * the generator-time warning. Operators running HA fleets need an external
   * collection store (Redis-backed).
   */
  supportsPersistentCollections: boolean;
  /**
   * Whether the engine ships the `@detectSQLi` operator. All four shipping
   * engines do (libmodsecurity3 native operator; Coraza v3 re-implements it).
   * Used by the standalone-SPOA SQLi heuristic emission for JSON body fields
   * when no CRS PL1 is bundled.
   */
  supportsDetectSQLi: boolean;
  /**
   * Whether the engine ships the `@detectXSS` operator. Mirrors
   * `supportsDetectSQLi`: all four shipping engines provide it natively
   * (libmodsecurity3 native operator; Coraza v3 re-implements it). Used by the
   * W19 injection-guard emission for the `xss` sink — the rule is skipped (not
   * placeholdered) on any future profile that lacks the operator (Rule D-1).
   */
  supportsDetectXSS: boolean;
  /**
   * Whether the engine implements `SecResponseBodyAccess` + the
   * `RESPONSE_BODY` variable in phase 4.
   *
   * All four currently-shipping engines (libmodsecurity3 ≥3.0.x, Coraza-Go,
   * Coraza-SPOA) implement this; the flag exists so a future profile (e.g. a
   * reduced-footprint Coraza embed) can declare itself non-conformant and the
   * C-1 response inspection emission will skip + warn rather than emit dead
   * rules. Documented cost: enabling phase-4 inspection runs the engine over
   * the response body, which on the libmodsecurity3 engines roughly costs an
   * extra 10-15% throughput (Trustwave benchmarks; varies by body size).
   */
  supportsResponseBodyAccess: boolean;
}

/** ModSecurity-nginx (libmodsecurity3) — the most common deployment. */
export const MODSEC_NGINX_PROFILE: CorazaEngineProfile = Object.freeze({
  name: 'modsec-nginx',
  fileExt: 'conf',
  emitEngineGlobals: false,
  legalCollections: new Set<string>(['ip', 'global', 'resource']),
  supportsArbitraryCollection: false,
  jsonBodyProcessorCtl: true,
  supportsPersistentCollections: true,
  supportsDetectSQLi: true,
  supportsDetectXSS: true,
  supportsResponseBodyAccess: true,
});

/** ModSecurity for Apache httpd — same libmodsecurity3 quirks. */
export const MODSEC_APACHE_PROFILE: CorazaEngineProfile = Object.freeze({
  name: 'modsec-apache',
  fileExt: 'conf',
  emitEngineGlobals: false,
  legalCollections: new Set<string>(['ip', 'global', 'resource']),
  supportsArbitraryCollection: false,
  jsonBodyProcessorCtl: true,
  supportsPersistentCollections: true,
  supportsDetectSQLi: true,
  supportsDetectXSS: true,
  supportsResponseBodyAccess: true,
});

/** Coraza WAF v3 linked into a Go binary — runtime enforces setvar TX-only
 *  (corazawaf/coraza setvar.go rejects any other collection with "expected
 *  collection TX", verified empirically against ghcr.io/corazawaf/coraza-spoa).
 *  Cross-request rate-limits cannot be expressed through Coraza alone on this
 *  engine — operators must front the WAF with HAProxy stick-tables.
 *  `supportsPersistentCollections=false` reflects this runtime reality. */
export const CORAZA_GO_PROFILE: CorazaEngineProfile = Object.freeze({
  name: 'coraza-go',
  fileExt: 'yml',
  emitEngineGlobals: true,
  legalCollections: new Set<string>(['tx']),
  supportsArbitraryCollection: false,
  jsonBodyProcessorCtl: false,
  supportsPersistentCollections: false,
  supportsDetectSQLi: true,
  supportsDetectXSS: true,
  supportsResponseBodyAccess: true,
});

/** Coraza-SPOA bridge for HAProxy — same library surface as coraza-go. */
export const CORAZA_SPOA_PROFILE: CorazaEngineProfile = Object.freeze({
  name: 'coraza-spoa',
  fileExt: 'yml',
  emitEngineGlobals: true,
  legalCollections: new Set<string>(['tx']),
  supportsArbitraryCollection: false,
  jsonBodyProcessorCtl: false,
  supportsPersistentCollections: false,
  supportsDetectSQLi: true,
  supportsDetectXSS: true,
  supportsResponseBodyAccess: true,
});

export const ENGINE_PROFILES: Readonly<Record<CorazaEngineName, CorazaEngineProfile>> = Object.freeze({
  'modsec-nginx': MODSEC_NGINX_PROFILE,
  'modsec-apache': MODSEC_APACHE_PROFILE,
  'coraza-go': CORAZA_GO_PROFILE,
  'coraza-spoa': CORAZA_SPOA_PROFILE,
});

export const DEFAULT_ENGINE: CorazaEngineName = 'modsec-nginx';

export function getEngineProfile(name: string): CorazaEngineProfile {
  const p = (ENGINE_PROFILES as Record<string, CorazaEngineProfile | undefined>)[name];
  if (!p) {
    throw new Error(
      `Unknown --coraza-engine "${name}". Known: ${Object.keys(ENGINE_PROFILES).join(', ')}.`
    );
  }
  return p;
}

/**
 * Severity for an emission warning.
 *
 * - `downgrade` — the rule was emitted but a feature was lossy-translated
 *   (e.g. `initcol:user=...` rewritten to `initcol:global=...`). Operator
 *   should see this in the report.
 * - `skip` — the rule could not be expressed and was omitted. **Loud**; the
 *   operator must know enforcement is missing for that field.
 */
export type WarningSeverity = 'downgrade' | 'skip';

export interface EngineWarning {
  severity: WarningSeverity;
  engine: CorazaEngineName;
  /** Endpoint identity (or `*` for top-level directives). */
  endpoint: string;
  /** Short human-readable reason — surfaced verbatim in `--strict-fidelity` reports. */
  reason: string;
  /** Free-form metadata (the original spec field, the downgrade target, etc.). */
  detail?: Record<string, string | number | boolean>;
}
