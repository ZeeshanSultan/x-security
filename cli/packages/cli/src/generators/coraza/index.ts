/**
 * Coraza / ModSecurity generator.
 *
 * x-security emits ModSecurity-compatible rules for four runtime profiles:
 * `modsec-nginx`, `modsec-apache`, `coraza-go`, `coraza-spoa`. The profile
 * is selected via `--coraza-engine` (default: `modsec-nginx`, the most
 * common deployment shape — see REPORT-v3 §3 for why this default matters).
 *
 * Output shape per profile:
 *   - libmodsecurity3 engines (`modsec-nginx`, `modsec-apache`):
 *       * `x-security.conf`       — plain ModSecurity directives, no YAML
 *                                   wrapper. Loaded via `Include`.
 *       * `x-security-include.conf` — operator-facing snippet showing the
 *                                   right include path per engine.
 *       * `WARNINGS.md`           — structured downgrade/skip warnings if any.
 *   - Coraza-Go engines (`coraza-go`, `coraza-spoa`):
 *       * `coraza.yml`            — YAML wrapper with a `directives: |`
 *                                   block, fed into `coraza.NewWAFConfig()
 *                                   .WithDirectives(...)`.
 *
 * Engine globals (`SecRuleEngine On`, `SecDefaultAction "phase:N,..."`) are
 * only emitted when `profile.emitEngineGlobals === true`. The libmodsecurity3
 * engines reject a second `SecDefaultAction` per phase because the bundled
 * `crs-setup.conf` already calls it; emitting our own would crash the load
 * (REPORT-v3 §3.2).
 */

import { dump } from 'js-yaml';
import type { ConfigArtifact, EndpointIR, Generator, SpecIR, CapabilityMatrix } from '@x-security/core';
import { buildPolicyRules, parseByteSize } from './rules.js';
import { collectSsrfPolicyWarnings } from '../ssrf-policy-check.js';
import { buildHaproxyStickTables, parseCorazaPeers, type HaproxyPeer } from './templates/haproxy-stick-tables.js';
import { buildModsecNginxServerConf } from './templates/modsec-nginx-server.js';
import {
  getEngineProfile,
  MODSEC_NGINX_PROFILE,
  type CorazaEngineName,
  type CorazaEngineProfile,
  type EngineWarning,
} from './profiles.js';

// The *generator's* internal default stays `coraza-go` for backwards
// compatibility (golden snapshots, library consumers). The *CLI* default
// (x-security.ts `--coraza-engine`) is `modsec-nginx` per REPORT-v3 §3,
// and the CLI calls `configure({ engine })` to flip the profile before
// invoking generate(). DEFAULT_ENGINE (`modsec-nginx`) is re-exported for
// the bin layer to consume.
export { DEFAULT_ENGINE } from './profiles.js';
const SINGLETON_DEFAULT_ENGINE: CorazaEngineName = 'coraza-go';

const VERSION = '0.1.0';

/** W10-7: any endpoint declares a rateLimit (drives SecCollectionTimeout emission). */
function anyEndpointHasRateLimit(endpoints: EndpointIR[]): boolean {
  return endpoints.some((ep) => {
    const rl = ep.policy.rateLimit;
    if (!rl) return false;
    return Array.isArray(rl) ? rl.length > 0 : true;
  });
}

/** C-1: any endpoint declares response.schema field constraints or stripUnknownFields. */
function anyEndpointNeedsResponseInspection(endpoints: EndpointIR[]): boolean {
  return endpoints.some((ep) => {
    const r = ep.policy.response;
    if (!r) return false;
    if (r.stripUnknownFields === true) return true;
    if (r.schema) {
      for (const ps of Object.values(r.schema)) {
        if ((typeof ps.maxLength === 'number' && ps.maxLength > 0) || typeof ps.pattern === 'string') {
          return true;
        }
      }
    }
    return false;
  });
}

/** Compute the smallest declared maxBodySize across endpoints (or null). */
function smallestBodyLimit(endpoints: EndpointIR[]): number | null {
  let min: number | null = null;
  for (const ep of endpoints) {
    const v = parseByteSize(ep.policy.request?.maxBodySize);
    if (Number.isFinite(v) && v > 0) {
      if (min === null || v < min) min = v;
    }
  }
  return min;
}

function buildDirectives(spec: SpecIR, profile: CorazaEngineProfile, warnings: EngineWarning[]): string {
  const lines: string[] = [];
  // Preserve the legacy banner verbatim for coraza-go so the existing golden
  // snapshot stays byte-stable. New profiles get the engine-aware banner.
  if (profile.name === 'coraza-go') {
    lines.push('# x-security → Coraza v3.x — auto-generated. DO NOT EDIT BY HAND.');
    lines.push(`# generator: x-security-coraza v${VERSION}`);
    lines.push(`# source: ${spec.info.title} ${spec.info.version}`);
  } else {
    lines.push('# x-security → Coraza/ModSecurity — auto-generated. DO NOT EDIT BY HAND.');
    lines.push(`# generator: x-security-coraza v${VERSION}`);
    lines.push(`# engine:    ${profile.name}`);
    lines.push(`# source:    ${spec.info.title} ${spec.info.version}`);
  }
  lines.push('');

  const needResponseInspect = anyEndpointNeedsResponseInspection(spec.endpoints);
  const needRateLimitCollection = anyEndpointHasRateLimit(spec.endpoints);

  // W10-7: when any endpoint declares a rateLimit AND we're on a Coraza-Go-
  // family engine using the IP persistent collection, surface a structured
  // warning about the in-memory per-process collection store. Multi-instance
  // (HA) deployments must front the WAF with a Redis-backed CollectionStore
  // or move enforcement to HAProxy stick-tables for true cross-request limits.
  if (
    needRateLimitCollection &&
    (profile.name === 'coraza-go' || profile.name === 'coraza-spoa') &&
    profile.supportsPersistentCollections &&
    profile.legalCollections.has('ip')
  ) {
    warnings.push({
      severity: 'downgrade',
      engine: profile.name,
      endpoint: '*',
      reason:
        `[coraza:cross-request-rate-limit] in-memory collection store is per-process; ` +
        `for HA, add a Redis-backed CollectionStore — see coraza-spoa docs.`,
      detail: { mechanism: 'initcol:ip', backing: 'in-memory-per-process' },
    });
  }

  if (profile.emitEngineGlobals) {
    lines.push('# ── Engine globals ───────────────────────────────────────────');
    lines.push('SecRuleEngine On');
    lines.push('SecRequestBodyAccess On');
    if (needResponseInspect && profile.supportsResponseBodyAccess) {
      // C-1: response inspection requires phase-4 access to RESPONSE_BODY.
      lines.push('SecResponseBodyAccess On');
      lines.push('SecResponseBodyMimeType application/json application/vnd.api+json');
      lines.push('SecResponseBodyLimit 524288');
      lines.push('SecResponseBodyLimitAction ProcessPartial');
    } else {
      lines.push('SecResponseBodyAccess Off');
    }

    const cap = smallestBodyLimit(spec.endpoints);
    if (cap !== null) {
      lines.push(`# smallest maxBodySize across endpoints (per-endpoint caps still apply)`);
      lines.push(`SecRequestBodyLimit ${cap}`);
      lines.push(`SecRequestBodyNoFilesLimit ${cap}`);
      lines.push(`SecRequestBodyLimitAction Reject`);
    } else {
      lines.push('SecRequestBodyLimit 13107200');
      lines.push('SecRequestBodyNoFilesLimit 131072');
      lines.push('SecRequestBodyLimitAction Reject');
    }
    lines.push('SecDefaultAction "phase:1,log,auditlog,deny,status:403"');
    lines.push('SecDefaultAction "phase:2,log,auditlog,deny,status:403"');
    // W10-7: persistent-collection TTL for cross-request rate-limit counters.
    // Only relevant when at least one endpoint emits an IP-collection counter.
    if (needRateLimitCollection && profile.supportsPersistentCollections && profile.legalCollections.has('ip')) {
      lines.push('# W10-7: persistent collection garbage-collect window for IP-keyed rate-limit counters.');
      lines.push('SecCollectionTimeout 600');
    }
    lines.push('');
  } else {
    // libmodsecurity3 path. The host (crs-setup.conf) already sets engine
    // globals + SecDefaultAction for both phases. Emitting our own would
    // crash with "SecDefaultActions can only be placed once per phase".
    lines.push('# ── Engine globals: SKIPPED (host owns SecDefaultAction) ─────');
    lines.push(`# profile=${profile.name}: host config (crs-setup.conf) already calls`);
    lines.push('# SecDefaultAction per phase; emitting our own would crash the load.');
    lines.push('# Per-endpoint rules below carry explicit `phase:N,deny,status:NNN`.');
    if (needResponseInspect && profile.supportsResponseBodyAccess) {
      // C-1: SecResponseBodyAccess is repeatable (unlike SecDefaultAction);
      // toggling it On here overrides the host's likely-default Off. This is
      // necessary for the phase-4 SecRules below to ever see RESPONSE_BODY.
      lines.push('# C-1: response-body inspection required by spec; toggling on.');
      lines.push('SecResponseBodyAccess On');
      lines.push('SecResponseBodyMimeType application/json application/vnd.api+json');
      lines.push('SecResponseBodyLimit 524288');
      lines.push('SecResponseBodyLimitAction ProcessPartial');
    }
    if (needRateLimitCollection && profile.supportsPersistentCollections && profile.legalCollections.has('ip')) {
      lines.push('# W10-7: persistent collection garbage-collect window for IP-keyed rate-limit counters.');
      lines.push('SecCollectionTimeout 600');
    }
    lines.push('');
  }

  // ── Per-endpoint rule blocks (stable order) ───────────────────────────
  const sorted = [...spec.endpoints].sort((a, b) =>
    a.method === b.method ? a.path.localeCompare(b.path) : a.method.localeCompare(b.method)
  );

  for (const ep of sorted) {
    lines.push(`# ════════════════════════════════════════════════════════════`);
    lines.push(`# ${ep.method} ${ep.path}  (operationId: ${ep.operationId})`);
    lines.push(`# ════════════════════════════════════════════════════════════`);
    const rules = buildPolicyRules(ep, profile, warnings);
    if (rules.length === 0) {
      lines.push('# (no enforceable policy fields)');
    } else {
      for (const r of rules) {
        lines.push(r);
        lines.push('');
      }
    }
  }

  return lines.join('\n');
}

/** Include-snippet shown to the operator so they know the right mount path. */
function buildIncludeSnippet(profile: CorazaEngineProfile): string {
  if (profile.name === 'modsec-nginx') {
    // For the `owasp/modsecurity-crs:nginx` image, the durable hook is to
    // append `Include /etc/modsecurity.d/x-security.conf` to setup.conf
    // AFTER the image's entrypoint scripts have regenerated it. The image
    // regenerates setup.conf + modsecurity-override.conf from templates at
    // every container start (REPORT-v3 §3.1), so mounting over those files
    // directly does NOT survive a restart.
    //
    // DO NOT mount x-security.conf into /etc/nginx/conf.d/ — that path is
    // auto-included by nginx itself, which can't parse SecRule directives.
    //
    // See deployment-recipes/modsec-nginx.md for the entrypoint wrapper.
    return [
      '# === x-security include for owasp/modsecurity-crs:nginx ===',
      '#',
      '# Mount x-security.conf to /etc/modsecurity.d/x-security.conf and use',
      '# the entrypoint wrapper documented in deployment-recipes/modsec-nginx.md',
      '# to append this Include line after the image regenerates setup.conf:',
      '#',
      'Include /etc/modsecurity.d/x-security.conf',
      '',
    ].join('\n');
  }
  if (profile.name === 'modsec-apache') {
    return [
      '# Drop into Apache config (e.g. /etc/apache2/mods-enabled/security2.conf):',
      'Include /etc/modsecurity/x-security.conf',
      '',
    ].join('\n');
  }
  // Coraza-Go / SPOA — directives are loaded programmatically. No include needed.
  return '';
}

function buildWarningsDoc(profile: CorazaEngineProfile, warnings: EngineWarning[]): string {
  const lines: string[] = [
    `# x-security → ${profile.name} — emission warnings`,
    '',
    `Generator version: ${VERSION}`,
    `Engine profile:    ${profile.name}`,
    '',
  ];
  if (warnings.length === 0) {
    lines.push('No downgrades or skips. All emitted rules use the engine\'s native syntax.');
    return lines.join('\n');
  }
  const downgrades = warnings.filter((w) => w.severity === 'downgrade');
  const skips = warnings.filter((w) => w.severity === 'skip');
  if (downgrades.length) {
    lines.push(`## Downgrades (${downgrades.length})`, '');
    lines.push('These rules were emitted but a feature was lossy-translated:');
    lines.push('');
    for (const w of downgrades) {
      lines.push(`- **${w.endpoint}** — ${w.reason}`);
    }
    lines.push('');
  }
  if (skips.length) {
    lines.push(`## Skips (${skips.length})`, '');
    lines.push('These policy fields were NOT emitted because the engine cannot express them:');
    lines.push('');
    for (const w of skips) {
      lines.push(`- **${w.endpoint}** — ${w.reason}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export interface CorazaGeneratorOptions {
  /** Which engine flavour to emit for. Default: `modsec-nginx`. */
  engine?: CorazaEngineName;
  /** W13-D: `--coraza-peers "name1:host1:port1,name2:host2:port2"` raw value.
   *  When supplied (and engine is a coraza-go family), the emitted
   *  haproxy-stick-tables.cfg gets a `peers x-security` section + each
   *  stick-table opts in. Malformed strings → loud warning + omit peers. */
  peers?: string;
}

export interface CorazaGenerator extends Generator {
  /** CLI calls this after parsing `--coraza-engine`. */
  configure(opts: CorazaGeneratorOptions): void;
  /** Structured warnings from the most recent generate() call. */
  readonly lastWarnings: readonly string[];
  /** The active profile (for tests + diagnostics). */
  readonly engine: CorazaEngineName;
}

export function createCorazaGenerator(opts: CorazaGeneratorOptions = {}): CorazaGenerator {
  let engineName: CorazaEngineName = opts.engine ?? SINGLETON_DEFAULT_ENGINE;
  let peersRaw: string | undefined = opts.peers;
  let lastWarnings: string[] = [];

  const gen: CorazaGenerator = {
    name: 'coraza',
    targets: ['coraza-v3', 'coraza', 'modsec-nginx', 'modsec-apache'],

    configure(o: CorazaGeneratorOptions): void {
      if (o.engine !== undefined) engineName = o.engine;
      if (o.peers !== undefined) peersRaw = o.peers;
    },

    get lastWarnings(): readonly string[] {
      return lastWarnings;
    },

    get engine(): CorazaEngineName {
      return engineName;
    },

    generate(spec: SpecIR): ConfigArtifact[] {
      const profile = getEngineProfile(engineName);
      const warnings: EngineWarning[] = [];
      const directives = buildDirectives(spec, profile, warnings);
      lastWarnings = warnings.map((w) => `[coraza:${w.engine}:${w.severity}] ${w.endpoint}: ${w.reason}`);

      // Spec-hygiene: surface SSRF-policy gaps. The Coraza-SPOA wave-9 incident
      // (vAPI /vapi/serversurfer) was caused by a missing blockPrivateRanges.
      const ssrfWarnings = collectSsrfPolicyWarnings(spec, 'coraza');
      if (ssrfWarnings.length > 0) {
        lastWarnings = [...lastWarnings, ...ssrfWarnings.map((w) => w.message)];
      }

      const artifacts: ConfigArtifact[] = [];

      if (profile.fileExt === 'conf') {
        // libmodsecurity3 path — emit the .conf directly.
        artifacts.push({
          path: 'x-security.conf',
          content: directives + '\n',
          format: 'conf',
        });
        const snippet = buildIncludeSnippet(profile);
        if (snippet) {
          artifacts.push({
            path: 'x-security-include.conf',
            content: snippet,
            format: 'conf',
          });
        }
      } else {
        // Coraza-Go path — wrap in YAML so the Go consumer can read metadata.
        // Field order matches the legacy golden: generator, version, source,
        // directives. `engine` is only added for non-default profiles to keep
        // the byte-stable coraza-go snapshot passing.
        const meta: Record<string, unknown> = {
          generator: 'x-security-coraza',
          version: VERSION,
        };
        if (profile.name !== 'coraza-go') meta['engine'] = profile.name;
        meta['source'] = { title: spec.info.title, version: spec.info.version };
        meta['directives'] = directives;
        const yaml = dump(meta, { lineWidth: -1, noRefs: true });
        artifacts.push({
          path: 'coraza.yml',
          content: yaml,
          format: 'yaml',
        });
      }

      // W11: HAProxy stick-tables sibling artifact for Coraza-Go-family engines.
      // The runtime rejects setvar on the IP collection, so cross-request RL
      // genuinely cannot live inside the Coraza ruleset for SPOA deployments —
      // emit a separate haproxy-stick-tables.cfg the operator merges into
      // their haproxy.cfg. Only fires when at least one endpoint declares
      // rateLimit; libmodsec3 engines keep their native IP-collection path.
      if (
        (profile.name === 'coraza-spoa' || profile.name === 'coraza-go') &&
        anyEndpointHasRateLimit(spec.endpoints)
      ) {
        const peerList: HaproxyPeer[] = parseCorazaPeers(peersRaw, profile.name, warnings);
        const haproxyCfg = buildHaproxyStickTables(spec, profile.name, warnings, peerList);
        if (haproxyCfg) {
          artifacts.push({
            path: 'haproxy-stick-tables.cfg',
            content: haproxyCfg + '\n',
            format: 'conf',
          });
          // Refresh lastWarnings to include any composite-identifier downgrades
          // emitted while walking the rate-limits (preserve already-appended
          // SSRF warnings by re-appending them after the rebuild).
          const ssrfTail = ssrfWarnings.map((w) => w.message);
          lastWarnings = [
            ...warnings.map((w) => `[coraza:${w.engine}:${w.severity}] ${w.endpoint}: ${w.reason}`),
            ...ssrfTail,
          ];
        }
      }

      // modsec-nginx server-side directives (timeouts / TLS / lifecycle).
      // SecRules cannot enforce proxy_*_timeout or ssl_protocols — those
      // belong to nginx itself. Emit ONLY for the modsec-nginx profile so
      // Coraza-Go / SPOA / Apache deployments don't get a stray nginx conf.
      if (profile === MODSEC_NGINX_PROFILE) {
        const serverConf = buildModsecNginxServerConf(spec);
        if (serverConf) {
          artifacts.push({
            path: 'nginx-server.conf',
            content: serverConf + '\n',
            format: 'conf',
          });
        }
      }

      if (warnings.length > 0) {
        artifacts.push({
          path: 'WARNINGS.md',
          content: buildWarningsDoc(profile, warnings),
          format: 'text',
        });
      }

      return artifacts;
    },

    capabilities(): CapabilityMatrix {
      const profile = getEngineProfile(engineName);
      const userIdRateLimit = profile.supportsArbitraryCollection ? 'full' : 'partial';
      // v0.7 edge-enforceable residuals — gated on the SAME profile flags the
      // emitters (v07-rules.ts) gate on, so the matrix never claims a status the
      // emitted config can't back (Rule D-1).
      //   accountLockout: needs a persistent, non-TX named collection
      //   (initcol:global + expirevar). True on libmodsec3; coraza-go/spoa honor
      //   setvar on TX only → the cross-request counter is skipped → partial.
      const statefulNamedCollection =
        profile.supportsPersistentCollections && profile.legalCollections.has('global');
      return {
        fields: {
          'authentication.type':         'partial',
          'authentication.jwksUri':      'unsupported',
          'authentication.scopes':       'unsupported',
          'authentication.issuer':       'unsupported',
          'authentication.audience':     'unsupported',
          'authorization':               'partial',
          'rateLimit':                   userIdRateLimit,
          'rateLimit.identifier.ip':     'full',
          'rateLimit.identifier.user-id': userIdRateLimit,
          'rateLimit.identifier.api-key': userIdRateLimit,
          'timeout':                     'unsupported',
          'cacheable':                   'unsupported',
          'cors':                        'unsupported',
          'mtls':                        'unsupported',
          'ipPolicy.allow':              'full',
          'ipPolicy.deny':               'full',
          'request.contentType':         'full',
          'request.maxBodySize':         'full',
          'request.schema.minLength':    'full',
          'request.schema.maxLength':    'full',
          'request.schema.fixedLength':  'full',
          'request.schema.min':          'full',
          'request.schema.max':          'full',
          'request.schema.pattern':      'full',
          // OPP-2 (API8): every format-bearing SemanticType (email/uuid/integer/
          // float/boolean/date/datetime/ip-address/phone/url) emits an enforcing
          // `!@rx <format>` SecRule (TYPE_VALIDATION_RX in rules.ts, RE2-safe).
          // The four format-free types (string/name/free-text/binary) impose no
          // syntactic constraint and are recorded in UNCONSTRAINED_TYPES, so the
          // type space is provably exhaustive — no silent fall-through. → full.
          'request.schema.type':         'full',
          // OPP-2 (API8): two enforcing rules — request Content-Type header
          // (`!@rx ^(allowed)(;.*)?$` → 415) and multipart per-part MIME
          // (FILES_TMP_CONTENT/FILES → 415). Both genuinely reject a disallowed
          // MIME on the surfaces it can appear. → full.
          'request.schema.allowedMimeTypes': 'full',
          'request.schema.domainAllowlist':  'full',         // W19-A: SecRule id:980000+
          // W19 / v0.7: per-arg injection guards (request.schema.<f>.injectionGuard).
          // Each declared sink emits a real enforcing phase-2 SecRule over BOTH
          // ARGS:<field> (query/form) AND ARGS:json.<field> (JSON body), id range
          // 430000-438999:
          //   sql        → @detectSQLi (Coraza built-in; all 4 profiles ship it)
          //   os-command → !@rx shell-metachar allowlist (deny on ; | & $ ` etc.)
          //   code-eval  → !@rx same metachar allowlist (shared eval/exec alphabet)
          //   nosql      → @rx Mongo operator-token denylist ($where/$gt/$ne/…)
          //   xpath      → @rx query-metachar denylist ('"()[]/= ::, and/or)
          //   ldap       → @rx filter-metachar denylist (()&|* and \NN escapes)
          //   xss        → @detectXSS (Coraza built-in; all 4 profiles ship it)
          //   deserialization → @rx serialized-object-preamble denylist
          //                     (node-serialize _$$ND_FUNC$$_, Java rO0, PHP O:n:,
          //                      python pickle \x80 opcode frame) [v0.7]
          //   ai-prompt  → @rx LLM prompt-injection marker denylist (jailbreak /
          //                system-prompt-leak / role-override). Distinct tag
          //                x-security-prompt → SSEC-PROMPT (NOT SSEC-INJECTION) [v0.7]
          // Every sink is a real enforcing matcher on all four profiles (sql/xss
          // need the dedicated operator, present on all shipping engines; the rest
          // are plain RE2-safe @rx). → full.
          'request.schema.injectionGuard':   'full',
          // OPP-2 (API6): Content-Type-guarded strict ARGS_NAMES allowlist
          // (`!@rx ^json\.(allowlist)$` → 403). The Content-Type guard removes
          // the prior false-403-on-query/form-args defect, so it genuinely
          // rejects unknown top-level JSON body keys (mass-assignment). Nested
          // keys are out of scope (mass-assignment binds at the top level). → full.
          'request.denyUnknownFields':   'full',
          'request.allowedFields':       'partial',
          // v0.8 (API6): request.serializeBy + concurrencyLimit. A crude
          // SecCollection short-window same-key cap (buildSerializeByRules) —
          // edge serialization only, NOT an in-handler mutex; it cannot make
          // the upstream handler transaction-atomic. Per the schema disclaimer
          // ("edge serialization only — does NOT provide in-handler transaction
          // atomicity") this is 'partial', never 'full'. The matching jwt.sub /
          // claim.* key shape is not extractable by the WAF and is skipped
          // override-only with a warning, but the body/query/header-keyed case
          // genuinely emits an enforcing counter → partial.
          'request.serializeBy':         'partial',
          'request.concurrencyLimit':    'partial',
          // v0.8 (SSEC-STORAGE): request.dataAtRest is ADVISORY-ONLY. The WAF
          // never sees the DB write, so it compiles to NOTHING enforcing — we
          // emit a commented advisory block only and the reporter drives the
          // out-of-band SSEC-STORAGE finding. Hard-pinned override-only on every
          // target (never full, never partial) per the schema contract.
          'request.dataAtRest':          'override-only',
          // C-1: response-body inspection via SecResponseBodyAccess + phase-4 SecRules.
          // Per-field constraints (maxLength / pattern) are emitted as regex
          // checks over the JSON body — heuristic but catches the obvious
          // BOPLA / data-exposure leak the corpus tests for. stripUnknownFields
          // is partial: emits deny-on-unknown (true strip requires Lua).
          'response':                    'partial',
          // OPP-4 (API3): phase-4 RESPONSE_BODY SecRules ARE emitted for typed
          // response constraints (maxLength, pattern) — see
          // buildResponseInspectionRules. They stay 'partial', NOT 'full',
          // because the matchers are regex-over-the-raw-JSON-body heuristics,
          // not a real JSON parser: pretty-printed bodies, unicode-escaped
          // quotes, and nested structures evade them (documented in rules.ts).
          // Per Rule D-1 a heuristic the code itself calls fragile must not be
          // advertised as fully enforcing. Explicit key (not just child rollup)
          // so the verdict is self-documenting.
          'response.schema':             profile.supportsResponseBodyAccess ? 'partial' : 'unsupported',
          'response.schema.maxLength':   profile.supportsResponseBodyAccess ? 'partial' : 'unsupported',
          'response.schema.pattern':     profile.supportsResponseBodyAccess ? 'partial' : 'unsupported',
          'response.stripUnknownFields': profile.supportsResponseBodyAccess ? 'partial' : 'unsupported',
          'response.contentType':        'partial',
          'supportsResponseBodyAccess':  profile.supportsResponseBodyAccess ? 'full' : 'unsupported',
          'deprecated':                  'partial',
          'sunsetDate':                  'partial',
          'replacementEndpoint':         'partial',
          'cors.credentials':            'partial',
          'cors.exposeHeaders':          'partial',
          'cors.maxAge':                 'partial',
          'csrf':                        'partial',
          'request.duplicateParamPolicy': 'partial',
          'timeout.connect':             profile.name === 'modsec-nginx' ? 'partial' : 'unsupported',
          'timeout.read':                profile.name === 'modsec-nginx' ? 'partial' : 'unsupported',
          'timeout.write':               profile.name === 'modsec-nginx' ? 'partial' : 'unsupported',
          'tls.minVersion':              profile.name === 'modsec-nginx' ? 'partial' : 'unsupported',
          'tls.allowedCipherSuites':     profile.name === 'modsec-nginx' ? 'partial' : 'unsupported',
          // v0.8 (API4): graphql.staticLimits — coarse, NON-PARSING GraphQL
          // guards over the raw body (buildGraphqlStaticLimitRules):
          // disableIntrospection (deny on __schema/__type), maxAliases and
          // batchLimit (crude token counts). These are genuine enforcing
          // SecRules that need no GraphQL parser, so 'partial' is honest and
          // backed by real config. maxDepth / maxComplexity need a real parse
          // and are explicitly skipped (not faked) — so this is 'partial', never
          // 'full'.
          'graphql.staticLimits':        'partial',
          // v0.8 (API1 BOLA / API5 BFLA): graphql.operations[].authz is
          // OVERRIDE-ONLY. Per-resolver authorization requires an operator-
          // supplied GraphQL-aware processor (the WAF cannot parse the query and
          // bind the resolved object to an identity claim per operation). We emit
          // commented scaffolding ONLY — no enforcing SecRule — so this can never
          // be 'full' or 'partial'.
          'graphql.operations.authz':    'override-only',
          // v0.7 (API2:2023): body-carried password strength. phase:2 `!@rx`
          // strength SecRules on ARGS:json.password|ARGS:password (minLength/
          // uppercase/digit/symbol) + a `@rx` blocklist deny → 422. Plain @rx,
          // no engine-specific capability needed, so a real enforcing rule is
          // emitted on every profile. → full.
          'authentication.passwordPolicy': 'full',
          // v0.7 (API2:2023): stateful failed-login lockout. A persistent named
          // collection (initcol:global) keyed on the identifier, incremented on
          // each >=400 auth response, denied at @gt attempts → 429. FULL only
          // where the engine can host a cross-request named collection
          // (libmodsec3). coraza-go/spoa honor setvar on the per-transaction TX
          // collection ONLY, so the counter can't survive across requests — the
          // emitter SKIPS it + warns rather than ship a counter that never trips
          // (Rule D-1). → full on libmodsec3, partial on coraza-go/spoa.
          'authentication.accountLockout': statefulNamedCollection ? 'full' : 'partial',
          // v0.7 (API3:2023): JSON-hijacking defense. phase:4 RESPONSE_BODY
          // `@rx ^\s*\[` rejecting a bare top-level array → 500. FULL where the
          // engine implements SecResponseBodyAccess; an engine without phase:4
          // body access cannot inspect the response at all, so the emitter skips
          // + warns. → full where supportsResponseBodyAccess, else unsupported.
          'response.forbidArrayRoot': profile.supportsResponseBodyAccess ? 'full' : 'unsupported',
          // v0.7 (API6:2023): idempotency-key replay defense. Two halves — the
          // header-presence check (→400) is a stateless &REQUEST_HEADERS test,
          // FULL on every profile; the replay-dedupe half needs the same
          // persistent named collection as accountLockout and is emitted only
          // where available. Even where both halves emit, this is PARTIAL: it
          // stops cross-request replay but NOT concurrent in-flight races (no
          // atomic check-and-set at the WAF — that lives in the handler/store).
          // Per the schema disclaimer this is never 'full'. → partial.
          'request.idempotencyKey': 'partial',
          // v0.7 (SSEC-AUDIT): declarative audit/access logging. We emit the
          // SecAuditLog opt-in (log,auditlog on a phase:5 endpoint rule for the
          // request/response events) and, when piiRedaction is set, a
          // ctl:auditLogParts that DROPS the body parts so pii body fields never
          // reach the log. PARTIAL — per-event sink routing, arbitrary
          // http-collector sinks, and field-level (keep-body) masking are not
          // expressible at the WAF (the audit log is part-granular); those are
          // surfaced as an operator note, not faked. → partial.
          'logging':                     'partial',
        },
      };
    },
  };

  return gen;
}

/** Default singleton — wired into the generator registry. */
export const corazaGenerator: CorazaGenerator = createCorazaGenerator();

export default corazaGenerator;
