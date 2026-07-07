/**
 * Per-field BunkerWeb setting builders.
 *
 * Each builder maps a slice of XSecurityPolicy → BunkerWeb settings entries.
 * BunkerWeb settings are flat key/value pairs the operator sets as per-service
 * compose env vars (`<SERVICE>_<KEY>=<value>` under multisite mode). Some
 * settings support indexed suffixes (`_1`, `_2`, …) for per-URL variants — we
 * use those to attach per-endpoint policies under a single service. The
 * generator surfaces these as commented hints at the bottom of
 * `configs/modsec/x-security.conf` (the only file BunkerWeb actually loads
 * via libmodsec is the SecRule block at the top).
 *
 * R2.3 mapping (see api-security-toolkit-prd.md):
 *   rateLimit    → USE_LIMIT_REQ + LIMIT_REQ_URL_<n>/LIMIT_REQ_RATE_<n>
 *   ipPolicy     → WHITELIST_IP / BLACKLIST_IP
 *   cors         → USE_CORS + CORS_ALLOW_ORIGIN / CORS_ALLOW_METHODS / ...
 *   maxBodySize  → MAX_CLIENT_SIZE
 *   contentType  → ALLOWED_MIME_TYPES (response/upload), ALLOWED_METHODS (per op)
 *   auth         → USE_AUTH_BASIC or proxy header check
 *   timeout      → CONNECT_TIMEOUT / SEND_TIMEOUT / READ_TIMEOUT
 */

import type {
  Authentication,
  Cors,
  IpPolicy,
  RateLimit,
  RequestPolicy,
  XSecurityPolicy
} from '@x-security/schema';

import { buildJwtNativeSettings } from './jwt.js';

/** XSecurityPolicy.timeout — re-declared because @x-security/schema does not re-export Timeout. */
export interface Timeout {
  connect?: number;
  read?: number;
  write?: number;
}

export type SettingValue = string | number | boolean;
export type SettingMap = Record<string, SettingValue>;

const DURATION_RE = /^(\d+)\s*(ms|s|m|h|d)$/i;

/**
 * BunkerWeb `LIMIT_REQ_RATE_*` expects the nginx limit_req_zone "rate" form:
 *   "<n>r/s" or "<n>r/m"
 * We convert any window ≤ 1m to per-second, otherwise per-minute.
 */
export function rateLimitToBunkerRate(rl: RateLimit): string {
  const m = DURATION_RE.exec(rl.window.trim());
  if (!m) return `${rl.requests}r/s`;
  const n = Number(m[1]);
  const unit = (m[2] ?? 's').toLowerCase();
  // Normalize to seconds
  const seconds =
    unit === 'ms' ? Math.max(1, Math.round(n / 1000)) :
    unit === 's' ? n :
    unit === 'm' ? n * 60 :
    unit === 'h' ? n * 3600 :
    /* d */          n * 86400;
  if (seconds <= 60) {
    const perSec = Math.max(1, Math.ceil(rl.requests / seconds));
    return `${perSec}r/s`;
  }
  const perMin = Math.max(1, Math.ceil((rl.requests / seconds) * 60));
  return `${perMin}r/m`;
}

/** Convert ByteSize like "10KB", "50MB", "1mb" → nginx-style "10k"/"50m"/"1m". */
export function byteSizeToNginx(size: string): string {
  const m = /^\s*(\d+)\s*([KMG]?)B?\s*$/i.exec(size);
  if (!m) return size;
  const n = m[1];
  const unit = (m[2] ?? '').toUpperCase();
  return `${n}${unit === '' ? '' : unit.toLowerCase()}`;
}

/** Milliseconds → seconds (rounded up, min 1). */
function msToSec(ms: number): number {
  return Math.max(1, Math.ceil(ms / 1000));
}

/**
 * Read the primary identifier from a RateLimit.identifier (which may be a
 * string, string[], or {components, combinator}). We only honor a primary of
 * `user-id` for the BW per-user keying path; everything else falls through to
 * the default `binary_remote_addr` keying that LIMIT_REQ_URL emits.
 */
function primaryIdentifier(rl: RateLimit): string | undefined {
  const id = rl.identifier;
  if (!id) return undefined;
  if (typeof id === 'string') return id;
  if (Array.isArray(id)) return id[0];
  return id.components?.[0];
}

export function buildRateLimitSettings(
  rl: RateLimit | RateLimit[] | undefined,
  url: string,
  index: number
): SettingMap {
  if (!rl) return {};
  const list = Array.isArray(rl) ? rl : [rl];
  if (list.length === 0) return {};
  const out: SettingMap = { USE_LIMIT_REQ: 'yes' };
  list.forEach((r, i) => {
    const n = index + i + 1;
    out[`LIMIT_REQ_URL_${n}`] = url;
    out[`LIMIT_REQ_RATE_${n}`] = rateLimitToBunkerRate(r);
    // Drift: rateLimit.identifier=user-id. BW's native LIMIT_REQ_URL keys
    // every entry on $binary_remote_addr (one shared zone per server). For
    // per-principal limits we emit a CUSTOM_CONF_HTTP_* snippet declaring a
    // dedicated limit_req_zone keyed on $http_x_forwarded_user, plus a
    // marker that the operator wires to nginx (DEPLOYMENT.md recipe). The
    // primary LIMIT_REQ_URL_n entry stays as defense-in-depth IP-keyed
    // ceiling — both layers fire, the stricter wins per request.
    if (primaryIdentifier(r) === 'user-id') {
      const zoneName = `lazy_user_${n}`;
      const rate = rateLimitToBunkerRate(r);
      out[`CUSTOM_CONF_HTTP_LIMIT_REQ_USER_${n}`] =
        `# x-security: per-user-id rate limit for ${url} (drift closure)\n` +
        `limit_req_zone $http_x_forwarded_user zone=${zoneName}:10m rate=${rate};\n`;
      // Marker the operator can grep for to wire the matching `limit_req`
      // directive into the per-location server block.
      out[`X_SECURITY_USER_RL_ZONE_${n}`] = `${zoneName}@${url}`;
    }
  });
  return out;
}

export function buildIpPolicySettings(ip: IpPolicy | undefined): SettingMap {
  if (!ip) return {};
  const out: SettingMap = {};
  if (Array.isArray(ip.allow) && ip.allow.length > 0) {
    out.USE_WHITELIST = 'yes';
    out.WHITELIST_IP = ip.allow.join(' ');
  }
  if (Array.isArray(ip.deny) && ip.deny.length > 0) {
    out.USE_BLACKLIST = 'yes';
    out.BLACKLIST_IP = ip.deny.join(' ');
  }
  return out;
}

export function buildCorsSettings(cors: Cors | undefined): SettingMap {
  if (!cors) return {};
  const out: SettingMap = { USE_CORS: 'yes' };
  if (cors.allowedOrigins?.length) out.CORS_ALLOW_ORIGIN = cors.allowedOrigins.join(' ');
  if (cors.allowedMethods?.length) out.CORS_ALLOW_METHODS = cors.allowedMethods.join(', ');
  if (cors.allowedHeaders?.length) out.CORS_ALLOW_HEADERS = cors.allowedHeaders.join(', ');
  if (cors.exposeHeaders?.length) out.CORS_EXPOSE_HEADERS = cors.exposeHeaders.join(', ');
  if (typeof cors.maxAge === 'number') out.CORS_MAX_AGE = String(cors.maxAge);
  if (typeof cors.credentials === 'boolean') out.CORS_ALLOW_CREDENTIALS = cors.credentials ? 'yes' : 'no';
  return out;
}

export function buildRequestSettings(req: RequestPolicy | undefined): SettingMap {
  if (!req) return {};
  const out: SettingMap = {};
  if (req.maxBodySize) out.MAX_CLIENT_SIZE = byteSizeToNginx(req.maxBodySize);
  if (req.contentType?.length) out.ALLOWED_MIME_TYPES = req.contentType.join(' ');
  // Per-field upload mime allowlist (e.g. file uploads)
  if (req.schema) {
    const fileMimes: string[] = [];
    for (const v of Object.values(req.schema)) {
      if (v?.allowedMimeTypes?.length) fileMimes.push(...v.allowedMimeTypes);
    }
    if (fileMimes.length > 0) {
      const merged = new Set<string>([
        ...(req.contentType ?? []),
        ...fileMimes
      ]);
      out.ALLOWED_MIME_TYPES = Array.from(merged).join(' ');
    }
  }
  return out;
}

/**
 * Escape a string for safe inclusion inside a ModSecurity `SecRule ... "..."`
 * action list. Double quotes and backslashes must be escaped.
 */
function escMsec(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Build the ModSecurity v3 rule snippet that enforces `auth` at phase 1.
 *
 * - bearer-jwt / oauth2: header-presence check only. BunkerWeb's libmodsec3
 *   has no Lua support, so signature validation is impossible at the WAF
 *   layer; the generator surfaces a structured warning telling the operator
 *   to put an OIDC sidecar / Kong+OIDC in front of BunkerWeb for real
 *   verification. The id:990000..990011 chain still denies unauth requests.
 * - api-key: require a non-empty value in the configured header.
 * - basic: require `Authorization: Basic <base64>` (BunkerWeb's USE_AUTH_BASIC
 *   handles credential validation; we only fail-fast on missing header).
 *
 * Rule IDs use the 990000-block to avoid colliding with the OWASP CRS range.
 */
export function buildAuthModSecRules(auth: Authentication): string {
  const lines: string[] = [
    `# x-security-generated authentication rules (${auth.type})`,
    // initcol is for ip/global/resource collections; tx is request-scoped and
    // does not need initcol. We just zero the relevant TX var directly.
    `SecAction "id:990000,phase:1,nolog,pass,setvar:tx.jwt_invalid=0"`
  ];
  const header = auth.headerName ?? (auth.type === 'api-key' ? 'X-API-Key' : 'Authorization');

  switch (auth.type) {
    case 'bearer-jwt':
    case 'oauth2': {
      // Header-presence chain only. Signature validation requires Lua, which
      // BunkerWeb's libmodsec3 lacks — see DEPLOYMENT.md warnings.
      lines.push(
        `SecRule REQUEST_HEADERS:${escMsec(header)} "@rx ^Bearer (.+)$" ` +
          `"id:990010,phase:1,nolog,pass,capture,setvar:tx.bearer_token=%{TX.1}"`,
        `SecRule &TX:bearer_token "@eq 0" ` +
          `"id:990011,phase:1,deny,status:401,log,msg:'x-security: missing bearer token (signature NOT verified — external auth layer required)'"`
      );
      if (auth.type === 'oauth2' && auth.scopes?.length) {
        lines.push(`# oauth2 required scopes (NOT enforced here — needs external auth): ${auth.scopes.join(' ')}`);
      }
      break;
    }
    case 'api-key': {
      lines.push(
        `SecRule REQUEST_HEADERS:${escMsec(header)} "@rx ^.+$" ` +
          `"id:990020,phase:1,nolog,pass,setvar:tx.api_key_present=1"`,
        `SecRule &TX:api_key_present "@eq 0" ` +
          `"id:990021,phase:1,deny,status:401,log,msg:'x-security: missing API key (${escMsec(header)})'"`
      );
      break;
    }
    case 'basic': {
      lines.push(
        `SecRule REQUEST_HEADERS:Authorization "!@rx ^Basic [A-Za-z0-9+/=]+$" ` +
          `"id:990030,phase:1,deny,status:401,log,msg:'x-security: missing/invalid Basic credentials'"`
      );
      break;
    }
    case 'mtls':
    case 'none':
      // handled outside of ModSecurity
      break;
  }
  return lines.join('\n') + '\n';
}

export function buildAuthSettings(auth: Authentication | undefined): SettingMap {
  if (!auth || auth.type === 'none') return {};
  const out: SettingMap = {};
  switch (auth.type) {
    case 'basic': {
      out.USE_AUTH_BASIC = 'yes';
      out.USE_MODSECURITY = 'yes';
      out.CUSTOM_CONF_MODSEC_1 = buildAuthModSecRules(auth);
      break;
    }
    case 'bearer-jwt':
    case 'oauth2':
    case 'api-key': {
      const header = auth.headerName ?? (auth.type === 'api-key' ? 'X-API-Key' : 'Authorization');
      out.USE_MODSECURITY = 'yes';
      out.CUSTOM_CONF_MODSEC_1 = buildAuthModSecRules(auth);
      // Markers consumed by the Lua verifier via os.getenv().
      out.X_SECURITY_AUTH_HEADER = header;
      out.X_SECURITY_AUTH_TYPE = auth.type;
      if (auth.jwksUri) out.X_SECURITY_JWKS_URI = String(auth.jwksUri);
      if (auth.issuer) out.X_SECURITY_AUTH_ISSUER = String(auth.issuer);
      if (auth.audience) out.X_SECURITY_AUTH_AUDIENCE = String(auth.audience);
      if (auth.type === 'oauth2' && auth.scopes?.length) {
        out.X_SECURITY_AUTH_SCOPES = auth.scopes.join(' ');
      }
      // Drift closure: BW 1.6+ ships nginx_jwt_module. When jwksUri is
      // present, layer the native USE_AUTH_JWT chain on top of the
      // header-presence SecRule. Both fire; the WAF chain stays in place as
      // defense-in-depth in case the native chain is disabled by the operator.
      const jwtSettings = buildJwtNativeSettings(auth);
      for (const [k, v] of Object.entries(jwtSettings)) out[k] = v;
      break;
    }
    case 'mtls':
      out.USE_CLIENT_SSL = 'yes';
      break;
  }
  return out;
}

export function buildTimeoutSettings(t: Timeout | undefined): SettingMap {
  if (!t) return {};
  const out: SettingMap = {};
  if (typeof t.connect === 'number') out.CONNECT_TIMEOUT = `${msToSec(t.connect)}s`;
  if (typeof t.write === 'number') out.SEND_TIMEOUT = `${msToSec(t.write)}s`;
  if (typeof t.read === 'number') out.READ_TIMEOUT = `${msToSec(t.read)}s`;
  return out;
}

export function buildMethodSettings(method: string): SettingMap {
  return { ALLOWED_METHODS: method.toUpperCase() };
}

/** Merge multiple SettingMaps; later wins. */
export function mergeSettings(...maps: SettingMap[]): SettingMap {
  return Object.assign({}, ...maps);
}

/**
 * Build the full per-endpoint setting block. Indexed suffix counters are passed
 * in by the caller so that per-URL settings don't collide across endpoints.
 */
export function buildEndpointSettings(
  policy: XSecurityPolicy,
  url: string,
  method: string,
  rlIndex: number
): SettingMap {
  return mergeSettings(
    buildMethodSettings(method),
    buildAuthSettings(policy.authentication),
    buildRateLimitSettings(policy.rateLimit, url, rlIndex),
    buildIpPolicySettings(policy.ipPolicy),
    buildCorsSettings(policy.cors),
    buildRequestSettings(policy.request),
    buildTimeoutSettings(policy.timeout)
  );
}
