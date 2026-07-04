// Internal types modelling Kong Gateway 3.x declarative (DBless) config.
// Reference: https://docs.konghq.com/gateway/latest/production/deployment-topologies/db-less-and-declarative-config/

export interface KongPlugin {
  name: string;
  id?: string;
  config?: Record<string, unknown>;
  enabled?: boolean;
  protocols?: string[];
  tags?: string[];
}

export interface KongRoute {
  name: string;
  paths: string[];
  methods?: string[];
  strip_path?: boolean;
  preserve_host?: boolean;
  plugins?: KongPlugin[];
  tags?: string[];
}

export interface KongService {
  name: string;
  url: string;
  connect_timeout?: number;
  read_timeout?: number;
  write_timeout?: number;
  routes: KongRoute[];
  plugins?: KongPlugin[];
  tags?: string[];
}

// ---- Consumers + per-plugin credentials (top-level declarative entities) ----
// Reference: https://docs.konghq.com/gateway/latest/production/deployment-topologies/db-less-and-declarative-config/
// OSS Kong's jwt/key-auth/acl/hmac-auth plugins all require a pre-provisioned
// Consumer; without these top-level entities the gateway 401s every request.

export interface KongConsumer {
  username: string;
  custom_id?: string;
  tags?: string[];
}

export interface KongJwtSecret {
  consumer: string; // username
  key: string;      // matches the JWT `iss` claim (key_claim_name)
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384';
  secret?: string;          // HS*
  rsa_public_key?: string;  // RS*/ES*
  tags?: string[];
}

export interface KongKeyAuthCredential {
  consumer: string;
  key: string;
  tags?: string[];
}

export interface KongHmacAuthCredential {
  consumer: string;
  username: string;
  secret: string;
  tags?: string[];
}

export interface KongAcl {
  consumer: string;
  group: string;
  tags?: string[];
}

export interface KongDeclarativeConfig {
  _format_version: string;
  _transform: boolean;
  // NOTE: spec→runtime divergences (HS256 downgrade, hmac-auth header
  // overrides, etc.) are NOT embedded here — Kong rejects unknown top-
  // level keys. The kong generator emits them as a YAML-commented
  // `# _writ_warnings:` block in the file header instead, so
  // `grep _writ_warnings kong.yml` and `grep '^# WARNING' kong.yml`
  // both surface them without breaking Kong's parser.
  services: KongService[];
  plugins?: KongPlugin[];
  consumers?: KongConsumer[];
  jwt_secrets?: KongJwtSecret[];
  keyauth_credentials?: KongKeyAuthCredential[];
  hmacauth_credentials?: KongHmacAuthCredential[];
  acls?: KongAcl[];
}

// Structured spec→runtime divergence record. Lives in the generated
// kong.yml under `_writ_warnings:` so operators have a single grep
// target for "what did Writ silently drop or downgrade?".
export interface WritWarning {
  field: string;       // e.g. "authentication.allowedAlgorithms"
  endpoint?: string;   // operationId (omit for spec-wide warnings)
  declared: string;    // what the spec asked for
  emitted: string;     // what the generator actually produced
  reason: string;      // why the gap exists
}

// Kong deployment topology — controls upstream URL rewriting + trusted-ip
// handling. Default "standalone" preserves legacy behavior (services use
// spec.servers[0].url).
export type KongDeployment =
  | 'standalone'
  | 'behind-proxy'
  | 'with-coraza'
  | 'with-istio';
