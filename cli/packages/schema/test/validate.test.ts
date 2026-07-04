import test from 'node:test';
import assert from 'node:assert/strict';
import { validateXSecurity, owaspMapping, SCHEMA_VERSION } from '../src/index.js';

test('schema version is 0.8.0', () => {
  assert.equal(SCHEMA_VERSION, '0.8.0');
});

test('OWASP mapping covers all 10 categories', () => {
  for (let i = 1; i <= 10; i++) {
    const key = `API${i}:2023`;
    assert.ok((owaspMapping as Record<string, unknown>)[key], `Missing ${key}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.2 baseline tests (preserved — existing policies must still validate)
// ─────────────────────────────────────────────────────────────────────────────

test('valid login policy passes (R1.6)', () => {
  const result = validateXSecurity({
    authentication: { type: 'none' },
    rateLimit: { requests: 5, window: '1m', identifier: 'ip', burst: 2 },
    request: {
      contentType: ['application/json'],
      maxBodySize: '10KB',
      schema: {
        email: { type: 'email', maxLength: 254, mitigates: ['API2:2023'] },
        password: { type: 'free-text', minLength: 8, maxLength: 128 }
      }
    },
    cacheable: false,
    timeout: { read: 5000 }
  });
  assert.equal(result.valid, true);
});

test('CORS wildcard + credentials is rejected (R1.9)', () => {
  const result = validateXSecurity({
    cors: { allowedOrigins: ['*'], credentials: true }
  });
  assert.equal(result.valid, false);
});

test('ipPolicy allow+deny mutual exclusivity (R1.13)', () => {
  const result = validateXSecurity({
    ipPolicy: { allow: ['10.0.0.0/8'], deny: ['1.2.3.4/32'] }
  });
  assert.equal(result.valid, false);
});

test('OAuth2 requires scopes (R1.4)', () => {
  const result = validateXSecurity({
    authentication: { type: 'oauth2' }
  });
  assert.equal(result.valid, false);
});

test('rateLimit duration format enforced (R1.6)', () => {
  const bad = validateXSecurity({
    rateLimit: { requests: 100, window: '1 minute' }
  });
  assert.equal(bad.valid, false);

  const good = validateXSecurity({
    rateLimit: { requests: 100, window: '1m' }
  });
  assert.equal(good.valid, true);
});

test('multi-tier rate limits (R1.18)', () => {
  const result = validateXSecurity({
    rateLimit: [
      { requests: 10, window: '1m', when: 'unauthenticated' },
      { requests: 100, window: '1m', when: 'authenticated' }
    ]
  });
  assert.equal(result.valid, true);
});

test('VarRef pattern accepts ${ENV} and $vault.path (R1.14)', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: '${JWKS_ENDPOINT}',
      issuer: '$vault.auth/issuer',
      allowedAlgorithms: ['RS256']
    }
  });
  assert.equal(result.valid, true);
});

test('Timeout must be positive (R1.7)', () => {
  const result = validateXSecurity({ timeout: { read: 0 } });
  assert.equal(result.valid, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.3 additions
// ─────────────────────────────────────────────────────────────────────────────

// PW-1: RuleRef
test('v0.3 PW-1: RuleRef value (jwt.sub vs resource.ownerId) is valid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [
        { field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }
      ]
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 PW-1: RuleRef with bad prefix is invalid', () => {
  // v0.5 S-10 widened the allowed namespaces — pick a namespace that's still NOT in the set.
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [
        { field: 'x', operator: 'equals', value: { ref: 'env.SOMETHING' } }
      ]
    }
  });
  assert.equal(result.valid, false);
});

// #2: Authentication.allowedAlgorithms
test('v0.3 #2: bearer-jwt with RS256 allowlist is valid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://example.com/.well-known/jwks.json',
      allowedAlgorithms: ['RS256', 'ES256']
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #2: bearer-jwt missing allowedAlgorithms is invalid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://example.com/.well-known/jwks.json'
    }
  });
  assert.equal(result.valid, false);
});

test('v0.3 #2: HS256 is rejected (asymmetric only)', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://example.com/.well-known/jwks.json',
      allowedAlgorithms: ['HS256']
    }
  });
  assert.equal(result.valid, false);
});

// #3: Authorization.resourceLookup
test('v0.3 #3: resourceLookup is valid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      resourceLookup: {
        endpoint: '/users/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId']
      },
      rules: [
        { field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } }
      ]
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #3: resourceLookup missing expose is invalid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      resourceLookup: { endpoint: '/users/{id}', identifierFrom: 'request.params.id' },
      rules: [{ field: 'x', operator: 'equals', value: 'y' }]
    }
  });
  assert.equal(result.valid, false);
});

// #4: csrf
test('v0.3 #4: csrf origin-check with allowedOrigins is valid', () => {
  const result = validateXSecurity({
    csrf: { method: 'origin-check', allowedOrigins: ['https://app.example.com'] }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #4: csrf double-submit needs tokenHeader+tokenCookie', () => {
  const ok = validateXSecurity({
    csrf: { method: 'double-submit', tokenHeader: 'X-CSRF-Token', tokenCookie: 'csrf_token' }
  });
  assert.equal(ok.valid, true);

  const bad = validateXSecurity({
    csrf: { method: 'double-submit', tokenHeader: 'X-CSRF-Token' }
  });
  assert.equal(bad.valid, false);
});

test('v0.3 #4: csrf origin-check missing allowedOrigins is invalid', () => {
  const result = validateXSecurity({ csrf: { method: 'origin-check' } });
  assert.equal(result.valid, false);
});

// #5: response.cookies
test('v0.3 #5: response.cookies.defaults is valid', () => {
  const result = validateXSecurity({
    response: {
      cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 3600 } }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #5: response.cookies.defaults with bad sameSite is invalid', () => {
  const result = validateXSecurity({
    response: { cookies: { defaults: { sameSite: 'Sometimes' } } }
  });
  assert.equal(result.valid, false);
});

// PW-2 #6: denyUnknownFields
test('v0.3 #6: request.denyUnknownFields true is valid', () => {
  const result = validateXSecurity({
    request: { denyUnknownFields: true, schema: { id: { type: 'uuid' } } }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #6: request.denyUnknownFields wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional bad type
    request: { denyUnknownFields: 'yes' }
  });
  assert.equal(result.valid, false);
});

// #7: request.signature
test('v0.3 #7: webhook HMAC signature is valid', () => {
  const result = validateXSecurity({
    request: {
      signature: {
        algorithm: 'hmac-sha256',
        headerName: 'X-Signature',
        secretRef: '${WEBHOOK_SECRET}',
        body: 'raw',
        timestampHeader: 'X-Timestamp',
        timestampToleranceSeconds: 300
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #7: signature with tolerance over 3600 is invalid', () => {
  const result = validateXSecurity({
    request: {
      signature: {
        algorithm: 'hmac-sha256',
        headerName: 'X-Signature',
        secretRef: '${WEBHOOK_SECRET}',
        body: 'raw',
        timestampToleranceSeconds: 99999
      }
    }
  });
  assert.equal(result.valid, false);
});

// #8: request.allowedHosts
test('v0.3 #8: allowedHosts is valid', () => {
  const result = validateXSecurity({
    request: { allowedHosts: ['api.example.com'] }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #8: allowedHosts wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { allowedHosts: 'api.example.com' }
  });
  assert.equal(result.valid, false);
});

// #9: duplicateParamPolicy
test('v0.3 #9: duplicateParamPolicy reject is valid', () => {
  const result = validateXSecurity({
    request: { duplicateParamPolicy: 'reject' }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #9: duplicateParamPolicy unknown value is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { duplicateParamPolicy: 'merge' }
  });
  assert.equal(result.valid, false);
});

// #10: headerInjectionGuard
test('v0.3 #10: headerInjectionGuard true is valid', () => {
  const result = validateXSecurity({ request: { headerInjectionGuard: true } });
  assert.equal(result.valid, true);
});

test('v0.3 #10: headerInjectionGuard wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { headerInjectionGuard: 1 }
  });
  assert.equal(result.valid, false);
});

// #11: pathCanonicalization
test('v0.3 #11: pathCanonicalization true is valid', () => {
  const result = validateXSecurity({ request: { pathCanonicalization: true } });
  assert.equal(result.valid, true);
});

test('v0.3 #11: pathCanonicalization wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { pathCanonicalization: 'on' }
  });
  assert.equal(result.valid, false);
});

// #12: ParamSchema binary upload fields
test('v0.3 #12: binary upload with magicByteCheck, extensionAllowlist, denyDoubleExtension is valid', () => {
  const result = validateXSecurity({
    request: {
      schema: {
        avatar: {
          type: 'binary',
          allowedMimeTypes: ['image/png', 'image/jpeg'],
          maxSize: '2MB',
          magicByteCheck: true,
          extensionAllowlist: ['.png', '.jpg', '.jpeg'],
          denyDoubleExtension: true
        }
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #12: extensionAllowlist without leading dot is invalid', () => {
  const result = validateXSecurity({
    request: {
      schema: { avatar: { type: 'binary', extensionAllowlist: ['png'] } }
    }
  });
  assert.equal(result.valid, false);
});

// #13: response.headers
test('v0.3 #13: full response.headers block is valid', () => {
  const result = validateXSecurity({
    response: {
      headers: {
        csp: "default-src 'self'; script-src 'self'",
        hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
        frameOptions: 'DENY',
        contentTypeOptions: 'nosniff',
        referrerPolicy: 'strict-origin-when-cross-origin',
        permissionsPolicy: 'camera=(), microphone=()',
        coop: 'same-origin',
        coep: 'require-corp',
        corp: 'same-origin',
        cacheControl: 'no-store'
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #13: frameOptions ALLOWALL is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    response: { headers: { frameOptions: 'ALLOWALL' } }
  });
  assert.equal(result.valid, false);
});

test('v0.3 #13: hsts requires maxAge', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    response: { headers: { hsts: { includeSubDomains: true } } }
  });
  assert.equal(result.valid, false);
});

// #14: Cacheable.unkeyedHeadersStrip
test('v0.3 #14: cacheable.unkeyedHeadersStrip is valid', () => {
  const result = validateXSecurity({
    cacheable: {
      enabled: true,
      ttl: 60,
      unkeyedHeadersStrip: ['Cookie', 'Authorization']
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #14: unkeyedHeadersStrip on boolean cacheable is rejected', () => {
  // boolean form has no place to hang the field; we assert that the object form
  // is the only acceptable carrier — accidentally putting unkeyedHeadersStrip
  // alongside a stray field is caught by additionalProperties: false on the object branch.
  const result = validateXSecurity({
    cacheable: {
      enabled: true,
      // @ts-expect-error intentional unknown
      unkeyedHeadersStrip: 'Cookie'
    }
  });
  assert.equal(result.valid, false);
});

// #15: graphql
test('v0.3 #15: graphql limits are valid', () => {
  const result = validateXSecurity({
    graphql: {
      maxDepth: 10,
      maxComplexity: 1000,
      maxAliases: 15,
      batchLimit: 10,
      disableIntrospection: true,
      allowedOperations: ['query', 'mutation']
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #15: empty graphql block is invalid (minProperties:1)', () => {
  const result = validateXSecurity({ graphql: {} });
  assert.equal(result.valid, false);
});

test('v0.3 #15: maxDepth over 50 is invalid', () => {
  const result = validateXSecurity({ graphql: { maxDepth: 100 } });
  assert.equal(result.valid, false);
});

// #16: websocket
test('v0.3 #16: websocket with origins is valid', () => {
  const result = validateXSecurity({
    websocket: {
      allowedOrigins: ['https://app.example.com'],
      maxMessageSize: '64KB',
      messageRateLimit: { messages: 100, window: '1s' },
      maxConnectionsPerIdentifier: 5,
      idleTimeout: '5m'
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #16: websocket missing allowedOrigins is invalid', () => {
  // @ts-expect-error intentional
  const result = validateXSecurity({ websocket: { maxMessageSize: '64KB' } });
  assert.equal(result.valid, false);
});

// #17: botProtection
test('v0.3 #17: botProtection with turnstile is valid', () => {
  const result = validateXSecurity({
    botProtection: {
      provider: 'turnstile',
      secretRef: '${TURNSTILE_SECRET}',
      threshold: 0.7,
      mode: 'enforce'
    }
  });
  assert.equal(result.valid, true);
});

test('v0.3 #17: botProtection threshold over 1 is invalid', () => {
  const result = validateXSecurity({
    botProtection: {
      provider: 'recaptcha',
      secretRef: '${RECAPTCHA_SECRET}',
      threshold: 1.5,
      mode: 'observe'
    }
  });
  assert.equal(result.valid, false);
});

test('v0.3 #17: botProtection missing mode is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    botProtection: { provider: 'hcaptcha', secretRef: '${HCAPTCHA_SECRET}' }
  });
  assert.equal(result.valid, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.4 additions (S-1..S-8)
// ─────────────────────────────────────────────────────────────────────────────

// S-1: custom-token auth
test('v0.4 S-1: custom-token with headerName + tokenFormat is valid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'custom-token',
      headerName: 'X-API-Token',
      tokenFormat: 'opaque',
      validationEndpoint: 'https://auth.example.com/introspect'
    }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-1: custom-token missing tokenFormat is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional missing required
    authentication: { type: 'custom-token', headerName: 'X-API-Token' }
  });
  assert.equal(result.valid, false);
});

test('v0.4 S-1: bearer-jwt still requires jwksUri + allowedAlgorithms (regression)', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    authentication: { type: 'bearer-jwt', jwksUri: 'https://e.com/jwks.json' }
  });
  assert.equal(result.valid, false);
});

// S-2: bannedAlgorithms
test('v0.4 S-2: bannedAlgorithms with HS256 + none is valid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://e.com/jwks.json',
      allowedAlgorithms: ['RS256'],
      bannedAlgorithms: ['HS256', 'HS384', 'HS512', 'none']
    }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-2: allowed and banned overlap (RS256 in both) is invalid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://e.com/jwks.json',
      allowedAlgorithms: ['RS256', 'ES256'],
      bannedAlgorithms: ['RS256', 'none']
    }
  });
  assert.equal(result.valid, false);
});

// S-3: request.allowedMethods
test('v0.4 S-3: request.allowedMethods is valid', () => {
  const result = validateXSecurity({
    request: { allowedMethods: ['GET', 'POST'] }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-3: request.allowedMethods with TRACE is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { allowedMethods: ['TRACE'] }
  });
  assert.equal(result.valid, false);
});

// S-4: ParamSchema.blockPrivateRanges
test('v0.4 S-4: ParamSchema.blockPrivateRanges true is valid', () => {
  const result = validateXSecurity({
    request: {
      schema: { webhookUrl: { type: 'url', blockPrivateRanges: true } }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-4: blockPrivateRanges wrong type is invalid', () => {
  const result = validateXSecurity({
    request: {
      // @ts-expect-error intentional
      schema: { webhookUrl: { type: 'url', blockPrivateRanges: 'yes' } }
    }
  });
  assert.equal(result.valid, false);
});

// S-5: XXE flags
test('v0.4 S-5: disableExternalEntities + disallowXml is valid', () => {
  const result = validateXSecurity({
    request: { disableExternalEntities: true, disallowXml: true }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-5: disallowXml wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    request: { disallowXml: 'yes' }
  });
  assert.equal(result.valid, false);
});

// S-6: composite rateLimit.identifier
test('v0.4 S-6: composite identifier array is valid', () => {
  const result = validateXSecurity({
    rateLimit: { requests: 10, window: '1m', identifier: ['ip', 'user-id'] }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-6: single-element identifier array is invalid (minItems 2)', () => {
  const result = validateXSecurity({
    rateLimit: { requests: 10, window: '1m', identifier: ['ip'] }
  });
  assert.equal(result.valid, false);
});

test('v0.4 S-6: duplicate component in identifier array is invalid', () => {
  const result = validateXSecurity({
    rateLimit: { requests: 10, window: '1m', identifier: ['ip', 'ip'] }
  });
  assert.equal(result.valid, false);
});

test('v0.4 S-6: string identifier (back-compat) still works', () => {
  const result = validateXSecurity({
    rateLimit: { requests: 10, window: '1m', identifier: 'header:X-Tenant' }
  });
  assert.equal(result.valid, true);
});

// S-8: allowedFields shorthand
test('v0.4 S-8: allowedFields alone is valid', () => {
  const result = validateXSecurity({
    request: { allowedFields: ['email', 'password'] }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-8: allowedFields + denyUnknownFields:true is valid', () => {
  const result = validateXSecurity({
    request: { allowedFields: ['id'], denyUnknownFields: true }
  });
  assert.equal(result.valid, true);
});

test('v0.4 S-8: allowedFields + denyUnknownFields:false is invalid', () => {
  const result = validateXSecurity({
    request: { allowedFields: ['id'], denyUnknownFields: false }
  });
  assert.equal(result.valid, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.5 additions (S-10..S-18)
// ─────────────────────────────────────────────────────────────────────────────

// S-10: RuleRef namespace expansion
test('v0.5 S-10: principal.* ref is valid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'principal.id' } }]
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-10: session.* ref is valid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'resource.ownerId', operator: 'equals', value: { ref: 'session.userId' } }]
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-10: header.* ref is valid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'resource.tenantId', operator: 'equals', value: { ref: 'header.X-Tenant-Id' } }]
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-10: unknown namespace (env.*) is invalid', () => {
  const result = validateXSecurity({
    authorization: {
      type: 'rule-based',
      rules: [{ field: 'x', operator: 'equals', value: { ref: 'env.HOME' } }]
    }
  });
  assert.equal(result.valid, false);
});

// S-11: outboundCalls
test('v0.5 S-11: outboundCalls with signed HMAC is valid', () => {
  const result = validateXSecurity({
    outboundCalls: [
      {
        endpoint: 'https://webhook.example.com/notify',
        signatureAlgorithm: 'hmac-sha256',
        secretRef: '${WEBHOOK_SECRET}',
        timestampToleranceSeconds: 300,
        timeoutMs: 5000,
        allowedTlsVersions: ['TLSv1.3']
      }
    ]
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-11: signed outboundCall missing secretRef is invalid', () => {
  const result = validateXSecurity({
    outboundCalls: [
      { endpoint: 'https://webhook.example.com/notify', signatureAlgorithm: 'hmac-sha256' }
    ]
  });
  assert.equal(result.valid, false);
});

test('v0.5 S-11: unsigned (signatureAlgorithm:none) outboundCall is valid without secretRef', () => {
  const result = validateXSecurity({
    outboundCalls: [
      { endpoint: 'https://public.example.com/api', signatureAlgorithm: 'none' }
    ]
  });
  assert.equal(result.valid, true);
});

// S-12: auth depth
test('v0.5 S-12: full auth depth (mfa, tokenSources, lockout, passwordPolicy) is valid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://e.com/jwks.json',
      allowedAlgorithms: ['RS256'],
      mfaRequired: true,
      tokenSources: ['header', 'cookie'],
      accountLockout: { attempts: 5, window: '15m', identifier: 'header:X-Username' },
      passwordPolicy: { minLength: 12, requireUppercase: true, requireDigit: true }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-12: accountLockout missing required `window` is invalid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://e.com/jwks.json',
      allowedAlgorithms: ['RS256'],
      // @ts-expect-error intentional missing
      accountLockout: { attempts: 5, identifier: 'header:X-Username' }
    }
  });
  assert.equal(result.valid, false);
});

test('v0.5 S-12: passwordPolicy minLength below 8 is invalid', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://e.com/jwks.json',
      allowedAlgorithms: ['RS256'],
      passwordPolicy: { minLength: 4 }
    }
  });
  assert.equal(result.valid, false);
});

// S-13: errorScrubbing
test('v0.5 S-13: errorScrubbing with status override is valid', () => {
  const result = validateXSecurity({
    response: {
      errorScrubbing: {
        stripStackTraces: true,
        stripServerHeaders: true,
        genericMessages: true,
        statusOverride: { '500': 'Internal error', '503': '' }
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-13: errorScrubbing with non-4xx/5xx status key is invalid', () => {
  const result = validateXSecurity({
    response: {
      errorScrubbing: { statusOverride: { '200': 'should not be here' } }
    }
  });
  assert.equal(result.valid, false);
});

// S-14: identifier combinator
test('v0.5 S-14: identifier with combinator:distinct is valid', () => {
  const result = validateXSecurity({
    rateLimit: {
      requests: 10,
      window: '1m',
      identifier: { components: ['ip', 'user-id'], combinator: 'distinct' }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-14: identifier with bad combinator is invalid', () => {
  const result = validateXSecurity({
    rateLimit: {
      requests: 10,
      window: '1m',
      // @ts-expect-error intentional
      identifier: { components: ['ip', 'user-id'], combinator: 'xor' }
    }
  });
  assert.equal(result.valid, false);
});

test('v0.5 S-14: identifier object with 1 component is invalid (minItems 2)', () => {
  const result = validateXSecurity({
    rateLimit: { requests: 10, window: '1m', identifier: { components: ['ip'] } }
  });
  assert.equal(result.valid, false);
});

// S-15: redirectAllowedDomains
test('v0.5 S-15: redirectAllowedDomains on url param is valid', () => {
  const result = validateXSecurity({
    request: {
      schema: {
        next: { type: 'url', redirectAllowedDomains: ['*.example.com', 'app.example.org'] }
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-15: redirectAllowedDomains wrong type is invalid', () => {
  const result = validateXSecurity({
    request: {
      // @ts-expect-error intentional
      schema: { next: { type: 'url', redirectAllowedDomains: 'example.com' } }
    }
  });
  assert.equal(result.valid, false);
});

// S-16: sessionRotateOnAuth
test('v0.5 S-16: sessionRotateOnAuth true is valid', () => {
  const result = validateXSecurity({
    authentication: { type: 'basic', sessionRotateOnAuth: true }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-16: sessionRotateOnAuth wrong type is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    authentication: { type: 'basic', sessionRotateOnAuth: 'yes' }
  });
  assert.equal(result.valid, false);
});

// S-17: signature.nonceCacheTtl
test('v0.5 S-17: signature with nonceCacheTtl + nonceHeader is valid', () => {
  const result = validateXSecurity({
    request: {
      signature: {
        algorithm: 'hmac-sha256',
        headerName: 'X-Signature',
        secretRef: '${WEBHOOK_SECRET}',
        body: 'raw',
        nonceHeader: 'X-Nonce',
        nonceCacheTtl: '5m'
      }
    }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-17: nonceCacheTtl without nonceHeader is invalid', () => {
  const result = validateXSecurity({
    request: {
      signature: {
        algorithm: 'hmac-sha256',
        headerName: 'X-Signature',
        secretRef: '${WEBHOOK_SECRET}',
        body: 'raw',
        nonceCacheTtl: '5m'
      }
    }
  });
  assert.equal(result.valid, false);
});

// S-18: TLS floor
test('v0.5 S-18: tls.minVersion TLSv1.3 is valid', () => {
  const result = validateXSecurity({
    tls: { minVersion: 'TLSv1.3', allowedCipherSuites: ['TLS_AES_256_GCM_SHA384'] }
  });
  assert.equal(result.valid, true);
});

test('v0.5 S-18: tls.minVersion TLSv1.1 (legacy) is invalid', () => {
  const result = validateXSecurity({
    // @ts-expect-error intentional
    tls: { minVersion: 'TLSv1.1' }
  });
  assert.equal(result.valid, false);
});

// Integration: a realistic v0.3 admin write-endpoint
test('v0.3: realistic admin policy combining many additions', () => {
  const result = validateXSecurity({
    authentication: {
      type: 'bearer-jwt',
      jwksUri: 'https://auth.example.com/.well-known/jwks.json',
      allowedAlgorithms: ['RS256', 'ES256']
    },
    authorization: {
      type: 'rule-based',
      resourceLookup: {
        endpoint: '/orders/{id}',
        identifierFrom: 'request.params.id',
        expose: ['ownerId', 'tenantId']
      },
      rules: [
        { field: 'resource.ownerId', operator: 'equals', value: { ref: 'jwt.sub' } },
        { field: 'resource.tenantId', operator: 'equals', value: { ref: 'jwt.tenant' } }
      ]
    },
    csrf: { method: 'double-submit', tokenHeader: 'X-CSRF-Token', tokenCookie: 'csrf_token' },
    request: {
      contentType: ['application/json'],
      maxBodySize: '64KB',
      denyUnknownFields: true,
      duplicateParamPolicy: 'reject',
      headerInjectionGuard: true,
      pathCanonicalization: true,
      allowedHosts: ['api.example.com']
    },
    response: {
      headers: {
        csp: "default-src 'self'",
        hsts: { maxAge: 31536000, includeSubDomains: true },
        frameOptions: 'DENY',
        contentTypeOptions: 'nosniff',
        referrerPolicy: 'no-referrer',
        cacheControl: 'no-store'
      },
      cookies: { defaults: { httpOnly: true, secure: true, sameSite: 'Strict' } }
    },
    botProtection: { provider: 'turnstile', secretRef: '${TURNSTILE_SECRET}', mode: 'enforce' }
  });
  assert.equal(result.valid, true);
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.6 W19: per-arg injection hardening (request.schema.<f>.injectionGuard)
// ─────────────────────────────────────────────────────────────────────────────

test('injectionGuard accepts a valid sink list (W19)', () => {
  const result = validateXSecurity({
    request: {
      schema: {
        query: { type: 'string', injectionGuard: ['sql'] },
        cmd: { type: 'string', injectionGuard: ['os-command', 'code-eval'] }
      }
    }
  });
  assert.equal(result.valid, true);
});

test('injectionGuard rejects an empty array (minItems 1)', () => {
  const result = validateXSecurity({
    request: { schema: { q: { type: 'string', injectionGuard: [] } } }
  });
  assert.equal(result.valid, false);
});

test('injectionGuard rejects an unknown sink', () => {
  const result = validateXSecurity({
    request: { schema: { q: { type: 'string', injectionGuard: ['ssti'] } } }
  });
  assert.equal(result.valid, false);
});

test('injectionGuard rejects duplicate sinks (uniqueItems)', () => {
  const result = validateXSecurity({
    request: { schema: { q: { type: 'string', injectionGuard: ['sql', 'sql'] } } }
  });
  assert.equal(result.valid, false);
});

test('SSEC-INJECTION is a real owasp-mapping category with the injectionGuard cap key', () => {
  const entry = (owaspMapping as Record<string, { name: string; mitigatedBy: string[] }>)['SSEC-INJECTION'];
  assert.ok(entry, 'SSEC-INJECTION missing from owasp-mapping');
  assert.ok(entry.mitigatedBy.includes('request.schema.injectionGuard'));
});

test('mitigates arrays stay OWASP-pure: SSEC-INJECTION is NOT a valid mitigates id', () => {
  const result = validateXSecurity({
    request: { schema: { q: { type: 'string', mitigates: ['SSEC-INJECTION'] } } }
  });
  assert.equal(result.valid, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// v0.7 (edge-enforceable-residuals)
// ─────────────────────────────────────────────────────────────────────────────

test('injectionGuard accepts the new deserialization + ai-prompt sinks', () => {
  const result = validateXSecurity({
    request: {
      schema: {
        payload: { type: 'string', injectionGuard: ['deserialization'] },
        prompt: { type: 'string', injectionGuard: ['ai-prompt'] }
      }
    }
  });
  assert.equal(result.valid, true);
});

test('SSEC-PROMPT and SSEC-AUDIT are real owasp-mapping categories', () => {
  const map = owaspMapping as Record<string, { name: string; mitigatedBy: string[] }>;
  assert.ok(map['SSEC-PROMPT'], 'SSEC-PROMPT missing from owasp-mapping');
  assert.ok(map['SSEC-PROMPT'].mitigatedBy.includes('request.schema.injectionGuard'));
  assert.ok(map['SSEC-AUDIT'], 'SSEC-AUDIT missing from owasp-mapping');
  assert.ok(map['SSEC-AUDIT'].mitigatedBy.includes('logging'));
});

test('mitigates arrays still reject the new synthetic ids (SSEC-PROMPT/SSEC-AUDIT)', () => {
  for (const id of ['SSEC-PROMPT', 'SSEC-AUDIT']) {
    const result = validateXSecurity({ mitigates: [id] });
    assert.equal(result.valid, false, `${id} must not be a valid mitigates id`);
  }
});

test('logging policy validates with events, sink, and piiRedaction', () => {
  const result = validateXSecurity({
    logging: { events: ['auth-failure', 'injection-block'], sink: 'http-collector', sinkRef: '${LOG_COLLECTOR_URL}', piiRedaction: true }
  });
  assert.equal(result.valid, true);
});

test('logging rejects empty events array', () => {
  const result = validateXSecurity({ logging: { events: [] } });
  assert.equal(result.valid, false);
});

test('logging rejects an unknown event', () => {
  const result = validateXSecurity({ logging: { events: ['kaboom'] } });
  assert.equal(result.valid, false);
});

test('logging sink http-collector without sinkRef is invalid', () => {
  const result = validateXSecurity({ logging: { events: ['request'], sink: 'http-collector' } });
  assert.equal(result.valid, false);
});

test('response.forbidArrayRoot validates as a boolean', () => {
  assert.equal(validateXSecurity({ response: { forbidArrayRoot: true } }).valid, true);
  assert.equal(validateXSecurity({ response: { forbidArrayRoot: 'yes' } }).valid, false);
});

test('request.idempotencyKey validates with header + ttl', () => {
  assert.equal(
    validateXSecurity({ request: { idempotencyKey: { header: 'Idempotency-Key', ttl: '10m' } } }).valid,
    true
  );
});

test('request.idempotencyKey requires header and ttl', () => {
  assert.equal(validateXSecurity({ request: { idempotencyKey: { header: 'Idempotency-Key' } } }).valid, false);
  assert.equal(validateXSecurity({ request: { idempotencyKey: { ttl: '10m' } } }).valid, false);
});

test('request.idempotencyKey rejects a malformed Duration ttl', () => {
  assert.equal(
    validateXSecurity({ request: { idempotencyKey: { header: 'Idempotency-Key', ttl: '10 minutes' } } }).valid,
    false
  );
});

test('API2 mapping wires passwordPolicy + accountLockout cap keys', () => {
  const map = owaspMapping as Record<string, { mitigatedBy: string[] }>;
  assert.ok(map['API2:2023'].mitigatedBy.includes('authentication.passwordPolicy'));
  assert.ok(map['API2:2023'].mitigatedBy.includes('authentication.accountLockout'));
});

test('API3 mapping wires response.forbidArrayRoot; API6 wires request.idempotencyKey', () => {
  const map = owaspMapping as Record<string, { mitigatedBy: string[] }>;
  assert.ok(map['API3:2023'].mitigatedBy.includes('response.forbidArrayRoot'));
  assert.ok(map['API6:2023'].mitigatedBy.includes('request.idempotencyKey'));
});

// ── v0.8 deferred-residuals ────────────────────────────────────────────────

test('graphql.operations[] validates with per-operation authz + cost', () => {
  assert.equal(
    validateXSecurity({
      graphql: {
        maxDepth: 5,
        operations: [
          {
            name: 'systemDiagnostics',
            operationType: 'query',
            authz: { type: 'rbac', roles: ['admin'] },
            maxComplexity: 50
          },
          {
            name: 'pastes',
            authz: {
              type: 'rule-based',
              rules: [{ field: 'jwt.sub', operator: 'equals', value: { ref: 'resource.ownerId' } }]
            }
          }
        ]
      }
    }).valid,
    true
  );
});

test('graphql.operations[] satisfies minProperties without coarse block limits', () => {
  assert.equal(
    validateXSecurity({ graphql: { operations: [{ name: 'importPaste' }] } }).valid,
    true
  );
});

test('graphql.operations[] item requires name and rejects unknown props', () => {
  assert.equal(validateXSecurity({ graphql: { operations: [{ operationType: 'query' }] } }).valid, false);
  assert.equal(validateXSecurity({ graphql: { operations: [{ name: 'x', foo: 1 }] } }).valid, false);
});

test('request.serializeBy validates with key + scope and concurrencyLimit', () => {
  assert.equal(
    validateXSecurity({
      request: { serializeBy: { key: 'request.body.account_id', scope: 'per-identifier' }, concurrencyLimit: 1 }
    }).valid,
    true
  );
});

test('request.serializeBy requires key; concurrencyLimit must be >= 1', () => {
  assert.equal(validateXSecurity({ request: { serializeBy: { scope: 'global' } } }).valid, false);
  assert.equal(validateXSecurity({ request: { concurrencyLimit: 0 } }).valid, false);
});

test('request.dataAtRest (advisory) validates with fields + protection', () => {
  assert.equal(
    validateXSecurity({ request: { dataAtRest: { fields: ['password', 'pan', 'cvv'], protection: 'hashed' } } }).valid,
    true
  );
  assert.equal(validateXSecurity({ request: { dataAtRest: { fields: ['x'], protection: 'plaintext' } } }).valid, false);
  assert.equal(validateXSecurity({ request: { dataAtRest: { fields: [] , protection: 'hashed' } } }).valid, false);
});

test('API1/API5 wire graphql.operations.authz; API4 wires graphql.staticLimits; API6 wires request.serializeBy', () => {
  const map = owaspMapping as Record<string, { mitigatedBy: string[] }>;
  assert.ok(map['API1:2023'].mitigatedBy.includes('graphql.operations.authz'));
  assert.ok(map['API5:2023'].mitigatedBy.includes('graphql.operations.authz'));
  assert.ok(map['API4:2023'].mitigatedBy.includes('graphql.staticLimits'));
  assert.ok(map['API6:2023'].mitigatedBy.includes('request.serializeBy'));
});

test('SSEC-STORAGE is registered (advisory) and wires request.dataAtRest', () => {
  const map = owaspMapping as Record<string, { mitigatedBy: string[] }>;
  assert.ok(map['SSEC-STORAGE'], 'SSEC-STORAGE missing from owasp-mapping');
  assert.ok(map['SSEC-STORAGE'].mitigatedBy.includes('request.dataAtRest'));
});
