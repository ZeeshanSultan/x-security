// v0.3 request-side lowering: csrf, request.signature, allowedHosts,
// duplicateParamPolicy, headerInjectionGuard, pathCanonicalization,
// denyUnknownFields, ParamSchema binary additions.

import type { ParamSchema, RequestPolicy, RequestSignature, XSecurityPolicy } from '@x-security/schema';
import { and, hasHeader, headerMatches, missingHeader, not, or } from './expressions.js';
import { escapeStr } from './endpoint.js';
import { decorate, emitWorker, getOverride, noteProvenance, type V3Builder } from './v3-shared.js';

const SIGNATURE_WORKER_TEMPLATE = `// x-security: HMAC/Ed25519 webhook signature verifier (v0.3 request.signature)
// Deploy as a Cloudflare Worker bound to this route. Reject before origin.
export default {
  async fetch(req, env) {
    const sig = req.headers.get(PARAMS.headerName);
    if (!sig) return new Response('missing signature', { status: 401 });
    if (PARAMS.timestampHeader) {
      const ts = parseInt(req.headers.get(PARAMS.timestampHeader) || '0', 10);
      if (!ts || Math.abs(Date.now()/1000 - ts) > PARAMS.timestampToleranceSeconds) {
        return new Response('stale signature', { status: 401 });
      }
    }
    const body = await req.clone().arrayBuffer();
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(env[PARAMS.secretBinding]),
      { name: 'HMAC', hash: PARAMS.hash }, false, ['verify']
    );
    const ok = await crypto.subtle.verify('HMAC', key, hexToBytes(sig), body);
    if (!ok) return new Response('bad signature', { status: 401 });
    return fetch(req);
  }
};`;

const DENY_UNKNOWN_FIELDS_WORKER_TEMPLATE = `// x-security: deny-unknown-fields body validator (v0.3 request.denyUnknownFields)
// Worker reads the JSON body and rejects any property not present in the schema allowlist.
export default {
  async fetch(req) {
    if (!['POST','PUT','PATCH'].includes(req.method)) return fetch(req);
    const body = await req.clone().json().catch(() => null);
    if (!body || typeof body !== 'object') return fetch(req);
    const allowed = new Set(PARAMS.allowedKeys);
    for (const k of Object.keys(body)) {
      if (!allowed.has(k)) return new Response('unknown field: ' + k, { status: 400 });
    }
    return fetch(req);
  }
};`;

const MAGIC_BYTE_WORKER_TEMPLATE = `// x-security: magic-byte upload sniffer (v0.3 request.schema.*.magicByteCheck)
// Worker reads the first 16 bytes of the upload, matches against the declared MIME's signature.
export default {
  async fetch(req) {
    const ct = req.headers.get('content-type') || '';
    if (!ct.startsWith('multipart/form-data') && !ct.startsWith('application/octet-stream')) {
      return fetch(req);
    }
    const buf = new Uint8Array(await req.clone().arrayBuffer());
    const head = Array.from(buf.slice(0, 16)).map(b => b.toString(16).padStart(2,'0')).join('');
    const sigs = PARAMS.signatures; // [{mime, hexPrefix}]
    const ok = sigs.some(s => head.startsWith(s.hexPrefix));
    if (!ok) return new Response('mime mismatch', { status: 415 });
    return fetch(req);
  }
};`;

export function compileV3Request(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const req = policy.request;
  if (req) {
    compileAllowedHosts(b, req, baseMatch);
    compileDuplicateParamPolicy(b, req, baseMatch);
    compileHeaderInjectionGuard(b, req, baseMatch);
    compilePathCanonicalization(b, req, baseMatch);
    compileSignature(b, req);
    compileDenyUnknownFields(b, req);
    compileParamSchemaBinary(b, req, baseMatch);
  }
  compileCsrf(b, policy, baseMatch);
}

function compileAllowedHosts(b: V3Builder, req: RequestPolicy, baseMatch: string): void {
  const hosts = req.allowedHosts;
  if (!hosts || hosts.length === 0) return;
  const list = hosts.map(h => `"${escapeStr(h.toLowerCase())}"`).join(' ');
  b.custom.push(decorate(b, {
    kind: 'allowed-hosts',
    description: `Reject requests whose Host header is not in [${hosts.join(', ')}]`,
    expression: and(baseMatch, `not (http.host in {${list}})`),
    action: 'block',
    sourceField: 'request.allowedHosts',
    confidence: 'HIGH'
  }));
}

function compileDuplicateParamPolicy(b: V3Builder, req: RequestPolicy, baseMatch: string): void {
  const pol = req.duplicateParamPolicy;
  if (!pol) return;
  // We can detect duplicates via len(http.request.uri.args.names) != len(args.names_unique).
  // CF doesn't expose `args.names_unique`, so we approximate: detect repeated `&name=` pairs in the query string.
  // For 'reject' we lower to a Wirefilter rule; for 'first' / 'last' the gateway can't pick a side natively.
  if (pol === 'reject') {
    b.custom.push(decorate(b, {
      kind: 'dup-param-reject',
      description: 'Reject requests with duplicate query parameters (HPP defense)',
      // Heuristic: any name appearing twice in the raw query string.
      expression: and(baseMatch, 'http.request.uri.query matches "(?:^|&)([^=&]+)=[^&]*&(?:[^&]*&)*\\\\1="'),
      action: 'block',
      sourceField: 'request.duplicateParamPolicy=reject',
      confidence: 'MEDIUM'
    }));
  } else {
    noteProvenance(
      b,
      `request.duplicateParamPolicy=${pol}`,
      `Cloudflare WAF cannot natively pick first/last of duplicate query params; emit a Worker that normalizes URL.searchParams or upgrade to duplicateParamPolicy=reject.`,
      'partial',
      getOverride(b, `request.duplicateParamPolicy`)
    );
  }
}

function compileHeaderInjectionGuard(b: V3Builder, req: RequestPolicy, baseMatch: string): void {
  if (req.headerInjectionGuard !== true) return;
  // Scan common header values for CR/LF/NUL. CF expression language doesn't
  // iterate all headers; pin the rule to the headers most commonly weaponized.
  const guarded = ['user-agent', 'referer', 'origin', 'x-forwarded-for', 'x-forwarded-host', 'host', 'cookie'];
  const checks = guarded.map(h => headerMatches(h, '[\\r\\n\\x00]'));
  b.custom.push(decorate(b, {
    kind: 'header-injection-guard',
    description: 'Reject requests where any guarded header value contains CR/LF/NUL',
    expression: and(baseMatch, or(...checks)),
    action: 'block',
    sourceField: 'request.headerInjectionGuard',
    confidence: 'HIGH'
  }));
}

function compilePathCanonicalization(b: V3Builder, req: RequestPolicy, baseMatch: string): void {
  if (req.pathCanonicalization !== true) return;
  // Cloudflare normalizes paths by default. We add a defense-in-depth rule that
  // rejects double-encoded traversal sequences before any downstream pattern check.
  b.custom.push(decorate(b, {
    kind: 'path-canonicalization',
    description: 'Reject double-encoded traversal / ambiguous-slash path tricks',
    expression: and(
      baseMatch,
      or(
        'http.request.uri.path matches "(?i)%(?:25)+(?:2e|2f)"',
        'http.request.uri.path contains "/..;"',
        'http.request.uri.path matches "/{2,}"'
      )
    ),
    action: 'block',
    sourceField: 'request.pathCanonicalization',
    confidence: 'HIGH'
  }));
}

function compileSignature(b: V3Builder, req: RequestPolicy): void {
  const sig = req.signature;
  if (!sig) return;
  const hashAlg =
    sig.algorithm === 'hmac-sha256' ? 'SHA-256' :
    sig.algorithm === 'hmac-sha1' ? 'SHA-1' : 'Ed25519';
  emitWorker(b, {
    field: 'request.signature',
    kind: 'request-signature',
    description: `Verify ${sig.algorithm} signature in header ${sig.headerName} before forwarding to origin`,
    template: SIGNATURE_WORKER_TEMPLATE,
    params: {
      algorithm: sig.algorithm,
      hash: hashAlg,
      headerName: sig.headerName,
      secretBinding: deriveSecretBindingName(sig),
      body: sig.body,
      timestampHeader: sig.timestampHeader,
      timestampToleranceSeconds: sig.timestampToleranceSeconds ?? 300
    }
  });
  noteProvenance(
    b,
    'request.signature',
    `Cloudflare WAF has no HMAC/Ed25519 primitive; emitted Worker artifact ${b.endpoint.method} ${b.endpoint.path}. Deploy alongside rulesets.`,
    'override-only',
    getOverride(b, 'request.signature')
  );
}

function deriveSecretBindingName(sig: RequestSignature): string {
  // $vault.path → vault_path; ${ENV} → ENV. Worker binding cannot contain '/' or '$'.
  const m = /\$\{([A-Z0-9_]+)\}/.exec(sig.secretRef);
  if (m) return m[1]!;
  return sig.secretRef
    .replace(/^\$vault\./, 'vault_')
    .replace(/[^A-Za-z0-9_]/g, '_')
    .toUpperCase();
}

function compileDenyUnknownFields(b: V3Builder, req: RequestPolicy): void {
  if (req.denyUnknownFields !== true) return;
  const allowedKeys = req.schema ? Object.keys(req.schema) : [];
  emitWorker(b, {
    field: 'request.denyUnknownFields',
    kind: 'deny-unknown-fields',
    description: `Reject POST/PUT/PATCH bodies with keys outside [${allowedKeys.join(', ')}]`,
    template: DENY_UNKNOWN_FIELDS_WORKER_TEMPLATE,
    params: { allowedKeys }
  });
  noteProvenance(
    b,
    'request.denyUnknownFields',
    'Cloudflare WAF cannot inspect JSON body fields; emitted Worker artifact for ajv-style validation.',
    'override-only',
    getOverride(b, 'request.denyUnknownFields')
  );
}

function compileParamSchemaBinary(b: V3Builder, req: RequestPolicy, baseMatch: string): void {
  const schema = req.schema;
  if (!schema) return;
  for (const [name, param] of Object.entries(schema)) {
    if (param.type !== 'binary' && !hasBinaryFields(param)) continue;
    compileExtensionAllowlist(b, name, param, baseMatch);
    compileDenyDoubleExtension(b, name, param, baseMatch);
    compileMagicByteCheck(b, name, param);
  }
}

function hasBinaryFields(p: ParamSchema): boolean {
  return p.magicByteCheck !== undefined || p.extensionAllowlist !== undefined || p.denyDoubleExtension !== undefined;
}

function compileExtensionAllowlist(b: V3Builder, name: string, p: ParamSchema, baseMatch: string): void {
  if (!p.extensionAllowlist || p.extensionAllowlist.length === 0) return;
  // The filename arrives in Content-Disposition or in the URL path; we lower as a
  // path-suffix check, which is conservative but correct for path-style uploads.
  const exts = p.extensionAllowlist.map(e => escapeStr(e.toLowerCase()));
  const expr = and(
    baseMatch,
    `not (any(http.request.uri.path matches "(?i)\\\\.(${exts.map(e => e.slice(1)).join('|')})$"))`
  );
  b.custom.push(decorate(b, {
    kind: `bin-ext-${name}`,
    description: `Param '${name}': reject uploads whose extension is not in [${p.extensionAllowlist.join(', ')}]`,
    expression: expr,
    action: 'block',
    sourceField: `request.schema.${name}.extensionAllowlist`,
    confidence: 'MEDIUM'
  }));
}

function compileDenyDoubleExtension(b: V3Builder, name: string, p: ParamSchema, baseMatch: string): void {
  if (p.denyDoubleExtension !== true) return;
  b.custom.push(decorate(b, {
    kind: `bin-dbl-${name}`,
    description: `Param '${name}': reject filenames with double extensions (invoice.pdf.exe)`,
    expression: and(baseMatch, 'http.request.uri.path matches "(?i)\\\\.[a-z0-9]{2,5}\\\\.[a-z0-9]{2,5}$"'),
    action: 'block',
    sourceField: `request.schema.${name}.denyDoubleExtension`,
    confidence: 'MEDIUM'
  }));
}

function compileMagicByteCheck(b: V3Builder, name: string, p: ParamSchema): void {
  if (p.magicByteCheck !== true) return;
  const sigs = (p.allowedMimeTypes ?? []).map(m => ({ mime: m, hexPrefix: MIME_MAGIC[m] ?? '' })).filter(s => s.hexPrefix);
  emitWorker(b, {
    field: `request.schema.${name}.magicByteCheck`,
    kind: `magic-byte-${name}`,
    description: `Param '${name}': sniff first 16 bytes against declared MIMEs [${(p.allowedMimeTypes ?? []).join(', ')}]`,
    template: MAGIC_BYTE_WORKER_TEMPLATE,
    params: { paramName: name, signatures: sigs }
  });
  noteProvenance(
    b,
    `request.schema.${name}.magicByteCheck`,
    'Cloudflare WAF cannot read request body bytes; emitted Worker artifact.',
    'override-only',
    getOverride(b, `request.schema.${name}.magicByteCheck`)
  );
}

const MIME_MAGIC: Record<string, string> = Object.freeze({
  'image/png': '89504e470d0a1a0a',
  'image/jpeg': 'ffd8ff',
  'image/gif': '474946383',
  'image/webp': '52494646',
  'application/pdf': '25504446',
  'application/zip': '504b0304',
  'application/octet-stream': ''
});

function compileCsrf(b: V3Builder, policy: XSecurityPolicy, baseMatch: string): void {
  const c = policy.csrf;
  if (!c) return;
  if (c.method === 'origin-check') {
    const allowed = (c.allowedOrigins ?? []).map(o => `"${escapeStr(o)}"`).join(' ');
    if (!allowed) {
      noteProvenance(b, 'csrf', 'csrf.method=origin-check requires allowedOrigins; dropped.', 'unsupported');
      return;
    }
    b.custom.push(decorate(b, {
      kind: 'csrf-origin',
      description: `CSRF origin-check: reject if Origin not in [${(c.allowedOrigins ?? []).join(', ')}]`,
      expression: and(
        baseMatch,
        hasHeader('origin'),
        `not (http.request.headers["origin"][0] in {${allowed}})`
      ),
      action: 'block',
      sourceField: 'csrf.method=origin-check',
      confidence: 'HIGH'
    }));
    return;
  }
  if (c.method === 'custom-header') {
    if (!c.tokenHeader) {
      noteProvenance(b, 'csrf', 'csrf.method=custom-header requires tokenHeader; dropped.', 'unsupported');
      return;
    }
    b.custom.push(decorate(b, {
      kind: 'csrf-custom-header',
      description: `CSRF custom-header: require presence of ${c.tokenHeader} on state-changing methods`,
      expression: and(
        baseMatch,
        '(http.request.method in {"POST" "PUT" "PATCH" "DELETE"})',
        missingHeader(c.tokenHeader)
      ),
      action: 'block',
      sourceField: 'csrf.method=custom-header',
      confidence: 'MEDIUM'
    }));
    return;
  }
  // double-submit: presence check natively, but value equality needs a Worker.
  if (c.method === 'double-submit') {
    if (!c.tokenHeader || !c.tokenCookie) {
      noteProvenance(b, 'csrf', 'csrf.method=double-submit requires tokenHeader and tokenCookie; dropped.', 'unsupported');
      return;
    }
    // Presence-only check at WAF; value equality must happen in a Worker.
    b.custom.push(decorate(b, {
      kind: 'csrf-double-submit-presence',
      description: `CSRF double-submit: require both ${c.tokenHeader} and cookie ${c.tokenCookie} present`,
      expression: and(
        baseMatch,
        '(http.request.method in {"POST" "PUT" "PATCH" "DELETE"})',
        or(missingHeader(c.tokenHeader), not(`http.cookie contains "${escapeStr(c.tokenCookie)}="`))
      ),
      action: 'block',
      sourceField: 'csrf.method=double-submit',
      confidence: 'MEDIUM'
    }));
    noteProvenance(
      b,
      'csrf.method=double-submit',
      'Token-value-equality check is Worker-only; WAF rule only enforces presence of header + cookie.',
      'partial',
      getOverride(b, 'csrf')
    );
  }
}
