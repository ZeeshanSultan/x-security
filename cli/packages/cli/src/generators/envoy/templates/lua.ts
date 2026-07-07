/**
 * Residual Lua template for the Envoy filter chain (wave-9).
 *
 * Wave-7's Lua filter enforced everything: JWT header presence, RBAC, rate
 * limit (as a breadcrumb), CORS, method allowlist, body size, content-type.
 * Wave-9 moved JWT, RBAC, rate-limit, and CORS to native Envoy filters
 * (`jwt_authn`, `rbac`, `local_ratelimit`, `cors`). The residual Lua module
 * only handles fields with **no native equivalent**:
 *
 *   - request.duplicateParamPolicy   (HPP defense)
 *   - request.headerInjectionGuard   (CR/LF/NUL in headers → 400)
 *   - request.signature              (HMAC / Ed25519 verification)
 *   - request.maxBodySize            (kept here — `request_body_buffer_limit`
 *                                     on the HCM enforces the *largest* global
 *                                     cap, but per-route caps still need
 *                                     content-length compare)
 *   - request.contentType allowlist  (315 reject; cheap in Lua, no native equivalent)
 *   - method-allowlist (405)          (preserved so wave-7 behaviour holds)
 *
 * Block markers (`-- xSecurity:<METHOD>:<path>:START` / `-- xSecurity:END`)
 * remain — the file-mode drift detector and the verify reader both key off
 * them. Without these markers, every wave-7 verify call would regress.
 *
 * If the spec triggers *zero* residual fields, the generator returns `null`
 * and the lua filter is omitted from the bootstrap entirely.
 */

import type { EndpointIR } from '@x-security/core';
import { parseByteSize } from '../../coraza/rules.js';

export const VERSION = '0.2.0';

/** Does this endpoint need the residual Lua module at all? */
export function endpointNeedsLua(ep: EndpointIR): boolean {
  const p = ep.policy;
  const r = p.request;
  if (!r) return false;
  return Boolean(
    r.contentType ||
    r.maxBodySize ||
    r.duplicateParamPolicy ||
    r.headerInjectionGuard ||
    r.signature
  );
}

/**
 * Convert an OpenAPI path template to a Lua pattern. Replaces `{param}` with
 * `[^/]+`. Escapes Lua-magic characters in literal segments. Anchored.
 */
export function envoyPathPattern(path: string): string {
  const parts: string[] = [];
  let i = 0;
  while (i < path.length) {
    const open = path.indexOf('{', i);
    if (open === -1) {
      parts.push(escapeLuaPattern(path.slice(i)));
      break;
    }
    if (open > i) parts.push(escapeLuaPattern(path.slice(i, open)));
    const close = path.indexOf('}', open + 1);
    if (close === -1) {
      parts.push(escapeLuaPattern(path.slice(open)));
      break;
    }
    parts.push('[^/]+');
    i = close + 1;
  }
  return `^${parts.join('')}$`;
}

function escapeLuaPattern(s: string): string {
  return s.replace(/([().%+\-*?\[\]^$])/g, '%$1');
}

function luaStr(s: string): string {
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

interface EndpointBlockOptions {
  endpoint: EndpointIR;
}

/**
 * Emit the per-endpoint Lua block. Wrapped in
 * `-- xSecurity:<METHOD>:<path>:START` / `-- xSecurity:END` markers.
 *
 * Returns null when the endpoint needs no residual Lua (all fields covered by
 * native filters). The caller must skip null blocks to keep the module body
 * concise.
 */
export function buildEndpointBlock(opts: EndpointBlockOptions): string | null {
  const { endpoint } = opts;
  const policy = endpoint.policy;
  if (!endpointNeedsLua(endpoint)) return null;

  const pattern = envoyPathPattern(endpoint.path);
  const body: string[] = [];

  body.push(`    -- ${endpoint.method} ${endpoint.path}  (operationId: ${endpoint.operationId})`);
  body.push(`    if method == ${luaStr(endpoint.method)} and string.match(path, ${luaStr(pattern)}) then`);
  body.push(`      matched = true`);

  // Header injection guard: reject CR/LF/NUL in any header value → 400.
  if (policy.request?.headerInjectionGuard) {
    body.push(`      -- request.headerInjectionGuard: reject CR/LF/NUL in header values`);
    body.push(`      for k, v in pairs(headers) do`);
    body.push(`        if type(v) == "string" and string.match(v, "[\\r\\n\\0]") then`);
    body.push(`          request_handle:respond({[":status"] = "400"}, "x-security: invalid header value")`);
    body.push(`          return`);
    body.push(`        end`);
    body.push(`      end`);
  }

  // HPP: duplicateParamPolicy=reject → 400 on duplicate query params.
  if (policy.request?.duplicateParamPolicy === 'reject') {
    body.push(`      -- request.duplicateParamPolicy=reject: 400 on duplicate query params`);
    body.push(`      local seen = {}`);
    body.push(`      local q_string = headers:get(":path") or ""`);
    body.push(`      local q_pos = string.find(q_string, "?", 1, true)`);
    body.push(`      if q_pos then`);
    body.push(`        for kv in string.gmatch(string.sub(q_string, q_pos + 1), "([^&]+)") do`);
    body.push(`          local k = string.match(kv, "^([^=]+)")`);
    body.push(`          if k and seen[k] then`);
    body.push(`            request_handle:respond({[":status"] = "400"}, "x-security: duplicate query parameter")`);
    body.push(`            return`);
    body.push(`          end`);
    body.push(`          if k then seen[k] = true end`);
    body.push(`        end`);
    body.push(`      end`);
  }

  // Content-Type allowlist: 415 on mismatch.
  const allowedCT = policy.request?.contentType;
  if (allowedCT && allowedCT.length) {
    body.push(`      -- request.contentType allowlist`);
    body.push(`      local ct = request_handle:headers():get("content-type") or ""`);
    body.push(`      local ct_ok = false`);
    for (const c of allowedCT) {
      const pat = '^' + escapeLuaPattern(c) + '($|;.*)';
      body.push(`      if string.match(ct, ${luaStr(pat)}) then ct_ok = true end`);
    }
    body.push(`      if not ct_ok then`);
    body.push(`        request_handle:respond({[":status"] = "415"}, "x-security: unsupported Content-Type")`);
    body.push(`        return`);
    body.push(`      end`);
  }

  // Body size: 413 on exceed.
  const bytes = parseByteSize(policy.request?.maxBodySize);
  if (Number.isFinite(bytes) && bytes > 0) {
    body.push(`      -- request.maxBodySize=${bytes} bytes`);
    body.push(`      local cl = tonumber(request_handle:headers():get("content-length") or "0") or 0`);
    body.push(`      if cl > ${bytes} then`);
    body.push(`        request_handle:respond({[":status"] = "413"}, "x-security: request body exceeds endpoint limit")`);
    body.push(`        return`);
    body.push(`      end`);
  }

  // Note: request.signature requires async body access; we emit a TODO
  // comment so operators see the gap. Implementing it inline requires the
  // body filter callback, which is too invasive to land in wave-9.
  if (policy.request?.signature) {
    body.push(`      -- request.signature (${policy.request.signature.algorithm}): TODO — needs body filter callback`);
  }

  body.push(`    end`);

  const startMarker = `    -- xSecurity:${endpoint.method}:${endpoint.path}:START`;
  const endMarker = `    -- xSecurity:END`;
  return [startMarker, ...body, endMarker].join('\n');
}

export interface MethodAllowlistEntry {
  path: string;
  pattern: string;
  methods: string[];
}

/**
 * Build the residual Lua module. Returns null when there are no per-endpoint
 * blocks and the method-allowlist is the only signal — even then, the
 * method-allowlist is useful (405 has no native filter equivalent in Envoy
 * outside per-route :method header matching, which only short-circuits to
 * 404 not 405), so we always emit the module when this function is called.
 */
export function buildLuaModule(
  specTitle: string,
  specVersion: string,
  blocks: string[],
  methodMap: MethodAllowlistEntry[]
): string {
  const lines: string[] = [];

  lines.push(`-- x-security → Envoy residual Lua filter — auto-generated. DO NOT EDIT BY HAND.`);
  lines.push(`-- generator: x-security-envoy v${VERSION}`);
  lines.push(`-- source: ${specTitle} ${specVersion}`);
  lines.push(`-- This module handles ONLY fields with no native Envoy filter equivalent.`);
  lines.push(`-- JWT auth, RBAC, rate-limit, and CORS are enforced by their native filters`);
  lines.push(`-- earlier in the chain (jwt_authn, rbac, local_ratelimit, cors).`);
  lines.push('');

  lines.push(`-- xSecurity:method-allowlist:START`);
  lines.push(`local method_allowlist = {`);
  const sorted = [...methodMap].sort((a, b) => a.path.localeCompare(b.path));
  for (const e of sorted) {
    const methods = e.methods.slice().sort();
    lines.push(`  { pattern = ${luaStr(e.pattern)}, methods = { ${methods.map(luaStr).join(', ')} } },`);
  }
  lines.push(`}`);
  lines.push(`-- xSecurity:method-allowlist:END`);
  lines.push('');

  lines.push(`function envoy_on_request(request_handle)`);
  lines.push(`  local headers = request_handle:headers()`);
  lines.push(`  local method = headers:get(":method") or ""`);
  lines.push(`  local path = headers:get(":path") or ""`);
  lines.push(`  local q = string.find(path, "?", 1, true)`);
  lines.push(`  if q then path = string.sub(path, 1, q - 1) end`);
  lines.push('');
  lines.push(`  local matched = false`);
  lines.push('');

  lines.push(`  -- 405 if method not in spec for matched path`);
  lines.push(`  for _, entry in ipairs(method_allowlist) do`);
  lines.push(`    if string.match(path, entry.pattern) then`);
  lines.push(`      local method_ok = false`);
  lines.push(`      for _, m in ipairs(entry.methods) do`);
  lines.push(`        if m == method then method_ok = true; break end`);
  lines.push(`      end`);
  lines.push(`      if not method_ok then`);
  lines.push(`        request_handle:respond({[":status"] = "405"}, "x-security: method not allowed")`);
  lines.push(`        return`);
  lines.push(`      end`);
  lines.push(`      break`);
  lines.push(`    end`);
  lines.push(`  end`);
  lines.push('');

  for (const b of blocks) {
    lines.push(b);
    lines.push('');
  }

  lines.push(`  if not matched then return end`);
  lines.push(`end`);
  lines.push('');
  return lines.join('\n');
}
