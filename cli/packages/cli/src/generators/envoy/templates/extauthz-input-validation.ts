/**
 * W18-A: strict-body / input-validation defense class for the Envoy ext_authz
 * + OPA path. Split out of extauthz.ts (W20-B) to comply with Rule G-1.
 *
 * Owns:
 *   - collectInputValidation: spec → endpoints with an allowed-key set
 *   - emitInputValidationBranches: Rego decision-chain branches that emit
 *     opa-input-validation-403 when the request body contains a key outside
 *     the allowlist.
 */

import type { EndpointIR, SpecIR } from '@x-security/core';
import type { BranchEmitDeps } from './extauthz-rego-util.js';

export interface InputValidationEndpoint {
  endpoint: EndpointIR;
  /** Allowed top-level body keys derived from `request.schema` / `allowedFields`. */
  allowedFields: string[];
}

/**
 * W18-A + OPP-3: strict-body endpoints (denyUnknownFields or allowedFields).
 * The allowed key set is the union of explicit allowedFields and the keys of
 * request.schema.
 *
 * OPP-3 change: endpoints that declare `denyUnknownFields: true` are ALWAYS
 * emitted, even when the allowed set is empty. An empty allowlist is the
 * correct, strictest interpretation of "deny unknown fields with no declared
 * schema": the Rego `body[key]; not allowed[key]` check with an empty set
 * rejects ANY top-level body key (an empty body still passes — no key matches
 * `some key`). Previously these endpoints were silently skipped, which left
 * `denyUnknownFields` partially enforced; per Rule D-1 we never mark a field
 * `full` while any declaring endpoint goes un-enforced.
 *
 * Endpoints with only `allowedFields` (no denyUnknownFields) still require a
 * non-empty set — an empty allowedFields array carries no allowlist intent.
 */
export function collectInputValidation(spec: SpecIR): InputValidationEndpoint[] {
  const out: InputValidationEndpoint[] = [];
  for (const ep of spec.endpoints) {
    const req = ep.policy.request;
    if (!req) continue;
    const denyUnknown = req.denyUnknownFields === true;
    const hasAllowList = (req.allowedFields && req.allowedFields.length > 0) ?? false;
    if (!denyUnknown && !hasAllowList) continue;
    const fromSchema = req.schema ? Object.keys(req.schema) : [];
    const fromAllow = req.allowedFields ?? [];
    const fields = Array.from(new Set([...fromAllow, ...fromSchema])).sort();
    // denyUnknownFields with no declared keys → empty allowlist (reject all
    // body keys). allowedFields-only with an empty derived set carries no
    // intent and is skipped.
    if (fields.length === 0 && !denyUnknown) continue;
    out.push({ endpoint: ep, allowedFields: fields });
  }
  return out;
}

/** Emit input-validation branches into the shared lines[]. */
export function emitInputValidationBranches(items: InputValidationEndpoint[], d: BranchEmitDeps): void {
  const sorted = [...items].sort((a, b) => {
    if (a.endpoint.method !== b.endpoint.method) return a.endpoint.method.localeCompare(b.endpoint.method);
    return a.endpoint.path.localeCompare(b.endpoint.path);
  });

  for (const item of sorted) {
    const method = item.endpoint.method.toUpperCase();
    const pathRegex = d.pathToRegoRegex(item.endpoint.path);
    const allowedSetLiteral = '{' + item.allowedFields.map(d.regoString).join(', ') + '}';
    d.lines.push(`# ${item.endpoint.method} ${item.endpoint.path} — strict body, allowed=${item.allowedFields.join(',')} (W18-A input-validation)`);
    d.pushBranch(
      [
        `    input.attributes.request.http.method == ${d.regoString(method)}`,
        `    regex.match(${d.regoString(pathRegex)}, input.attributes.request.http.path)`,
        '    body := json.unmarshal(input.attributes.request.http.body)',
        `    allowed := ${allowedSetLiteral}`,
        '    some key',
        '    body[key]',
        '    not allowed[key]'
      ],
      d.denyLiteral('input-validation')
    );
    d.lines.push('');
  }
}
