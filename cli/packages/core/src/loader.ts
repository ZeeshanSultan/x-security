import SwaggerParser from '@apidevtools/swagger-parser';
import { validateXSecurity, type XSecurityPolicy } from '@writ/schema';
import type { OpenAPIV3, OpenAPIV3_1 } from 'openapi-types';
import { SchemaValidationError, UnresolvedVariableError, UnsupportedDialectError } from './errors.js';
import type { EndpointIR, HttpMethod, ParamIR, SpecIR } from './ir.js';
import { resolveVariables, type VariableResolver, EnvResolver } from './variables.js';

const METHODS: HttpMethod[] = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

export interface LoadOptions {
  /** Custom variable resolver chain. Defaults to env-only. */
  resolver?: VariableResolver;
  /** Fail-fast on any unresolved variable. Default true. */
  strict?: boolean;
  /** Validate every x-security block against the schema during load. Default true. */
  validate?: boolean;
}

function detectDialect(version: string): '3.0' | '3.1' {
  if (version.startsWith('3.1')) return '3.1';
  if (version.startsWith('3.0')) return '3.0';
  throw new UnsupportedDialectError(version);
}

function deriveOperationId(method: string, path: string, explicit?: string): string {
  if (explicit) return explicit;
  return `${method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '')}`;
}

function collectParameters(
  op: OpenAPIV3.OperationObject | OpenAPIV3_1.OperationObject,
  pathItem: OpenAPIV3.PathItemObject | OpenAPIV3_1.PathItemObject
): ParamIR[] {
  const all = [...(pathItem.parameters ?? []), ...(op.parameters ?? [])];
  const params: ParamIR[] = [];
  for (const p of all) {
    if ('$ref' in p) continue; // SwaggerParser.dereference resolves $refs; defensive guard
    params.push({
      name: p.name,
      in: p.in as ParamIR['in'],
      required: p.required ?? (p.in === 'path'),
      schema: p.schema as ParamIR['schema']
    });
  }
  // Body
  if ('requestBody' in op && op.requestBody && !('$ref' in op.requestBody)) {
    const content = (op.requestBody as OpenAPIV3.RequestBodyObject).content;
    const first = content && Object.values(content)[0];
    if (first?.schema) {
      params.push({ name: 'body', in: 'body', required: op.requestBody.required ?? false, schema: first.schema as ParamIR['schema'] });
    }
  }
  return params;
}

/**
 * Load an annotated OpenAPI spec → SpecIR.
 * Resolves $refs, extracts x-security per operation, validates against schema,
 * resolves variables, normalizes parameters.
 */
export async function loadSpec(specPath: string, opts: LoadOptions = {}): Promise<SpecIR> {
  const resolver = opts.resolver ?? new EnvResolver();
  const strict = opts.strict ?? true;
  const validate = opts.validate ?? true;

  const doc = (await SwaggerParser.dereference(specPath)) as OpenAPIV3.Document | OpenAPIV3_1.Document;
  const dialect = detectDialect(doc.openapi);

  const endpoints: EndpointIR[] = [];
  const unprotected: { method: string; path: string }[] = [];
  // Aggregate unresolved variables across the entire spec so the caller sees
  // every missing var in one error rather than running and failing repeatedly.
  const unresolvedAgg = new Map<string, string[]>();

  for (const [path, pathItem] of Object.entries(doc.paths ?? {})) {
    if (!pathItem) continue;
    for (const method of METHODS) {
      const op = (pathItem as Record<string, unknown>)[method] as
        | OpenAPIV3.OperationObject
        | OpenAPIV3_1.OperationObject
        | undefined;
      if (!op) continue;

      const rawXSecurity = (op as unknown as { 'x-security'?: unknown })['x-security'];

      if (!rawXSecurity) {
        unprotected.push({ method: method.toUpperCase(), path });
        continue;
      }

      if (validate) {
        const result = validateXSecurity(rawXSecurity, dialect === '3.1' ? '2020-12' : 'draft-04');
        if (!result.valid) {
          throw new SchemaValidationError(
            `Invalid x-security at ${method.toUpperCase()} ${path}: ${result.errors.map((e) => `${e.instancePath} ${e.message}`).join('; ')}`,
            result.errors
          );
        }
      }

      // Always non-strict per-endpoint; we aggregate and throw once at the end
      // so the user sees every missing var across the spec in a single error.
      const { value: policy, resolved, unresolved } = await resolveVariables(rawXSecurity as XSecurityPolicy, {
        resolver,
        strict: false
      });
      if (unresolved.length > 0) {
        const opRef = `${method.toUpperCase()} ${path}`;
        for (const v of unresolved) {
          const list = unresolvedAgg.get(v) ?? [];
          list.push(opRef);
          unresolvedAgg.set(v, list);
        }
      }

      endpoints.push({
        method: method.toUpperCase() as Uppercase<HttpMethod>,
        path,
        operationId: deriveOperationId(method, path, op.operationId),
        policy,
        parameters: collectParameters(op, pathItem),
        raw: op,
        resolvedVars: resolved
      });
    }
  }

  if (strict && unresolvedAgg.size > 0) {
    const vars = Array.from(unresolvedAgg.keys()).sort();
    const paths: Record<string, string[]> = {};
    for (const v of vars) paths[v] = unresolvedAgg.get(v)!;
    throw new UnresolvedVariableError(vars, paths);
  }

  return {
    openapi: doc.openapi,
    dialect,
    info: { title: doc.info.title, version: doc.info.version },
    servers: (doc.servers ?? []).map((s) => ({ url: s.url })),
    endpoints,
    unprotectedEndpoints: unprotected
  };
}
