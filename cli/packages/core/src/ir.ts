import type { XSecurityPolicy } from '@x-security/schema';
import type { OpenAPIV3, OpenAPIV3_1 } from 'openapi-types';

export type HttpMethod = 'get' | 'post' | 'put' | 'patch' | 'delete' | 'head' | 'options';

export interface ParamIR {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie' | 'body' | 'formData';
  required: boolean;
  // Carries OpenAPI schema in normalized form for generators that need it
  schema?: OpenAPIV3.SchemaObject | OpenAPIV3_1.SchemaObject | undefined;
}

export interface EndpointIR {
  /** Uppercase HTTP method, e.g. "POST" */
  method: Uppercase<HttpMethod>;
  /** OpenAPI path template, e.g. "/api/users/{id}" */
  path: string;
  /** operationId if present, else "<method>_<path>" sanitized */
  operationId: string;
  /** Effective security policy after profile expansion + variable resolution */
  policy: XSecurityPolicy;
  /** Normalized parameter list across query/header/path/cookie/body */
  parameters: ParamIR[];
  /** Raw operation object for escape-hatch use by generators */
  raw: OpenAPIV3.OperationObject | OpenAPIV3_1.OperationObject;
  /** Variables resolved at compile time, recorded for audit/debug */
  resolvedVars: ReadonlyMap<string, string>;
}

export interface SpecIR {
  openapi: string;
  dialect: '3.0' | '3.1';
  info: { title: string; version: string };
  servers: { url: string }[];
  endpoints: EndpointIR[];
  /** Endpoints that have NO x-security annotation (used by `report --coverage`) */
  unprotectedEndpoints: { method: string; path: string }[];
}

export interface ConfigArtifact {
  /** Relative output path, e.g. "kong.yml" or "rules/01-rate-limit.conf" */
  path: string;
  /** File contents */
  content: string;
  /** MIME for tooling (yaml|json|text|conf) */
  format: 'yaml' | 'json' | 'text' | 'conf';
  /** Optional comment annotations describing which spec fields produced this */
  provenance?: Array<{ line: number; endpoint: string; field: string }>;
}

export interface CapabilityMatrix {
  /** Map of XSecurityPolicy field path → "full" | "partial" | "override-only" | "unsupported" */
  fields: Record<string, 'full' | 'partial' | 'override-only' | 'unsupported'>;
}

export interface Generator {
  readonly name: string;
  readonly targets: readonly string[];
  generate(spec: SpecIR): Promise<ConfigArtifact[]> | ConfigArtifact[];
  capabilities(): CapabilityMatrix;
}
