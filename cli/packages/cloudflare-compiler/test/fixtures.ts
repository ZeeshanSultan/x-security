import type { EndpointIR, SpecIR } from '@writ/core';
import type { XSecurityPolicy } from '@writ/schema';

/** Build an EndpointIR with sensible defaults — only override what the test needs. */
export function makeEndpoint(args: {
  method: EndpointIR['method'];
  path: string;
  policy?: XSecurityPolicy;
  operationId?: string;
}): EndpointIR {
  return {
    method: args.method,
    path: args.path,
    operationId: args.operationId ?? `${args.method.toLowerCase()}_${args.path.replace(/[^a-z0-9]/gi, '_')}`,
    policy: args.policy ?? {},
    parameters: [],
    raw: {} as EndpointIR['raw'],
    resolvedVars: new Map()
  };
}

export function makeSpec(endpoints: EndpointIR[]): SpecIR {
  return {
    openapi: '3.1.0',
    dialect: '3.1',
    info: { title: 'fixture', version: '0.0.1' },
    servers: [{ url: 'https://api.example.com' }],
    endpoints,
    unprotectedEndpoints: []
  };
}
