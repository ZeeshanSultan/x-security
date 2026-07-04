// Per-rule assertions. Each function takes the spec endpoint + a way to
// send traffic and returns a TestCaseResult. Built so each rule can be run
// in isolation (parallel-friendly) and produces a clear pass/fail message.

import type { EndpointIR } from '@writ/core';
import type { TestCaseResult, TestVerdict } from '../reporters/types.js';
import { sendN, sendOnce, type TrafficRequest, type TrafficResponse } from './traffic.js';

function endpointLabel(e: EndpointIR): string {
  return `${e.method} ${e.path}`;
}

function makePath(endpoint: EndpointIR): string {
  // Replace path templates with placeholder values for traffic.
  return endpoint.path.replace(/\{[^}]+\}/g, '1');
}

function baseRequest(endpoint: EndpointIR, headers: Record<string, string> = {}, body?: string): TrafficRequest {
  const req: TrafficRequest = {
    method: endpoint.method,
    path: makePath(endpoint),
    headers
  };
  if (body !== undefined) req.body = body;
  return req;
}

function result(
  endpoint: EndpointIR,
  rule: string,
  verdict: TestVerdict,
  message: string,
  startMs: number
): TestCaseResult {
  return {
    endpoint: endpointLabel(endpoint),
    rule,
    verdict,
    message,
    durationMs: Date.now() - startMs
  };
}

// ---------- rate limit ----------

export async function assertRateLimit(
  baseUrl: string,
  endpoint: EndpointIR
): Promise<TestCaseResult[]> {
  const rls = endpoint.policy.rateLimit;
  if (!rls) return [];
  const list = Array.isArray(rls) ? rls : [rls];
  const out: TestCaseResult[] = [];
  for (const rl of list) {
    const start = Date.now();
    const total = rl.requests + 1;
    try {
      const responses = await sendN(baseUrl, baseRequest(endpoint), total);
      const last = responses[responses.length - 1]!;
      if (last.status === 429) {
        out.push(result(endpoint, 'rateLimit', 'PASS', `429 after ${rl.requests} requests`, start));
      } else {
        out.push(
          result(
            endpoint,
            'rateLimit',
            'FAIL',
            `Expected 429 after ${rl.requests} requests, got ${last.status}`,
            start
          )
        );
      }
    } catch (e) {
      out.push(result(endpoint, 'rateLimit', 'SKIP', `traffic error: ${(e as Error).message}`, start));
    }
  }
  return out;
}

// ---------- auth ----------

export async function assertAuth(baseUrl: string, endpoint: EndpointIR): Promise<TestCaseResult | null> {
  const auth = endpoint.policy.authentication;
  if (!auth || auth.type === 'none') return null;
  const start = Date.now();
  try {
    const res = await sendOnce(baseUrl, baseRequest(endpoint));
    if (res.status === 401 || res.status === 403) {
      return result(endpoint, 'authentication', 'PASS', `Unauth → ${res.status}`, start);
    }
    return result(
      endpoint,
      'authentication',
      'FAIL',
      `Expected 401/403 without credentials, got ${res.status}`,
      start
    );
  } catch (e) {
    return result(endpoint, 'authentication', 'SKIP', `traffic error: ${(e as Error).message}`, start);
  }
}

// ---------- cors ----------

export async function assertCors(baseUrl: string, endpoint: EndpointIR): Promise<TestCaseResult | null> {
  const cors = endpoint.policy.cors;
  if (!cors || !cors.allowedOrigins?.length) return null;
  const start = Date.now();
  const origin = cors.allowedOrigins[0]!;
  try {
    const res = await sendOnce(baseUrl, {
      method: 'OPTIONS',
      path: makePath(endpoint),
      headers: {
        Origin: origin,
        'Access-Control-Request-Method': endpoint.method
      }
    });
    const allowed = res.headers['access-control-allow-origin'];
    if (allowed && (allowed === origin || allowed === '*')) {
      return result(endpoint, 'cors', 'PASS', `CORS preflight echoed ${allowed}`, start);
    }
    return result(endpoint, 'cors', 'FAIL', `CORS allow-origin not set (got ${String(allowed)})`, start);
  } catch (e) {
    return result(endpoint, 'cors', 'SKIP', `traffic error: ${(e as Error).message}`, start);
  }
}

// ---------- request size ----------

export async function assertMaxBodySize(
  baseUrl: string,
  endpoint: EndpointIR
): Promise<TestCaseResult | null> {
  const maxBody = endpoint.policy.request?.maxBodySize;
  if (!maxBody) return null;
  const start = Date.now();
  // Send 2x the declared max-body-size.
  const m = maxBody.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?$/i);
  if (!m) return null;
  const mult: Record<string, number> = { B: 1, KB: 1024, MB: 1024 * 1024, GB: 1024 ** 3 };
  const bytes = Math.round(Number(m[1]) * (mult[(m[2] ?? 'B').toUpperCase()] ?? 1) * 2);
  const big = Buffer.alloc(bytes, 'x');
  try {
    const res = await sendOnce(baseUrl, {
      ...baseRequest(endpoint, { 'Content-Type': 'application/octet-stream' }),
      body: big
    });
    if (res.status === 413) {
      return result(endpoint, 'maxBodySize', 'PASS', `413 on ${bytes}B payload`, start);
    }
    return result(endpoint, 'maxBodySize', 'FAIL', `Expected 413, got ${res.status}`, start);
  } catch (e) {
    return result(endpoint, 'maxBodySize', 'SKIP', `traffic error: ${(e as Error).message}`, start);
  }
}

// ---------- content type ----------

export async function assertContentType(
  baseUrl: string,
  endpoint: EndpointIR
): Promise<TestCaseResult | null> {
  const allowed = endpoint.policy.request?.contentType;
  if (!allowed?.length) return null;
  if (endpoint.method === 'GET' || endpoint.method === 'HEAD') return null;
  const start = Date.now();
  try {
    const res = await sendOnce(baseUrl, {
      ...baseRequest(endpoint, { 'Content-Type': 'application/x-disallowed-type' }),
      body: 'x'
    });
    if (res.status === 415 || res.status === 400) {
      return result(endpoint, 'contentType', 'PASS', `${res.status} on bad content-type`, start);
    }
    return result(endpoint, 'contentType', 'FAIL', `Expected 415/400, got ${res.status}`, start);
  } catch (e) {
    return result(endpoint, 'contentType', 'SKIP', `traffic error: ${(e as Error).message}`, start);
  }
}

// ---------- schema ----------

export async function assertSchema(baseUrl: string, endpoint: EndpointIR): Promise<TestCaseResult | null> {
  const schema = endpoint.policy.request?.schema;
  if (!schema || Object.keys(schema).length === 0) return null;
  const start = Date.now();
  try {
    // Send an empty object — should fail required-property checks for any
    // typed field declared in the schema.
    const res = await sendOnce(baseUrl, {
      ...baseRequest(endpoint, { 'Content-Type': 'application/json' }),
      body: '{}'
    });
    if (res.status === 400 || res.status === 422) {
      return result(endpoint, 'requestSchema', 'PASS', `${res.status} on empty body`, start);
    }
    return result(endpoint, 'requestSchema', 'FAIL', `Expected 400/422, got ${res.status}`, start);
  } catch (e) {
    return result(endpoint, 'requestSchema', 'SKIP', `traffic error: ${(e as Error).message}`, start);
  }
}

// ---------- driver ----------

export async function runAllAssertions(
  baseUrl: string,
  endpoint: EndpointIR
): Promise<TestCaseResult[]> {
  const cases: TestCaseResult[] = [];
  const auth = await assertAuth(baseUrl, endpoint);
  if (auth) cases.push(auth);
  const cors = await assertCors(baseUrl, endpoint);
  if (cors) cases.push(cors);
  const ct = await assertContentType(baseUrl, endpoint);
  if (ct) cases.push(ct);
  const sz = await assertMaxBodySize(baseUrl, endpoint);
  if (sz) cases.push(sz);
  const sch = await assertSchema(baseUrl, endpoint);
  if (sch) cases.push(sch);
  cases.push(...(await assertRateLimit(baseUrl, endpoint)));
  return cases;
}

/** Use TrafficResponse so the import isn't dead. */
export type { TrafficResponse };
