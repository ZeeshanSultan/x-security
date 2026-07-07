// Undici-based traffic generator. Each test case yields a `TrafficRequest`,
// the harness sends it, and we capture status/headers/body for assertions.

import { request as undiciRequest } from 'undici';

export interface TrafficRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  /** ms */
  timeout?: number;
}

export interface TrafficResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  durationMs: number;
}

export async function sendOnce(baseUrl: string, req: TrafficRequest, timeoutMs?: number): Promise<TrafficResponse> {
  const start = Date.now();
  const url = baseUrl.replace(/\/$/, '') + req.path;
  const opts: Parameters<typeof undiciRequest>[1] = {
    method: req.method as 'GET',
    headers: req.headers ?? {}
  };
  if (req.body !== undefined) opts.body = req.body;
  if (req.timeout) opts.headersTimeout = req.timeout;
  if (timeoutMs !== undefined) opts.signal = AbortSignal.timeout(timeoutMs);

  try {
    const res = await undiciRequest(url, opts);
    const buf = await res.body.arrayBuffer();
    return {
      status: res.statusCode,
      headers: res.headers as Record<string, string | string[] | undefined>,
      body: Buffer.from(buf).toString('utf8'),
      durationMs: Date.now() - start
    };
  } catch (e) {
    const name = (e as Error).name;
    if (name === 'TimeoutError' || name === 'AbortError') {
      throw new Error(`${req.method} ${url} timed out after ${timeoutMs}ms`);
    }
    throw e;
  }
}

export async function sendN(
  baseUrl: string,
  req: TrafficRequest,
  count: number,
  timeoutMs?: number
): Promise<TrafficResponse[]> {
  const out: TrafficResponse[] = [];
  for (let i = 0; i < count; i++) {
    out.push(await sendOnce(baseUrl, req, timeoutMs));
  }
  return out;
}
