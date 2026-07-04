// Regression for the missing-auth anchor (mlflow CVE-2026-0545): a FastAPI router whose
// mount prefix is declared on the CONSTRUCTOR — `APIRouter(prefix="/ajax-api/3.0/jobs")` —
// must compose that prefix onto every route. Before this the prefix was read only from the
// include site, so the whole router grounded as a bare `/` and its routes were invisible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseFastapi } from '../src/frameworks/fastapi.js';

async function withPyFile(src: string, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'fastapi-prefix-'));
  try {
    await fs.writeFile(path.join(dir, 'job_api.py'), src, 'utf8');
    await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test('APIRouter(prefix="…") constructor prefix composes onto every route', async () => {
  const src = [
    'from fastapi import APIRouter',
    'job_api_router = APIRouter(prefix="/ajax-api/3.0/jobs", tags=["Job"])',
    '@job_api_router.post("/")',
    'def submit_job(payload: SubmitJobPayload) -> Job:',
    '    return submit_job(payload)',
    '@job_api_router.get("/{job_id}")',
    'def get_job(job_id: str) -> Job:',
    '    return get(job_id)',
  ].join('\n');
  await withPyFile(src, async (dir) => {
    const routes = await parseFastapi(dir);
    assert.ok(
      routes.some((r) => r.method === 'POST' && r.path === '/ajax-api/3.0/jobs/'),
      'POST route grounds under the constructor prefix',
    );
    assert.ok(
      routes.some((r) => r.method === 'GET' && /\/ajax-api\/3\.0\/jobs\/\{job_id\}/.test(r.path)),
      'GET route grounds under the constructor prefix too',
    );
    assert.ok(!routes.some((r) => r.path === '/'), 'no route grounds as a bare /');
  });
});
