// Unit tests for `x-security push`. The HTTP layer is injected (Poster) so no
// real network is touched. Headline assertions mirror the hard rules:
//   D-1: citeBacked:false aborts before any POST.
//   G-2: the token is read from WRIT_API_TOKEN env only.
//   G-4: an arbitrary WRIT_API_URL is refused (token-exfil guard).

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import os from 'node:os';
import path from 'node:path';

import { runCompile } from '../src/commands/detect/compile.js';
import { persistPolicy } from '../src/commands/detect/store.js';
import {
  runPush,
  PushError,
  resolveApiUrl,
  resolveToken,
  normalizeRemoteUrl,
  DEFAULT_API_URL,
  type Poster,
  type PostResult,
} from '../src/commands/detect/push.js';

const execFileAsync = promisify(execFile);
const PING_QUOTE = "require('child_process').exec('ping ' + req.body.target);";

let dir: string;

/** A poster that records the call and returns a canned result. */
function recordingPoster(result: PostResult): { poster: Poster; calls: Array<{ url: string; headers: Record<string, string>; body: string }> } {
  const calls: Array<{ url: string; headers: Record<string, string>; body: string }> = [];
  const poster: Poster = async (url, init) => {
    calls.push({ url, headers: init.headers, body: init.body });
    return result;
  };
  return { poster, calls };
}

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'cli-push-'));
  await fs.mkdir(path.join(dir, 'src'), { recursive: true });
  await fs.writeFile(
    path.join(dir, 'src', 'app.js'),
    [
      "const app = require('express')();",
      "app.post('/api/ping', (req, res) => {",
      `  ${PING_QUOTE}`,
      '});',
    ].join('\n'),
  );

  // Make it a real git repo with an origin remote + a commit, so resolveRepoIdentity passes.
  await execFileAsync('git', ['-C', dir, 'init', '-q']);
  await execFileAsync('git', ['-C', dir, 'config', 'user.email', 't@t.dev']);
  await execFileAsync('git', ['-C', dir, 'config', 'user.name', 'T']);
  await execFileAsync('git', ['-C', dir, 'remote', 'add', 'origin', 'git@github.com:acme/widgets.git']);
  await execFileAsync('git', ['-C', dir, 'add', '.']);
  await execFileAsync('git', ['-C', dir, 'commit', '-q', '-m', 'init']);

  // Compile + persist a genuinely cite-backed policy so the local audit passes.
  const compiled = await runCompile({
    repoDir: dir,
    route: { method: 'POST', path: '/api/ping' },
    findings: [
      {
        controlHint: { kind: 'injectionGuard', sink: 'os-command' },
        cite: { file: 'src/app.js', lineStart: 3, lineEnd: 3, quote: PING_QUOTE },
        param: 'target',
      },
    ],
  });
  assert.ok(compiled.policy, 'fixture policy compiled');
  await persistPolicy(dir, { method: 'POST', path: '/api/ping' }, compiled.policy!, compiled.cites);
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------- G-4: host allowlist

test('resolveApiUrl: defaults to the fixed production host', () => {
  assert.equal(resolveApiUrl({}), DEFAULT_API_URL);
});

test('resolveApiUrl: REFUSES an arbitrary host (token-exfil guard)', () => {
  assert.throws(
    () => resolveApiUrl({ WRIT_API_URL: 'https://attacker.com' }),
    (e: unknown) => e instanceof PushError && /Refusing to send the API token/.test((e as Error).message),
  );
});

test('resolveApiUrl: accepts an allowlisted chain305 host', () => {
  assert.equal(resolveApiUrl({ WRIT_API_URL: 'https://lazy.chain305.com/' }), 'https://lazy.chain305.com');
});

test('resolveApiUrl: accepts localhost for dev', () => {
  assert.equal(resolveApiUrl({ WRIT_API_URL: 'http://localhost:3004' }), 'http://localhost:3004');
});

test('resolveApiUrl: accepts canonical X_SECURITY_API_URL', () => {
  assert.equal(resolveApiUrl({ X_SECURITY_API_URL: 'https://lazy.chain305.com' }), 'https://lazy.chain305.com');
});

test('resolveApiUrl: X_SECURITY_API_URL takes precedence over legacy WRIT_API_URL', () => {
  assert.equal(
    resolveApiUrl({ X_SECURITY_API_URL: 'https://lazy.chain305.com', WRIT_API_URL: 'http://localhost:3004' }),
    'https://lazy.chain305.com',
  );
});

test('resolveToken: reads canonical then falls back to legacy WRIT_API_TOKEN', () => {
  assert.equal(resolveToken({ X_SECURITY_API_TOKEN: 'new' }), 'new');
  assert.equal(resolveToken({ WRIT_API_TOKEN: 'legacy' }), 'legacy');
  assert.equal(resolveToken({ X_SECURITY_API_TOKEN: 'new', WRIT_API_TOKEN: 'legacy' }), 'new');
});

test('resolveApiUrl: rejects non-https for a remote host', () => {
  assert.throws(
    () => resolveApiUrl({ WRIT_API_URL: 'http://lazy.chain305.com' }),
    (e: unknown) => e instanceof PushError && /https/.test((e as Error).message),
  );
});

test('runPush refuses an arbitrary host even on --dry-run', async () => {
  await assert.rejects(
    runPush(dir, { dryRun: true, env: { WRIT_API_URL: 'https://evil.example' } }),
    PushError,
  );
});

// ---------------------------------------------------------------- remote normalization

test('normalizeRemoteUrl: scp + https forms collapse to canonical https', () => {
  assert.equal(normalizeRemoteUrl('git@github.com:acme/widgets.git'), 'https://github.com/acme/widgets');
  assert.equal(normalizeRemoteUrl('https://github.com/acme/widgets.git'), 'https://github.com/acme/widgets');
  assert.equal(normalizeRemoteUrl('ssh://git@github.com/acme/widgets'), 'https://github.com/acme/widgets');
});

// ---------------------------------------------------------------- D-1: citeBacked gate

test('runPush ABORTS when the local audit is not cite-backed (D-1)', async () => {
  // Tamper the sidecar so the cite no longer byte-matches → citeBacked:false.
  const sidecar = path.join(dir, '.x-security', 'policies', 'POST__api__ping.cites.json');
  const original = await fs.readFile(sidecar, 'utf8');
  const j = JSON.parse(original) as { cites: Array<{ quote: string }> };
  j.cites[0]!.quote = 'this string was never in the source';
  await fs.writeFile(sidecar, JSON.stringify(j));

  const { poster, calls } = recordingPoster({ status: 200, body: { importId: 'x', imported: 1, reportUrl: 'u' } });
  try {
    await assert.rejects(
      runPush(dir, { env: { WRIT_API_TOKEN: 'tok' }, poster }),
      (e: unknown) => e instanceof PushError && /citeBacked=false/.test((e as Error).message),
    );
    assert.equal(calls.length, 0, 'never POSTs an unverified bundle');
  } finally {
    await fs.writeFile(sidecar, original); // restore for later tests
  }
});

// ---------------------------------------------------------------- non-git

test('runPush errors clearly outside a git repo', async () => {
  const plain = await fs.mkdtemp(path.join(os.tmpdir(), 'cli-push-nogit-'));
  try {
    // Give it a cite-backed bundle so the abort is specifically about git, not audit.
    await fs.mkdir(path.join(plain, 'src'), { recursive: true });
    await fs.writeFile(path.join(plain, 'src', 'app.js'), `app.post('/x', () => { ${PING_QUOTE} });`);
    const compiled = await runCompile({
      repoDir: plain,
      route: { method: 'POST', path: '/x' },
      findings: [
        { controlHint: { kind: 'injectionGuard', sink: 'os-command' }, cite: { file: 'src/app.js', lineStart: 1, lineEnd: 1, quote: PING_QUOTE }, param: 'target' },
      ],
    });
    await persistPolicy(plain, { method: 'POST', path: '/x' }, compiled.policy!, compiled.cites);

    await assert.rejects(
      runPush(plain, { env: { WRIT_API_TOKEN: 'tok' }, poster: recordingPoster({ status: 200, body: {} }).poster }),
      (e: unknown) => e instanceof PushError && /not a git repository/.test((e as Error).message),
    );
  } finally {
    await fs.rm(plain, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- G-2: token from env

test('runPush errors when WRIT_API_TOKEN is unset (G-2: env only)', async () => {
  await assert.rejects(
    runPush(dir, { env: {}, poster: recordingPoster({ status: 200, body: {} }).poster }),
    (e: unknown) => e instanceof PushError && /WRIT_API_TOKEN/.test((e as Error).message),
  );
});

// ---------------------------------------------------------------- happy path payload shape

test('runPush sends the correct payload + Bearer token, prints imported result', async () => {
  const { poster, calls } = recordingPoster({
    status: 200,
    body: { importId: 'imp_123', imported: 1, reportUrl: 'https://usewaf.com/r/imp_123' },
  });

  const r = await runPush(dir, { env: { WRIT_API_TOKEN: 'secret-key' }, poster });

  assert.equal(calls.length, 1);
  const call = calls[0]!;
  // Routes through the web proxy, not the api's /v1/* directly.
  assert.equal(call.url, `${DEFAULT_API_URL}/api/web/v1/policies/import`);
  assert.equal(call.headers.Authorization, 'Bearer secret-key');
  assert.equal(call.headers['Content-Type'], 'application/json');

  const sent = JSON.parse(call.body) as Record<string, unknown>;
  assert.equal(sent.repoUrl, 'https://github.com/acme/widgets');
  assert.match(sent.commitSha as string, /^[0-9a-f]{40}$/);
  const audit = sent.audit as Record<string, unknown>;
  assert.equal(audit.citeBacked, true);
  assert.equal(audit.coverage, 1);
  assert.ok(Array.isArray(sent.policies) && (sent.policies as unknown[]).length === 1);
  const pol = (sent.policies as Array<Record<string, unknown>>)[0]!;
  assert.equal(pol.id, 'POST__api__ping');
  assert.ok(pol.policy && Array.isArray(pol.cites));

  assert.equal(r.response!.imported, 1);
  assert.equal(r.response!.reportUrl, 'https://usewaf.com/r/imp_123');

  // G-2: the raw token must never appear in the returned payload/result object.
  assert.ok(!JSON.stringify(r.payload).includes('secret-key'));
});

test('the bearer token never appears in stdout or stderr (G-2)', async () => {
  // Capture everything the push path could write while the secret is in play.
  const TOKEN = 'sk_super_secret_leak_canary';
  const out: string[] = [];
  const err: string[] = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stdout.write = ((c: any, ...a: any[]) => { out.push(String(c)); return (origOut as any)(c, ...a); }) as any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  process.stderr.write = ((c: any, ...a: any[]) => { err.push(String(c)); return (origErr as any)(c, ...a); }) as any;

  try {
    const { poster } = recordingPoster({
      status: 200,
      body: { importId: 'imp_x', imported: 1, reportUrl: 'https://usewaf.com/api/web/v1/policies/import/imp_x' },
    });
    const r = await runPush(dir, { env: { WRIT_API_TOKEN: TOKEN }, poster });
    // Mirror what the bin prints so a regression in the print path is covered.
    process.stdout.write(`imported ${r.response!.imported} policies → ${r.response!.reportUrl}\n`);

    const combined = out.join('') + err.join('');
    assert.ok(!combined.includes(TOKEN), 'token must never be written to stdout/stderr');
    // Belt + suspenders: the token isn't in the surfaced result object either.
    assert.ok(!JSON.stringify(r).includes(TOKEN), 'token must never be in the result object');
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
});

test('buildPayload aborts when origin is not a github.com repo (UX pre-validation)', async () => {
  // A repo whose origin is a non-github host must abort locally, before any POST.
  const nongh = await fs.mkdtemp(path.join(os.tmpdir(), 'cli-push-nongh-'));
  try {
    await fs.mkdir(path.join(nongh, 'src'), { recursive: true });
    await fs.writeFile(path.join(nongh, 'src', 'app.js'), `app.post('/x', () => { ${PING_QUOTE} });`);
    await execFileAsync('git', ['-C', nongh, 'init', '-q']);
    await execFileAsync('git', ['-C', nongh, 'config', 'user.email', 't@t.dev']);
    await execFileAsync('git', ['-C', nongh, 'config', 'user.name', 'T']);
    await execFileAsync('git', ['-C', nongh, 'remote', 'add', 'origin', 'git@gitlab.com:acme/widgets.git']);
    await execFileAsync('git', ['-C', nongh, 'add', '.']);
    await execFileAsync('git', ['-C', nongh, 'commit', '-q', '-m', 'init']);
    const compiled = await runCompile({
      repoDir: nongh,
      route: { method: 'POST', path: '/x' },
      findings: [
        { controlHint: { kind: 'injectionGuard', sink: 'os-command' }, cite: { file: 'src/app.js', lineStart: 1, lineEnd: 1, quote: PING_QUOTE }, param: 'target' },
      ],
    });
    await persistPolicy(nongh, { method: 'POST', path: '/x' }, compiled.policy!, compiled.cites);

    const { poster, calls } = recordingPoster({ status: 200, body: { importId: 'x', imported: 1, reportUrl: 'u' } });
    await assert.rejects(
      runPush(nongh, { env: { WRIT_API_TOKEN: 'tok' }, poster }),
      (e: unknown) => e instanceof PushError && /not an accepted import URL/.test((e as Error).message),
    );
    assert.equal(calls.length, 0, 'never POSTs a non-github origin');
  } finally {
    await fs.rm(nongh, { recursive: true, force: true });
  }
});

test('runPush --dry-run validates without POSTing', async () => {
  const { poster, calls } = recordingPoster({ status: 200, body: {} });
  const r = await runPush(dir, { dryRun: true, env: { WRIT_API_TOKEN: 'tok' }, poster });
  assert.equal(r.dryRun, true);
  assert.equal(calls.length, 0, 'dry-run never sends');
  assert.equal(r.payload.repoUrl, 'https://github.com/acme/widgets');
  assert.equal(r.payload.audit.citeBacked, true);
});

// ---------------------------------------------------------------- D-1: server error surfaced

test('runPush surfaces a non-2xx server response verbatim (D-1)', async () => {
  const { poster } = recordingPoster({ status: 400, body: { message: 'citeBacked must be true' } });
  await assert.rejects(
    runPush(dir, { env: { WRIT_API_TOKEN: 'tok' }, poster }),
    (e: unknown) => e instanceof PushError && /HTTP 400/.test((e as Error).message) && /citeBacked must be true/.test((e as Error).message),
  );
});

test('runPush rejects a 200 with an unexpected body shape', async () => {
  const { poster } = recordingPoster({ status: 200, body: { nope: true } });
  await assert.rejects(
    runPush(dir, { env: { WRIT_API_TOKEN: 'tok' }, poster }),
    (e: unknown) => e instanceof PushError && /unexpected body shape/.test((e as Error).message),
  );
});
