import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { SpecIR, EndpointIR } from '@writ/core';
import { firewallGenerator } from '../../src/generators/firewall/index.js';
import {
  buildIptablesV4,
  buildIptablesV6,
} from '../../src/generators/firewall/iptables.js';
import {
  CLOUD_METADATA_BLOCKS,
  PRIVATE_RANGE_BLOCKS,
} from '../../src/generators/firewall/metadata-blocks.js';

function endpoint(
  operationId: string,
  partial: Partial<EndpointIR> = {}
): EndpointIR {
  return {
    method: 'POST',
    path: '/x',
    operationId,
    policy: {},
    parameters: [],
    raw: {} as EndpointIR['raw'],
    resolvedVars: new Map(),
    ...partial,
  };
}

function spec(endpoints: EndpointIR[]): SpecIR {
  return {
    openapi: '3.1.0',
    dialect: '3.1',
    info: { title: 't', version: '0' },
    servers: [],
    endpoints,
    unprotectedEndpoints: [],
  };
}

describe('firewall generator', () => {
  it('emits v4 + v6 artifacts at expected paths', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{ path: string }>;
    const rulePaths = out
      .map((a) => a.path)
      .filter((p) => p.endsWith('.rules'))
      .sort();
    assert.deepEqual(rulePaths, [
      'firewall/ip6tables.rules',
      'firewall/iptables.rules',
    ]);
  });

  it('always blocks cloud metadata endpoints (v4) with DROP, never REJECT', () => {
    const out = buildIptablesV4(spec([]));
    for (const entry of CLOUD_METADATA_BLOCKS.filter((e) => e.family === 'v4')) {
      assert.ok(
        out.includes(`-d ${entry.cidr}`),
        `missing metadata block for ${entry.cidr}`
      );
    }
    assert.ok(out.includes('-j DROP'));
    assert.ok(!out.includes('-j REJECT'), 'must never emit REJECT');
  });

  it('always blocks RFC1918 ranges (v4)', () => {
    const out = buildIptablesV4(spec([]));
    for (const entry of PRIVATE_RANGE_BLOCKS.filter((e) => e.family === 'v4')) {
      assert.ok(
        out.includes(`-d ${entry.cidr}`),
        `missing private-range block for ${entry.cidr}`
      );
    }
  });

  it('always blocks v6 metadata + ULA + link-local', () => {
    const out = buildIptablesV6(spec([]));
    for (const entry of [...CLOUD_METADATA_BLOCKS, ...PRIVATE_RANGE_BLOCKS].filter(
      (e) => e.family === 'v6'
    )) {
      assert.ok(out.includes(entry.cidr), `missing v6 block for ${entry.cidr}`);
    }
    assert.ok(!out.includes('-j REJECT'));
  });

  it('emits ACCEPT rule (before DROPs) for each domain in a URL allowlist', () => {
    const ep = endpoint('callWebhook', {
      method: 'POST',
      path: '/webhooks/dispatch',
      policy: {
        request: {
          schema: {
            target: {
              type: 'url',
              domainAllowlist: ['hooks.example.com', 'api.partner.io'],
            },
          },
        },
      },
    });
    const out = buildIptablesV4(spec([ep]));
    const acceptIdx = out.indexOf('@@WRIT_RESOLVE:hooks.example.com@@');
    const partnerIdx = out.indexOf('@@WRIT_RESOLVE:api.partner.io@@');
    const firstDropIdx = out.indexOf('-j DROP');
    assert.ok(acceptIdx > -1, 'missing resolver token for hooks.example.com');
    assert.ok(partnerIdx > -1, 'missing resolver token for api.partner.io');
    assert.ok(
      acceptIdx < firstDropIdx,
      'ACCEPT rules must precede DROPs for correct iptables precedence'
    );
    assert.ok(out.includes('-j ACCEPT'));
  });

  it('records provenance with `# writ:` markers on every rule', () => {
    const out = buildIptablesV4(spec([]));
    const lines = out.split('\n');
    // Every non-empty, non-header, non-`-A` line in body should be a comment.
    // Simpler invariant: every `-A OUTPUT` line has a matching `# writ:`
    // comment immediately preceding it.
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line || !line.startsWith('-A OUTPUT')) continue;
      const prev = lines[i - 1] ?? '';
      assert.ok(
        prev.startsWith('# writ:'),
        `rule on line ${i} missing provenance comment, got: ${prev}`
      );
    }
  });

  it('appends a fail-closed default-deny terminator', () => {
    const out = buildIptablesV4(spec([]));
    assert.ok(out.includes('writ/default-deny'));
    assert.ok(out.includes('default-deny -- fail-closed terminator'));
    // Terminator must appear after the last per-rule ACCEPT/DROP body.
    const terminatorIdx = out.indexOf('writ/default-deny');
    const commitIdx = out.indexOf('COMMIT');
    assert.ok(terminatorIdx > 0 && terminatorIdx < commitIdx);
  });

  it('skips URL fields with no domainAllowlist', () => {
    const ep = endpoint('unrestricted', {
      policy: { request: { schema: { target: { type: 'url' } } } },
    });
    const out = buildIptablesV4(spec([ep]));
    assert.ok(!out.includes('-j ACCEPT'), 'should not emit allowlist rule');
  });

  it('skips non-URL fields even when they have a domainAllowlist (defensive)', () => {
    const ep = endpoint('weird', {
      policy: {
        request: {
          schema: {
            name: { type: 'string', domainAllowlist: ['nope.example.com'] },
          },
        },
      },
    });
    const out = buildIptablesV4(spec([ep]));
    assert.ok(!out.includes('nope.example.com'));
  });

  it('capabilities matrix reports only domainAllowlist as full', () => {
    const caps = firewallGenerator.capabilities();
    assert.equal(caps.fields['request.schema.*.domainAllowlist'], 'full');
    // Spot-check a few unsupported fields:
    assert.equal(caps.fields['authentication'], 'unsupported');
    assert.equal(caps.fields['rateLimit'], 'unsupported');
    assert.equal(caps.fields['cors'], 'unsupported');
  });

  it('uses iptables-restore-compatible header (*filter + COMMIT)', () => {
    const out = buildIptablesV4(spec([]));
    assert.ok(out.startsWith('# Generated by Writ'));
    assert.ok(out.includes('*filter'));
    assert.ok(out.includes(':OUTPUT ACCEPT'));
    assert.ok(out.trimEnd().endsWith('COMMIT'));
  });

  it('scopes all DROPs by --uid-owner so we do not block system processes', () => {
    const out = buildIptablesV4(spec([]));
    const dropLines = out.split('\n').filter((l) => l.includes('-j DROP'));
    assert.ok(dropLines.length > 0);
    for (const line of dropLines) {
      assert.ok(
        line.includes('--uid-owner'),
        `DROP rule missing uid scope: ${line}`
      );
    }
  });

  it('emits deploy-time DNS wrapper scripts as additional artifacts', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
      format: string;
    }>;
    const paths = out.map((a) => a.path);
    for (const p of [
      'firewall/scripts/writ-resolve.sh',
      'firewall/scripts/writ-refresh.sh',
      'firewall/scripts/writ-refresh.service',
      'firewall/scripts/writ-refresh.timer',
      'firewall/scripts/writ.logrotate',
      'firewall/scripts/README.md',
    ]) {
      assert.ok(paths.includes(p), `missing wrapper artifact ${p}`);
    }
  });

  it('resolver and refresh scripts begin with a POSIX shebang', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const resolve = out.find((a) => a.path.endsWith('writ-resolve.sh'));
    const refresh = out.find((a) => a.path.endsWith('writ-refresh.sh'));
    assert.ok(resolve, 'resolver script missing');
    assert.ok(refresh, 'refresh script missing');
    assert.ok(
      resolve!.content.startsWith('#!/bin/sh'),
      `resolver shebang wrong, got: ${resolve!.content.split('\n')[0]}`
    );
    assert.ok(
      refresh!.content.startsWith('#!/bin/sh'),
      `refresh shebang wrong, got: ${refresh!.content.split('\n')[0]}`
    );
  });

  it('resolver script references getent/dig and never emits REJECT', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const resolve = out.find((a) => a.path.endsWith('writ-resolve.sh'))!;
    assert.ok(resolve.content.includes('getent'), 'resolver should use getent');
    assert.ok(resolve.content.includes('dig'), 'resolver should fall back to dig');
    assert.ok(
      !resolve.content.match(/-j\s+REJECT/),
      'wrapper must never emit REJECT'
    );
  });

  it('resolver script guards against the three wave-7 busybox/alpine regressions', () => {
    // 1. Pass-1 token extraction must skip comment lines so the header's
    //    documentation token `@@WRIT_RESOLVE:<fqdn>@@` is not
    //    treated as a real FQDN.
    // 2. `grep -c` zero-match must not be combined with `|| echo 0`
    //    (yields multi-line output that breaks $((TOTAL - FAILED))).
    // 3. busybox awk's `(x in y ? ... : ...)` ternary has a key-creating
    //    side effect; presence MUST be tracked via an explicit flag.
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const resolve = out.find((a) => a.path.endsWith('writ-resolve.sh'))!;
    assert.ok(
      /grep -v ['"]\^\[\[:space:\]\]\*#['"]/.test(resolve.content),
      'Pass-1 must skip comment lines (wave-7 regression #1)'
    );
    assert.ok(
      !/grep -c [^\n|]*\|\|\s*echo 0/.test(resolve.content),
      'grep -c || echo 0 produces multi-line on zero matches (wave-7 regression #2)'
    );
    // Strip comments before checking — the NOTE explains the bug and
    // legitimately quotes the broken ternary syntax in prose.
    const resolveCode = resolve.content
      .split('\n')
      .filter((line) => !/^\s*#/.test(line))
      .join('\n');
    assert.ok(
      /seen\[/.test(resolveCode) &&
        !/\(f\[1\] in addrs \?/.test(resolveCode),
      'busybox awk requires explicit seen[] flag, not `in addrs` ternary (wave-7 regression #3)'
    );
  });

  it('refresh script invokes iptables-restore and implements flap detection', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const refresh = out.find((a) => a.path.endsWith('writ-refresh.sh'))!;
    assert.ok(refresh.content.includes('iptables-restore'));
    assert.ok(
      /FLAP|flap/.test(refresh.content),
      'refresh script must implement flap detection'
    );
  });

  it('systemd timer fires every 5 minutes', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const timer = out.find((a) => a.path.endsWith('writ-refresh.timer'))!;
    assert.ok(timer.content.includes('OnUnitActiveSec=5min'));
    assert.ok(timer.content.includes('[Timer]'));
  });

  it('README is non-empty and documents WRIT_APP_UID', () => {
    const out = firewallGenerator.generate(spec([])) as Array<{
      path: string;
      content: string;
    }>;
    const readme = out.find((a) => a.path.endsWith('scripts/README.md'))!;
    assert.ok(readme.content.length > 200, 'README too short');
    assert.ok(
      readme.content.includes('WRIT_APP_UID'),
      'README must document WRIT_APP_UID requirement'
    );
  });

  it('records provenance entries on artifacts when URL fields exist', () => {
    const ep = endpoint('callWebhook', {
      policy: {
        request: {
          schema: {
            target: { type: 'url', domainAllowlist: ['x.example.com'] },
          },
        },
      },
    });
    const out = firewallGenerator.generate(spec([ep])) as Array<{
      provenance?: Array<{ endpoint: string; field: string }>;
    }>;
    assert.ok(out[0]?.provenance?.[0]);
    assert.equal(
      out[0]?.provenance?.[0]?.field,
      'request.schema.target.domainAllowlist'
    );
  });
});

describe('firewall W11-B: ssrf-policy-missing warning', () => {
  it('fires when type=url param lacks domainAllowlist/blockPrivateRanges', () => {
    const ep = endpoint('redir', {
      method: 'GET',
      path: '/redirect',
      policy: { request: { schema: { url: { type: 'url' } } } },
    });
    firewallGenerator.generate(spec([ep]));
    const joined = firewallGenerator.lastWarnings.join('\n');
    assert.match(joined, /\[firewall:ssrf-policy-missing\] GET \/redirect/);
    assert.match(joined, /parameter "url"/);
    assert.match(joined, /Firewall can enforce SSRF policy ONLY when domainAllowlist/);
  });
});
