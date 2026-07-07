/**
 * Host-firewall drift detector (file-mode only).
 *
 * Accepts either:
 *   - a single `iptables-save` output / `.rules` file, OR
 *   - a directory containing `iptables.rules` and/or `ip6tables.rules`.
 *
 * Strategy:
 *   1. Regenerate expected v4/v6 rulesets from the SpecIR via the firewall
 *      generator.
 *   2. Extract the XSecurity-tagged rules from both expected and actual by
 *      grepping for the `# x-security:` provenance prefix and pairing each
 *      comment with its following non-comment rule line.
 *   3. Diff the canonical (comment, rule) pairs as ordered sets — missing
 *      pairs are reported by severity bucket based on the comment tag.
 */
import { readFile, stat } from 'node:fs/promises';
import * as path from 'node:path';
import type { SpecIR } from '@x-security/core';
import type { DriftIssue, DriftReport, DriftSeverity } from '../reporters/types.js';
import { firewallGenerator } from '../generators/firewall/index.js';

export interface FirewallDriftOptions {
  /** Path to a single rules file OR a directory containing iptables.rules/ip6tables.rules. */
  filePath: string;
  /** Optional override content for tests. If set, treated as a single ruleset. */
  rulesContent?: string;
  /** If true, only consider v4 ruleset (used internally for dir-walk). */
  family?: 'v4' | 'v6';
}

/** A XSecurity-tagged (comment, rule) pair extracted from a ruleset. */
interface TaggedRule {
  comment: string; // full `# x-security: ...` line
  rule: string;    // following `-A OUTPUT ...` line (whitespace-normalized)
  tag: string;     // the `endpoint field` portion (between `x-security:` and ` -- `)
}

function normalizeRuleLine(line: string): string {
  return line.replace(/\s+/g, ' ').trim();
}

/**
 * Extract the destination identifier from a normalized iptables rule line —
 * either a `-d <cidr>` argument or a `@@X_SECURITY_RESOLVE:<fqdn>@@` token.
 * Returns the empty string for rules without a destination (e.g. the
 * default-deny terminator). Two rules sharing a tag but with different
 * destinations are independent protections.
 */
function destOf(rule: string): string {
  const cidr = /-d\s+(\S+)/.exec(rule);
  if (cidr && cidr[1]) return cidr[1];
  const fqdn = /@@(?:X_SECURITY|WRIT)_RESOLVE:([^@]+)@@/.exec(rule);
  if (fqdn && fqdn[1]) return `fqdn:${fqdn[1]}`;
  return '';
}

function extractTagged(content: string): TaggedRule[] {
  const lines = content.split(/\r?\n/);
  const out: TaggedRule[] = [];
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (!l) continue;
    if (!l.startsWith('# x-security:')) continue;
    // Find the next non-empty, non-comment line.
    let j = i + 1;
    while (j < lines.length) {
      const next = lines[j];
      if (next && next.trim() !== '' && !next.trim().startsWith('#')) break;
      j++;
    }
    const ruleLine = lines[j];
    if (!ruleLine) continue;
    // Tag is everything after `# x-security:` and before ` -- ` (or whole line).
    const body = l.slice('# x-security:'.length).trim();
    const sepIdx = body.indexOf(' -- ');
    const tag = sepIdx >= 0 ? body.slice(0, sepIdx).trim() : body;
    out.push({
      comment: l.trim(),
      rule: normalizeRuleLine(ruleLine),
      tag
    });
  }
  return out;
}

function severityForTag(tag: string): DriftSeverity {
  // `*  ssrf-metadata-block` and `*  ssrf-private-range-block` — losing these
  // is a critical SSRF exposure.
  if (/ssrf-metadata-block/.test(tag)) return 'CRITICAL';
  if (/ssrf-private-range-block/.test(tag)) return 'CRITICAL';
  if (/default-deny/.test(tag)) return 'CRITICAL';
  // Per-endpoint domainAllowlist ACCEPT rules — losing them is HIGH (apps
  // fail-closed under the default deny terminator, but still a drift).
  if (/domainAllowlist|allow=/.test(tag)) return 'HIGH';
  return 'LOW';
}

function endpointFromTag(tag: string): string {
  // Tag is shaped like `<endpoint> <field>` (space-separated). Take everything
  // up to the last space as the endpoint label.
  const lastSpace = tag.lastIndexOf(' ');
  if (lastSpace <= 0) return tag;
  return tag.slice(0, lastSpace);
}

function fieldFromTag(tag: string): string {
  const lastSpace = tag.lastIndexOf(' ');
  if (lastSpace <= 0) return tag;
  return tag.slice(lastSpace + 1);
}

function diffRuleset(
  family: 'v4' | 'v6',
  expected: TaggedRule[],
  actual: TaggedRule[]
): DriftIssue[] {
  const issues: DriftIssue[] = [];
  const actByKey = new Map<string, TaggedRule>();
  for (const a of actual) actByKey.set(`${a.tag}::${a.rule}`, a);
  const actByTag = new Map<string, TaggedRule[]>();
  for (const a of actual) {
    const list = actByTag.get(a.tag) ?? [];
    list.push(a);
    actByTag.set(a.tag, list);
  }

  // Tags shared across many rules (SSRF metadata/private-range blocks): every
  // rule is independent protection, so a missing exact (tag, rule) pair is a
  // missing protection at the tag's full severity. Tags with only one rule per
  // ruleset (per-endpoint allowlist entries, default-deny) get the same
  // missing-rule classification; body-drift gets a softer severity since the
  // owner/comment metadata may have shifted while the destination still matches.
  for (const e of expected) {
    const exact = actByKey.get(`${e.tag}::${e.rule}`);
    if (exact) continue;
    // Check whether there is *any* actual rule with this exact destination
    // (the post-`-d <cidr>`/`@@X_SECURITY_RESOLVE:<fqdn>@@` portion). Two
    // rules sharing a tag with different destinations are independent
    // protections — drop one and the other doesn't cover for it.
    const expDest = destOf(e.rule);
    const sameDest = actual.find((a) => a.tag === e.tag && destOf(a.rule) === expDest);
    if (!sameDest) {
      issues.push({
        endpoint: endpointFromTag(e.tag),
        field: `${family}.${fieldFromTag(e.tag)}`,
        severity: severityForTag(e.tag),
        expected: e.rule,
        actual: undefined,
        message: `Firewall (${family}) rule missing: ${e.comment}`
      });
      continue;
    }
    // Destination matches but rest of rule body drifts — softer severity.
    issues.push({
      endpoint: endpointFromTag(e.tag),
      field: `${family}.${fieldFromTag(e.tag)}`,
      severity: severityForTag(e.tag) === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
      expected: e.rule,
      actual: sameDest.rule,
      message: `Firewall (${family}) rule body drift for tag "${e.tag}" dest "${expDest}"`
    });
  }
  void actByTag;

  // Unknown x-security-tagged rules in actual but not expected → LOW.
  const expByKey = new Set(expected.map((e) => `${e.tag}::${e.rule}`));
  for (const a of actual) {
    if (!expByKey.has(`${a.tag}::${a.rule}`)) {
      // Avoid double-reporting tag drift; only report if tag is genuinely unknown.
      const tagInExpected = expected.some((e) => e.tag === a.tag);
      if (tagInExpected) continue;
      issues.push({
        endpoint: endpointFromTag(a.tag),
        field: `${family}.${fieldFromTag(a.tag)}`,
        severity: 'LOW',
        expected: undefined,
        actual: a.rule,
        message: `Unknown XSecurity-tagged firewall (${family}) rule: ${a.comment}`
      });
    }
  }

  return issues;
}

async function readMaybeDir(p: string): Promise<{ v4?: string; v6?: string; single?: string }> {
  try {
    const s = await stat(p);
    if (s.isDirectory()) {
      const out: { v4?: string; v6?: string } = {};
      try {
        out.v4 = await readFile(path.join(p, 'iptables.rules'), 'utf8');
      } catch {
        // optional
      }
      try {
        out.v6 = await readFile(path.join(p, 'ip6tables.rules'), 'utf8');
      } catch {
        // optional
      }
      return out;
    }
  } catch {
    // fall through to file read
  }
  const single = await readFile(p, 'utf8');
  return { single };
}

function classifyFamily(content: string): 'v4' | 'v6' {
  // Heuristic: ip6tables-save mentions ipv6 in its header comment.
  return /IPv6|ip6tables-restore/i.test(content) ? 'v6' : 'v4';
}

export async function detectFirewallDrift(
  spec: SpecIR,
  opts: FirewallDriftOptions
): Promise<DriftReport> {
  const artifacts = await Promise.resolve(firewallGenerator.generate(spec));
  const expectedV4 = artifacts.find((a) => a.path.endsWith('iptables.rules'))?.content ?? '';
  const expectedV6 = artifacts.find((a) => a.path.endsWith('ip6tables.rules'))?.content ?? '';

  let actualV4 = '';
  let actualV6 = '';

  if (opts.rulesContent !== undefined) {
    const fam = opts.family ?? classifyFamily(opts.rulesContent);
    if (fam === 'v6') actualV6 = opts.rulesContent;
    else actualV4 = opts.rulesContent;
  } else {
    const sources = await readMaybeDir(opts.filePath);
    if (sources.v4 !== undefined) actualV4 = sources.v4;
    if (sources.v6 !== undefined) actualV6 = sources.v6;
    if (sources.single !== undefined) {
      const fam = opts.family ?? classifyFamily(sources.single);
      if (fam === 'v6') actualV6 = sources.single;
      else actualV4 = sources.single;
    }
  }

  const issues: DriftIssue[] = [];
  if (expectedV4 && actualV4) {
    issues.push(...diffRuleset('v4', extractTagged(expectedV4), extractTagged(actualV4)));
  } else if (expectedV4 && !actualV4) {
    // No v4 ruleset deployed at all — count every expected SSRF block as missing.
    for (const e of extractTagged(expectedV4)) {
      issues.push({
        endpoint: endpointFromTag(e.tag),
        field: `v4.${fieldFromTag(e.tag)}`,
        severity: severityForTag(e.tag),
        expected: e.rule,
        actual: undefined,
        message: `Firewall (v4) ruleset absent: ${e.comment}`
      });
    }
  }
  if (expectedV6 && actualV6) {
    issues.push(...diffRuleset('v6', extractTagged(expectedV6), extractTagged(actualV6)));
  } else if (expectedV6 && !actualV6) {
    for (const e of extractTagged(expectedV6)) {
      issues.push({
        endpoint: endpointFromTag(e.tag),
        field: `v6.${fieldFromTag(e.tag)}`,
        severity: severityForTag(e.tag),
        expected: e.rule,
        actual: undefined,
        message: `Firewall (v6) ruleset absent: ${e.comment}`
      });
    }
  }

  return {
    kind: 'drift',
    target: 'firewall',
    gatewaySource: opts.filePath,
    issues
  };
}
