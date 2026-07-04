import { escapeStr } from './endpoint.js';

/**
 * Helpers for Cloudflare Firewall Rule Language expressions.
 * Reference: https://developers.cloudflare.com/ruleset-engine/rules-language/
 */

export function and(...parts: string[]): string {
  const filtered = parts.filter(p => p && p.trim().length > 0);
  if (filtered.length === 0) return 'true';
  if (filtered.length === 1) return filtered[0]!;
  return filtered.map(p => `(${p})`).join(' and ');
}

export function or(...parts: string[]): string {
  const filtered = parts.filter(p => p && p.trim().length > 0);
  if (filtered.length === 0) return 'false';
  if (filtered.length === 1) return filtered[0]!;
  return filtered.map(p => `(${p})`).join(' or ');
}

export function not(expr: string): string {
  return `not (${expr})`;
}

/** `http.request.headers["x-foo"][0]` accessor. */
export function header(name: string): string {
  return `http.request.headers["${escapeStr(name.toLowerCase())}"][0]`;
}

export function hasHeader(name: string): string {
  return `len(http.request.headers["${escapeStr(name.toLowerCase())}"]) > 0`;
}

export function missingHeader(name: string): string {
  return `len(http.request.headers["${escapeStr(name.toLowerCase())}"]) == 0`;
}

export function headerEquals(name: string, value: string): string {
  return `${header(name)} eq "${escapeStr(value)}"`;
}

export function headerMatches(name: string, regex: string): string {
  return `${header(name)} matches "${escapeStr(regex)}"`;
}

export function inCidrAny(cidrs: string[], field = 'ip.src'): string {
  if (cidrs.length === 0) return 'false';
  return `${field} in {${cidrs.map(c => escapeStr(c)).join(' ')}}`;
}

export function bodySizeGt(bytes: number): string {
  return `http.request.body.size > ${bytes}`;
}

export function contentTypeNotIn(allowed: string[]): string {
  if (allowed.length === 0) return 'false';
  const list = allowed.map(t => `"${escapeStr(t)}"`).join(' ');
  return `not (any(http.request.headers["content-type"][*] in {${list}}))`;
}

/** Parse "1MB" / "256KB" / "10kb" → bytes. */
export function parseByteSize(size: string): number {
  const m = /^(\d+(?:\.\d+)?)\s*([KMG]?B)$/i.exec(size.trim());
  if (!m) throw new Error(`Invalid byte size: ${size}`);
  const n = parseFloat(m[1]!);
  const unit = m[2]!.toUpperCase();
  const mul = unit === 'B' ? 1 : unit === 'KB' ? 1024 : unit === 'MB' ? 1024 ** 2 : 1024 ** 3;
  return Math.round(n * mul);
}

/** Parse "5m" / "30s" / "1h" → seconds (Cloudflare rate-limit period units). */
export function parseDurationSeconds(d: string): number {
  const m = /^(\d+)\s*([smhd])$/i.exec(d.trim());
  if (!m) throw new Error(`Invalid duration: ${d}`);
  const n = parseInt(m[1]!, 10);
  const unit = m[2]!.toLowerCase();
  return unit === 's' ? n : unit === 'm' ? n * 60 : unit === 'h' ? n * 3600 : n * 86400;
}
