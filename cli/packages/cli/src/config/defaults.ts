import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import type { Command } from 'commander';

export interface WritConfig {
  format?: string;
  timeout?: number;
  out?: string;
}

// Only these keys are honored from config. `target` is intentionally excluded:
// it's a commander requiredOption on subcommands, and commander enforces
// requiredness during parse — before our preAction hook runs — so a config
// value could never satisfy it anyway.
const KNOWN_KEYS = ['format', 'timeout', 'out'] as const;

// Attribute-name mapping: long flag -> commander option attribute name.
const OPTION_ATTRS: Record<keyof WritConfig, string> = {
  format: 'format',
  timeout: 'timeout',
  out: 'out',
};

const LONG_FLAGS: Record<keyof WritConfig, string> = {
  format: '--format',
  timeout: '--timeout',
  out: '--out',
};

// Parse one file best-effort. A malformed/unreadable file must never throw —
// a bad config in one location shouldn't sink the whole run; we just skip it.
function readConfigFile(file: string): WritConfig {
  try {
    if (!existsSync(file)) return {};
    const raw = readFileSync(file, 'utf8');
    const doc = yaml.load(raw);
    return pickKnown(doc);
  } catch {
    return {};
  }
}

// Extract only the known keys from an arbitrary parsed doc, coercing types.
// Unknown keys are ignored; anything malformed is dropped rather than trusted.
function pickKnown(doc: unknown): WritConfig {
  if (doc === null || typeof doc !== 'object') return {};
  const src = doc as Record<string, unknown>;
  const out: WritConfig = {};

  if (typeof src.format === 'string') out.format = src.format;
  if (typeof src.out === 'string') out.out = src.out;

  if (src.timeout !== undefined) {
    const n = Number(src.timeout);
    if (!Number.isNaN(n)) out.timeout = n;
  }

  return out;
}

// Return the first existing path from a candidate list, or undefined.
function firstExisting(candidates: string[]): string | undefined {
  return candidates.find((c) => existsSync(c));
}

export function loadConfig(cwd: string = process.cwd(), home: string = os.homedir()): WritConfig {
  // New `x-security` paths take precedence; legacy `xsecurity` paths are kept
  // as fallback so configs written before the CLI rename still load.
  const homeFile = firstExisting([
    path.join(home, '.config', 'x-security', 'config.yaml'),
    path.join(home, '.config', 'x-security', 'config.yml'),
    path.join(home, '.config', 'x-security', 'config.json'),
    path.join(home, '.config', 'xsecurity', 'config.yaml'),
    path.join(home, '.config', 'xsecurity', 'config.yml'),
    path.join(home, '.config', 'xsecurity', 'config.json'),
  ]);

  const projectFile = firstExisting([
    path.join(cwd, '.x-securityrc.yaml'),
    path.join(cwd, '.x-securityrc.yml'),
    path.join(cwd, '.x-securityrc.json'),
    path.join(cwd, '.x-securityrc'),
    path.join(cwd, '.xsecurityrc.yaml'),
    path.join(cwd, '.xsecurityrc.yml'),
    path.join(cwd, '.xsecurityrc.json'),
    path.join(cwd, '.xsecurityrc'),
  ]);

  // Precedence low -> high: home config < project config < XSECURITY_CONFIG.
  let merged: WritConfig = {};
  if (homeFile) merged = { ...merged, ...readConfigFile(homeFile) };
  if (projectFile) merged = { ...merged, ...readConfigFile(projectFile) };

  const envPath = process.env.XSECURITY_CONFIG;
  if (envPath) merged = { ...merged, ...readConfigFile(envPath) };

  return merged;
}

export function applyConfigDefaults(program: Command): void {
  const config = loadConfig();
  if (Object.keys(config).length === 0) return;

  program.hook('preAction', (_thisCommand, actionCommand) => {
    for (const key of KNOWN_KEYS) {
      const value = config[key];
      if (value === undefined) continue;

      // Only apply if the running subcommand actually declares this option.
      const longFlag = LONG_FLAGS[key];
      const hasOption = actionCommand.options.some((o) => o.long === longFlag);
      if (!hasOption) continue;

      const attr = OPTION_ATTRS[key];
      // Fill from config only when the value came from the built-in default
      // (or has no recorded source), i.e. the user didn't pass the flag or env.
      // This preserves precedence: explicit CLI/env always wins.
      const source = actionCommand.getOptionValueSource(attr);
      if (source !== 'default' && source !== undefined) continue;

      actionCommand.setOptionValue(attr, value);
      const withSource = actionCommand as unknown as {
        setOptionValueWithSource?: (name: string, val: unknown, src: string) => void;
      };
      withSource.setOptionValueWithSource?.(attr, value, 'config');
    }
  });
}
