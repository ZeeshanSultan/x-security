import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Command } from 'commander';
import { loadConfig, applyConfigDefaults } from '../../src/config/defaults.js';

function tmp(): string {
  return mkdtempSync(path.join(os.tmpdir(), 'x-security-cfg-'));
}

test('loadConfig reads a project .xsecurityrc.yaml', () => {
  const cwd = tmp();
  const home = tmp();
  try {
    writeFileSync(path.join(cwd, '.xsecurityrc.yaml'), 'format: json\ntimeout: 1500\n');
    const cfg = loadConfig(cwd, home);
    assert.deepEqual(cfg, { format: 'json', timeout: 1500 });
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('project config overrides home config for the same key', () => {
  const cwd = tmp();
  const home = tmp();
  try {
    const homeDir = path.join(home, '.config', 'xsecurity');
    mkdirSync(homeDir, { recursive: true });
    writeFileSync(path.join(homeDir, 'config.yaml'), 'format: table\nout: home-out\n');
    writeFileSync(path.join(cwd, '.xsecurityrc.yaml'), 'format: sarif\n');

    const cfg = loadConfig(cwd, home);
    // format from project wins; out only present in home is preserved.
    assert.equal(cfg.format, 'sarif');
    assert.equal(cfg.out, 'home-out');
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('a malformed config file does not throw', () => {
  const cwd = tmp();
  const home = tmp();
  try {
    // Unclosed bracket -> yaml parse error; must be swallowed.
    writeFileSync(path.join(cwd, '.xsecurityrc.yaml'), 'format: [unclosed\n  : : :');
    const cfg = loadConfig(cwd, home);
    assert.deepEqual(cfg, {});
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test('XSECURITY_CONFIG path overrides project and home config', () => {
  const cwd = tmp();
  const home = tmp();
  const envDir = tmp();
  const prev = process.env.XSECURITY_CONFIG;
  try {
    writeFileSync(path.join(cwd, '.xsecurityrc.yaml'), 'format: table\n');
    const envFile = path.join(envDir, 'override.json');
    writeFileSync(envFile, '{"format":"csv","timeout":900}');
    process.env.XSECURITY_CONFIG = envFile;

    const cfg = loadConfig(cwd, home);
    assert.equal(cfg.format, 'csv');
    assert.equal(cfg.timeout, 900);
  } finally {
    if (prev === undefined) delete process.env.XSECURITY_CONFIG;
    else process.env.XSECURITY_CONFIG = prev;
    rmSync(cwd, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
    rmSync(envDir, { recursive: true, force: true });
  }
});

function buildProgram(seen: { format?: string }): Command {
  const program = new Command();
  program.exitOverride();
  program
    .command('scan')
    .requiredOption('--target <t>', 'target')
    .option('--format <f>', 'output format', 'table')
    .action((opts) => {
      seen.format = opts.format;
    });
  return program;
}

test('applyConfigDefaults fills option from config when user did not pass it', async () => {
  const envDir = tmp();
  const prev = process.env.XSECURITY_CONFIG;
  try {
    const envFile = path.join(envDir, 'cfg.json');
    writeFileSync(envFile, '{"format":"json"}');
    process.env.XSECURITY_CONFIG = envFile;

    const seen: { format?: string } = {};
    const program = buildProgram(seen);
    applyConfigDefaults(program);

    await program.parseAsync(['scan', '--target', 'x'], { from: 'user' });
    assert.equal(seen.format, 'json');
  } finally {
    if (prev === undefined) delete process.env.XSECURITY_CONFIG;
    else process.env.XSECURITY_CONFIG = prev;
    rmSync(envDir, { recursive: true, force: true });
  }
});

test('applyConfigDefaults does not override an explicit CLI flag', async () => {
  const envDir = tmp();
  const prev = process.env.XSECURITY_CONFIG;
  try {
    const envFile = path.join(envDir, 'cfg.json');
    writeFileSync(envFile, '{"format":"json"}');
    process.env.XSECURITY_CONFIG = envFile;

    const seen: { format?: string } = {};
    const program = buildProgram(seen);
    applyConfigDefaults(program);

    await program.parseAsync(['scan', '--target', 'x', '--format', 'csv'], { from: 'user' });
    assert.equal(seen.format, 'csv');
  } finally {
    if (prev === undefined) delete process.env.XSECURITY_CONFIG;
    else process.env.XSECURITY_CONFIG = prev;
    rmSync(envDir, { recursive: true, force: true });
  }
});
