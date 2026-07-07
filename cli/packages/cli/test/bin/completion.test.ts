import test from 'node:test';
import assert from 'node:assert/strict';
import { generateCompletion } from '../../src/bin/completion.js';

test('generateCompletion: bash contains binName, subcommands, and bash tokens', () => {
  const script = generateCompletion('bash', 'xsecurity', ['generate', 'validate']);
  assert.ok(script.length > 0);
  assert.match(script, /xsecurity/);
  assert.match(script, /generate/);
  assert.match(script, /validate/);
  assert.match(script, /complete|compgen/);
});

test('generateCompletion: zsh contains #compdef and subcommands', () => {
  const script = generateCompletion('zsh', 'xsecurity', ['generate', 'validate']);
  assert.ok(script.length > 0);
  assert.match(script, /#compdef xsecurity/);
  assert.match(script, /generate/);
  assert.match(script, /validate/);
});

test('generateCompletion: fish contains complete -c and subcommands', () => {
  const script = generateCompletion('fish', 'xsecurity', ['generate', 'validate']);
  assert.ok(script.length > 0);
  assert.match(script, /complete -c xsecurity/);
  assert.match(script, /generate/);
  assert.match(script, /validate/);
});

test('generateCompletion: dashed binName sanitizes identifiers but keeps real command', () => {
  const bash = generateCompletion('bash', 'x-security', ['generate']);
  assert.match(bash, /complete -F _x_security_completions x-security/);

  const zsh = generateCompletion('zsh', 'x-security', ['generate']);
  assert.match(zsh, /#compdef x-security/);
  assert.match(zsh, /compdef _x_security x-security/);

  const fish = generateCompletion('fish', 'x-security', ['generate']);
  assert.match(fish, /complete -c x-security/);
});
