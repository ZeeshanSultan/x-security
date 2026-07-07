// commander v12 has no built-in shell completion. This module generates
// static completion scripts (bash/zsh/fish) that complete top-level
// subcommand names only — no runtime completion server.

import type { Command } from 'commander';

// Shell function/compdef identifiers can't contain dashes or other
// punctuation. The completed command itself keeps the real binName.
function sanitizeIdentifier(binName: string): string {
  return binName.replace(/[^A-Za-z0-9_]/g, '_');
}

function generateBash(binName: string, subcommands: string[]): string {
  const fnName = `_${sanitizeIdentifier(binName)}_completions`;
  const words = subcommands.join(' ');
  return `# bash completion for ${binName}
${fnName}() {
  local cur
  cur="\${COMP_WORDS[1]}"
  COMPREPLY=( $(compgen -W "${words}" -- "$cur") )
}
complete -F ${fnName} ${binName}
`;
}

function generateZsh(binName: string, subcommands: string[]): string {
  const words = subcommands.join(' ');
  return `#compdef ${binName}
# zsh completion for ${binName}
_${sanitizeIdentifier(binName)}() {
  local -a subcommands
  subcommands=(${words})
  _describe 'command' subcommands
}
compdef _${sanitizeIdentifier(binName)} ${binName}
`;
}

function generateFish(binName: string, subcommands: string[]): string {
  const words = subcommands.join(' ');
  return `# fish completion for ${binName}
complete -c ${binName} -f -n '__fish_use_subcommand' -a '${words}'
`;
}

export function generateCompletion(
  shell: 'bash' | 'zsh' | 'fish',
  binName: string,
  subcommands: string[]
): string {
  switch (shell) {
    case 'bash':
      return generateBash(binName, subcommands);
    case 'zsh':
      return generateZsh(binName, subcommands);
    case 'fish':
      return generateFish(binName, subcommands);
  }
}

const SUPPORTED_SHELLS = ['bash', 'zsh', 'fish'] as const;

function isSupportedShell(shell: string): shell is (typeof SUPPORTED_SHELLS)[number] {
  return (SUPPORTED_SHELLS as readonly string[]).includes(shell);
}

export function registerCompletion(program: Command): void {
  program
    .command('completion [shell]')
    .description(
      'Print a shell completion script. Usage: eval "$(<bin> completion zsh)" or add to your rc file.'
    )
    .addHelpText(
      'after',
      `
Examples:
  # bash: add to ~/.bashrc
  eval "$(${program.name()} completion bash)"

  # zsh: add to ~/.zshrc
  eval "$(${program.name()} completion zsh)"

  # fish: write to a completions file
  ${program.name()} completion fish > ~/.config/fish/completions/${program.name()}.fish
`
    )
    .action((shell: string | undefined) => {
      const binName = program.name();
      const subcommands = program.commands
        .map((c) => c.name())
        .filter((name) => name !== 'completion' && name !== 'help');

      const resolvedShell = shell ?? 'bash';
      if (!isSupportedShell(resolvedShell)) {
        process.stderr.write(`unsupported shell "${resolvedShell}" (use bash|zsh|fish)\n`);
        process.exit(1);
        return;
      }

      process.stdout.write(generateCompletion(resolvedShell, binName, subcommands));
    });
}
