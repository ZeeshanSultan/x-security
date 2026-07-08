export class WritError extends Error {
  constructor(message: string, public readonly code: string, public readonly details?: unknown) {
    super(message);
    this.name = 'WritError';
  }
}

export class SchemaValidationError extends WritError {
  constructor(message: string, details?: unknown) {
    super(message, 'SCHEMA_VALIDATION', details);
  }
}

export class UnresolvedVariableError extends WritError {
  constructor(
    public readonly variables: string[],
    public readonly paths: Record<string, string[]> = {}
  ) {
    super(UnresolvedVariableError.format(variables, paths), 'UNRESOLVED_VARIABLE', { variables, paths });
  }

  private static format(variables: string[], paths: Record<string, string[]>): string {
    if (variables.length === 0) return 'Unresolved variables: (none)';
    if (variables.length === 1 && (!paths[variables[0]!] || paths[variables[0]!]!.length === 0)) {
      return `Unresolved variables: ${variables[0]}`;
    }
    const lines = [`${variables.length} unresolved variable${variables.length === 1 ? '' : 's'} in spec:`];
    for (const v of variables) {
      const refs = paths[v] ?? [];
      if (refs.length === 0) {
        lines.push(`  - ${v}`);
      } else {
        const shown = refs.slice(0, 3).join(', ');
        const more = refs.length > 3 ? `, +${refs.length - 3} more` : '';
        lines.push(`  - ${v}   (referenced at: ${shown}${more})`);
      }
    }
    lines.push('Hint: set these env vars, use --vault / --aws-secrets, or re-run with --no-strict to allow placeholders.');
    return lines.join('\n');
  }
}

export class UnsupportedDialectError extends WritError {
  constructor(version: string) {
    super(`Unsupported OpenAPI version: ${version}`, 'UNSUPPORTED_DIALECT');
  }
}

/**
 * Honest --strict contract. The four gates each map to a distinct exit code so
 * a CI pipeline can branch on the *cause* of the failure rather than a generic
 * non-zero.
 *
 *   S1 (exit 2) — Resolution: an env var / vault ref was missing OR resolved
 *                 to a placeholder-shaped value (e.g. "x", "changeme").
 *   S2 (exit 3) — Emission: at least one endpoint in the spec produced zero
 *                 enforceable artifacts in the generator output.
 *   S3 (exit 4) — Fidelity: a spec field cannot be enforced by the chosen
 *                 target+engine (e.g. RS256 declared, HS256 actually emitted).
 *   S4 (exit 5) — Loading: reserved for `x-security verify` (workstream C).
 *                 NOT raised here; this constant exists so other gates can't
 *                 accidentally collide with it.
 */
export type StrictGate = 'S1' | 'S2' | 'S3' | 'S4';
export const STRICT_EXIT_CODES: Record<StrictGate, number> = {
  S1: 2,
  S2: 3,
  S3: 4,
  S4: 5
};

export class StrictnessViolation extends WritError {
  constructor(
    public readonly gate: StrictGate,
    message: string,
    details?: unknown
  ) {
    super(message, `STRICT_${gate}`, details);
    this.name = 'StrictnessViolation';
  }
  get exitCode(): number {
    return STRICT_EXIT_CODES[this.gate];
  }
}
