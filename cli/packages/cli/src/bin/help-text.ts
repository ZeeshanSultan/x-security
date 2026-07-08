// Example blocks appended to command help via `.addHelpText('after', ...)`.
// Kept out of x-security.ts to hold that file under 500 lines. Examples hardcode
// `x-security` to match the existing `test` command help style.

export const generateExamples = `
Examples:
  # Compile a spec on disk into Kong config
  $ x-security generate --target kong spec.yaml

  # Read the spec from stdin (- means stdin)
  $ cat spec.yaml | x-security generate --target kong -
`;

export const validateExamples = `
Examples:
  # Check a running Kong gateway against the spec
  $ x-security validate --target kong --gateway http://localhost:8001 spec.yaml

  # Pipe the spec in and diff against an exported kong.yml
  $ cat spec.yaml | x-security validate --target kong --gateway ./kong.yml -
`;

export const verifyExamples = `
Examples:
  # Confirm the gateway actually loaded what we emitted
  $ x-security verify --target kong --gateway http://localhost:8001 spec.yaml

  # Read the spec from stdin
  $ cat spec.yaml | x-security verify --target kong --gateway http://localhost:8001 -
`;

export const reportExamples = `
Examples:
  # OWASP API Top 10 coverage report
  $ x-security report --owasp spec.yaml

  # Read the spec from stdin
  $ cat spec.yaml | x-security report --owasp -
`;

export const diffExamples = `
Examples:
  # Diff generated Kong config across two spec versions
  $ x-security diff --target kong old.yaml new.yaml

  # Read the new spec from stdin (only one side may be -)
  $ cat new.yaml | x-security diff --target kong old.yaml -

Exit code: 0 when the two specs produce identical config, 1 when they differ
(git diff --exit-code style).
`;
