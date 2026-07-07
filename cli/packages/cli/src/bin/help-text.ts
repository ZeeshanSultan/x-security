// Example blocks appended to command help via `.addHelpText('after', ...)`.
// Kept out of lazy.ts to hold that file under 500 lines. Examples hardcode
// `lazy` to match the existing `test` command help style.

export const generateExamples = `
Examples:
  # Compile a spec on disk into Kong config
  $ lazy generate --target kong spec.yaml

  # Read the spec from stdin (- means stdin)
  $ cat spec.yaml | lazy generate --target kong -
`;

export const validateExamples = `
Examples:
  # Check a running Kong gateway against the spec
  $ lazy validate --target kong --gateway http://localhost:8001 spec.yaml

  # Pipe the spec in and diff against an exported kong.yml
  $ cat spec.yaml | lazy validate --target kong --gateway ./kong.yml -
`;

export const verifyExamples = `
Examples:
  # Confirm the gateway actually loaded what we emitted
  $ lazy verify --target kong --gateway http://localhost:8001 spec.yaml

  # Read the spec from stdin
  $ cat spec.yaml | lazy verify --target kong --gateway http://localhost:8001 -
`;

export const reportExamples = `
Examples:
  # OWASP API Top 10 coverage report
  $ lazy report --owasp spec.yaml

  # Read the spec from stdin
  $ cat spec.yaml | lazy report --owasp -
`;

export const diffExamples = `
Examples:
  # Diff generated Kong config across two spec versions
  $ lazy diff --target kong old.yaml new.yaml

  # Read the new spec from stdin (only one side may be -)
  $ cat new.yaml | lazy diff --target kong old.yaml -

Exit code: 0 when the two specs produce identical config, 1 when they differ
(git diff --exit-code style).
`;
