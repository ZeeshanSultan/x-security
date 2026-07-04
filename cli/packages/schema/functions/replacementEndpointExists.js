// Spectral custom function for the `xsec-replacement-endpoint-exists` rule
// (S-7 from the Writ schema spec).
//
// Asserts that the value of an `x-security.replacementEndpoint` field points
// to a path actually declared in the same OpenAPI document. Spectral's
// built-in functions (truthy, falsy, pattern, schema) can only see the
// targeted leaf value, so a cross-document lookup like this needs a custom
// function that walks the document via `context.document.data`.
//
// Returns:
//   - undefined (no error) if the replacementEndpoint resolves to a known path
//   - an array of one {message} object describing the error otherwise
//
// Spectral does template substitution on `message`, so we hand back the bare
// rule message and let Spectral compose it with the rule's `message` field.

export default function replacementEndpointExists(targetVal, _opts, context) {
  // Defensive: rule wires this to a string field, but Spectral can pass
  // through `null`/objects on malformed specs.
  if (typeof targetVal !== 'string' || targetVal.length === 0) {
    return [{ message: 'replacementEndpoint must be a non-empty string' }];
  }

  const doc = context && context.document && context.document.data;
  if (!doc || typeof doc !== 'object') {
    // Spectral always provides the document; if it doesn't, we cannot verify
    // and choose to PASS rather than block (linting infrastructure should
    // never fail closed on a missing document).
    return;
  }

  const paths = doc.paths;
  if (!paths || typeof paths !== 'object') {
    return [
      {
        message: `replacementEndpoint "${targetVal}" cannot be verified — document has no \`paths\` section`
      }
    ];
  }

  // Normalize: an OpenAPI path is a templated string. Two specs may write the
  // same logical endpoint differently (`/users/{id}` vs `/users/{userId}`).
  // We accept either an exact match OR a structural match where every
  // parameterized segment is treated as a wildcard.
  const declared = Object.keys(paths);
  if (declared.includes(targetVal)) return;

  const targetSig = pathSignature(targetVal);
  for (const p of declared) {
    if (pathSignature(p) === targetSig) return;
  }

  return [
    {
      message: `replacementEndpoint "${targetVal}" does not match any path in this document (declared: ${declared.slice(0, 5).join(', ')}${declared.length > 5 ? `, +${declared.length - 5} more` : ''})`
    }
  ];
}

// Collapse every `{var}` segment into a single `*` so two equivalent path
// templates with different parameter names compare equal.
function pathSignature(p) {
  return p
    .split('/')
    .map((seg) => (seg.startsWith('{') && seg.endsWith('}') ? '*' : seg))
    .join('/');
}
