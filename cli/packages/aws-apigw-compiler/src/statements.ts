import type { FieldToMatch, TextTransformation, WafStatement } from './types.js';

/** byteSize parser shared with cloudflare-compiler — accepts `5KB`, `1MB`, `10GB`, bare bytes. */
export function parseByteSize(s: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?\s*$/i.exec(s);
  if (!m) throw new Error(`Invalid byte size: ${s}`);
  const n = parseFloat(m[1]!);
  const u = (m[2] ?? 'B').toUpperCase();
  const mult = u === 'GB' ? 1024 ** 3 : u === 'MB' ? 1024 ** 2 : u === 'KB' ? 1024 : 1;
  return Math.floor(n * mult);
}

/** Duration parser — returns seconds. */
export function parseDurationSeconds(s: string): number {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(s|m|h|d)?\s*$/i.exec(s);
  if (!m) throw new Error(`Invalid duration: ${s}`);
  const n = parseFloat(m[1]!);
  const u = (m[2] ?? 's').toLowerCase();
  const mult = u === 'd' ? 86_400 : u === 'h' ? 3_600 : u === 'm' ? 60 : 1;
  return Math.floor(n * mult);
}

export const NO_TRANSFORM: TextTransformation[] = [{ Priority: 0, Type: 'NONE' }];
export const LOWERCASE_TRANSFORM: TextTransformation[] = [{ Priority: 0, Type: 'LOWERCASE' }];

export function and(...statements: WafStatement[]): WafStatement {
  const filtered = statements.filter(s => s && Object.keys(s).length > 0);
  if (filtered.length === 0) return {};
  if (filtered.length === 1) return filtered[0]!;
  return { AndStatement: { Statements: filtered } };
}

export function or(...statements: WafStatement[]): WafStatement {
  const filtered = statements.filter(s => s && Object.keys(s).length > 0);
  if (filtered.length === 0) return {};
  if (filtered.length === 1) return filtered[0]!;
  return { OrStatement: { Statements: filtered } };
}

export function not(s: WafStatement): WafStatement {
  return { NotStatement: { Statement: s } };
}

/** ByteMatch on URI path (exact). */
export function uriPathExact(path: string): WafStatement {
  return {
    ByteMatchStatement: {
      SearchString: path,
      FieldToMatch: { UriPath: {} },
      TextTransformations: NO_TRANSFORM,
      PositionalConstraint: 'EXACTLY'
    }
  };
}

/** ByteMatch on method (exact, case-insensitive via LOWERCASE transform). */
export function methodEquals(method: string): WafStatement {
  return {
    ByteMatchStatement: {
      SearchString: method.toLowerCase(),
      FieldToMatch: { Method: {} },
      TextTransformations: LOWERCASE_TRANSFORM,
      PositionalConstraint: 'EXACTLY'
    }
  };
}

/** Single-header presence: matches when header is NOT empty. */
export function headerPresent(name: string): WafStatement {
  return {
    ByteMatchStatement: {
      SearchString: '',
      FieldToMatch: { SingleHeader: { Name: name.toLowerCase() } },
      TextTransformations: NO_TRANSFORM,
      PositionalConstraint: 'CONTAINS'
    }
  };
}

/** Header missing — wraps headerPresent in NotStatement. */
export function headerMissing(name: string): WafStatement {
  // AWS WAFv2 has no "field is missing" primitive; we emulate by matching the
  // header field with a zero-size constraint (size == 0 ⇒ missing or empty).
  return {
    SizeConstraintStatement: {
      FieldToMatch: { SingleHeader: { Name: name.toLowerCase() } },
      ComparisonOperator: 'EQ',
      Size: 0,
      TextTransformations: NO_TRANSFORM
    }
  };
}

/** Header value starts with prefix (e.g. `Bearer `). */
export function headerStartsWith(name: string, prefix: string): WafStatement {
  return {
    ByteMatchStatement: {
      SearchString: prefix,
      FieldToMatch: { SingleHeader: { Name: name.toLowerCase() } },
      TextTransformations: NO_TRANSFORM,
      PositionalConstraint: 'STARTS_WITH'
    }
  };
}

/** Body size strictly greater than `bytes`. */
export function bodySizeGt(bytes: number): WafStatement {
  return {
    SizeConstraintStatement: {
      FieldToMatch: { Body: { OversizeHandling: 'CONTINUE' } },
      ComparisonOperator: 'GT',
      Size: bytes,
      TextTransformations: NO_TRANSFORM
    }
  };
}

/** Single-header equals via two ByteMatches (STARTS_WITH + ENDS_WITH proxies an exact match). */
export function headerEquals(name: string, value: string): WafStatement {
  return {
    ByteMatchStatement: {
      SearchString: value,
      FieldToMatch: { SingleHeader: { Name: name.toLowerCase() } },
      TextTransformations: NO_TRANSFORM,
      PositionalConstraint: 'EXACTLY'
    }
  };
}

/** Header value in a closed set — translated as Or(headerEquals...). */
export function headerIn(name: string, values: string[]): WafStatement {
  if (values.length === 0) return {};
  if (values.length === 1) return headerEquals(name, values[0]!);
  return or(...values.map(v => headerEquals(name, v)));
}

export function makeFieldToMatch(field: 'body' | 'uri' | 'query'): FieldToMatch {
  switch (field) {
    case 'body':
      return { Body: { OversizeHandling: 'CONTINUE' } };
    case 'uri':
      return { UriPath: {} };
    case 'query':
      return { QueryString: {} };
  }
}
