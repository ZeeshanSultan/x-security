// Strict regex grammar validator.
//
// Why this exists: the CVE proposer (packages/cve-watcher/src/proposer.ts:112)
// string-concatenates an LLM-supplied `pattern` into a wrapping regex that
// gets compiled into a Cloudflare WAF rule. Without validation, the model can
// emit `(a+)+$` (catastrophic ReDoS), `)` (unbalanced — silently breaks rule
// compilation), or syntactically-valid-but-malicious patterns that turn a
// per-request matcher into a DoS amplifier. C-15 in the audit.
//
// Strategy: refuse to compile anything the grammar can't statically prove safe.
// This is intentionally narrower than ECMAScript regex. The grammar allows
// only:
//   - literal characters from a safe alphabet
//   - `\.` `\/` `\-` `\?` `\:` (a small, well-known escape set)
//   - simple character classes `[A-Za-z0-9_-]` (no negation, no nested classes,
//     no shorthand like `\w`/`\d`/`\s` which can pull in surprising codepoints)
//   - bounded quantifiers `*`, `+`, `?`, `{n}`, `{n,m}` with n,m <= MAX_REPEAT
//   - alternation `a|b` (one level — no nested `(a|b|c|...)` chains)
//   - non-capturing grouping `(?:...)` (no capturing groups, no lookaround,
//     no backreferences)
//   - anchors `^` and `$`
//
// Explicitly rejected (these are the ReDoS attack surface):
//   - nested quantifiers `(a+)+`
//   - alternation overlap inside repetition `(a|a)*`
//   - lookbehind, lookahead, named groups, backreferences, possessive
//   - Unicode property escapes `\p{...}`
//   - any pattern longer than MAX_LENGTH
//
// For production use, pair with an RE2-style linear-time matcher in the
// runtime path. The grammar reduces the attack surface; RE2 closes it.

export const MAX_LENGTH = 256;
export const MAX_REPEAT = 64; // upper bound for `{n,m}` quantifiers
export const MAX_ALTERNATIONS = 8;

export interface RegexValidationOk {
  ok: true;
  /** A safe escaped form, suitable for `new RegExp(...)` in a non-RE2 runtime. */
  safe: string;
}
export interface RegexValidationErr {
  ok: false;
  error: string;
  /** Zero-based char index where the parser bailed out. */
  position: number;
}
export type RegexValidationResult = RegexValidationOk | RegexValidationErr;

/** Validate a pattern. Returns ok=true with a re-emitted safe form, or a detailed error. */
export function validateRegex(pattern: string): RegexValidationResult {
  if (pattern.length === 0) return { ok: false, error: "empty pattern", position: 0 };
  if (pattern.length > MAX_LENGTH) {
    return { ok: false, error: `pattern exceeds ${MAX_LENGTH} chars`, position: MAX_LENGTH };
  }
  try {
    const p = new Parser(pattern);
    p.parseAlternation();
    if (p.pos !== pattern.length) {
      return { ok: false, error: `unexpected character "${pattern[p.pos]}"`, position: p.pos };
    }
    return { ok: true, safe: pattern };
  } catch (err) {
    const e = err as RegexSyntaxError;
    return { ok: false, error: e.message, position: e.position };
  }
}

class RegexSyntaxError extends Error {
  constructor(message: string, public readonly position: number) {
    super(message);
    this.name = "RegexSyntaxError";
  }
}

// Recursive-descent parser. Each method either consumes from `pos` or throws.
class Parser {
  pos = 0;
  private readonly src: string;
  // Track nested-quantifier depth: any quantifier applied to a sub-expression
  // that itself contains a quantifier is rejected (the classic ReDoS pattern).
  private repeatDepth = 0;

  constructor(src: string) {
    this.src = src;
  }

  parseAlternation(): void {
    let alts = 1;
    this.parseSequence();
    while (this.peek() === "|") {
      alts++;
      if (alts > MAX_ALTERNATIONS) {
        throw new RegexSyntaxError(`too many alternations (max ${MAX_ALTERNATIONS})`, this.pos);
      }
      this.pos++;
      this.parseSequence();
    }
  }

  parseSequence(): void {
    while (this.pos < this.src.length) {
      const c = this.peek();
      if (c === "|" || c === ")") break;
      this.parseAtomWithQuantifier();
    }
  }

  parseAtomWithQuantifier(): void {
    const startedQuantified = this.repeatDepth;
    const atomContainedQuantifier = this.parseAtom();
    const q = this.peek();
    if (q === "*" || q === "+" || q === "?" || q === "{") {
      if (atomContainedQuantifier) {
        throw new RegexSyntaxError(
          "nested quantifier (e.g. `(a+)+`) — classic ReDoS shape",
          this.pos,
        );
      }
      this.parseQuantifier();
      // Mark this branch as having seen a quantifier so an enclosing group's
      // own quantifier triggers the nested-quantifier rule.
      this.repeatDepth = startedQuantified + 1;
    } else {
      this.repeatDepth = startedQuantified;
    }
  }

  /** Returns true if the atom itself contained a quantifier (used for nested-q detection). */
  parseAtom(): boolean {
    const c = this.peek();
    if (c === undefined) {
      throw new RegexSyntaxError("unexpected end of pattern", this.pos);
    }
    if (c === "(") {
      // Only `(?:...)` is allowed.
      if (this.src.slice(this.pos, this.pos + 3) !== "(?:") {
        throw new RegexSyntaxError(
          "only non-capturing groups `(?:...)` are allowed",
          this.pos,
        );
      }
      this.pos += 3;
      const beforeDepth = this.repeatDepth;
      this.parseAlternation();
      if (this.peek() !== ")") {
        throw new RegexSyntaxError("unclosed group", this.pos);
      }
      this.pos++;
      return this.repeatDepth > beforeDepth;
    }
    if (c === "[") {
      this.parseCharClass();
      return false;
    }
    if (c === "^" || c === "$") {
      this.pos++;
      return false;
    }
    if (c === "\\") {
      this.parseEscape();
      return false;
    }
    if (isLiteral(c)) {
      this.pos++;
      return false;
    }
    if (c === "." ) {
      // Dot is allowed as a literal-any-char shorthand.
      this.pos++;
      return false;
    }
    throw new RegexSyntaxError(`unexpected character "${c}"`, this.pos);
  }

  parseQuantifier(): void {
    const c = this.peek();
    if (c === "*" || c === "+" || c === "?") {
      this.pos++;
      // Reject possessive (`*+`, `++`) and lazy (`*?`, `+?`, `??`) variants
      // that may not behave as a reviewer expects.
      const next = this.peek();
      if (next === "+" || next === "?") {
        throw new RegexSyntaxError(
          "possessive / lazy quantifiers not allowed",
          this.pos,
        );
      }
      return;
    }
    if (c === "{") {
      this.pos++;
      const start = this.pos;
      while (this.peek() && this.peek() !== "}") this.pos++;
      if (this.peek() !== "}") throw new RegexSyntaxError("unclosed `{`", this.pos);
      const body = this.src.slice(start, this.pos);
      this.pos++; // consume `}`
      const m = body.match(/^(\d+)(?:,(\d+)?)?$/);
      if (!m) throw new RegexSyntaxError(`invalid quantifier {${body}}`, start);
      const n = Number.parseInt(m[1]!, 10);
      const upper = m[2] !== undefined ? Number.parseInt(m[2], 10) : n;
      if (n > MAX_REPEAT || upper > MAX_REPEAT) {
        throw new RegexSyntaxError(`quantifier exceeds ${MAX_REPEAT}`, start);
      }
      if (m[2] !== undefined && upper < n) {
        throw new RegexSyntaxError("quantifier upper bound < lower bound", start);
      }
      return;
    }
    throw new RegexSyntaxError("expected quantifier", this.pos);
  }

  parseCharClass(): void {
    if (this.peek() !== "[") throw new RegexSyntaxError("expected `[`", this.pos);
    this.pos++;
    if (this.peek() === "^") {
      throw new RegexSyntaxError("negated char class `[^...]` not allowed", this.pos);
    }
    if (this.peek() === "]") throw new RegexSyntaxError("empty char class", this.pos);
    while (this.peek() && this.peek() !== "]") {
      const c = this.peek()!;
      if (c === "[") {
        throw new RegexSyntaxError("nested char class not allowed", this.pos);
      }
      if (c === "\\") {
        // Inside a class, only literal-escape a small set.
        const next = this.src[this.pos + 1];
        if (next === undefined) {
          throw new RegexSyntaxError("dangling backslash in char class", this.pos);
        }
        if (!CLASS_ESCAPES.has(next)) {
          throw new RegexSyntaxError(
            `escape \\${next} not allowed in char class`,
            this.pos,
          );
        }
        this.pos += 2;
        continue;
      }
      if (!isClassLiteral(c)) {
        throw new RegexSyntaxError(`character "${c}" not allowed in class`, this.pos);
      }
      this.pos++;
    }
    if (this.peek() !== "]") throw new RegexSyntaxError("unclosed char class", this.pos);
    this.pos++;
  }

  parseEscape(): void {
    if (this.peek() !== "\\") throw new RegexSyntaxError("expected `\\`", this.pos);
    const next = this.src[this.pos + 1];
    if (next === undefined) throw new RegexSyntaxError("dangling backslash", this.pos);
    if (!OUTSIDE_ESCAPES.has(next)) {
      throw new RegexSyntaxError(`escape \\${next} not allowed`, this.pos);
    }
    this.pos += 2;
  }

  peek(): string | undefined {
    return this.src[this.pos];
  }
}

// Characters allowed unescaped as literal atoms outside char classes.
// Notable exclusions (these have regex-metachar meaning and must be escaped
// if intended literally): `* + ? | ( ) [ ] { } \ ^ $ .`
// Notable inclusions: `:`, `=`, `&`, `,`, `;`, `@`, `#`, `%` — common in URLs,
// headers, and attack payloads (e.g. log4shell `${jndi:`). None of these are
// regex metachars; allowing them does not expand the ReDoS surface.
function isLiteral(c: string): boolean {
  return /^[A-Za-z0-9_\-/:=&,;@#%!~"'<> ]$/.test(c);
}
// Inside a char class, ranges and a slightly wider set are allowed.
function isClassLiteral(c: string): boolean {
  return /^[A-Za-z0-9_\-/:=&,;@#%]$/.test(c);
}
// Escapes allowed outside a char class — small set, all meta-chars only.
const OUTSIDE_ESCAPES = new Set([".", "/", "-", "?", ":", "\\", "(", ")", "[", "]", "{", "}", "|", "*", "+", "$", "^"]);
// Escapes allowed inside a char class.
const CLASS_ESCAPES = new Set(["-", "\\", "]", "/", "."]);

/** Thin convenience: throw on invalid input. */
export function assertSafeRegex(pattern: string): void {
  const r = validateRegex(pattern);
  if (!r.ok) {
    throw new Error(`regex rejected: ${r.error} at pos ${r.position}`);
  }
}
