// graphene (Python code-first GraphQL) route parser (Wave 1) — ports the
// prototype's `parse_graphene` / `_graphene_fields` / `snake_to_camel` / `_gql_op`
// (/tmp/route-extractor-proto/extract.py) to TypeScript.
//
// graphene declares its API surface in code, not a `.graphql` SDL: a class that
// subclasses `graphene.ObjectType` and whose name contains Query / Mutation(s) /
// Subscription is an operation root. Each class-body field assignment
// (`x = graphene.<Type>(...)` or `x = <Mod>.Field(...)`) or `resolve_x` method is
// ONE GraphQL operation. Every operation is reachable at `POST /graphql`.
//
// SCHEMA HINT: a GraphQL schema is a *declared contract* — the arg list and
// return type are typed at the field declaration — so these routes carry
// `source: 'spec'` and `schemaHint: 'declared'` (matching the spec-layer
// treatment in the plan). This is intentionally NOT `framework`-sourced even
// though the surface is discovered from code: the contract is declared, like SDL.
//
// PAREN-DEPTH / INDENT ANCHOR (the bug this fixes): a multi-line
// `graphene.Field(...)` call body contains argument lines like
// `description="..."` or `user_id=graphene.Int()` at a DEEPER indent than the
// class body. A naive line scan mistakes those nested kwargs for sibling fields
// and over-extracts (e.g. `userId` as a phantom operation). We anchor to the
// class body's own indentation level AND track paren depth: any line inside an
// open paren group, or at a different indent than the body, is skipped for
// field-role matching while still being counted toward paren depth.

import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { ExtractedRoute } from './types.js';
import { listFilesByExt } from './walk.js';

const PY_EXTS: ReadonlySet<string> = new Set(['.py']);

/**
 * snake_case → camelCase, ported from the prototype's `snake_to_camel`:
 * the first segment stays lowercase, every later segment is title-cased and
 * concatenated. `system_diagnostics` → `systemDiagnostics`; a name with no
 * underscore is returned unchanged.
 */
export function snakeToCamel(s: string): string {
  const parts = s.split('_');
  return (
    parts[0] +
    parts
      .slice(1)
      .map((p) => (p ? p.charAt(0).toUpperCase() + p.slice(1) : ''))
      .join('')
  );
}

// Class declaration whose name contains Query / Mutation(s) / Subscription.
// Ported from r"class\s+(\w*(?:Query|Mutation|Mutations|Subscription)\w*)\s*\([^)]*\)\s*:".
const CLASS_RE =
  /class\s+(\w*(?:Query|Mutation|Mutations|Subscription)\w*)\s*\([^)]*\)\s*:/g;

// Next top-level class boundary, used to bound a class body. Ported from
// r"\nclass\s+\w+".
const NEXT_CLASS_RE = /\nclass\s+\w+/;

// A class-body field assignment: `name = graphene.<...>` or `name = <Mod>.Field(`.
// Ported from r"([a-z_][a-z0-9_]*)\s*=\s*(?:graphene\.|\w+\.Field\()".
const FIELD_RE = /^([a-z_][a-z0-9_]*)\s*=\s*(?:graphene\.|\w+\.Field\()/;

// A `resolve_<name>(` resolver method. Ported from
// r"def\s+resolve_([a-z_][a-z0-9_]*)\s*\(".
const RESOLVER_RE = /^def\s+resolve_([a-z_][a-z0-9_]*)\s*\(/;

/** GraphQL operation label inferred from the class name (case-insensitive),
 * matching the prototype's mutation→subscription→query precedence. */
function classLabel(cls: string): 'query' | 'mutation' | 'subscription' | null {
  const low = cls.toLowerCase();
  if (low.includes('mutation')) return 'mutation';
  if (low.includes('subscription')) return 'subscription';
  if (low.includes('query')) return 'query';
  return null;
}

/** Count net paren depth contributed by a line: `(` minus `)`. */
function parenDelta(line: string): number {
  let open = 0;
  let close = 0;
  for (const ch of line) {
    if (ch === '(') open++;
    else if (ch === ')') close++;
  }
  return open - close;
}

/**
 * Extract class-body operation names from a class block, paren-depth + indent
 * aware. Ports `_graphene_fields`.
 *
 * Returns camelCased names in declaration order. Lines inside an open paren
 * group (a multi-line field-constructor call) and lines whose indent differs
 * from the class body's anchor are skipped for field matching but still update
 * paren depth, so nested constructor kwargs never leak in as phantom fields.
 */
function grapheneFields(block: string): string[] {
  const names: string[] = [];
  let bodyIndent: number | null = null;
  let depth = 0;

  for (const line of block.split('\n')) {
    if (depth > 0) {
      depth = Math.max(depth + parenDelta(line), 0);
      continue;
    }
    const stripped = line.trim();
    if (!stripped) continue;

    const indent = line.length - line.trimStart().length;
    const first = stripped[0] ?? '';
    if (bodyIndent === null && (/[a-z]/i.test(first) || first === '_')) {
      bodyIndent = indent;
    }
    if (indent !== bodyIndent) {
      depth = Math.max(depth + parenDelta(line), 0);
      continue;
    }

    const fm = FIELD_RE.exec(stripped);
    if (fm?.[1]) names.push(snakeToCamel(fm[1]));
    const rm = RESOLVER_RE.exec(stripped);
    if (rm?.[1]) names.push(snakeToCamel(rm[1]));

    depth = Math.max(depth + parenDelta(line), 0);
  }
  return names;
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

/**
 * Strip Python full-line `#` comments so commented-out declarations are not
 * extracted. Conservative line-comment stripping (mirrors the prototype's
 * `strip_comments(text, "py")` and `flask.ts`). Trailing/inline `#` is left
 * intact to avoid clobbering `#` inside strings.
 */
function stripPyComments(text: string): string {
  return text
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');
}

/**
 * Parse every graphene operation under `repoDir`.
 *
 * Async because the shared walker is async; the prototype is synchronous only
 * because Python's `os.walk` is. Files without the substring `graphene` are
 * skipped cheaply, mirroring the prototype's `continue` guard.
 */
export async function parseGraphene(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const seen = new Set<string>();
  const files = await listFilesByExt(repoDir, PY_EXTS);

  for (const file of files) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    if (!raw.includes('graphene')) continue;

    const text = stripPyComments(raw);
    const sourceFile = path.relative(repoDir, file);

    CLASS_RE.lastIndex = 0;
    let cm: RegExpExecArray | null;
    while ((cm = CLASS_RE.exec(text)) !== null) {
      const label = classLabel(cm[1] ?? '');
      if (!label) continue;

      const start = CLASS_RE.lastIndex;
      const rest = text.slice(start);
      const nxt = NEXT_CLASS_RE.exec(rest);
      const block = nxt ? rest.slice(0, nxt.index) : rest;
      const classLine = lineAt(text, cm.index);

      for (const name of grapheneFields(block)) {
        const key = `${label}.${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        routes.push({
          method: 'POST',
          path: `/graphql#${label}.${name}`,
          source: 'spec',
          framework: 'graphene',
          handler: name,
          schemaHint: 'declared',
          sourceFile,
          sourceLine: classLine,
        });
      }
    }
  }

  return routes;
}
