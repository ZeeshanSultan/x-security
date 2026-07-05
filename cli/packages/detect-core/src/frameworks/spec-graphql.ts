// Apollo / SDL GraphQL route parser (Wave 1) — ports the prototype's
// `find_graphql_sdl` + `parse_apollo_sdl` (/tmp/route-extractor-proto/extract.py)
// to TypeScript.
//
// A GraphQL SDL schema is a *declared contract*: `type Query { ... }`,
// `type Mutation { ... }`, and `type Subscription { ... }` enumerate the
// operations a client may invoke. Each field on one of those root types is ONE
// GraphQL operation, reachable at `POST /graphql`. SDL is read from two sources:
//   1. Standalone `.graphql` / `.gql` schema files.
//   2. `gql`...`` tagged-template literals embedded in JS/TS source (the Apollo
//      `typeDefs` convention).
//
// SCHEMA HINT: the operation's args + return type are declared in the SDL, so
// every route carries `source: 'spec'` and `schemaHint: 'declared'` — consistent
// with the graphene parser and the spec layer's contract treatment.
//
// We do NOT parse the full GraphQL grammar; we extract root-type field names the
// same line-oriented way the prototype does. The brace match is non-greedy up to
// the first `}` (`[^}]*`), which is correct for the flat root types GraphQL
// requires (Query/Mutation/Subscription bodies contain only field declarations,
// never nested braces).

import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { ExtractedRoute } from './types.js';
import { listFilesByExt } from './walk.js';

const SDL_EXTS: ReadonlySet<string> = new Set(['.graphql', '.gql']);
const JS_EXTS: ReadonlySet<string> = new Set(['.js', '.ts', '.jsx', '.tsx']);

const OP_TYPES: ReadonlyArray<{
  type: string;
  label: 'query' | 'mutation' | 'subscription';
}> = [
  { type: 'Query', label: 'query' },
  { type: 'Mutation', label: 'mutation' },
  { type: 'Subscription', label: 'subscription' },
];

// `gql`...`` tagged-template literal. Ported from r"gql`([^`]*)`" with DOTALL —
// captures the backtick-delimited SDL chunk. `[^`]` already crosses newlines.
const GQL_TEMPLATE_RE = /gql`([^`]*)`/g;

// A `type <Op> { ... }` block. Built per op-type; ported from
// r"type\s+<Op>\s*\{([^}]*)\}" with DOTALL.
function opBlockRe(type: string): RegExp {
  return new RegExp(`type\\s+${type}\\s*\\{([^}]*)\\}`, 'g');
}

// A field declaration line: `name(args): Type` / `name: Type`. Ported from
// r"([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*:". Anchored at line start since
// we match per stripped line.
const FIELD_LINE_RE = /^([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*:/;

/** Strip JS/PHP-style block + line comments around `gql` templates so a
 * commented-out `typeDefs` block isn't scraped. Conservative: full-line `//`
 * and `/* *​/` blocks only (mirrors the prototype's `strip_comments(text,"js")`
 * for the template-bearing files). */
function stripJsComments(text: string): string {
  // Preserve line count so `lineAt` maps to the real source line (Rule D-3):
  // blank block-comment content (keep newlines) and blank `//`-lines instead of
  // deleting them. Same fix as express.ts stripComments.
  const noBlocks = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  return noBlocks
    .split('\n')
    .map((line) => (line.trimStart().startsWith('//') ? '' : line))
    .join('\n');
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

/** Collect (sdlText, sourceFile, baseLine) chunks: whole `.graphql`/`.gql`
 * files, plus each `gql`...`` template found in JS/TS source. `baseLine` is the
 * 1-based line in the origin file where the chunk's content begins, so field
 * citations resolve to a real line. Ports `find_graphql_sdl`. */
async function findSdlChunks(
  repoDir: string,
): Promise<Array<{ text: string; sourceFile: string; baseLine: number }>> {
  const chunks: Array<{ text: string; sourceFile: string; baseLine: number }> = [];

  for (const file of await listFilesByExt(repoDir, SDL_EXTS)) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    chunks.push({ text: raw, sourceFile: path.relative(repoDir, file), baseLine: 1 });
  }

  for (const file of await listFilesByExt(repoDir, JS_EXTS)) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      continue;
    }
    if (!raw.includes('gql`')) continue;
    const text = stripJsComments(raw);
    const sourceFile = path.relative(repoDir, file);
    GQL_TEMPLATE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = GQL_TEMPLATE_RE.exec(text)) !== null) {
      // content starts after the `gql\`` opener; its line = line of the match
      // start plus any newlines between the match start and the backtick body.
      const bodyStart = m.index + m[0].indexOf('`') + 1;
      chunks.push({ text: m[1] ?? '', sourceFile, baseLine: lineAt(text, bodyStart) });
    }
  }

  return chunks;
}

/**
 * Parse every Apollo / SDL GraphQL operation under `repoDir`.
 *
 * De-dupes on `(label, name)` across all chunks (a schema split across files or
 * re-declared in a `gql` literal yields one op), matching the prototype's
 * `seen` set.
 */
export async function parseApolloSdl(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const seen = new Set<string>();

  for (const chunk of await findSdlChunks(repoDir)) {
    for (const { type, label } of OP_TYPES) {
      const blockRe = opBlockRe(type);
      let bm: RegExpExecArray | null;
      while ((bm = blockRe.exec(chunk.text)) !== null) {
        const body = bm[1] ?? '';
        const blockBaseLine = chunk.baseLine + lineAt(chunk.text, bm.index) - 1;
        const lines = body.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = (lines[i] ?? '').trim();
          if (!line || line.startsWith('#')) continue;
          const fm = FIELD_LINE_RE.exec(line);
          if (!fm?.[1]) continue;
          const name = fm[1];
          const key = `${label}.${name}`;
          if (seen.has(key)) continue;
          seen.add(key);
          routes.push({
            method: 'POST',
            path: `/graphql#${label}.${name}`,
            source: 'spec',
            framework: 'apollo',
            handler: name,
            schemaHint: 'declared',
            sourceFile: chunk.sourceFile,
            sourceLine: blockBaseLine + i,
          });
        }
      }
    }
  }

  return routes;
}
