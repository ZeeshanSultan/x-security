// NestJS route parser (Layer 2 — framework-aware).
//
// NestJS declares routes as HTTP-method decorators (`@Get('p')`, `@Post()`, …) on
// methods INSIDE a `@Controller('prefix')` class. The full path is
//   [global prefix] + [controller prefix] + [method path]
// where the global prefix comes from `app.setGlobalPrefix('api')` in the bootstrap
// (best-effort across the repo, mirroring FastAPI's include_router prefix handling).
//
// Per Rule D-3 every emitted route cites its source file + line (the method
// decorator). Per Rule D-1 the schemaHint is derived from the signature, never a
// placeholder: a `@Body() dto: SomeDto` param → `declared`.

import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ExtractedRoute, SchemaHint } from './types.js';
import { underMount } from './dedupe.js';
import { listFilesByExt } from './walk.js';

const TS_EXTS: ReadonlySet<string> = new Set(['.ts', '.js']);

// NestJS HTTP-method decorators (PascalCase). `All` → an any-verb route.
const VERB_DECORATORS: Record<string, string> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH', Delete: 'DELETE',
  Options: 'OPTIONS', Head: 'HEAD', All: 'ALL',
};

interface TsFile {
  rel: string;
  text: string;
}

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/** The controller prefix in effect at character `idx`: the nearest preceding
 *  `@Controller(...)` in the same file. NestJS files are one-controller-per-class
 *  and classes are sequential, so nearest-preceding is the enclosing controller. */
function controllerPrefixAt(controllers: Array<{ idx: number; prefix: string }>, idx: number): string {
  let prefix = '';
  for (const c of controllers) {
    if (c.idx < idx) prefix = c.prefix;
    else break;
  }
  return prefix;
}

/** `@Controller('users')` / `@Controller()` / `@Controller({ path: 'users' })`. */
function collectControllers(text: string): Array<{ idx: number; prefix: string }> {
  const out: Array<{ idx: number; prefix: string }> = [];
  const re = /@Controller\(\s*(?:(["'`])([^"'`]*)\1|\{[^}]*?\bpath\s*:\s*(["'`])([^"'`]*)\3[^}]*\})?\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push({ idx: m.index, prefix: m[2] ?? m[4] ?? '' });
  }
  return out;
}

export async function parseNestjs(repoDir: string): Promise<ExtractedRoute[]> {
  const absPaths = await listFilesByExt(repoDir, TS_EXTS);
  const files: TsFile[] = await Promise.all(
    absPaths.map(async (abs) => ({ rel: path.relative(repoDir, abs), text: await readFile(abs) })),
  );

  // Global prefix: `app.setGlobalPrefix('api')` anywhere in the repo (bootstrap).
  let globalPrefix = '';
  for (const f of files) {
    const g = /\.setGlobalPrefix\(\s*(["'`])([^"'`]+)\1/.exec(f.text);
    if (g) { globalPrefix = '/' + g[2]!.replace(/^\/+/, ''); break; } // leading slash so underMount composes
  }

  const verbAlt = Object.keys(VERB_DECORATORS).join('|');
  // `@Get('p')` / `@Get()` then any number of intervening decorators, then the method
  // name. The method-path arg is an optional string literal (first arg).
  // The method-path arg is optional and may be a single string literal OR an array of
  // them — `@Post(['/api/v1/x', '/api/v2/x'])` (nocodb registers v1+v2 aliases on one
  // method). Capture the whole spec (`[...]` or `"..."`) and expand arrays to one route
  // per literal below.
  const methodRe = new RegExp(
    String.raw`@(${verbAlt})\(\s*(\[[^\]]*\]|["'\`][^"'\`]*["'\`])?[^)]*\)` + // verb decorator + optional path spec
      String.raw`(?:\s*@[\w.]+\s*\([\s\S]*?\)\s*)*` +                          // intervening decorators (@UseGuards, …)
      String.raw`\s*(?:public\s+|private\s+|protected\s+)?(?:async\s+)?(\w+)\s*\(([\s\S]*?)\)`,
    'g',
  );

  const routes: ExtractedRoute[] = [];
  for (const f of files) {
    if (!f.text.includes('@Controller')) continue; // not a NestJS controller file
    const controllers = collectControllers(f.text);
    if (controllers.length === 0) continue;

    methodRe.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = methodRe.exec(f.text)) !== null) {
      const verb = VERB_DECORATORS[m[1]!]!;
      const pathSpec = m[2] ?? '';
      const handler = m[3]!;
      const sig = m[4] ?? '';
      const ctrlPrefix = controllerPrefixAt(controllers, m.index);
      const sourceLine = lineAt(f.text, m.index);
      // `@Body() dto: SomeDto` → a declared body shape.
      const hint: SchemaHint = /@Body\(\)\s*\w+\s*:\s*[A-Z]\w*/.test(sig) ? 'declared' : 'inferred-untyped';
      // Expand a path-spec to one path per literal: `['/a','/b']` → ['/a','/b'];
      // a single `'/x'` → ['/x']; an absent path → [''] (the controller prefix alone).
      const methodPaths = pathSpec.startsWith('[')
        ? [...pathSpec.matchAll(/["'`]([^"'`]*)["'`]/g)].map((x) => x[1]!)
        : [pathSpec.replace(/^["'`]/, '').replace(/["'`]$/, '')];
      for (const methodPath of methodPaths.length > 0 ? methodPaths : ['']) {
        routes.push({
          method: verb,
          path: underMount(globalPrefix, underMount(ctrlPrefix, methodPath)),
          source: 'framework',
          framework: 'nestjs',
          sourceFile: f.rel,
          sourceLine,
          handler,
          schemaHint: hint,
        });
      }
    }
  }
  return routes;
}

async function readFile(p: string): Promise<string> {
  try {
    return await fs.readFile(p, 'utf8');
  } catch {
    return '';
  }
}
