// Rails `config/routes.rb` parser.
//
// Rails declares routes in a Ruby DSL, not as decorators: nested `namespace`/`scope`
// blocks build a path prefix, and `resources`/`resource` expand to the RESTful action
// set (filtered by `only:`/`except:`). Handlers are controller methods (`<ctrl>#<action>`)
// resolved by convention. We track block nesting with a do/end stack so every prefix
// composes, then expand resources and explicit verb routes.
//
// Scope (intentionally bounded — covers the common app surface, not the whole DSL):
//   - `namespace :api do` / `scope 'path' do` / `scope path: 'x' do` → prefix segment.
//   - `*.routes.draw do` / `*.add_routes do` (engine) → a prefix-less block frame.
//   - `resources :x` / `resource :x` (+ `only:`/`except:`/`controller:`) → RESTful routes.
//   - `get/post/put/patch/delete 'path', to: 'ctrl#action'` (and `=> 'ctrl#action'`).
//   - member-action shorthand inside a resource block: `patch :advance` → /<resource>/advance.
// Not modeled: concerns, `on: :member`/`:collection` option form, constraints rewriting.

import { promises as fs } from 'node:fs';
import path from 'node:path';

import type { ExtractedRoute, SchemaHint } from './types.js';
import { underMount } from './dedupe.js';
import { listFilesByExt } from './walk.js';

const RB_EXTS: ReadonlySet<string> = new Set(['.rb']);

interface RestRoute { action: string; verb: string; suffix: string }

// Plural `resources :x` → collection + member routes (member carry `:id`).
function pluralRoutes(name: string): RestRoute[] {
  return [
    { action: 'index', verb: 'GET', suffix: `/${name}` },
    { action: 'create', verb: 'POST', suffix: `/${name}` },
    { action: 'new', verb: 'GET', suffix: `/${name}/new` },
    { action: 'edit', verb: 'GET', suffix: `/${name}/:id/edit` },
    { action: 'show', verb: 'GET', suffix: `/${name}/:id` },
    { action: 'update', verb: 'PATCH', suffix: `/${name}/:id` },
    { action: 'update', verb: 'PUT', suffix: `/${name}/:id` },
    { action: 'destroy', verb: 'DELETE', suffix: `/${name}/:id` },
  ];
}

// Singular `resource :x` → no `:id` (the resource is scoped to the current user/session).
function singularRoutes(name: string): RestRoute[] {
  return [
    { action: 'new', verb: 'GET', suffix: `/${name}/new` },
    { action: 'edit', verb: 'GET', suffix: `/${name}/edit` },
    { action: 'show', verb: 'GET', suffix: `/${name}` },
    { action: 'create', verb: 'POST', suffix: `/${name}` },
    { action: 'update', verb: 'PATCH', suffix: `/${name}` },
    { action: 'update', verb: 'PUT', suffix: `/${name}` },
    { action: 'destroy', verb: 'DELETE', suffix: `/${name}` },
  ];
}

/** Parse an `only:`/`except:` action filter — `%i[update show]` or `[:update, :show]`. */
function parseActionList(opts: string, key: string): Set<string> | null {
  const re = new RegExp(`${key}\\s*:\\s*(?:%i\\[([^\\]]*)\\]|\\[([^\\]]*)\\])`);
  const m = re.exec(opts);
  if (!m) return null;
  const raw = m[1] ?? m[2] ?? '';
  const items = raw.split(/[\s,]+/).map((s) => s.replace(/^:/, '').trim()).filter(Boolean);
  return new Set(items);
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

const opensBlock = (line: string): boolean => /\bdo\b(\s*\|[^|]*\|)?\s*$/.test(line);

/** Strip a Ruby `#` line-comment, but NOT a `#` inside a string/symbol — `'ctrl#action'`
 *  carries a literal `#`, and a naive `#.*$` strip would eat the action name. */
function stripRubyComment(line: string): string {
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '\\') { i++; continue; }
    if (inS) { if (ch === "'") inS = false; continue; }
    if (inD) { if (ch === '"') inD = false; continue; }
    if (ch === "'") inS = true;
    else if (ch === '"') inD = true;
    else if (ch === '#') return line.slice(0, i);
  }
  return line;
}

export async function parseRails(repoDir: string): Promise<ExtractedRoute[]> {
  const absPaths = (await listFilesByExt(repoDir, RB_EXTS)).filter((p) => /routes\.rb$/.test(p));
  const routes: ExtractedRoute[] = [];

  for (const abs of absPaths) {
    let raw: string;
    try {
      raw = await fs.readFile(abs, 'utf8');
    } catch {
      continue;
    }
    if (!/\.(?:routes\.draw|add_routes)\b|\bnamespace\b|\bresources?\b/.test(raw)) continue;
    const rel = path.relative(repoDir, abs);
    const lines = raw.split('\n');
    const stack: string[] = []; // each frame's path segment ('' for prefix-less blocks)
    let offset = 0;

    for (const rawLine of lines) {
      const lineStart = offset;
      offset += rawLine.length + 1;
      const line = stripRubyComment(rawLine).trim();
      if (!line) continue;

      if (/^end\b/.test(line)) { stack.pop(); continue; }

      const prefix = stack.join('');
      const opens = opensBlock(line);
      const srcLine = lineAt(raw, lineStart);

      // namespace :x do  → segment '/x'
      let m = /^namespace\s+:?(\w+)/.exec(line);
      if (m) { if (opens) stack.push('/' + m[1]); continue; }

      // scope 'x' do / scope path: 'x' do  → segment '/x' (best-effort; bare scope → '')
      m = /^scope\b(.*)$/.exec(line);
      if (m) {
        const seg = /path\s*:\s*["']([^"']+)["']/.exec(m[1]!)?.[1] ?? /^\s*["']([^"']+)["']/.exec(m[1]!)?.[1] ?? '';
        if (opens) stack.push(seg ? '/' + seg.replace(/^\/+/, '') : '');
        continue;
      }

      // engine/app route blocks: `Spree::Core::Engine.add_routes do`, `*.routes.draw do`
      if (/\.(?:routes\.draw|add_routes)\b/.test(line)) { if (opens) stack.push(''); continue; }

      // resources :x / resource :x  (+ only/except/controller)
      m = /^(resources?)\s+:(\w+)\b(.*)$/.exec(line);
      if (m) {
        const plural = m[1] === 'resources';
        const name = m[2]!;
        const opts = m[3] ?? '';
        const ctrl = /controller\s*:\s*:?["']?(\w+)["']?/.exec(opts)?.[1] ?? name;
        const only = parseActionList(opts, 'only');
        const except = parseActionList(opts, 'except');
        const all = plural ? pluralRoutes(name) : singularRoutes(name);
        for (const r of all) {
          if (only && !only.has(r.action)) continue;
          if (except && except.has(r.action)) continue;
          routes.push({
            method: r.verb,
            path: underMount(prefix, r.suffix),
            source: 'framework',
            framework: 'rails',
            sourceFile: rel,
            sourceLine: srcLine,
            handler: `${ctrl}#${r.action}`,
            schemaHint: 'inferred-untyped' as SchemaHint,
          });
        }
        // A resource block nests member/collection routes under the resource path; plural
        // member routes carry `:id`, singular do not.
        if (opens) stack.push(plural ? `/${name}/:id` : `/${name}`);
        continue;
      }

      // explicit verb route: get 'path'[, to: 'ctrl#action' | => 'ctrl#action']
      m = /^(get|post|put|patch|delete|match)\s+(.*)$/.exec(line);
      if (m) {
        const verb = m[1]!.toUpperCase();
        const rest = m[2]!;
        const strPath = /^["']([^"']+)["']/.exec(rest)?.[1];
        const action = /(?:to\s*:\s*|=>\s*)["'](\w+#\w+)["']/.exec(rest)?.[1];
        if (strPath) {
          routes.push({
            method: verb === 'MATCH' ? 'GET' : verb,
            path: underMount(prefix, '/' + strPath.replace(/^\/+/, '')),
            source: 'framework',
            framework: 'rails',
            sourceFile: rel,
            sourceLine: srcLine,
            handler: action ?? strPath,
            schemaHint: 'inferred-untyped' as SchemaHint,
          });
        } else {
          // member-action shorthand inside a resource block: `patch :advance` → /<resource>/advance
          const sym = /^:(\w+)/.exec(rest)?.[1];
          if (sym) {
            routes.push({
              method: verb,
              path: underMount(prefix, '/' + sym),
              source: 'framework',
              framework: 'rails',
              sourceFile: rel,
              sourceLine: srcLine,
              handler: sym,
              schemaHint: 'inferred-untyped' as SchemaHint,
            });
          }
        }
        if (opens) stack.push('');
        continue;
      }

      // any other block opener (member do / collection do / if ... do) — keep the stack balanced
      if (opens) stack.push('');
    }
  }
  return routes;
}
