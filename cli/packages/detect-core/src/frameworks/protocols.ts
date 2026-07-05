// Non-HTTP protocol + dynamic-blueprint parsers (Wave 1) — ports the prototype's
// `parse_protocols` / `parse_flask_blueprints` (/tmp/route-extractor-proto/protocols.py)
// to TypeScript.
//
// Two surfaces live here because neither is an HTTP route in the REST sense:
//
//   - SOAP: a `.wsdl` declares `<operation name="...">`; the operations are
//     reachable via a single POST mount path (e.g. `POST /dvwsuserservice`). We
//     emit one route per operation keyed `<mount>#<op>`, tagged
//     `source: 'protocol', protocol: 'soap'`. The mount is resolved by following
//     the JS/TS module that reads the WSDL through its `app.use('/mount', mod)`
//     registration; failing that, we fall back to the WSDL basename.
//
//   - XML-RPC: methods are registered via `server.on('m.name', ...)`,
//     `.addMethod('m.name', ...)`, or Python `register_function(fn, 'm.name')`.
//     We emit one route per method keyed `<endpoint>#<method>`, tagged
//     `source: 'protocol', protocol: 'xml-rpc'`. The endpoint is an
//     `xmlrpc://<port><path>` pseudo-URL resolved from the listen config + env.
//
//   - Dynamic blueprints: Flask routes registered via
//     `register_blueprint(bp, url_prefix=...)` rather than `@app.route`. We only
//     emit the swagger-ui surface (`flask_swagger_ui.get_swaggerui_blueprint`),
//     yielding `<prefix>` + `<prefix>/:path`, tagged `source: 'framework',
//     framework: 'flask'`.
//
// Per Rule D-3 every emitted route cites a source file + line.

import path from 'node:path';
import { promises as fs } from 'node:fs';
import type { ExtractedRoute } from './types.js';
import { listFiles, listFilesByExt } from './walk.js';

const WSDL_EXTS: ReadonlySet<string> = new Set(['.wsdl']);
const JS_EXTS: ReadonlySet<string> = new Set(['.js', '.ts']);
const CODE_EXTS: ReadonlySet<string> = new Set(['.js', '.ts', '.py']);
const PY_EXTS: ReadonlySet<string> = new Set(['.py']);

/** 1-based line number of `index` within `text`. */
function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

/**
 * Strip block + line comments so commented-out declarations are not extracted.
 * Ports the prototype's `strip_comments(text, lang)`. Conservative: drops `/*…*\/`
 * blocks and `//`/`#` line comments; does not attempt to honor comment chars
 * inside string literals.
 */
function stripComments(text: string, lang: 'js' | 'py'): string {
  // Preserve line count so `lineAt` maps to the real source line (Rule D-3):
  // blank block-comment content (keep newlines) and blank full-line comments
  // instead of deleting them. Same fix as express.ts stripComments.
  let t = text;
  if (lang === 'js') {
    t = t.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
  }
  const out: string[] = [];
  for (let line of t.split('\n')) {
    const s = line.trimStart();
    if (lang === 'js' && s.startsWith('//')) {
      out.push('');
      continue;
    }
    if (lang === 'py' && s.startsWith('#')) {
      out.push('');
      continue;
    }
    if (lang === 'js') {
      line = line.replace(/(^|[^:'"])\/\/.*$/, '$1');
    }
    out.push(line);
  }
  return out.join('\n');
}

function langFor(file: string): 'js' | 'py' {
  return path.extname(file).toLowerCase() === '.py' ? 'py' : 'js';
}

async function readFile(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------- //
// SOAP
// --------------------------------------------------------------------------- //

// `require('./x')` binding capture and `app.use('/mount', var)`.
const REQUIRE_RE = /\b(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["'](\.[^"']+)["']\)/g;
const USE_MOUNT_RE = /\b(?:app|router)\.use\(\s*["'](\/[^"']*)["']\s*,\s*(\w+)/g;
const WSDL_READ_RE = /readFileSync\(\s*[^,)]*["']([^"']+\.wsdl)["']/;
const WSDL_LITERAL_RE = /["']([^"']+\.wsdl)["']/;
const OPERATION_RE = /<operation\s+name=["']([^"']+)["']/g;

/** Resolve a relative `require('./x')` to an absolute file. Ports
 * `_resolve_require`: tries the path bare, then `.js`/`.ts`/`/index.js`/`/index.ts`. */
async function resolveRequire(fromFile: string, reqPath: string): Promise<string | null> {
  const base = path.dirname(path.resolve(fromFile));
  const cand = path.normalize(path.join(base, reqPath));
  for (const suffix of ['', '.js', '.ts', '/index.js', '/index.ts']) {
    const full = cand + suffix;
    try {
      const st = await fs.stat(full);
      if (st.isFile()) return path.resolve(full);
    } catch {
      // not this suffix
    }
  }
  return null;
}

/** WSDL abspath that the given module reads, if any. */
async function wsdlForModule(file: string, code: string): Promise<string | null> {
  const m = WSDL_READ_RE.exec(code) ?? WSDL_LITERAL_RE.exec(code);
  if (!m || m[1] === undefined) return null;
  const cand = path.normalize(path.join(path.dirname(path.resolve(file)), m[1]));
  try {
    if ((await fs.stat(cand)).isFile()) return path.resolve(cand);
  } catch {
    // no such file
  }
  return null;
}

/**
 * Map a `.wsdl` abspath → SOAP mount path, via the JS/TS module that reads it and
 * the `app.use('/mount', <thatModule>)` declaration. Ports `_soap_mounts`.
 */
async function soapMounts(repoDir: string): Promise<Map<string, string>> {
  const mounts = new Map<string, string>();
  const jsFiles = await listFilesByExt(repoDir, JS_EXTS);

  // module abspath -> wsdl abspath
  const modWsdl = new Map<string, string>();
  const codeByFile = new Map<string, string>();
  for (const p of jsFiles) {
    const raw = await readFile(p);
    if (raw === null) continue;
    const code = stripComments(raw, 'js');
    codeByFile.set(p, code);
    const wsdl = await wsdlForModule(p, code);
    if (wsdl) modWsdl.set(path.resolve(p), wsdl);
  }

  for (const p of jsFiles) {
    const code = codeByFile.get(p);
    if (!code) continue;
    const reqMap = new Map<string, string>();
    REQUIRE_RE.lastIndex = 0;
    let rm: RegExpExecArray | null;
    while ((rm = REQUIRE_RE.exec(code)) !== null) {
      const varName = rm[1];
      const reqPath = rm[2];
      if (varName === undefined || reqPath === undefined) continue;
      const resolved = await resolveRequire(p, reqPath);
      if (resolved) reqMap.set(varName, resolved);
    }
    USE_MOUNT_RE.lastIndex = 0;
    let um: RegExpExecArray | null;
    while ((um = USE_MOUNT_RE.exec(code)) !== null) {
      const rawMount = um[1];
      const varName = um[2];
      if (rawMount === undefined || varName === undefined) continue;
      const mount = rawMount.replace(/\/+$/, '');
      const target = reqMap.get(varName);
      if (target && modWsdl.has(target)) {
        mounts.set(modWsdl.get(target)!, mount);
      }
    }
  }
  return mounts;
}

function defaultSoapMount(wsdl: string): string {
  return '/' + path.basename(wsdl, path.extname(wsdl));
}

async function parseSoap(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const mounts = await soapMounts(repoDir);
  const wsdls = await listFilesByExt(repoDir, WSDL_EXTS);

  for (const wsdl of wsdls) {
    const text = await readFile(wsdl);
    if (text === null) continue;
    const mount = mounts.get(path.resolve(wsdl)) ?? defaultSoapMount(wsdl);
    const sourceFile = path.relative(repoDir, wsdl);

    const seen = new Set<string>();
    OPERATION_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = OPERATION_RE.exec(text)) !== null) {
      const op = m[1];
      if (op === undefined || seen.has(op)) continue;
      seen.add(op);
      routes.push({
        method: 'POST',
        path: `${mount}#${op}`,
        source: 'protocol',
        protocol: 'soap',
        handler: op,
        schemaHint: 'declared',
        sourceFile,
        sourceLine: lineAt(text, m.index),
        notes: 'declared-wsdl',
      });
    }
  }
  return routes;
}

/**
 * SOAP mount paths declared in the repo (e.g. `['/dvwsuserservice']`). The
 * express parser's caller suppresses internal soap-router REST false-positives
 * by checking routes against these prefixes — the soap router registers its own
 * helper REST endpoints that are not real API surface.
 */
export async function soapMountPaths(repoDir: string): Promise<string[]> {
  const mounts = await soapMounts(repoDir);
  const out = new Set<string>();
  for (const mount of mounts.values()) out.add(mount);
  const wsdls = await listFilesByExt(repoDir, WSDL_EXTS);
  for (const wsdl of wsdls) {
    if (!mounts.has(path.resolve(wsdl))) out.add(defaultSoapMount(wsdl));
  }
  return [...out].sort();
}

// --------------------------------------------------------------------------- //
// XML-RPC
// --------------------------------------------------------------------------- //

const XMLRPC_SKIP: ReadonlySet<string> = new Set([
  'error', 'notfound', 'uncaughtexception', 'connection', 'close', 'listening',
]);

const SERVER_ON_RE = /\b\w*server\w*\.on\(\s*["']([\w.]+)["']/g;
const ADD_METHOD_RE = /\.addMethod\(\s*["']([\w.]+)["']/g;
const REGISTER_FN_RE = /register_function\(\s*[^,)]*,\s*["']([\w.]+)["']/g;

const ENV_LINE_RE = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(\S+)/;

const ENV_FILES: ReadonlySet<string> = new Set(['.env', '.env.example', '.env.sample']);

/** Read `KEY=value` pairs from any `.env*` file under the repo. Ports `_load_env`.
 * Env files are matched by basename, not extension: `.env` has an empty extname,
 * so an ext-filtered walk would silently miss it (Rule D-2). */
async function loadEnv(repoDir: string): Promise<Map<string, string>> {
  const env = new Map<string, string>();
  const all = await listFiles(repoDir);
  for (const f of all) {
    if (!ENV_FILES.has(path.basename(f))) continue;
    const text = await readFile(f);
    if (text === null) continue;
    for (const line of text.split('\n')) {
      const m = ENV_LINE_RE.exec(line);
      if (m && m[1] !== undefined && m[2] !== undefined && !env.has(m[1])) {
        env.set(m[1], m[2]);
      }
    }
  }
  return env;
}

/** Build the `xmlrpc://<port><path>` endpoint id. Ports `_xmlrpc_endpoint`. */
function xmlrpcEndpoint(t: string, env: Map<string, string>): string {
  let port: string | null = null;
  const ev = /port\s*:\s*process\.env\.(\w+)/.exec(t);
  if (ev && ev[1] !== undefined) {
    const v = env.get(ev[1]);
    if (v && /^\d+$/.test(v)) port = v;
  }
  if (!port) {
    const m =
      /XML_RPC_PORT[^,)\n]*\|\|\s*["']?(\d+)/.exec(t) ??
      /port\s*:\s*(?:[\w.]+\|\|\s*)?(\d+)/.exec(t);
    port = m ? m[1] ?? null : null;
  }
  const pm = /path\s*:\s*["']([^"']+)["']/.exec(t);
  const pth = pm ? pm[1] ?? '/RPC2' : '/RPC2';
  return port ? `xmlrpc://${port}${pth}` : `xmlrpc://${pth}`;
}

async function parseXmlRpc(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const seen = new Set<string>();
  const env = await loadEnv(repoDir);
  const files = await listFilesByExt(repoDir, CODE_EXTS);

  for (const file of files) {
    const raw = await readFile(file);
    if (raw === null) continue;
    if (!raw.toLowerCase().includes('xmlrpc') && !file.toLowerCase().includes('xmlrpc')) {
      continue;
    }
    const code = stripComments(raw, langFor(file));
    const endpoint = xmlrpcEndpoint(code, env);
    const sourceFile = path.relative(repoDir, file);

    for (const re of [SERVER_ON_RE, ADD_METHOD_RE, REGISTER_FN_RE]) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(code)) !== null) {
        const name = m[1];
        if (name === undefined) continue;
        const dedupeKey = `${endpoint}#${name}`;
        if (XMLRPC_SKIP.has(name.toLowerCase()) || seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        routes.push({
          method: 'POST',
          path: dedupeKey,
          source: 'protocol',
          protocol: 'xml-rpc',
          handler: name,
          schemaHint: 'inferred-untyped',
          sourceFile,
          sourceLine: lineAt(code, m.index),
          notes: 'xml-rpc',
        });
      }
    }
  }
  return routes;
}

/**
 * Parse all non-HTTP protocol surfaces (SOAP + XML-RPC) under `repoDir`. Ports
 * the prototype's `parse_protocols`.
 */
export async function parseProtocols(repoDir: string): Promise<ExtractedRoute[]> {
  const [soap, xmlrpc] = await Promise.all([parseSoap(repoDir), parseXmlRpc(repoDir)]);
  return [...soap, ...xmlrpc];
}

// --------------------------------------------------------------------------- //
// Dynamic Flask blueprints (swagger-ui)
// --------------------------------------------------------------------------- //

const PY_CONST_RE = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*["']([^"']+)["']/gm;
const SWAGGER_VAR_RE = /(\w+)\s*=\s*get_swaggerui_blueprint\(/g;
const REGISTER_BP_RE =
  /register_blueprint\(\s*(\w+)\s*(?:,\s*url_prefix\s*=\s*(["']?)([\w/]*?)\2\s*)?\)/g;

function collapseSlashes(p: string): string {
  return p.replace(/\/\/+/g, '/');
}

/**
 * Parse dynamically-registered Flask blueprints under `repoDir` — specifically
 * `flask_swagger_ui.get_swaggerui_blueprint(...)` mounted via
 * `register_blueprint(bp, url_prefix=...)`. Ports `parse_flask_blueprints`.
 * Emits `<prefix>` (swagger-ui index) and `<prefix>/:path` (its static assets).
 */
export async function parseDynamicBlueprints(repoDir: string): Promise<ExtractedRoute[]> {
  const routes: ExtractedRoute[] = [];
  const files = await listFilesByExt(repoDir, PY_EXTS);

  for (const file of files) {
    const raw = await readFile(file);
    if (raw === null) continue;
    if (!raw.includes('register_blueprint') && !raw.toLowerCase().includes('swaggerui')) {
      continue;
    }
    const text = stripComments(raw, 'py');
    const sourceFile = path.relative(repoDir, file);

    const consts = new Map<string, string>();
    PY_CONST_RE.lastIndex = 0;
    let cm: RegExpExecArray | null;
    while ((cm = PY_CONST_RE.exec(text)) !== null) {
      const k = cm[1];
      const v = cm[2];
      if (k !== undefined && v !== undefined && !consts.has(k)) consts.set(k, v);
    }

    const swaggerVars = new Set<string>();
    SWAGGER_VAR_RE.lastIndex = 0;
    let sv: RegExpExecArray | null;
    while ((sv = SWAGGER_VAR_RE.exec(text)) !== null) {
      if (sv[1] !== undefined) swaggerVars.add(sv[1]);
    }

    REGISTER_BP_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGISTER_BP_RE.exec(text)) !== null) {
      const bp = m[1];
      if (bp === undefined) continue;
      let prefix = m[3] || '';
      if (prefix && !prefix.startsWith('/')) {
        prefix = consts.get(prefix) ?? prefix;
      }
      prefix = prefix ? '/' + prefix.replace(/^\/+|\/+$/g, '') : '';
      if (swaggerVars.has(bp) && prefix) {
        const line = lineAt(text, m.index);
        routes.push(blueprintRoute(collapseSlashes(prefix), 'swagger-ui', sourceFile, line));
        routes.push(
          blueprintRoute(collapseSlashes(prefix + '/:path'), 'swagger-ui-static', sourceFile, line),
        );
      }
    }
  }
  return routes;
}

function blueprintRoute(
  routePath: string,
  handler: string,
  sourceFile: string,
  sourceLine: number,
): ExtractedRoute {
  return {
    method: 'GET',
    path: routePath,
    source: 'framework',
    framework: 'flask',
    handler,
    sourceFile,
    sourceLine,
    notes: 'flask-blueprint',
  };
}
