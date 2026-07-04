// Deterministic Pass-3 pre-pass. Per route, statically extract the handler
// body plus observed I/O so Pass 3 doesn't burn tool budget rediscovering
// what regex can lift. Mirrors auth-context.ts; no LLM, no fallbacks. Per
// CLAUDE.md D-1/D-2 this IS the context-resolution layer.

import type { AgentTools, GrepHit } from './tool-types.js';
import type { RouteInventoryEntry } from './schema.js';

export interface ObservedInput {
  name: string;
  source: 'path' | 'query' | 'body' | 'header' | 'cookie' | 'unknown';
  file: string;
  line: number;
  excerpt: string;
}

export interface ObservedValidator {
  name: string;
  kind: 'sanitizer' | 'validator' | 'escape' | 'auth-check' | 'orm-binding' | 'unknown';
  file: string;
  line: number;
  excerpt: string;
}

export interface ObservedOutput {
  kind: 'json' | 'html' | 'binary' | 'plaintext' | 'stream' | 'unknown';
  file: string;
  line: number;
  excerpt: string;
}

/**
 * An attacker-controlled object-id surface (BOLA candidate). `param` is the
 * id-shaped input; the booleans are the deterministic tells that it reaches a
 * fetch/mutate sink and whether the handler already compares it to the
 * principal. `ownerFieldCandidate`, when present, is a request-visible owner
 * field (query/body) the detector can pin to the principal instead.
 */
export interface ObjectIdSurface {
  param: ObservedInput;
  /** id name co-occurs with an orm-binding / `.findOne(` / `WHERE … =`. */
  usedInFetchOrMutate: boolean;
  /** a principal token co-occurs in a comparison with the id / fetched record. */
  comparedToPrincipal: boolean;
  /** a request-visible owner field (query/body) — the A2 pin-to-principal shape. */
  ownerFieldCandidate?: ObservedInput;
}

export interface EvidencePack {
  endpointId: string;
  handlerSnippet?: {
    file: string;
    lineStart: number;
    lineEnd: number;
    snippet: string;
    truncated: boolean;
  };
  observedInputs: ObservedInput[];
  observedValidators: ObservedValidator[];
  observedOutputs: ObservedOutput[];
  /** Derived BOLA surfaces (attacker-controlled object ids). */
  objectIdParams: ObjectIdSurface[];
  /** A body-parse tell on a body-bearing route (the route reads a parsed
   *  request body) — the content-type-allowlist surface (phase B). null when no
   *  body parse was observed. */
  bodyParsed: { kind: 'json' | 'form' | 'multipart' | 'xml'; file: string; line: number } | null;
  /** Fail-loud analysis-coverage signal. When `complete` is false the handler body
   *  could not be resolved — the route is UNANALYZED and must be sent to review,
   *  never reported clean (silent false-negative). */
  coverage?: {
    handlerResolution: 'resolved' | 'inline' | 'unresolved';
    complete: boolean;
    reason?: string;
  };
  /** Bodies of project-local functions the handler calls with a tainted request
   *  input — the cross-file leg of a taint path. A dangerous call hidden behind a
   *  benign-named wrapper (e.g. `bson.toBSON(doc)` → `vm.runInNewContext(eval())`
   *  one file away) is invisible to a handler-only sink scan; resolving the callee
   *  surfaces it. Bounded: one hop, project-local defs only, capped count. */
  resolvedCallees?: CalleeSlice[];
  bytes: number;
}

/** True when the route's handler could not be analyzed and it is a plausible
 *  attack surface — the host agent must mark it reviewRequired, not clean. */
export function routeAnalysisIncomplete(pack: EvidencePack): boolean {
  return pack.coverage?.complete === false;
}

/** A project-local function body reached by a tainted argument from the handler. */
export interface CalleeSlice {
  file: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  /** The call as written in the handler, e.g. "bson.toBSON(doc)". */
  via: string;
  /** The request input name whose taint flowed into this call. */
  taintedInput: string;
  /** The callee's parameter carrying the inbound taint (when the taint reached this
   *  slice through a function parameter, not a named request field). A sink line that
   *  accesses `<taintedParam>.<prop>` names the real request field. */
  taintedParam?: string;
  /** True when `taintedInput` is a CONFIRMED request field (a named req.x source),
   *  false when it is only a fallback param name (taint arrived via the request
   *  object with no field named yet). A sink in a !fieldKnown slice only yields a
   *  candidate if the real field is recovered from a `param.<prop>` access. */
  fieldKnown?: boolean;
  /** EVERY callee parameter that received a tainted argument at this call site — a
   *  call can pass more than one (`getSyncRows(syncInfo, table, loadUntil, …)`). With
   *  a single tainted param the cross-file leg may attribute any sink in the body to
   *  it (recall); with several it must bind each sink to the param actually present on
   *  the sink line (precision). `taintedParam`/`taintedInput` mirror the first entry. */
  taintedParams?: Array<{ param: string; field?: string; fieldKnown: boolean }>;
}

export interface EvidencePackOptions {
  maxHandlerLines?: number;
  maxHandlerBytes?: number;
  maxInputsPerRoute?: number;
  maxValidatorsPerRoute?: number;
  maxOutputsPerRoute?: number;
  maxTotalBytes?: number;
  /** Max concurrent file reads. Default 6. */
  concurrency?: number;
}

const DEFAULTS = {
  maxHandlerLines: 300,
  maxHandlerBytes: 12_000,
  maxInputsPerRoute: 30,
  maxValidatorsPerRoute: 20,
  maxOutputsPerRoute: 10,
  maxTotalBytes: 256_000,
  concurrency: 6,
};

function endpointIdOf(r: RouteInventoryEntry): string {
  return `${r.method} ${r.path}`;
}

// Pattern banks. Not shared with verify-helpers.ts (V2's regexes serve the
// cite-gate contract); keep these inline so changes don't perturb V2.

type Src = ObservedInput['source'];
const INPUTS: Array<[Src, RegExp]> = [
  // PHP
  ['query', /\$_GET\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['body', /\$_POST\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['unknown', /\$_REQUEST\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['cookie', /\$_COOKIE\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['body', /\$_FILES\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['header', /\$_SERVER\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['query', /filter_input\(\s*INPUT_GET\s*,\s*['"]([^'"]+)['"]/g],
  ['body', /filter_input\(\s*INPUT_POST\s*,\s*['"]([^'"]+)['"]/g],
  ['cookie', /filter_input\(\s*INPUT_COOKIE\s*,\s*['"]([^'"]+)['"]/g],
  ['header', /filter_input\(\s*INPUT_SERVER\s*,\s*['"]([^'"]+)['"]/g],
  ['query', /\$request->(?:query|get)\(\s*['"]([^'"]+)['"]/g],
  ['body', /\$request->(?:input|post|json)\(\s*['"]([^'"]+)['"]/g],
  ['cookie', /\$request->cookie\(\s*['"]([^'"]+)['"]/g],
  ['header', /\$request->header\(\s*['"]([^'"]+)['"]/g],
  // JS / TS. `req` and `request` are both common Express param names — match both for
  // the body/query/params/files bags (no Python collision; Python `request.headers/
  // cookies.get(...)` is matched separately below, so those stay `req`-only here).
  ['path', /\breq(?:uest)?\.params\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['query', /\breq(?:uest)?\.query\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['body', /\breq(?:uest)?\.body\.([A-Za-z_][A-Za-z0-9_]*)/g],
  // Defensive idiom `(req.body || {}).field` (saltcorn) — the `|| {}` guard breaks the
  // plain `req.body.field` match; surface the field so the schema can tighten it.
  ['body', /\(\s*req(?:uest)?\.body\s*\|\|\s*\{\s*\}\s*\)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g],
  ['query', /\(\s*req(?:uest)?\.query\s*\|\|\s*\{\s*\}\s*\)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g],
  ['path', /\(\s*req(?:uest)?\.params\s*\|\|\s*\{\s*\}\s*\)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)/g],
  ['body', /\breq(?:uest)?\.files\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['body', /\brequest\.files\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['header', /\breq\.headers\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['cookie', /\breq\.cookies\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['path', /\breq(?:uest)?\.params\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['query', /\breq(?:uest)?\.query\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['body', /\breq(?:uest)?\.body\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['header', /\breq\.headers\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['cookie', /\breq\.cookies\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  ['path', /\bctx\.params\.([A-Za-z_][A-Za-z0-9_]*)/g],
  ['path', /\bc\.req\.param\(\s*['"]([^'"]+)['"]/g],
  ['query', /\bc\.req\.query\(\s*['"]([^'"]+)['"]/g],
  ['header', /\bc\.req\.header\(\s*['"]([^'"]+)['"]/g],
  ['query', /\bsearchParams\.get\(\s*['"]([^'"]+)['"]/g],
  // Python
  ['query', /\brequest\.(?:GET|args|query_params)\.get\(\s*['"]([^'"]+)['"]/g],
  ['body', /\brequest\.(?:POST|form|json|data)\.get\(\s*['"]([^'"]+)['"]/g],
  ['cookie', /\brequest\.cookies\.get\(\s*['"]([^'"]+)['"]/g],
  ['header', /\brequest\.headers\.get\(\s*['"]([^'"]+)['"]/g],
  ['query', /\brequest\.(?:GET|args|query_params)\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['body', /\brequest\.(?:POST|form|json|data)\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['cookie', /\brequest\.cookies\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['header', /\brequest\.headers\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['path', /\bPath\(\s*['"]([^'"]+)['"]/g],
  ['query', /\bQuery\(\s*['"]([^'"]+)['"]/g],
  ['body', /\bBody\(\s*['"]([^'"]+)['"]/g],
  // Go
  ['path', /\bc\.Param\(\s*['"]([^'"]+)['"]/g],
  ['query', /\bc\.Query\(\s*['"]([^'"]+)['"]/g],
  ['body', /\bc\.PostForm\(\s*['"]([^'"]+)['"]/g],
  ['header', /\bc\.GetHeader\(\s*['"]([^'"]+)['"]/g],
  ['query', /\br\.URL\.Query\(\)\.Get\(\s*['"]([^'"]+)['"]\s*\)/g],
  ['path', /\bmux\.Vars\(r\)\[\s*['"]([^'"\]]+)['"]\s*\]/g],
  // Ruby
  ['unknown', /\bparams\[\s*:([A-Za-z_][A-Za-z0-9_]*)\s*\]/g],
  ['unknown', /\bparams\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]/g],
  ['query', /\brequest\.GET\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['body', /\brequest\.POST\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['header', /\brequest\.headers\[\s*['"]([^'"]+)['"]\s*\]/g],
  ['cookie', /\brequest\.cookies\[\s*['"]([^'"]+)['"]\s*\]/g],
  // Java / C# / Kotlin
  ['path', /@PathVariable\s*(?:\(\s*(?:value\s*=\s*)?['"]([A-Za-z_][A-Za-z0-9_-]*)['"])?/g],
  ['query', /@RequestParam\s*(?:\(\s*(?:value\s*=\s*)?['"]([A-Za-z_][A-Za-z0-9_-]*)['"])?/g],
  ['path', /\[FromRoute(?:\s*\(\s*Name\s*=\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"])?/g],
  ['query', /\[FromQuery(?:\s*\(\s*Name\s*=\s*['"]([A-Za-z_][A-Za-z0-9_-]*)['"])?/g],
  // Rust (axum)
  ['path', /\bPath\(\(?\s*([A-Za-z_][A-Za-z0-9_]*)/g],
  ['query', /\bQuery\(\(?\s*([A-Za-z_][A-Za-z0-9_]*)/g],
  ['body', /\bJson\(\(?\s*([A-Za-z_][A-Za-z0-9_]*)/g],
];

type VKind = ObservedValidator['kind'];
const VALIDATORS: Array<[VKind, RegExp, string?]> = [
  ['sanitizer', /\b(htmlspecialchars|strip_tags|addslashes|mysqli_real_escape_string)\s*\(/g],
  ['escape', /\b(escapeshellarg|escapeshellcmd|escapeHtml|escape)\s*\(/g],
  ['sanitizer', /\b(DOMPurify(?:\.sanitize)?|bleach\.clean|sanitize_html|sanitize)\s*\(/g],
  ['validator', /\b(Joi)\.[A-Za-z_]/g],
  ['validator', /\b(Zod|z)\.[A-Za-z_]/g],
  ['validator', /\b(Yup|yup)\.[A-Za-z_]/g],
  ['validator', /\b(IsString|IsEmail|IsInt|IsBoolean|IsUUID|IsNumber|IsArray|IsObject|IsOptional|IsEnum)\s*\(/g],
  ['validator', /\b(Pydantic|BaseModel|Field|conint|constr|conlist)\b/g],
  ['validator', /\b(marshmallow|serde|serde_json|serde_derive)\b/g],
  ['validator', /\b(validator|validate)\.[A-Za-z_]/g],
  ['validator', /\b(validates_(?:presence|format|length|numericality)_of)\b/g],
  ['validator', /\b(intval|floatval|boolval|ctype_digit|ctype_alpha|ctype_alnum|is_numeric|is_int|is_string|is_array)\s*\(/g],
  ['validator', /\b(filter_var)\s*\(/g],
  ['validator', /\b(parseInt|parseFloat|Number)\s*\(/g],
  ['auth-check', /\b(password_verify|password_hash)\s*\(/g],
  ['auth-check', /\b(Auth::(?:check|user|guard|attempt|guest|id))\s*\(/g],
  ['auth-check', /\b(current_user|authenticate|authenticate_user|require_login|require_auth|requireRole|verify_jwt|jwt_verify)\b/g],
  ['auth-check', /\.isAuthenticated\s*\(/g, 'isAuthenticated'],
  ['auth-check', /@(login_required|require_auth|requires_auth|jwt_required)\b/g],
  ['orm-binding', /\b(findOrFail|findOneBy|findOneByOrFail|findByPk|find_by!?)\s*\(/g],
  ['orm-binding', /\b(prepare|bindParam|bindValue)\s*\(/g],
];

type OKind = ObservedOutput['kind'];
const OUTPUTS: Array<[OKind, RegExp]> = [
  ['json', /\bjson_encode\s*\(/g],
  ['json', /\bres\.(?:json|send)\s*\(/g],
  ['json', /\bjsonify\s*\(/g],
  ['json', /\b(?:JsonResponse|JSONResponse)\s*\(/g],
  ['json', /\bc\.JSON\s*\(/g],
  ['json', /\bJson\s*\(/g],
  ['json', /\bformat\.json\b/g],
  ['json', /\brespond_with\s+(?:json|@)/g],
  ['html', /\brender\s*\(\s*['"][^'"\)]+\.html/g],
  ['html', /\bres\.render\s*\(/g],
  ['html', /\brender_template\s*\(/g],
  ['html', /\bHttpResponse\s*\(/g],
  ['html', /\.html_safe\b/g],
  ['html', /<!DOCTYPE\s+html/gi],
  ['html', /<html[\s>]/gi],
  ['html', /\becho\s+(?!json)/g],
  ['binary', /Content-Type:\s*application\/(?:octet-stream|pdf|zip)/gi],
  ['binary', /\breadfile\s*\(/g],
  ['binary', /\bres\.(?:download|sendFile)\s*\(/g],
  ['binary', /\bsend_file\s*\(/g],
  ['stream', /\bStream\s*\(/g],
  ['plaintext', /text\/plain/g],
  ['plaintext', /\bresponse\.text\b/g],
];

// Handler-body trim. Curly-balance for C-family, def...end for Ruby, indent
// drop for Python.

function trimHandlerBody(snippet: string): { body: string; truncated: boolean } {
  const lines = snippet.split('\n');
  if (lines.length === 0) return { body: snippet, truncated: false };
  let defIdx = 0;
  while (defIdx < lines.length && /^\s*(?:\/\/|#|\/\*|\*|--)?\s*$/.test(lines[defIdx]!)) defIdx++;
  // Skip leading Python decorators so the `def` is the first significant line. A
  // factory-wrapped route (`@bp.route(...)` nested in a constructor fn) reads from the
  // decorator line; without this the def-detection below misses, the body falls to the
  // C-family brace counter, and the first `{}` dict literal truncates the slice before
  // the sink (changedetection.io rss/tag.py:34 `.get('tags', {})` is one line above the
  // XSS sink at :36). Only advance past `@…` lines when a `def` actually follows.
  while (
    defIdx < lines.length &&
    /^\s*@\w/.test(lines[defIdx]!) &&
    lines.slice(defIdx).some((l) => /^\s*(?:async\s+)?def\s+\w+\s*\(/.test(l))
  ) defIdx++;
  // Skip leading TS/JS decorators (`@Post([...])`, `@Acl('x', { scope:'org' })`,
  // `@HttpCode(200)`) — which precede a method and may span multiple lines carrying their
  // own `{}` options — so the C-family brace counter below starts at the METHOD body, not
  // a decorator's options object (NestJS controllers; without this the @Acl options brace
  // is mistaken for the handler body and the sink ~5 lines down never surfaces). Express
  // inline handlers start with `router.verb(` (no leading `@`), so this never fires there.
  while (defIdx < lines.length && /^\s*@[A-Za-z_$]/.test(lines[defIdx]!)) {
    if (!lines[defIdx]!.includes('(')) {
      defIdx++;
    } else {
      let pd = 0;
      let j = defIdx;
      let closed = false;
      for (; j < lines.length && !closed; j++) {
        for (const ch of lines[j]!) {
          if (ch === '(') pd++;
          else if (ch === ')') { pd--; if (pd === 0) closed = true; }
        }
      }
      defIdx = j;
    }
    while (defIdx < lines.length && lines[defIdx]!.trim() === '') defIdx++;
  }
  if (defIdx >= lines.length) return { body: snippet, truncated: false };
  const defLine = lines[defIdx]!;

  if (/^\s*(?:async\s+)?def\s+\w+\s*\(/.test(defLine)) {
    // Python: indent-based
    const indent = defLine.match(/^(\s*)/)?.[1]?.length ?? 0;
    let bodyStarted = false;
    for (let i = defIdx + 1; i < lines.length; i++) {
      const ln = lines[i]!;
      if (ln.trim().length === 0) continue;
      const cur = ln.match(/^(\s*)/)?.[1]?.length ?? 0;
      if (!bodyStarted) { if (cur > indent) bodyStarted = true; continue; }
      if (cur <= indent) return { body: lines.slice(0, i).join('\n'), truncated: false };
    }
    return { body: snippet, truncated: true };
  }

  if (/^\s*def\s+\w+/.test(defLine)) {
    // Ruby: def ... end with naive depth counting
    let depth = 1;
    for (let i = defIdx + 1; i < lines.length; i++) {
      const ln = lines[i]!;
      if (/^\s*(?:def|class|module|if|unless|while|until|do|begin|case)\b/.test(ln)) depth++;
      if (/^\s*end\b/.test(ln)) { depth--; if (depth === 0) return { body: lines.slice(0, i + 1).join('\n'), truncated: false }; }
    }
    return { body: snippet, truncated: true };
  }

  // C-family / PHP: curly-brace balance with string / comment / template-literal
  // awareness. A naive per-line scan miscounts braces inside multi-line backtick
  // template literals — a tagged SQL string like `…${db.sqlsanitize(x)}…` leaks its
  // `${…}` interpolation braces into the function-depth count and closes the body
  // early, truncating the cited range right before a downstream sink (Rule D-3).
  // Track string/comment state across line boundaries and distinguish interpolation
  // braces (which return to template mode) from real code-block braces.
  const text = lines.slice(defIdx).join('\n');
  type Mode = 'code' | 'line' | 'block' | 'sq' | 'dq' | 'tmpl';
  type FrameKind = 'block' | 'interp';
  let mode: Mode = 'code';
  const frames: FrameKind[] = [];
  let blockDepth = 0;
  let opened = false;
  let lineLeading = true; // at line-leading whitespace (for `#` comments)
  for (let p = 0; p < text.length; p++) {
    const ch = text[p]!;
    const nx = text[p + 1];
    if (ch === '\n') { lineLeading = true; if (mode === 'line') mode = 'code'; continue; }
    if (mode === 'block') { if (ch === '*' && nx === '/') { mode = 'code'; p++; } continue; }
    if (mode === 'line') continue;
    if (mode === 'sq') { if (ch === '\\') p++; else if (ch === "'") mode = 'code'; continue; }
    if (mode === 'dq') { if (ch === '\\') p++; else if (ch === '"') mode = 'code'; continue; }
    if (mode === 'tmpl') {
      if (ch === '\\') { p++; continue; }
      if (ch === '`') { mode = 'code'; continue; }
      if (ch === '$' && nx === '{') { frames.push('interp'); mode = 'code'; p++; }
      continue;
    }
    // mode === 'code'
    if (ch !== ' ' && ch !== '\t') {
      const wasLeading = lineLeading;
      lineLeading = false;
      if (ch === '#' && wasLeading) { mode = 'line'; continue; }
    }
    if (ch === '/' && nx === '/') { mode = 'line'; p++; continue; }
    if (ch === '/' && nx === '*') { mode = 'block'; p++; continue; }
    if (ch === "'") { mode = 'sq'; continue; }
    if (ch === '"') { mode = 'dq'; continue; }
    if (ch === '`') { mode = 'tmpl'; continue; }
    if (ch === '{') { frames.push('block'); blockDepth++; opened = true; }
    else if (ch === '}') {
      const f = frames.pop();
      if (f === 'interp') { mode = 'tmpl'; }
      else if (opened && --blockDepth === 0) {
        const lineNo = text.slice(0, p + 1).split('\n').length; // 1-based, within slice
        return { body: lines.slice(0, defIdx + lineNo).join('\n'), truncated: false };
      }
    }
  }
  return { body: snippet, truncated: !opened || blockDepth !== 0 };
}

/** Re-anchor an inline Express handler snippet to its REAL handler body when the
 *  registration lists middleware before a trailing handler — possibly HOF-wrapped,
 *  e.g. `router.post('/login', mwA, passport.authenticate('local',{...}), error_catcher(
 *  async (req,res) => {…}))`. Read from the `router.post(` line, the brace-balancer in
 *  trimHandlerBody would close on the FIRST `{}` (passport's options object) ~60 lines
 *  before the real handler's body — so `req.body.dest` (the open-redirect sink) never
 *  surfaces and the route fails to ground (saltcorn CVE-2026-42259). We slice the snippet
 *  to the start of the LAST depth-1 argument that is a req-taking handler (unwrapping a
 *  single HOF like error_catcher to the inner arrow/function). Returns the snippet
 *  unchanged for non-Express snippets, plain inline routes (re-anchors to the same arrow),
 *  or when no trailing handler arg is found — so the blast radius is the multi-arg case. */
function reanchorWrappedExpressHandler(snippet: string): string {
  const head = /[A-Za-z_$][\w$.]*\.(?:get|post|put|patch|delete|all|options|head)\s*\(/i.exec(snippet);
  if (!head || head.index > 120) return snippet;
  let i = head.index + head[0].length;
  let depth = 1;
  const argStarts: number[] = [i];
  let mode: 'code' | 'sq' | 'dq' | 'tmpl' | 'line' | 'block' = 'code';
  for (; i < snippet.length && depth > 0; i++) {
    const ch = snippet[i]!;
    const nx = snippet[i + 1];
    if (mode === 'sq') { if (ch === '\\') i++; else if (ch === "'") mode = 'code'; continue; }
    if (mode === 'dq') { if (ch === '\\') i++; else if (ch === '"') mode = 'code'; continue; }
    if (mode === 'tmpl') { if (ch === '\\') i++; else if (ch === '`') mode = 'code'; continue; }
    if (mode === 'line') { if (ch === '\n') mode = 'code'; continue; }
    if (mode === 'block') { if (ch === '*' && nx === '/') { mode = 'code'; i++; } continue; }
    if (ch === '/' && nx === '/') { mode = 'line'; i++; continue; }
    if (ch === '/' && nx === '*') { mode = 'block'; i++; continue; }
    if (ch === "'") { mode = 'sq'; continue; }
    if (ch === '"') { mode = 'dq'; continue; }
    if (ch === '`') { mode = 'tmpl'; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth === 0) break; }
    else if (ch === ',' && depth === 1) argStarts.push(i + 1);
  }
  const end = i;
  for (let k = argStarts.length - 1; k >= 1; k--) {
    const s = argStarts[k]!;
    const e = k + 1 < argStarts.length ? argStarts[k + 1]! - 1 : end;
    const arg = snippet.slice(s, e);
    const isHandler =
      (/=>/.test(arg) && /\breq(?:uest)?\b/.test(arg)) ||
      /\bfunction\s*\*?\s*\([^)]*\breq(?:uest)?\b/.test(arg);
    if (!isHandler) continue;
    // Unwrap a single HOF wrapper (error_catcher(fn)) to the inner arrow/function start.
    const inner = /(?:async\s+)?\([^)]*\breq(?:uest)?\b[^)]*\)\s*=>|\bfunction\s*\*?\s*\(/.exec(arg);
    return snippet.slice(s + (inner ? inner.index : 0));
  }
  return snippet;
}

function stripInline(line: string): string {
  let out = '';
  let i = 0;
  let inS = false, inD = false, inB = false;
  while (i < line.length) {
    const ch = line[i]!;
    const nx = line[i + 1];
    if (inB) { if (ch === '*' && nx === '/') { inB = false; i += 2; continue; } i++; continue; }
    if (inS) { if (ch === '\\' && nx !== undefined) { i += 2; continue; } if (ch === "'") inS = false; i++; continue; }
    if (inD) { if (ch === '\\' && nx !== undefined) { i += 2; continue; } if (ch === '"') inD = false; i++; continue; }
    if (ch === '/' && nx === '/') break;
    if (ch === '#' && line.slice(0, i).trim() === '') break;
    if (ch === '/' && nx === '*') { inB = true; i += 2; continue; }
    if (ch === "'") { inS = true; i++; continue; }
    if (ch === '"') { inD = true; i++; continue; }
    out += ch;
    i++;
  }
  return out;
}

// Extraction

function excerpt(line: string): string {
  const c = line.replace(/\s+/g, ' ').trim();
  return c.length > 200 ? c.slice(0, 197) + '...' : c;
}

function lineAt(src: string, offset: number, baseLine: number): { line: number; excerpt: string } {
  let line = baseLine;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (src.charCodeAt(i) === 10) { line++; lineStart = i + 1; }
  }
  let lineEnd = src.indexOf('\n', lineStart);
  if (lineEnd === -1) lineEnd = src.length;
  return { line, excerpt: excerpt(src.slice(lineStart, lineEnd)) };
}

function extractInputs(body: string, file: string, base: number, cap: number): ObservedInput[] {
  const seen = new Set<string>();
  const out: ObservedInput[] = [];
  for (const [source, re] of INPUTS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const name = m.slice(1).find((g) => typeof g === 'string' && g.length > 0);
      const { line, excerpt: ex } = lineAt(body, m.index, base);
      const finalName = name ?? '(unnamed)';
      const key = `${source}::${finalName}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: finalName, source, file, line, excerpt: ex });
      if (out.length >= cap) return out;
    }
  }
  // Destructured request reads: `const { a, b } = req.body` / `= req.query` /
  // `= req.params` (and `request.*`). Each key is a distinct input. The member-access
  // INPUTS above miss these because one match yields many names.
  const destr = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?req(?:uest)?\.(body|query|params)\b/g;
  let dm: RegExpExecArray | null;
  while ((dm = destr.exec(body)) !== null) {
    const src: Src = dm[2] === 'params' ? 'path' : (dm[2] as Src);
    const { line } = lineAt(body, dm.index, base);
    for (const raw of dm[1]!.split(',')) {
      // `{ a, b: c, d = 1 }` → the BOUND local name is after `:`, before `=`.
      const nm = /(?:[A-Za-z_$][\w$]*\s*:\s*)?([A-Za-z_$][\w$]*)/.exec(raw.trim());
      const name = nm?.[1];
      if (!name) continue;
      const key = `${src}::${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name, source: src, file, line, excerpt: excerpt(raw.trim()) });
      if (out.length >= cap) return out;
    }
  }
  return out;
}

function extractValidators(body: string, file: string, base: number, cap: number): ObservedValidator[] {
  const seen = new Set<string>();
  const out: ObservedValidator[] = [];
  for (const [kind, re, literal] of VALIDATORS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const name = literal ?? m.slice(1).find((g) => typeof g === 'string' && g.length > 0) ?? m[0];
      const { line, excerpt: ex } = lineAt(body, m.index, base);
      const key = `${name}@${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name, kind, file, line, excerpt: ex });
      if (out.length >= cap) return out;
    }
  }
  return out;
}

function extractOutputs(body: string, file: string, base: number, cap: number): ObservedOutput[] {
  const seen = new Set<string>();
  const out: ObservedOutput[] = [];
  for (const [kind, re] of OUTPUTS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const { line, excerpt: ex } = lineAt(body, m.index, base);
      const key = `${kind}@${line}@${m[0].slice(0, 20)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ kind, file, line, excerpt: ex });
      if (out.length >= cap) return out;
    }
  }
  return out;
}

// Object-id surface derivation (BOLA). Pure regex over the already-extracted
// snippet + observedInputs — no new IO.

// id-shaped param name: bare id tokens, `<thing>_id`/`<thing>Id`, or a known
// object handle (username/email/user/order/account). Tight by design.
const ID_NAME_RE =
  /^(?:id|uuid|guid|pid|uid)$|(?:_|-)?id$|uuid$|guid$|^(?:username|email|user|order|account)$|^(?:.*)id$/i;

// request-visible owner field: a query/body input whose name implies the owner.
const OWNER_NAME_RE = /(?:owner|user_?id|account|tenant|org)/i;

// principal tokens that, near a comparison operator, indicate an ownership check.
const PRINCIPAL_TOKEN_RE =
  /\breq\.user\b|\bjwt\.|\bsession\.|\bcurrent_user\b|\bcurrentUser\b|Auth::id|\bprincipal\b|\bg\.user\b|\brequest\.user\b/;

const COMPARISON_RE = /==|===|!=|!==|\.equals\(/;

// fetch/mutate sink tells near an id.
const FETCH_SINK_RE =
  /\bfindOrFail|\bfindOneBy|\bfindOneByOrFail|\bfindByPk|\bfind_by!?|\bfindOne\(|\b\.findById\(|\b\.get\(|\bget_object_or_404|\bobjects\.get\(|\bfindUnique\(|\bWHERE\b[^=\n]*=|\.query\(|\bSELECT\b[^;\n]*\bWHERE\b/i;

function escapeForRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Lines of the snippet where `name` appears as a word. */
function linesMentioning(lines: string[], name: string): number[] {
  const re = new RegExp(`\\b${escapeForRegex(name)}\\b`);
  const out: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]!)) out.push(i);
  }
  return out;
}

function withinWindow(lines: string[], idxs: number[], re: RegExp, window: number): boolean {
  for (const i of idxs) {
    const lo = Math.max(0, i - window);
    const hi = Math.min(lines.length - 1, i + window);
    for (let j = lo; j <= hi; j++) {
      if (re.test(lines[j]!)) return true;
    }
  }
  return false;
}

/** True when a principal token co-occurs with a comparison operator on a line
 *  that also mentions the id (or on an adjacent line — the fetched record is
 *  often compared on the next line). */
function comparedToPrincipalNear(lines: string[], idxs: number[], window: number): boolean {
  for (const i of idxs) {
    const lo = Math.max(0, i - window);
    const hi = Math.min(lines.length - 1, i + window);
    for (let j = lo; j <= hi; j++) {
      const ln = lines[j]!;
      if (PRINCIPAL_TOKEN_RE.test(ln) && COMPARISON_RE.test(ln)) return true;
    }
  }
  return false;
}

const ID_SURFACE_SOURCES = new Set<ObservedInput['source']>(['path', 'query', 'body']);
const OWNER_SOURCES = new Set<ObservedInput['source']>(['query', 'body']);

function deriveObjectIdSurfaces(
  inputs: ObservedInput[],
  snippet: string | undefined,
): ObjectIdSurface[] {
  if (!snippet) return [];
  const lines = snippet.split('\n');
  const ownerCandidate = inputs.find(
    (i) => OWNER_SOURCES.has(i.source) && OWNER_NAME_RE.test(i.name) && i.name !== '(unnamed)',
  );
  const surfaces: ObjectIdSurface[] = [];
  const seen = new Set<string>();
  for (const inp of inputs) {
    if (!ID_SURFACE_SOURCES.has(inp.source)) continue;
    if (inp.name === '(unnamed)') continue;
    if (!ID_NAME_RE.test(inp.name)) continue;
    const key = `${inp.source}.${inp.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const idxs = linesMentioning(lines, inp.name);
    const usedInFetchOrMutate = withinWindow(lines, idxs, FETCH_SINK_RE, 3);
    const comparedToPrincipal = comparedToPrincipalNear(lines, idxs, 3);
    const surface: ObjectIdSurface = {
      param: inp,
      usedInFetchOrMutate,
      comparedToPrincipal,
    };
    if (ownerCandidate && ownerCandidate.name !== inp.name) {
      surface.ownerFieldCandidate = ownerCandidate;
    }
    surfaces.push(surface);
  }
  return surfaces;
}

// Laravel route-model-binding BOLA surface. A controller method `show(User $user)`
// binds the `{user}` route placeholder to a fetched model — so the typed param IS
// an attacker-controlled object-id reaching a fetch, even though there is no
// explicit `find($id)` and the param isn't `*id*`-named. Neither generic heuristic
// (FETCH_SINK_RE, ID_NAME_RE) catches this; this derives it directly.
const LARAVEL_NON_MODEL =
  /^(?:\w*Request|JsonResponse|Response|RedirectResponse|Collection|LengthAwarePaginator|Builder|Carbon|bool|int|float|string|array|void|mixed|self|static|callable|iterable|object|null)$/;
// Ownership / authorization tells in a controller method body. Their presence
// means the method gates the bound resource against the principal (not a BOLA).
const LARAVEL_OWNERSHIP_RE =
  /\$this->authorize\s*\(|\bGate::|->cannot?\s*\(|\bpolicy\s*\(|\bAuth::id\s*\(|\bauth\(\)\s*->\s*(?:id|user)\s*\(|\$request->user\s*\(|->user_id\b|->id\s*===\s*\$|\$\w+->id\s*===/;

function laravelPlaceholders(routePath: string): Set<string> {
  const out = new Set<string>();
  for (const m of routePath.matchAll(/:(\w+)/g)) out.add(m[1]!);
  for (const m of routePath.matchAll(/\{(\w+)\??\}/g)) out.add(m[1]!);
  return out;
}

function deriveLaravelObjectIdSurfaces(
  route: RouteInventoryEntry,
  file: string,
  base: number,
  snippet: string | undefined,
): { inputs: ObservedInput[]; surfaces: ObjectIdSurface[] } {
  const inputs: ObservedInput[] = [];
  const surfaces: ObjectIdSurface[] = [];
  if (!snippet) return { inputs, surfaces };
  const sig = /function\s+\w+\s*\(([^)]*)\)/.exec(snippet);
  if (!sig) return { inputs, surfaces };
  const placeholders = laravelPlaceholders(route.path);
  if (placeholders.size === 0) return { inputs, surfaces };
  const ownershipChecked = LARAVEL_OWNERSHIP_RE.test(snippet);
  const lines = snippet.split('\n');
  const sigLineIdx = Math.max(0, lines.findIndex((l) => /function\s+\w+\s*\(/.test(l)));
  const paramRe = /\b([A-Z]\w+)\s+\$([a-z]\w*)/g;
  let pm: RegExpExecArray | null;
  const sigArgs = sig[1]!;
  while ((pm = paramRe.exec(sigArgs)) !== null) {
    const type = pm[1]!;
    const name = pm[2]!;
    if (LARAVEL_NON_MODEL.test(type)) continue; // not a bound model (Request/Response/...)
    if (!placeholders.has(name)) continue; // param must match a route placeholder
    const inp: ObservedInput = {
      name,
      source: 'path',
      file,
      line: base + sigLineIdx,
      excerpt: `${type} $${name}`,
    };
    inputs.push(inp);
    surfaces.push({ param: inp, usedInFetchOrMutate: true, comparedToPrincipal: ownershipChecked });
  }
  return { inputs, surfaces };
}

// FastAPI / Flask path-param BOLA surface. `@router.get("/{issue_id}")` binds the
// placeholder to a handler SIGNATURE arg (`async def get_issue(issue_id: str)`),
// then `svc.get(issue_id)` fetches it. The generic INPUTS table matches only
// request-object accessors (`request.args.get`), not signature path params — so the
// attacker-controlled id never surfaces. This derives it directly (PraisonAI
// CVE-2026-47415: svc.get(issue_id) with no workspace scoping → cross-tenant read).
// Ownership = an actual comparison/scoping against the principal — NOT mere presence
// of a scope variable, and NOT a membership Depends() (auth ≠ per-object ownership).
const PYTHON_OWNERSHIP_RE =
  /\bcurrent_user\b|\.user_id\s*[=!]=|[=!]=\s*[\w.]*current_user|\bowner_id\s*[=!]=|[=!]=\s*[\w.]*owner|\b(?:filter|where)\([^)]*\b(?:owner|user_id|workspace_id|account_id|tenant_id)\b|\b\w+\([^)]*\b(?:workspace_id|owner_id|user_id|tenant_id)\s*=[^=]/i;
const PY_ID_NAME = /^(?:id|pk|uuid|slug)$|_id$/i;

function pythonPlaceholders(routePath: string): Set<string> {
  const out = new Set<string>();
  for (const m of routePath.matchAll(/:(\w+)/g)) out.add(m[1]!);
  for (const m of routePath.matchAll(/\{(\w+)(?::[^}]+)?\}/g)) out.add(m[1]!);
  return out;
}

function derivePythonObjectIdSurfaces(
  route: RouteInventoryEntry,
  file: string,
  base: number,
  snippet: string | undefined,
): { inputs: ObservedInput[]; surfaces: ObjectIdSurface[] } {
  const inputs: ObservedInput[] = [];
  const surfaces: ObjectIdSurface[] = [];
  if (!snippet) return { inputs, surfaces };
  const sig = /\bdef\s+\w+\s*\(([\s\S]*?)\)\s*(?:->[^:]+)?:/.exec(snippet);
  if (!sig) return { inputs, surfaces };
  const placeholders = pythonPlaceholders(route.path);
  if (placeholders.size === 0) return { inputs, surfaces };
  const lines = snippet.split('\n');
  const sigLineIdx = Math.max(0, lines.findIndex((l) => /\bdef\s+\w+\s*\(/.test(l)));
  const sigEnd = sig.index + sig[0].length;
  const body = snippet.slice(sigEnd); // ownership/fetch tells live in the BODY, not the signature
  const ownershipChecked = PYTHON_OWNERSHIP_RE.test(body);
  // Top-level comma-split of the signature param list (paren/bracket aware).
  const args = topLevelArgList(sig[1]!);
  for (const arg of args) {
    const nm = /^([A-Za-z_]\w*)/.exec(arg.trim());
    if (!nm) continue;
    const name = nm[1]!;
    if (!placeholders.has(name) || !PY_ID_NAME.test(name)) continue;
    // The id must actually reach a fetch/mutate call in the body (e.g. svc.get(id)).
    const usedInFetchOrMutate = new RegExp(`[\\w.]+\\([^)]*\\b${escapeForRegex(name)}\\b`).test(body);
    if (!usedInFetchOrMutate) continue;
    const inp: ObservedInput = { name, source: 'path', file, line: base + sigLineIdx, excerpt: `${name} (path param)` };
    inputs.push(inp);
    surfaces.push({ param: inp, usedInFetchOrMutate: true, comparedToPrincipal: ownershipChecked });
  }
  return { inputs, surfaces };
}

// Generic Flask/Django/FastAPI path-param inputs. A route path placeholder arrives as a
// handler SIGNATURE arg (`def rss_tag_feed(tag_uuid)`), which the INPUTS regex table never
// matches. derivePythonObjectIdSurfaces only surfaces id-NAMED params reaching a
// fetch/mutate (BOLA); but ANY path param is an injection taint source (changedetection.io
// reflected XSS interpolates `tag_uuid` into an HTML response). Surface each route
// placeholder present in the signature as a `path` input.
function derivePythonPathInputs(
  route: RouteInventoryEntry,
  file: string,
  base: number,
  snippet: string | undefined,
): ObservedInput[] {
  const out: ObservedInput[] = [];
  if (!snippet) return out;
  const sig = /\bdef\s+\w+\s*\(([\s\S]*?)\)\s*(?:->[^:]+)?:/.exec(snippet);
  if (!sig) return out;
  const placeholders = pythonPlaceholders(route.path);
  if (placeholders.size === 0) return out;
  const lines = snippet.split('\n');
  const sigLineIdx = Math.max(0, lines.findIndex((l) => /\bdef\s+\w+\s*\(/.test(l)));
  for (const arg of topLevelArgList(sig[1]!)) {
    const nm = /^([A-Za-z_]\w*)/.exec(arg.trim());
    if (!nm) continue;
    const name = nm[1]!;
    if (!placeholders.has(name)) continue;
    out.push({ name, source: 'path', file, line: base + sigLineIdx, excerpt: `${name} (path param)` });
  }
  return out;
}

// FastAPI Pydantic body-model inputs. FastAPI binds a request body to a handler
// parameter typed with a Pydantic model — `async def process(form_data: ProcessUrlForm)`
// — and the body fields are read as ATTRIBUTES (`form_data.url`), which the generic
// INPUTS table (req.body.x / request.json.get) never matches. Without this the body
// taint source is invisible and no candidate fires (open-webui SSRF: observedInputs []).
// Derive each dereferenced field of the body-model param(s) as a `body` input.
const FASTAPI_NON_MODEL_TYPES = new Set([
  'str', 'int', 'float', 'bool', 'bytes', 'dict', 'list', 'set', 'tuple', 'frozenset',
  'complex', 'bytearray', 'Any', 'None', 'Optional', 'Union', 'List', 'Dict',
  'Request', 'Response', 'WebSocket', 'BackgroundTasks', 'UploadFile', 'HTTPConnection',
  'Session', 'AsyncSession', 'Connection', 'Depends', 'Annotated',
]);

function deriveFastApiBodyInputs(file: string, base: number, snippet: string | undefined): ObservedInput[] {
  const out: ObservedInput[] = [];
  if (!snippet) return out;
  const sig = /\bdef\s+\w+\s*\(([\s\S]*?)\)\s*(?:->[^:]+)?:/.exec(snippet);
  if (!sig) return out;
  const lines = snippet.split('\n');
  const sigLineIdx = Math.max(0, lines.findIndex((l) => /\bdef\s+\w+\s*\(/.test(l)));
  const body = snippet.slice(sig.index + sig[0].length);
  // Find body-model params: `name: PascalCaseModel` with no DI/query/path/etc default.
  // In valid FastAPI a bare model-typed param IS the request body (services need Depends).
  const modelParams: string[] = [];
  for (const arg of topLevelArgList(sig[1]!)) {
    const a = arg.trim();
    const m = /^([A-Za-z_]\w*)\s*:\s*([A-Za-z_][\w.]*)/.exec(a);
    if (!m) continue;
    const ptype = m[2]!.split('.').pop()!;
    if (!/^[A-Z]/.test(ptype) || FASTAPI_NON_MODEL_TYPES.has(ptype)) continue;
    if (/=\s*(?:Depends|Query|Path|Header|Cookie|Form|File|Security)\s*\(/.test(a)) continue;
    modelParams.push(m[1]!);
  }
  if (modelParams.length === 0) return out;
  const seen = new Set<string>();
  for (const p of modelParams) {
    const accessRe = new RegExp(`\\b${escapeForRegex(p)}\\.([A-Za-z_]\\w*)`, 'g');
    let am: RegExpExecArray | null;
    while ((am = accessRe.exec(body)) !== null) {
      const attr = am[1]!;
      if (attr.startsWith('__')) continue; // dunder / pydantic internals
      if (/^\s*\(/.test(body.slice(am.index + am[0].length))) continue; // a method call, not a field
      if (seen.has(attr)) continue;
      seen.add(attr);
      out.push({ name: attr, source: 'body', file, line: base + sigLineIdx, excerpt: `${p}.${attr} (request body field)` });
    }
  }
  return out;
}

// Django Form / DRF Serializer body inputs. A handler that binds `Form(request.POST)` /
// `Serializer(data=request.data)` never subscripts the request bag — the fields live as
// class attributes on the form (`url = forms.CharField(...)`), invisible to the INPUTS
// table. We surface them so the policy layer can emit a TIGHT schema per field (the
// product goal: a `url` field gets blockPrivateRanges regardless of any sink). Async —
// resolves the form class definition.
const FORM_FIELD_DECL = /^\s*([A-Za-z_]\w*)\s*=\s*[\w.]*(?:forms\.\w*Field|serializers\.\w+|TagField)\s*\(/;
async function resolveDjangoFormInputs(snippet: string | undefined, tools: AgentTools): Promise<ObservedInput[]> {
  const out: ObservedInput[] = [];
  if (!snippet) return out;
  // `<PascalCase>(request.POST)` / `(data=request.data)` / `(request.GET)`. Any class
  // built from the request bag is a candidate; only one with form/serializer field decls
  // yields inputs (a non-form class has none → emits nothing).
  const inst = /\b([A-Z]\w*)\s*\(\s*(?:data\s*=\s*)?request\.(POST|GET|data|query_params)\b/g;
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = inst.exec(snippet)) !== null) {
    const formName = m[1]!;
    if (seen.has(formName)) continue;
    seen.add(formName);
    const src: Src = m[2] === 'GET' || m[2] === 'query_params' ? 'query' : 'body';
    // The form is a CLASS — grepSymbolDef only knows function/const forms, so grep the
    // class def directly.
    let def;
    try { def = (await tools.grep(`class\\s+${escapeForRegex(formName)}\\b`, { maxResults: 5 }))?.[0]; } catch { continue; }
    if (!def) continue;
    let read;
    try { read = await tools.read_file(def.file, def.line, def.line + 80); } catch { continue; }
    if (!read?.content) continue;
    const lines = read.content.split('\n');
    for (let i = 1; i < lines.length; i++) {
      if (/^\s*class\s+\w/.test(lines[i]!)) break; // next class — end of this form body
      const fm = FORM_FIELD_DECL.exec(lines[i]!);
      if (!fm) continue;
      out.push({ name: fm[1]!, source: src, file: read.path, line: read.lineStart + i, excerpt: `${formName}.${fm[1]} (form field)` });
    }
  }
  return out;
}

// Body-parse derivation (phase B). A body-bearing route (POST/PUT/PATCH) that
// parses json/form/multipart/xml is a content-type-allowlist surface.

type BodyKind = NonNullable<EvidencePack['bodyParsed']>['kind'];
const BODY_PARSE: Array<[BodyKind, RegExp]> = [
  ['multipart', /\bmultipart\b|\$_FILES\b|\breq\.files\b|\brequest\.files\b|\bFormData\b|\.array\(|\.single\(|\bMultiValueDict\b/g],
  ['form', /\$_POST\b|\breq\.body\b.*urlencoded|urlencoded\(\)|\brequest\.form\b|\bbodyParser\.urlencoded/g],
  ['xml', /\bxml2js\b|\bparseString\b|\betree\b|\bElementTree\b|application\/xml|text\/xml/g],
  ['json', /\bexpress\.json\(\)|\bbodyParser\.json|\breq\.body\b|\brequest\.json\b|\brequest\.get_json\b|\bawait\s+request\.json\(\)|\bc\.req\.json\(\)|\.json\(\)\s*;?\s*$|\bJSON\.parse\s*\(\s*(?:req|request)\b/g],
];

function deriveBodyParsed(
  method: string,
  snippet: string | undefined,
  file: string,
  base: number,
  appParser?: 'form' | 'json' | null,
): EvidencePack['bodyParsed'] {
  if (!snippet) return null;
  if (!['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) return null;
  // multipart > form > xml > json (most specific first). multipart (req.files) and
  // xml are reliable from the handler; json vs form (both `req.body`) is NOT — the
  // parser is app-global. So when the handler match is json/form, OVERRIDE with the
  // app-global parser if we detected one (kills the dvna urlencoded-app over-block).
  for (const [kind, re] of BODY_PARSE) {
    re.lastIndex = 0;
    const m = re.exec(snippet);
    if (m) {
      const { line } = lineAt(snippet, m.index, base);
      const resolved = (kind === 'json' || kind === 'form') && appParser ? appParser : kind;
      return { kind: resolved, file, line };
    }
  }
  // Handler showed no parse tell but the app has a global parser + this is a write —
  // model it from the app parser anchored at the handler start (so the content-type
  // gate still fires with the right media type).
  if (appParser) return { kind: appParser, file, line: base };
  return null;
}

// Cross-file handler resolution (#2). For declaration-router frameworks the route
// entry's (sourceFile, sourceLine) is the DECLARATION — `router.post('/x',
// ctrl.handler)` — not the handler body, which lives in another file/symbol. Reading
// the decl slice yields router code (more route decls), not `req.body.x → sink`. So
// resolve the handlerSymbol to its real definition and read THAT body. Falls back to
// the decl read when the symbol can't be resolved (no regression). Reuses the
// deterministic `find_definition` (ripgrep def-pattern) the tools already expose.
/** The handler symbol to resolve: the route's `handlerSymbol` if the extractor set
 *  it (Python/FastAPI), else parsed from the route-declaration line — the last
 *  member-expr/identifier argument of a `router.post('/x', mw, ctrl.handler)`
 *  registration. Returns null for an inline function handler (the decl read already
 *  contains its body) or when nothing parseable is found. */
function tailIfIdent(s: string | undefined): string | null {
  if (!s) return null;
  const t = s.split('.').pop() || s;
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(t) ? t : null;
}

/** Scan an express-style `<obj>.<verb>(...)` registration with BALANCED-PAREN
 *  awareness, so a multi-line arg list and middleware-FACTORY args (`validating(
 *  schema)` — parens inside an arg) don't truncate the parse. Returns the depth-1
 *  args (arg[0] = path) up to the handler, plus `inline` = the handler is an
 *  inline function (a top-level `=>` / `function`). When NOT inline, the last arg
 *  is the referenced handler symbol. Null when no matching registration is found.
 *  The top-level arrow is the decisive tell even when earlier args are factory
 *  calls like `validating(getSchema, 'params')`. */
function scanExpressRegistration(
  text: string,
  verb: string,
  wantPath: string,
  np: (p: string) => string,
): { args: string[]; inline: boolean } | null {
  const re = new RegExp(`\\.(?:${verb}|all)\\s*\\(`, 'gi');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    let depth = 1;
    const args: string[] = [];
    let cur = '';
    let inline = false;
    let i = m.index + m[0].length;
    for (; i < text.length && depth > 0; i++) {
      const ch = text[i]!;
      if (depth === 1 && ch === '=' && text[i + 1] === '>') { inline = true; break; }
      if (depth === 1 && /\bfunction\b/.test(cur + ch) && /\bfunction$/.test(cur + ch)) { inline = true; break; }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth === 0) break; }
      else if (depth === 1 && ch === ',') { args.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    if (cur.trim()) args.push(cur.trim());
    const first = (args[0] ?? '').replace(/^['"`]/, '').replace(/['"`].*$/, '');
    const declPath = np(first);
    // The decl line carries the router-LOCAL path; route.path is the MOUNTED path
    // (with the router's prefix), so match by suffix too — else a mounted route falls
    // back to the extractor's handlerSymbol (the first middleware / a HOF wrapper like
    // `error_catcher(fn)`) and the real handler body is never read (saltcorn).
    if (!first || (declPath !== wantPath && !(declPath && wantPath.endsWith(declPath)))) continue;
    return { args, inline };
  }
  return null;
}

/** The callee/identifier of a middleware arg: `validating(schema)` → 'validating',
 *  `isLoggedOrGuest` → 'isLoggedOrGuest'. Null for inline fns / non-idents. */
function middlewareSymbolOf(arg: string): string | null {
  const call = /^([A-Za-z_$][\w$]*)\s*\(/.exec(arg);
  if (call) return call[1]!;
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(arg)) return tailIfIdent(arg);
  return null;
}

async function handlerSymbolFor(route: RouteInventoryEntry, tools: AgentTools): Promise<string | null> {
  // Laravel controller action `Ctrl@method` (or namespaced `App\\X\\Ctrl@method`):
  // the handler body is the controller method, in a separate file — resolveHandler
  // Location resolves the `@` form. Return it verbatim.
  const hsym = route.handlerSymbol ?? '';
  if (/^[\w\\]+@\w+$/.test(hsym)) return hsym;
  // 1. Parse the route-declaration line FIRST. For declaration routers
  // (`router.post('/x', mw, ctrl.handler)`) the handler is the LAST argument — the
  // extractor's `handler` field is unreliable here (it captures the first
  // middleware). Read a small WINDOW around sourceLine (the extractor's line can be
  // off-by-one) and pick the registration whose method + path match THIS route —
  // not blindly the sourceLine, which may point at the neighbouring route's decl.
  const line = Math.max(1, route.sourceLine || 1);
  let declText = '';
  try {
    declText = (await tools.read_file(route.sourceFile, Math.max(1, line - 1), line + 10))?.content ?? '';
  } catch {
    declText = '';
  }

  // Method-first PromiseRouter: `this.route('POST', '/path', ...args, handler)`.
  // The extractor's handler field caught the first middleware; the real handler is
  // the last arg, which is often an inline arrow that DELEGATES to a method
  // (`req => this.handleCreate(req)`). Resolve the delegated symbol so the pack
  // reads the actual handler body, not the arrow or the middleware.
  const mf = new RegExp(
    `\\.route\\(\\s*["'\`]${route.method}["'\`]\\s*,\\s*["'\`][^"'\`]*["'\`]\\s*,([\\s\\S]*)$`,
    'i',
  ).exec(declText);
  if (mf) {
    const tail = mf[1]!;
    const deleg =
      /=>\s*\{?\s*(?:return\s+)?(?:this\.)?([A-Za-z_$][\w$]*)\s*\(\s*req\b/.exec(tail) ??
      /\b(?:this\.)?([A-Za-z_$][\w$]*)\s*\(\s*req\s*\)/.exec(tail);
    if (deleg) return deleg[1]!; // delegated method (handleCreate)
    const args = tail.split(',').map((s) => s.trim()).filter(Boolean);
    const last = args[args.length - 1] ?? '';
    if (/\bfunction\b|=>/.test(last)) return null; // inline non-delegating handler
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$/.test(last)) return tailIfIdent(last);
  }
  const np = (p: string) => (p.replace(/[?#].*$/, '').replace(/\/+/g, '/').replace(/\/$/, '') || '/').toLowerCase().replace(/[:{<][^/}>]+[}>]?/g, '');
  const wantPath = np(route.path);
  const scanned = scanExpressRegistration(declText, route.method.toLowerCase(), wantPath, np);
  if (scanned) {
    if (scanned.inline) return null; // inline handler — the decl-region read holds its body
    const last = scanned.args[scanned.args.length - 1] ?? '';
    if (/\bfunction\b/.test(last)) return null;
    if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(last)) return tailIfIdent(last); // referenced handler (LAST arg)
    return null; // last arg is a path/string (no handler ref) — decl read covers it
  }
  // NestJS controllers: a bare PascalCase verb decorator (`@Post('/send')`) sits
  // directly above its method, so the method body IS at the route declaration —
  // treat it as inline (the decl-region read holds the body). Resolving the method
  // name as a symbol fails anyway: NestJS signatures carry decorator params
  // (`@Body()`, `@Query('url')`) whose parens break the def-grep, which would
  // mislabel a fully-readable handler as `unresolved` → spurious reviewRequired.
  // (FastAPI/Flask use dotted lowercase `@router.post(` and are unaffected.)
  if (/@(?:Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(/.test(declText)) {
    const sym = route.handlerSymbol;
    if (sym && new RegExp(`\\b${escapeForRegex(sym)}\\s*\\(`).test(declText)) return null;
  }
  // No express registration matched (decorator/def framework, e.g. FastAPI
  // `@app.get('/x')`): the extractor's handlerSymbol is the def name. Do NOT use
  // it for express routes — there it is the first middleware (a factory like
  // `validating(...)`), which would mis-resolve the handler.
  return tailIfIdent(route.handlerSymbol);
}

/** Resolve a Laravel controller action `Ctrl@method` to the method's location.
 *  Multiple controllers can share a class name, so pick the file whose path best
 *  overlaps the route's static segments (e.g. /api/v1/users → app/Api/V1/...). */
async function resolveLaravelAction(
  ctrlRaw: string,
  method: string,
  route: RouteInventoryEntry,
  tools: AgentTools,
): Promise<{ file: string; line: number } | null> {
  const ctrl = ctrlRaw.split('\\').pop() ?? ctrlRaw;
  let clsHits: GrepHit[];
  try {
    clsHits = (await tools.grep(`class\\s+${escapeForRegex(ctrl)}\\b`, { maxResults: 20 })) ?? [];
  } catch {
    return null;
  }
  if (clsHits.length === 0) return null;
  const tokens = route.path.toLowerCase().split('/').filter((t) => t && !t.startsWith(':') && !t.startsWith('{'));
  const best = clsHits
    .map((h) => {
      const lp = h.file.toLowerCase();
      return { h, score: tokens.reduce((s, t) => s + (lp.includes(t) ? 1 : 0), 0) };
    })
    .sort((a, b) => b.score - a.score)[0]!.h;
  let mHits: GrepHit[];
  try {
    mHits = (await tools.grep(`function\\s+${escapeForRegex(method)}\\s*\\(`, { maxResults: 60 })) ?? [];
  } catch {
    mHits = [];
  }
  const inFile = mHits.find((x) => x.file === best.file);
  return inFile ? { file: inFile.file, line: inFile.line } : { file: best.file, line: best.line };
}

// Handler-resolution provenance — drives the fail-loud coverage signal.
//   'resolved'   — found the real handler body (cross-file/far-in-file).
//   'inline'     — handler is an inline fn at the route decl (decl read holds it).
//   'unresolved' — a handler symbol exists but we could NOT locate its body
//                  (unmodeled framework, controller/def not found). The route is
//                  UNANALYZED: surface a coverage gap, never report it clean.
type HandlerLocation =
  | { file: string; line: number; provenance: 'resolved' }
  | { provenance: 'inline' }
  | { provenance: 'unresolved' };

async function resolveHandlerLocation(
  route: RouteInventoryEntry,
  tools: AgentTools,
): Promise<HandlerLocation> {
  const tail = await handlerSymbolFor(route, tools);
  if (!tail) return { provenance: 'inline' };
  const at = /^([\w\\]+)@(\w+)$/.exec(tail);
  if (at) {
    const loc = await resolveLaravelAction(at[1]!, at[2]!, route, tools);
    return loc ? { ...loc, provenance: 'resolved' } : { provenance: 'unresolved' };
  }
  // Grep for a DEFINITION/assignment of the symbol across the common forms — this
  // covers CommonJS `module.exports.x = function`, `exports.x =`, `const x =`,
  // `function x(`, object-method `x: function`/`x(`, and Python `def x(`. (The
  // tools' `find_definition` def patterns miss the export-assigned CommonJS form,
  // which is exactly how Express controllers are written.)
  const esc = escapeForRegex(tail);
  const defPattern =
    `(?:module\\.exports\\.|exports\\.|function\\s+\\*?\\s*|const\\s+|let\\s+|var\\s+|async\\s+def\\s+|def\\s+)${esc}\\b` +
    `|\\b${esc}\\s*[:=]\\s*(?:async\\s*)?(?:function\\b|\\()` +
    `|\\b${esc}\\s*\\([^)]*\\)\\s*\\{`;
  let hits;
  try {
    hits = await tools.grep(defPattern, { maxResults: 25 });
  } catch {
    return { provenance: 'unresolved' };
  }
  if (!hits || hits.length === 0) return { provenance: 'unresolved' };
  const declFile = route.sourceFile.replace(/^\.\//, '');
  const declLine = route.sourceLine || 0;
  // Prefer a definition that is genuinely ELSEWHERE than the route declaration: a
  // different file, or the same file but >2 lines from the decl (an inline
  // `@app.route` directly above `def handler` is already in the decl read — don't
  // bother). Among candidates, a cross-file hit wins over a same-file one.
  const scored = hits
    .map((h) => {
      const hf = h.file.replace(/^\.\//, '');
      const crossFile = hf !== declFile && !hf.endsWith('/' + declFile) && !declFile.endsWith('/' + hf);
      const farInFile = !crossFile && Math.abs(h.line - declLine) > 2;
      return { h, crossFile, farInFile };
    })
    .filter((s) => s.crossFile || s.farInFile)
    .sort((a, b) => Number(b.crossFile) - Number(a.crossFile));
  const best = scored[0];
  return best
    ? { file: best.h.file, line: best.h.line, provenance: 'resolved' }
    : { provenance: 'unresolved' };
}

// Cross-file sink resolution (#3). A handler that hands a tainted input to a
// project-local function hides the real sink one hop away — the dangerous call
// lives in the callee, not the handler slice. We resolve those callees so the
// candidate-finding pass (and the model) can see the wrapped sink. Bounded by
// design: one hop, project-local defs only, capped count + slice length.

/** Builtin / framework methods that are never a project-defined sink wrapper —
 *  skipped to avoid spending greps resolving defs that don't exist in-repo. */
const BUILTIN_CALLEES =
  /^(?:if|for|while|switch|catch|return|function|typeof|instanceof|new|await|throw|else|do|case|json|send|sendStatus|status|render|redirect|end|set|header|cookie|append|write|push|pop|shift|unshift|map|filter|forEach|reduce|find|some|every|join|split|concat|slice|splice|trim|replace|test|match|toString|toLowerCase|toUpperCase|parse|stringify|keys|values|entries|assign|freeze|from|isArray|now|log|error|warn|info|debug|next|then|catch|finally|resolve|reject|require|bind|call|apply)$/;

/** Project-local definition sites of `symbol` across CommonJS/ESM/Python forms. */
async function grepSymbolDef(symbol: string, tools: AgentTools): Promise<GrepHit[]> {
  const esc = escapeForRegex(symbol);
  const defPattern =
    `(?:module\\.exports\\.|exports\\.|function\\s+\\*?\\s*|const\\s+|let\\s+|var\\s+|async\\s+def\\s+|def\\s+)${esc}\\b` +
    `|\\b${esc}\\s*[:=]\\s*(?:async\\s*)?(?:function\\b|\\()` +
    `|\\b${esc}\\s*\\([^)]*\\)\\s*\\{`;
  try {
    return (await tools.grep(defPattern, { maxResults: 10 })) ?? [];
  } catch {
    return [];
  }
}

/** Tokens carrying request taint inside the handler snippet: every observed input
 *  name plus one-assignment-hop vars (`var x = <expr with input>`). token → origin
 *  input name. */
function taintedTokens(lines: string[], inputs: ObservedInput[]): Map<string, string> {
  const t = new Map<string, string>();
  for (const inp of inputs) t.set(inp.name, inp.name);
  const assign = /(?:^|;|\{)\s*(?:const|let|var|my|\$)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;
  // Loop / iteration variables inherit the iterable's taint:
  //   for (const [k, v] of Object.entries(<tainted>))  → k, v tainted
  //   <tainted>.forEach((x) => …) / .map((x) => …)
  // (saltcorn: `for (const [t, syncInfo] of Object.entries(syncInfos))`).
  const forOf = /\bfor\s*\(\s*(?:const|let|var)\s+(?:\[([^\]]+)\]|([A-Za-z_$][\w$]*))\s+(?:of|in)\s+([\s\S]+?)\)\s*\{?/;
  const iter = /\b([A-Za-z_$][\w$]*)\s*\.\s*(?:forEach|map|filter|find|some|every|reduce)\s*\(\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)/;
  const taintVarsFrom = (haystack: string, vars: string[]) => {
    for (const [tok, origin] of [...t]) {
      if (new RegExp(`\\b${escapeForRegex(tok)}\\b`).test(haystack)) {
        for (const v of vars) if (v && !t.has(v)) t.set(v, origin);
        return;
      }
    }
  };
  for (const ln of lines) {
    const m = assign.exec(ln);
    if (m) {
      const [, lhs, rhs] = m;
      if (lhs && rhs) {
        for (const [tok, origin] of [...t]) {
          if (tok === lhs) continue;
          if (new RegExp(`\\b${escapeForRegex(tok)}\\b`).test(rhs)) { t.set(lhs, origin); break; }
        }
      }
    }
    const fm = forOf.exec(ln);
    if (fm) {
      const vars = (fm[1] ?? fm[2] ?? '').split(',').map((s) => /([A-Za-z_$][\w$]*)/.exec(s.trim())?.[1] ?? '').filter(Boolean);
      taintVarsFrom(fm[3]!, vars);
    }
    const itm = iter.exec(ln);
    if (itm) taintVarsFrom(itm[1]!, [itm[2]!]);
  }
  return t;
}

const MAX_RESOLVED_CALLEES = 8;
const CALLEE_SLICE_LINES = 60;
const MAX_HOP_DEPTH = 3;
// A method name resolving to several project-local defs (polymorphic dispatch, e.g. a
// per-DB-engine `describe_table`) — follow at most this many so the sink scan can find
// the impl that interpolates the tainted value, without exploding on common names.
const MAX_CALLEE_DEFS = 4;
// The request object travels through middleware before any field is named, so it
// must be followed as a taint carrier across hops (auth/validation middleware is
// where real apps put the sink — your_spotify CVE-2024-28192 reaches the nosql
// findOne three hops deep via the auth middleware).
const REQUEST_CARRIERS = new Set(['req', 'request', 'ctx']);
const KEYWORD_ARGS = /^(?:async|await|function|return|new|typeof|this|null|undefined|true|false)$/;

/** Middleware identifier args on the route registration (between the path and the
 *  inline/final handler). These are the auth/validation chain real apps hang the
 *  sink off — distinct from the handler body. Handles express `.get('/p', mw, fn)`
 *  and method-first `.route('POST','/p', mw, fn)`. */
async function routeMiddlewareSymbols(route: RouteInventoryEntry, tools: AgentTools): Promise<string[]> {
  const line = Math.max(1, route.sourceLine || 1);
  let declText = '';
  try {
    declText = (await tools.read_file(route.sourceFile, Math.max(1, line - 1), line + 10))?.content ?? '';
  } catch {
    return [];
  }
  const np = (p: string) => (p.replace(/[?#].*$/, '').replace(/\/+/g, '/').replace(/\/$/, '') || '/').toLowerCase().replace(/[:{<][^/}>]+[}>]?/g, '');
  const want = np(route.path);
  const verb = route.method.toLowerCase();
  // Args between the path and the handler, balanced-paren aware so a factory-call
  // middleware (`validating(getSchema, 'params')`) doesn't truncate the list and
  // hide the auth middleware after it (`isLoggedOrGuest`).
  let mwArgs: string[] = [];
  const mf = new RegExp(`\\.route\\(\\s*["'\`]${route.method}["'\`]\\s*,\\s*(["'\`])([^"'\`]*)\\1\\s*,([\\s\\S]*)$`, 'i').exec(declText);
  if (mf && np(mf[2]!) === want) {
    // method-first: split the tail at top-level commas, drop the inline handler.
    mwArgs = topLevelArgList(mf[3]!);
  } else {
    const scanned = scanExpressRegistration(declText, verb, want, np);
    if (!scanned) return [];
    // arg[0] is the path; the last arg is the referenced handler when not inline.
    mwArgs = scanned.inline ? scanned.args.slice(1) : scanned.args.slice(1, -1);
  }
  const syms: string[] = [];
  for (const arg of mwArgs) {
    const s = middlewareSymbolOf(arg);
    if (s && !REQUEST_CARRIERS.has(s) && !KEYWORD_ARGS.test(s) && !BUILTIN_CALLEES.test(s)) syms.push(s);
  }
  return [...new Set(syms)];
}

/** Split a comma-separated arg tail at TOP-LEVEL commas (paren/bracket/brace
 *  aware), dropping a trailing inline-handler arg (one containing a top-level
 *  `=>`). */
function topLevelArgList(tail: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < tail.length; i++) {
    const ch = tail[i]!;
    if (depth === 0 && ch === '=' && tail[i + 1] === '>') break; // inline handler begins
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth--; }
    else if (depth === 0 && ch === ',') { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim() && !/=>/.test(cur)) out.push(cur.trim());
  return out;
}

/** Resolve project-local functions reachable from the route's handler AND its
 *  middleware chain by a tainted argument — a named request input, a one-hop var,
 *  or the request object itself — reading a bounded slice of each so a downstream
 *  sink scan sees sinks buried behind wrappers and middleware. Bounded BFS:
 *  depth ≤ MAX_HOP_DEPTH, total ≤ MAX_RESOLVED_CALLEES, each symbol once. */
async function resolveCallees(
  pack: EvidencePack,
  route: RouteInventoryEntry,
  tools: AgentTools,
): Promise<CalleeSlice[]> {
  const hs = pack.handlerSnippet;
  if (!hs?.snippet) return [];
  const out: CalleeSlice[] = [];
  const seen = new Set<string>();
  // A frame can inherit taint on SEVERAL parameters (a call may pass more than one
  // tainted arg). Each carries its own inherited field + whether that field is confirmed.
  type Frame = { file: string; lineStart: number; body: string; depth: number; params?: Array<{ param: string; origin?: string; fieldKnown: boolean }> };
  const queue: Frame[] = [{ file: hs.file, lineStart: hs.lineStart, body: hs.snippet, depth: 0 }];

  // Seed the middleware chain as depth-1 roots.
  for (const mwSym of await routeMiddlewareSymbols(route, tools)) {
    if (seen.has(mwSym)) continue;
    seen.add(mwSym);
    const def = (await grepSymbolDef(mwSym, tools))[0];
    if (!def) continue;
    let read;
    try { read = await tools.read_file(def.file, def.line, def.line + CALLEE_SLICE_LINES - 1); } catch { continue; }
    if (!read?.content) continue;
    const { body } = trimHandlerBody(read.content);
    out.push({ file: read.path, lineStart: read.lineStart, lineEnd: read.lineStart + body.split('\n').length - 1, snippet: body, via: `${mwSym}(req) [middleware]`, taintedInput: '' });
    queue.push({ file: read.path, lineStart: read.lineStart, body, depth: 1 });
    if (out.length >= MAX_RESOLVED_CALLEES) return out;
  }

  const callRe = /(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/g;
  while (queue.length > 0 && out.length < MAX_RESOLVED_CALLEES) {
    const fr = queue.shift()!;
    if (fr.depth >= MAX_HOP_DEPTH) continue;
    const bodyLines = fr.body.split('\n');
    // The root frame (the handler) seeds from the pack's full observedInputs — which
    // includes framework-derived fields the raw INPUTS table misses (FastAPI Pydantic
    // body fields, Python/Laravel signature params). Deeper callee frames re-extract.
    // (Path params reaching a PARAMETERIZED query no longer false-positive — the sql
    // candidate now requires the value to be built INTO the query string, not bound.)
    const localInputs = (fr.depth === 0 ? pack.observedInputs : extractInputs(fr.body, fr.file, fr.lineStart, 20))
      .filter((i) => i.name && i.name !== '(unnamed)');
    const tmap = taintedTokens(bodyLines, localInputs);
    // Tokens whose taint is a CONFIRMED request field (named req.x source + one-hop
    // vars) — captured BEFORE seeding the inbound param, which is NOT a real field.
    const realFields = new Set(tmap.keys());
    // Inbound taint via PARAMETERS: when this body was reached by `f(taintedArg, …)`,
    // each receiving parameter carries the taint — so calls passing those params are
    // followed (req.body → findOne(user) → getUsers(user) → SQL sink on user.username).
    const inboundMeta = new Map<string, { origin?: string; fieldKnown: boolean }>();
    for (const p of fr.params ?? []) {
      tmap.set(p.param, p.origin ?? p.param);
      inboundMeta.set(p.param, p.origin !== undefined ? { origin: p.origin, fieldKnown: p.fieldKnown } : { fieldKnown: p.fieldKnown });
    }
    // Scan the WHOLE body (not per-line) so a multi-line call —
    // `describe_table(\n  db_name, tb_name,\n  schema_name=schema_name\n)` (Archery) —
    // is matched: callRe's `[^)]*` arg group spans newlines. Per-line scanning missed
    // any call whose open-paren and close-paren sat on different lines.
    for (const ln of [fr.body]) {
      callRe.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = callRe.exec(ln)) !== null) {
        const method = m[2]!;
        const argStr = m[3] ?? '';
        if (BUILTIN_CALLEES.test(method) || seen.has(method) || tmap.has(method)) continue;
        // A route REGISTRATION (`app.post('/x', mw, fn)`) is framework plumbing, not a
        // data sink — its first arg is a `/path` string literal and its function arg
        // carries `req`, which would otherwise make the resolver follow it (and chain
        // into neighbouring route files → spurious candidates). Skip registrations.
        if (/^\s*["'`]\s*\//.test(argStr)) continue;
        // Find EVERY tainted argument (a call can pass more than one), with its index.
        const argList = topLevelArgList(argStr);
        const taintedArgs: Array<{ tok: string; origin?: string; argIdx: number }> = [];
        for (let ai = 0; ai < argList.length; ai++) {
          const a = argList[ai]!;
          let hit: { tok: string; origin?: string } | undefined;
          for (const [tok, o] of tmap) {
            if (tok === method) continue;
            if (new RegExp(`\\b${escapeForRegex(tok)}\\b`).test(a)) { hit = { tok, origin: o }; break; }
          }
          if (!hit) {
            // Carrier match fires for the WHOLE request object (`f(req)`) or a whole
            // input bag (`f(req.body)` / `.query` / `.params`). `req.user` / `req.session`
            // are auth context, not attacker input — a sink on `user.id` is not injection,
            // so those are excluded. Named fields (`req.body.x`) are already in `tmap`.
            const bare = a.trim();
            for (const rc of REQUEST_CARRIERS) {
              if (bare === rc || new RegExp(`^${escapeForRegex(rc)}\\.(?:body|query|params)\\b`).test(bare)) { hit = { tok: rc }; break; }
            }
          }
          if (hit) taintedArgs.push({ ...hit, argIdx: ai });
        }
        if (taintedArgs.length === 0) continue;
        seen.add(method);
        // The taint is a CONFIRMED request field only when it came from a real-field
        // token; via the request object or an inbound param it stays field-unknown (the
        // real field is recovered later from a `param.<prop>` access at the sink).
        const fieldOf = (ta: { tok: string; origin?: string }): { field?: string; fieldKnown: boolean } => {
          const field = realFields.has(ta.tok) ? ta.origin : inboundMeta.get(ta.tok)?.origin;
          const fieldKnown = realFields.has(ta.tok) ? true : (inboundMeta.get(ta.tok)?.fieldKnown ?? false);
          return field !== undefined ? { field, fieldKnown } : { fieldKnown };
        };
        // A method name can resolve to SEVERAL project-local defs. Follow only the ones
        // that are true POLYMORPHIC SIBLINGS — same parameter signature as the first def
        // (per-DB-engine `describe_table(self, db_name, tb_name, **kwargs)` in Archery).
        // This excludes unrelated defs that merely share a name (different signatures),
        // which is what false-positived firefly when following defs blindly. The sink
        // scan then finds whichever impl interpolates the tainted value; dedup by
        // sink:param collapses duplicates.
        const allDefs = await grepSymbolDef(method, tools);
        let sigKey: string | undefined;
        let followed = 0;
        for (const def of allDefs) {
          if (followed >= MAX_CALLEE_DEFS) break;
          let read;
          try { read = await tools.read_file(def.file, def.line, def.line + CALLEE_SLICE_LINES - 1); } catch { continue; }
          if (!read?.content) continue;
          const thisSig = defParamKey(read.content);
          if (sigKey === undefined) sigKey = thisSig;     // first def fixes the signature
          else if (thisSig !== sigKey) continue;          // not a polymorphic sibling — skip
          followed++;
          const { body } = trimHandlerBody(read.content);
          // Map each tainted arg to the callee PARAMETER it lands on; propagate the taint
          // onto that param so the chain continues into the next module's sink. Dedup by
          // param (same param hit by two args is one inheritance).
          const params: Array<{ param: string; origin?: string; fieldKnown: boolean }> = [];
          const seenParam = new Set<string>();
          for (const ta of taintedArgs) {
            const cp = calleeParamAt(body, ta.argIdx);
            if (!cp || seenParam.has(cp)) continue;
            seenParam.add(cp);
            const f = fieldOf(ta);
            params.push(f.field !== undefined ? { param: cp, origin: f.field, fieldKnown: f.fieldKnown } : { param: cp, fieldKnown: f.fieldKnown });
          }
          const primary = fieldOf(taintedArgs[0]!);
          out.push({
            file: read.path, lineStart: read.lineStart, lineEnd: read.lineStart + body.split('\n').length - 1,
            snippet: body, via: `${m[1] ? m[1] + '.' : ''}${method}(${argStr.trim()})`,
            taintedInput: primary.field ?? params[0]?.param ?? '',
            fieldKnown: primary.fieldKnown,
            ...(params[0] ? { taintedParam: params[0].param } : {}),
            ...(params.length ? { taintedParams: params.map((p) => ({ param: p.param, fieldKnown: p.fieldKnown, ...(p.origin !== undefined ? { field: p.origin } : {}) })) } : {}),
          });
          queue.push({ file: read.path, lineStart: read.lineStart, body, depth: fr.depth + 1, ...(params.length ? { params } : {}) });
          if (out.length >= MAX_RESOLVED_CALLEES) return out;
        }
      }
    }
  }
  return out;
}

/** The name of the callee's parameter at position `argIndex`, from its signature
 *  (first `(...)` in the slice). Lets the resolver propagate taint onto the param
 *  a tainted arg was passed into. */
function calleeParamAt(body: string, argIndex: number): string | undefined {
  const sig = /\(([^)]*)\)/.exec(body);
  if (!sig) return undefined;
  const params = topLevelArgList(sig[1]!);
  const nameOf = (p: string | undefined) => (p ? /^[\s{(]*([A-Za-z_$][\w$]*)/.exec(p.trim())?.[1] : undefined);
  // A Python METHOD def carries an implicit `self`/`cls` first parameter that the call
  // args never supply (`engine.describe_table(db, tb)` → def `(self, db, tb)`). Skip it
  // so arg N maps to the right param — else every field is mislabeled off-by-one.
  const first = nameOf(params[0]);
  const offset = first === 'self' || first === 'cls' ? 1 : 0;
  return nameOf(params[argIndex + offset]);
}

/** A normalized key for a def's parameter signature — the comma-joined param NAMES from
 *  its first `(...)`. Two defs with the same key are polymorphic siblings (the same
 *  interface implemented per backend); a same-name def with a different key is unrelated
 *  and must not be followed as if it were the dispatch target. */
function defParamKey(content: string): string {
  const sig = /\(([^)]*)\)/.exec(content);
  if (!sig) return '';
  return topLevelArgList(sig[1]!)
    .map((p) => /([A-Za-z_$][\w$]*)/.exec(p.trim())?.[1] ?? '')
    .filter(Boolean)
    .join(',');
}

/** Detect the app-global request body parser (json vs urlencoded), which is set
 *  once at app setup, not in the handler — so a handler that reads `req.body.x`
 *  reveals nothing about the on-the-wire content-type. Returns 'form' when only a
 *  urlencoded parser is configured, 'json' when only a json parser, null when both
 *  or neither (ambiguous → don't force a media type). */
async function detectAppBodyParser(tools: AgentTools): Promise<'form' | 'json' | null> {
  try {
    const url = await tools.grep('bodyParser\\.urlencoded|express\\.urlencoded|\\$app->register.*FormBody|request\\.form\\b', { maxResults: 3 });
    const json = await tools.grep('express\\.json\\s*\\(|bodyParser\\.json\\s*\\(|app\\.use\\(json\\(', { maxResults: 3 });
    const hasUrl = !!url && url.length > 0;
    const hasJson = !!json && json.length > 0;
    if (hasUrl && !hasJson) return 'form';
    if (hasJson && !hasUrl) return 'json';
    return null;
  } catch {
    return null;
  }
}

// Per-route pack

async function buildPackForRoute(
  route: RouteInventoryEntry,
  tools: AgentTools,
  opts: Required<EvidencePackOptions>,
  appParser?: 'form' | 'json' | null,
): Promise<EvidencePack> {
  const endpointId = endpointIdOf(route);
  const empty: EvidencePack = { endpointId, observedInputs: [], observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null, coverage: deriveCoverage(route, 'unresolved'), bytes: 0 };

  // #2: prefer the resolved handler-body location over the route declaration.
  const resolved = await resolveHandlerLocation(route, tools);
  const loc = resolved.provenance === 'resolved' ? resolved : undefined;
  const readFile = loc?.file ?? route.sourceFile;
  const startLine = Math.max(1, (loc?.line ?? route.sourceLine) || 1);
  const endLine = startLine + opts.maxHandlerLines - 1;

  let read;
  try {
    read = await tools.read_file(readFile, startLine, endLine);
  } catch {
    // resolved read failed — fall back to the declaration read.
    if (loc) {
      try { read = await tools.read_file(route.sourceFile, Math.max(1, route.sourceLine || 1), Math.max(1, route.sourceLine || 1) + opts.maxHandlerLines - 1); } catch { return empty; }
    } else {
      return empty;
    }
  }
  if (!read.content) return empty;

  // Inline Express handlers preceded by middleware (and/or wrapped in a HOF like
  // error_catcher) read from the `router.verb(` line; re-anchor to the real handler arg
  // so the body-trim balances the right closure. Track the dropped-line count to keep the
  // cited lineStart accurate (Rule D-3).
  let content = read.content;
  let lineOffset = 0;
  if (resolved.provenance === 'inline') {
    const reanchored = reanchorWrappedExpressHandler(content);
    if (reanchored !== content) {
      lineOffset = content.slice(0, content.length - reanchored.length).split('\n').length - 1;
      content = reanchored;
    }
  }
  const bodyStartLine = read.lineStart + lineOffset;

  const { body, truncated: trimTrunc } = trimHandlerBody(content);
  let snippet = body;
  let snippetTruncated = trimTrunc || read.truncated === true;
  if (Buffer.byteLength(snippet, 'utf8') > opts.maxHandlerBytes) {
    const lns = snippet.split('\n');
    let acc = '';
    for (let i = 0; i < lns.length; i++) {
      const next = i === 0 ? lns[i]! : acc + '\n' + lns[i]!;
      if (Buffer.byteLength(next, 'utf8') > opts.maxHandlerBytes) break;
      acc = next;
    }
    snippet = acc;
    snippetTruncated = true;
  }
  const snippetEndLine = bodyStartLine + snippet.split('\n').length - 1;

  const pack: EvidencePack = {
    endpointId,
    handlerSnippet: {
      file: read.path,
      lineStart: bodyStartLine,
      lineEnd: snippetEndLine,
      snippet,
      truncated: snippetTruncated,
    },
    observedInputs: extractInputs(snippet, read.path, bodyStartLine, opts.maxInputsPerRoute),
    observedValidators: extractValidators(snippet, read.path, bodyStartLine, opts.maxValidatorsPerRoute),
    observedOutputs: extractOutputs(snippet, read.path, bodyStartLine, opts.maxOutputsPerRoute),
    objectIdParams: [],
    bodyParsed: null,
    bytes: 0,
  };
  pack.objectIdParams = deriveObjectIdSurfaces(pack.observedInputs, snippet);
  if (read.path.endsWith('.php')) {
    const lar = deriveLaravelObjectIdSurfaces(route, read.path, read.lineStart, snippet);
    if (lar.inputs.length > 0) {
      pack.observedInputs = [...pack.observedInputs, ...lar.inputs];
      pack.objectIdParams = [...pack.objectIdParams, ...lar.surfaces];
    }
  } else if (read.path.endsWith('.py')) {
    const py = derivePythonObjectIdSurfaces(route, read.path, read.lineStart, snippet);
    if (py.inputs.length > 0) {
      pack.observedInputs = [...pack.observedInputs, ...py.inputs];
      pack.objectIdParams = [...pack.objectIdParams, ...py.surfaces];
    }
    const pp = derivePythonPathInputs(route, read.path, read.lineStart, snippet);
    if (pp.length > 0) {
      const have = new Set(pack.observedInputs.map((i) => `${i.source}::${i.name}`));
      pack.observedInputs = [...pack.observedInputs, ...pp.filter((i) => !have.has(`${i.source}::${i.name}`))];
    }
    const fa = deriveFastApiBodyInputs(read.path, read.lineStart, snippet);
    if (fa.length > 0) {
      const have = new Set(pack.observedInputs.map((i) => `${i.source}::${i.name}`));
      pack.observedInputs = [...pack.observedInputs, ...fa.filter((i) => !have.has(`${i.source}::${i.name}`))];
    }
    const dj = await resolveDjangoFormInputs(snippet, tools);
    if (dj.length > 0) {
      const have = new Set(pack.observedInputs.map((i) => `${i.source}::${i.name}`));
      pack.observedInputs = [...pack.observedInputs, ...dj.filter((i) => !have.has(`${i.source}::${i.name}`))];
    }
  }
  pack.bodyParsed = deriveBodyParsed(route.method, snippet, read.path, read.lineStart, appParser);
  const callees = await resolveCallees(pack, route, tools);
  if (callees.length > 0) pack.resolvedCallees = callees;
  pack.coverage = deriveCoverage(route, resolved.provenance);
  pack.bytes = Buffer.byteLength(JSON.stringify(pack), 'utf8');
  return pack;
}

// Fail-loud coverage signal. A route whose handler body we could NOT resolve is
// UNANALYZED — reporting it "clean" is a silent false-negative (the worst outcome
// for a security tool). Mark it incomplete so the route is sent to review instead.
// Scoped to plausible attack surfaces (writes or id-bearing routes) to avoid
// flagging trivial param-less GETs we legitimately have nothing to say about.
function deriveCoverage(
  route: RouteInventoryEntry,
  provenance: HandlerLocation['provenance'],
): NonNullable<EvidencePack['coverage']> {
  const isWrite = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method.toUpperCase());
  const hasPathParam = /[:{]/.test(route.path);
  const riskSurface = isWrite || hasPathParam;
  if (provenance === 'unresolved' && riskSurface) {
    return {
      handlerResolution: 'unresolved',
      complete: false,
      reason:
        'handler body could not be resolved (unmodeled framework or unlocatable controller/def) — route is UNANALYZED; mark reviewRequired rather than reporting it clean',
    };
  }
  return { handlerResolution: provenance, complete: true };
}

// Public entry

/**
 * Build deterministic evidence packs for every route. Bounded I/O concurrency.
 * Routes processed after `maxTotalBytes` is exhausted receive an empty pack.
 */
export async function buildEvidencePacks(args: {
  inventory: RouteInventoryEntry[];
  tools: AgentTools;
  options?: EvidencePackOptions;
}): Promise<Map<string, EvidencePack>> {
  const opts: Required<EvidencePackOptions> = {
    maxHandlerLines: args.options?.maxHandlerLines ?? DEFAULTS.maxHandlerLines,
    maxHandlerBytes: args.options?.maxHandlerBytes ?? DEFAULTS.maxHandlerBytes,
    maxInputsPerRoute: args.options?.maxInputsPerRoute ?? DEFAULTS.maxInputsPerRoute,
    maxValidatorsPerRoute: args.options?.maxValidatorsPerRoute ?? DEFAULTS.maxValidatorsPerRoute,
    maxOutputsPerRoute: args.options?.maxOutputsPerRoute ?? DEFAULTS.maxOutputsPerRoute,
    maxTotalBytes: args.options?.maxTotalBytes ?? DEFAULTS.maxTotalBytes,
    concurrency: args.options?.concurrency ?? DEFAULTS.concurrency,
  };

  const result = new Map<string, EvidencePack>();
  for (const route of args.inventory) {
    const id = endpointIdOf(route);
    result.set(id, { endpointId: id, observedInputs: [], observedValidators: [], observedOutputs: [], objectIdParams: [], bodyParsed: null, bytes: 0 });
  }

  // App-global body parser (json vs urlencoded is set app-wide, not in the handler;
  // detecting it here keeps the content-type gate from forcing the wrong media type —
  // the dvna urlencoded-app over-block). Computed once for the whole repo.
  const appParser = await detectAppBodyParser(args.tools);

  let bytesUsed = 0;
  let exhausted = false;
  let cursor = 0;

  const workers = Array.from({ length: opts.concurrency }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= args.inventory.length) return;
      if (exhausted) continue;
      const route = args.inventory[i]!;
      const pack = await buildPackForRoute(route, args.tools, opts, appParser);
      if (pack.bytes === 0) continue;
      if (bytesUsed + pack.bytes > opts.maxTotalBytes) { exhausted = true; continue; }
      bytesUsed += pack.bytes;
      result.set(pack.endpointId, pack);
    }
  });
  await Promise.all(workers);

  return result;
}

// Renderer — deterministic fenced block. Empty sections render `(none observed)`
// because explicit emptiness is data the model can use.

export function renderEvidencePackBlock(pack: EvidencePack): string {
  const out: string[] = [];
  out.push(`<<EVIDENCE_PACK route="${pack.endpointId}">>`);

  if (pack.handlerSnippet) {
    const { file, lineStart, lineEnd, truncated, snippet } = pack.handlerSnippet;
    const tm = truncated ? ' — TRUNCATED' : '';
    out.push(`HANDLER (${file}:${lineStart}-${lineEnd}${tm}):`);
    out.push('<<HANDLER>>');
    out.push(snippet);
    out.push('<</HANDLER>>');
  } else {
    out.push('HANDLER: (handler body not extracted)');
  }
  out.push('');

  out.push(`OBSERVED INPUTS (${pack.observedInputs.length}):`);
  if (pack.observedInputs.length === 0) out.push('  (none observed)');
  else for (const inp of pack.observedInputs) {
    out.push(`  - ${inp.source}.${inp.name}  // ${inp.file}:${inp.line}  ${inp.excerpt}`);
  }
  out.push('');

  out.push(`OBSERVED VALIDATORS (${pack.observedValidators.length}):`);
  if (pack.observedValidators.length === 0) out.push('  (none observed)');
  else for (const v of pack.observedValidators) {
    out.push(`  - [${v.kind}] ${v.name}  // ${v.file}:${v.line}  ${v.excerpt}`);
  }
  out.push('');

  out.push(`OBSERVED OUTPUTS (${pack.observedOutputs.length}):`);
  if (pack.observedOutputs.length === 0) out.push('  (none observed)');
  else for (const o of pack.observedOutputs) {
    out.push(`  - [${o.kind}]  // ${o.file}:${o.line}  ${o.excerpt}`);
  }
  out.push('');

  const objectIdParams = pack.objectIdParams ?? [];
  out.push(`OBJECT-ID SURFACES (${objectIdParams.length}):`);
  if (objectIdParams.length === 0) out.push('  (none observed)');
  else for (const s of objectIdParams) {
    const tells: string[] = [];
    tells.push(s.usedInFetchOrMutate ? 'usedInFetchOrMutate' : 'not-fetch-bound');
    tells.push(s.comparedToPrincipal ? 'comparedToPrincipal' : 'NOT-compared-to-principal');
    out.push(
      `  - ${s.param.source}.${s.param.name}  [${tells.join(', ')}]  // ${s.param.file}:${s.param.line}  ${s.param.excerpt}`,
    );
    if (s.usedInFetchOrMutate && !s.comparedToPrincipal) {
      const opt = s.ownerFieldCandidate
        ? ` or on the request-visible owner field \`${s.ownerFieldCandidate.source}.${s.ownerFieldCandidate.name}\``
        : '';
      out.push(
        `    BOLA CANDIDATE: this id reaches a fetch/mutate and is never compared to the principal. Pin it to the principal via an authorization rule \`request.${s.param.source}.${s.param.name} == jwt.<claim>\`${opt}, or a resourceLookup (resource.<owner> == jwt.sub). If the resource is public/principal-scoped, cite why and omit.`,
      );
    }
    if (s.ownerFieldCandidate) {
      out.push(
        `    OWNERSHIP CANDIDATE: request-visible owner field \`${s.ownerFieldCandidate.source}.${s.ownerFieldCandidate.name}\` // ${s.ownerFieldCandidate.file}:${s.ownerFieldCandidate.line}`,
      );
    }
  }
  out.push('');

  if (pack.bodyParsed) {
    const b = pack.bodyParsed;
    out.push(`BODY PARSE: [${b.kind}]  // ${b.file}:${b.line}`);
    out.push(
      `  CONTENT-TYPE SURFACE: this body-bearing route parses a ${b.kind} body. Emit a request.contentType allowlist (e.g. ['application/json']) so a mismatched content-type is rejected. If unconstrained by design, cite why and omit.`,
    );
  } else {
    out.push('BODY PARSE: (none observed)');
  }
  out.push('');

  const callees = pack.resolvedCallees ?? [];
  out.push(`RESOLVED CALLEES — cross-file taint sinks (${callees.length}):`);
  if (callees.length === 0) out.push('  (none resolved)');
  else for (const c of callees) {
    out.push(`  VIA \`${c.via}\` ← tainted by request input \`${c.taintedInput}\`  // ${c.file}:${c.lineStart}-${c.lineEnd}`);
    out.push('  <<CALLEE>>');
    for (const ln of c.snippet.split('\n')) out.push('  ' + ln);
    out.push('  <</CALLEE>>');
    out.push(`    NOTE: a sink in this callee body is reachable from request input \`${c.taintedInput}\`. Cite the sink at its real ${c.file} line, not the handler call site.`);
  }

  if (pack.coverage && pack.coverage.complete === false) {
    out.push('');
    out.push('COVERAGE GAP — ANALYSIS INCOMPLETE:');
    out.push(`  ${pack.coverage.reason}`);
    out.push('  ACTION: set reviewRequired:true for this route. Do NOT emit a clean'
      + ' pass or an empty policy — we did not see the handler body, so absence of a'
      + ' finding here is NOT evidence the route is safe.');
  }

  out.push('<</EVIDENCE_PACK>>');
  return out.join('\n');
}
