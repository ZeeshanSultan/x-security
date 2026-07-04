// Candidate-finding taint pass (#1). The injection classes (sql/nosql/os/eval/
// deserialization/xss/ssrf) were the last fully model-judged detection surface —
// the core surfaced raw inputs but left the model to find AND classify the sink.
// That is the largest remaining stochastic recall surface.
//
// This pass — pure, LLM-free, over the #2-resolved handler body — emits CITED,
// classified CANDIDATE findings: a sink line + the request input tainted into it.
// The model's job shrinks from "find + classify" to "confirm this cited candidate /
// reject with a cited reason / add the tail." Every candidate carries a byte-real
// sink cite (D-3) and flows through the SAME verify-finding/gate layer — it is a
// detection-assist starting point, NOT an auto-shipped control (D-1).

import type { EvidencePack, ObservedInput } from './evidence-pack.js';

export type InjectionSink =
  | 'sql' | 'nosql' | 'os-command' | 'code-eval' | 'deserialization' | 'xss' | 'ssrf';

export interface CandidateFinding {
  kind: 'injectionGuard';
  sink: InjectionSink;
  param: string;
  field: string; // request.schema.<param>
  cite: { file: string; lineStart: number; lineEnd: number; quote: string };
  // 'wrapped' = the sink is in a project-local callee the handler invoked with a
  // tainted argument (cross-file leg). The cite points at the callee's sink line.
  taint: 'direct' | 'one-hop' | 'wrapped';
  confidence: 'high' | 'medium';
}

// Sink detection — one regex per class, matched against a single handler line.
// Conservative: each targets a concrete sink CALL or a raw-query construction, not
// a mere mention. False positives are cheap (the model rejects them); misses are
// the cost we are buying down.
const SINKS: Array<[InjectionSink, RegExp]> = [
  ['sql', /\b(?:execute|query|raw)\s*\(|\btext\s*\(|(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;\n]*(?:\+|%|\$\{|\bformat\b|f["'])/i],
  // A SQL-string VARIABLE built by an f-string / .format() — the Python raw-query
  // construction lands on the assignment line while the execute/query verb is a
  // separate later line referencing the var (Archery describe_table:
  // `sql = f"show create table \`{tb_name}\`"` then `self.query(sql=sql)`). The verb
  // line can't see the taint. Still gated by rawSqlBuild (token must be interpolated),
  // so a non-tainted `sql = …` is ignored. Var names are SQL-specific (no bare `q`).
  ['sql', /\b(?:sql|query|stmt|statement|cmd)\w*\s*=\s*(?:f["']|[^=]*\.format\s*\()/i],
  ['nosql', /\.(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate|findOneAndUpdate)\s*\(\s*\{/],
  // NOTE: no bare `` `…${…}` `` branch — a template literal alone is not a shell sink.
  // It matched EVERY interpolated string (log lines, warnings, SQL), a pure false-
  // positive source. Real command-with-template sinks (`exec(`…${x}`)`) are caught by
  // the exec/spawn verbs below.
  ['os-command', /\b(?:exec|execSync|execFile|spawn|system|popen|fork)\s*\(|\bsubprocess\.\w+\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(|child_process|shell_exec\s*\(/],
  ['code-eval', /\beval\s*\(|\bnew\s+Function\s*\(|\bmathjs\.eval\b|\bvm\.runIn\w+\(|\bassert\s*\(|\bcompile\s*\(/],
  ['deserialization', /\bunserialize\s*\(|node-serialize|\bpickle\.loads\s*\(|\byaml\.load\s*\(|\bMarshal\.load\b|\breadObject\s*\(|\bphpversion\b.*unserialize/],
  // The trailing branch catches a reflected-XSS sink where a tainted value is
  // INTERPOLATED into a string RETURNED as the response body (Flask defaults to
  // text/html): `return f"Tag with UUID {tag_uuid} not found", 404` (changedetection.io).
  // Anchored to a response verb + an interpolated f-string so SQL f-strings / log lines
  // don't match; the candidate pass also requires a request input on the line (FP guard).
  ['xss', /<%-|\{\{\{|\|\s*safe\b|render_template_string\s*\(|dangerouslySetInnerHTML|\.html\s*\(|\binnerHTML\s*=|\becho\s+\$|\b(?:return|make_response|HttpResponse|Response)\s*\(?\s*f["'][^"']*\{[A-Za-z_]/],
  ['ssrf', /\brequests\.(?:get|post|put|head|delete)\s*\(|\burlopen\s*\(|\baxios\s*\(|\baxios\.(?:get|post)\s*\(|\bfetch\s*\(|\bhttp\.(?:get|request)\s*\(|\brequest\s*\(\s*[A-Za-z_$]/i],
];

const WORD = (name: string) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);

// A tainted value is a SQLi risk only when it is CONCATENATED / INTERPOLATED into the
// query string. Passed as a separate BIND parameter (`execute(text("… :id"), {id: x})`,
// `execute("… %s", (x,))`) it is safe — the driver escapes it. Distinguishing the two
// kills the parameterized-ORM false positive (praisonai `session.execute` on a path id)
// without suppressing real concat/f-string/template SQLi.
function rawSqlBuild(line: string, token: string): boolean {
  const t = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (
    new RegExp(`f["'][^"']*\\b${t}\\b`).test(line) ||            // python f"… token …"
    new RegExp(`\\$\\{[^}]*\\b${t}\\b`).test(line) ||            // js/ts `… ${ … token }`
    new RegExp(`\\.format\\s*\\([^)]*\\b${t}\\b`).test(line) ||  // "…".format(… token …)
    new RegExp(`["'\`]\\s*(?:\\+|\\.|%)\\s*[^"'\`]*\\b${t}\\b`).test(line) || // "…" + / . / % token
    new RegExp(`\\b${t}\\b\\s*(?:\\+|\\.)\\s*["'\`]`).test(line) // token + / . "…"
  );
}

/** Lines `var = <expr-with-input>` in the snippet → the var carries the input's
 *  taint (one hop). Returns a map varName → tainted input. */
function oneHopVars(lines: string[], inputs: ObservedInput[]): Map<string, ObservedInput> {
  const out = new Map<string, ObservedInput>();
  const assign = /(?:^|;|\{)\s*(?:const|let|var|my|\$)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;
  for (const ln of lines) {
    const m = assign.exec(ln);
    if (!m) continue;
    const [, lhs, rhs] = m;
    if (!lhs || !rhs) continue;
    for (const inp of inputs) {
      if (inp.name === '(unnamed)') continue;
      if (WORD(inp.name).test(rhs)) { out.set(lhs, inp); break; }
    }
  }
  return out;
}

/**
 * Derive candidate injectionGuard findings from a resolved evidence pack. Each is a
 * sink line with the request input that reaches it (direct, or via one assignment
 * hop). Bounded by design — same-statement + one hop; deeper flows are left to the
 * model. Pure, no IO.
 */
export function deriveCandidateFindings(pack: EvidencePack): CandidateFinding[] {
  const hs = pack.handlerSnippet;
  if (!hs || !hs.snippet) return [];
  const inputs = (pack.observedInputs ?? []).filter((i) => i.name && i.name !== '(unnamed)');
  // NOTE: don't early-return when the handler has no inputs — the taint may live
  // entirely in the middleware chain / cross-file callees (your_spotify
  // CVE-2024-28192). The handler loop below is a no-op without inputs; the callee
  // loop still runs.
  const lines = hs.snippet.split('\n');
  const hop = oneHopVars(lines, inputs);
  // request input name → source. NoSQL operator injection requires the value to
  // arrive as an OBJECT (`?q[$ne]=`); a PATH segment is structurally always a
  // string and cannot carry an operator, so `nosql` on a path param is a false
  // positive by construction (your_spotify GET /:query). SQLi is unaffected — a
  // string CAN carry `' OR 1=1`.
  const srcOf = new Map(inputs.map((i) => [i.name, i.source]));
  const structurallyImpossible = (sink: InjectionSink, param: string): boolean =>
    sink === 'nosql' && srcOf.get(param) === 'path';
  // Best candidate per (sink, param): a direct-taint hit beats a one-hop hit, and we
  // keep the first (closest) sink line. Avoids emitting both the concat line and the
  // execute line for the same SQLi.
  const best = new Map<string, CandidateFinding>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    for (const [sink, re] of SINKS) {
      re.lastIndex = 0;
      if (!re.test(line)) continue;
      // Which input reaches this sink line? direct (input name on the line) wins
      // over one-hop (a var on the line that carries an input's taint).
      let param: string | undefined;
      let taint: CandidateFinding['taint'] | undefined;
      let lineTok: string | undefined; // the identifier as it appears on the sink line
      for (const inp of inputs) {
        if (WORD(inp.name).test(line)) { param = inp.name; taint = 'direct'; lineTok = inp.name; break; }
      }
      if (!param) {
        for (const [v, inp] of hop) {
          if (WORD(v).test(line)) { param = inp.name; taint = 'one-hop'; lineTok = v; break; }
        }
      }
      if (!param || !taint) continue; // a sink with no request input reaching it — skip
      if (structurallyImpossible(sink, param)) continue; // nosql on a path param can't happen
      if (sink === 'sql' && !rawSqlBuild(line, lineTok!)) continue; // parameterized/bind value → not SQLi
      const fileLine = hs.lineStart + i;
      const key = `${sink}:${param}`;
      const prior = best.get(key);
      // keep a direct hit over a one-hop, else the first (closest) line.
      if (prior && (prior.taint === 'direct' || taint !== 'direct')) break;
      best.set(key, {
        kind: 'injectionGuard',
        sink,
        param,
        field: `request.schema.${param}`,
        cite: { file: hs.file, lineStart: fileLine, lineEnd: fileLine, quote: line.trim() },
        taint,
        confidence: taint === 'direct' ? 'high' : 'medium',
      });
      break; // one sink class per line is enough
    }
  }

  // Cross-file leg (#3): scan resolved callee bodies for sinks. The callee was
  // resolved BECAUSE a tainted request input flowed into the call, so any sink in
  // its (bounded) body is reachable from that input — `taintedInput`. The callee's
  // own param name differs from the request field, so we don't re-match the input
  // token here; the taint link is the call edge. A direct/one-hop handler hit for
  // the same (sink, param) wins, so we only add a wrapped finding when none exists.
  const escTok = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const cs of pack.resolvedCallees ?? []) {
    if (!cs.taintedInput) continue; // carrier slice with no named field reaching it
    // A call can pass several tainted args. With ONE inbound param there is no
    // ambiguity, so any sink in the bounded body is attributed to it (recall). With
    // SEVERAL we must bind each sink to the param actually present on the sink TEXT —
    // otherwise the one inbound field gets pinned to every sink in the body (D-3 false
    // positive: the taint→sink link is unproven).
    const multi = (cs.taintedParams?.length ?? 0) >= 2;
    // The request field a sink TEXT references, or undefined if no tainted token is
    // provably present. `<param>.<prop>` names the field (`syncInfo.maxLoadedId` →
    // `maxLoadedId`); a bare param names it only with a CONFIRMED inbound field.
    const bindParam = (text: string): string | undefined => {
      if (multi) {
        for (const p of cs.taintedParams!) {
          const prop = new RegExp(`\\b${escTok(p.param)}\\.([A-Za-z_$][\\w$]*)`).exec(text);
          if (prop) return prop[1]!;
          if (new RegExp(`\\b${escTok(p.param)}\\b`).test(text) && p.fieldKnown && p.field) return p.field;
        }
        return undefined;
      }
      if (cs.fieldKnown === false && cs.taintedParam) {
        const prop = new RegExp(`\\b${escTok(cs.taintedParam)}\\.([A-Za-z_$][\\w$]*)`).exec(text);
        return prop ? prop[1]! : undefined;
      }
      return cs.taintedInput; // single confirmed inbound param — permissive
    };
    const emit = (sink: InjectionSink, param: string, lineIdx: number, quote: string) => {
      if (structurallyImpossible(sink, param)) return;
      const key = `${sink}:${param}`;
      if (best.has(key)) return; // handler-local / earlier hit already covers it
      const fileLine = cs.lineStart + lineIdx;
      best.set(key, {
        kind: 'injectionGuard', sink, param,
        field: `request.schema.${param}`,
        cite: { file: cs.file, lineStart: fileLine, lineEnd: fileLine, quote: quote.trim() },
        taint: 'wrapped', confidence: 'medium',
      });
    };
    const clines = cs.snippet.split('\n');
    for (let i = 0; i < clines.length; i++) {
      const line = clines[i]!;
      for (const [sink, re] of SINKS) {
        re.lastIndex = 0;
        if (!re.test(line)) continue;
        // For SQL, a value wrapped in a sanitizer (`db.sqlsanitize(col)`) is safe by
        // design — bind against the line with sanitizer calls stripped so a tainted
        // token that only appears inside one doesn't produce a false positive.
        const scanText = sink === 'sql' ? line.replace(SANITIZER_CALL, '') : line;
        const param = bindParam(scanText);
        if (!param) continue;
        // SQLi only when the tainted value is built into the query string, not bound as
        // a parameter. Check the param and every inbound token actually on this line.
        if (sink === 'sql') {
          const toks = [param, cs.taintedInput, ...(cs.taintedParams ?? []).map((p) => p.param)].filter(Boolean) as string[];
          if (!toks.some((tk) => rawSqlBuild(scanText, tk))) continue;
        }
        emit(sink, param, i, line);
        break;
      }
    }
    // Multi-line SQL template sink: a raw-query call whose tagged template spans many
    // lines interpolates the tainted value on a DIFFERENT line than the `query(` verb
    // (saltcorn `db.query(\`select … > ${syncInfo.maxLoadedId}\`)` — verb and sink 8
    // lines apart). The per-line scan can't connect them. Walk each query template,
    // bind each UNSANITIZED `${…}` interpolation, cite it at its own line.
    for (const t of scanSqlTemplates(cs.snippet)) {
      const param = bindParam(t.expr);
      if (param) emit('sql', param, t.lineIdx, t.quote);
    }
  }
  return [...best.values()];
}

// A raw-query call (`query`/`execute`/`raw`/`text`) whose argument is a backtick
// template literal — possibly multi-line. Yields each interpolation `${expr}` that is
// NOT wrapped in a SQL sanitizer, with the line index (within the snippet) it sits on.
// SQLi lives in the UNSANITIZED interpolations; the sanitized ones are safe by design
// (saltcorn wraps table/column names in `db.sqlsanitize(...)` but not `maxLoadedId`).
const SQL_SANITIZER = /\b(?:sqlsanitize|escape|escapeId|escapeLiteral|quote|parameterize|sanitize)\s*\(/;
// Same sanitizers, as a whole-call stripper (non-nested args) for per-line scrubbing.
const SANITIZER_CALL = /\b(?:db\.)?(?:sqlsanitize|escape|escapeId|escapeLiteral|quote|parameterize|sanitize)\s*\([^()]*\)/g;
function scanSqlTemplates(snippet: string): Array<{ expr: string; lineIdx: number; quote: string }> {
  const out: Array<{ expr: string; lineIdx: number; quote: string }> = [];
  const lines = snippet.split('\n');
  const lineOf = (charIdx: number) => snippet.slice(0, charIdx).split('\n').length - 1;
  const call = /\b(?:query|execute|raw|text)\s*\(\s*`/g;
  let m: RegExpExecArray | null;
  while ((m = call.exec(snippet)) !== null) {
    const start = m.index + m[0].length; // first char inside the template
    // Find the matching close backtick, tracking `${…}` interpolation depth so a
    // backtick nested inside an interpolation doesn't end the template early.
    let depth = 0, end = -1;
    for (let j = start; j < snippet.length; j++) {
      const ch = snippet[j]!;
      if (ch === '\\') { j++; continue; }
      if (ch === '$' && snippet[j + 1] === '{') { depth++; j++; continue; }
      else if (ch === '}' && depth > 0) { depth--; continue; }
      else if (ch === '`' && depth === 0) { end = j; break; }
    }
    if (end === -1) continue;
    // Extract depth-0 `${…}` interpolations from the template body.
    for (let k = start; k < end; k++) {
      if (snippet[k] === '$' && snippet[k + 1] === '{') {
        let d = 1, e = k + 2;
        for (; e < end && d > 0; e++) { if (snippet[e] === '{') d++; else if (snippet[e] === '}') d--; }
        const expr = snippet.slice(k + 2, e - 1);
        if (!SQL_SANITIZER.test(expr)) {
          const lineIdx = lineOf(k);
          out.push({ expr, lineIdx, quote: lines[lineIdx]?.trim() ?? expr });
        }
        k = e - 1;
      }
    }
    call.lastIndex = end + 1;
  }
  return out;
}

// --- Mass-assignment (OWASP API6) -------------------------------------------
// A route that persists the WHOLE request body — `Model.create(req.body)`,
// `new User(req.body)`, `Object.assign(x, req.body)`, `{ ...req.body }`, or
// req.body handed wholesale to a create/save/insert/update — lets a client set
// any field, including server-controlled ones. The defense is a denyFields
// denylist of reserved keys (no allowlist needed — see RequestPolicy.denyFields).
// This is the deterministic surface; the model confirms and picks the denyFields.

/** Structurally-reserved keys a client must NEVER set — only the universally
 *  framework-internal identity + prototype-pollution primitives. These are never a
 *  legitimate client-supplied body field in any app, so denying them can't break
 *  real traffic. Privilege/role fields (role, roles, isAdmin, permissions, ...) are
 *  DELIBERATELY EXCLUDED: they are app-specific built-ins in many frameworks (Parse
 *  `_Role.roles` is a first-class relation column — a universal denylist there
 *  blocks legitimate role-hierarchy writes; the parse-server precision audit caught
 *  this). The model may still add an app-specific privilege key when it observes one
 *  is a real escalation vector in THAT app; the blanket list stays structural-only. */
export const RESERVED_BODY_FIELDS = [
  'objectId', '_id', 'id', '__proto__', 'constructor', 'prototype',
];

export interface MassAssignmentCandidate {
  kind: 'massAssignment';
  cite: { file: string; lineStart: number; lineEnd: number; quote: string };
  via: string; // the wholesale-body persistence call as written
  taint: 'direct' | 'wrapped';
  /** Reserved keys to deny via request.denyFields — the model trims to the route. */
  suggestedDenyFields: string[];
  /** denyFields is defense-in-depth hardening, NOT a confirmed exploited flow:
   *  the wholesale-body sink is real but whether the framework already governs the
   *  reserved keys is undecidable statically. Marked 'low' so the model emits it as
   *  hardening, not a high-confidence finding (parse-server precision audit). */
  confidence: 'low';
}

// Wholesale-body sinks: persistence calls / object spreads that consume the
// ENTIRE request body without naming fields. Matched across newlines (bounded)
// because real handlers split the call over many lines (Parse Server's
// `rest.create(\n req.config,\n ...,\n req.body,\n ...)`). `req.body` followed by
// `.field` is a NAMED access, not wholesale — excluded with a negative lookahead.
const MASS_ASSIGN_PATTERNS: RegExp[] = [
  /\b(?:create|insert|insertOne|insertMany|bulkCreate|save|update|updateOne|updateMany|replaceOne|findOneAndUpdate|findByIdAndUpdate)\s*\([\s\S]{0,240}?\breq(?:uest)?\.body\b(?!\s*\.)/gi,
  /\bnew\s+[A-Z]\w*\s*\(\s*req(?:uest)?\.body\b(?!\s*\.)/g,
  /\bObject\.assign\s*\([^,]+,\s*req(?:uest)?\.body\b(?!\s*\.)/g,
  /\{\s*\.\.\.\s*req(?:uest)?\.body\b/g,
];

/** Derive mass-assignment candidates from the handler body and resolved callees.
 *  Pure. One candidate per cited wholesale-body site (deduped by file:line). */
export function deriveMassAssignmentCandidates(pack: EvidencePack): MassAssignmentCandidate[] {
  const out: MassAssignmentCandidate[] = [];
  const seen = new Set<string>();
  const scan = (file: string, base: number, snippet: string, taint: 'direct' | 'wrapped') => {
    for (const pat of MASS_ASSIGN_PATTERNS) {
      pat.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pat.exec(snippet)) !== null) {
        // Cite the line where `req.body` actually appears (end of the match), not
        // the call head several lines up.
        const bodyOff = m.index + Math.max(0, m[0].lastIndexOf('req'));
        const lineNo = base + (snippet.slice(0, bodyOff).match(/\n/g)?.length ?? 0);
        const key = `${file}:${lineNo}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const quote = (snippet.split('\n')[lineNo - base] ?? m[0]).trim();
        out.push({
          kind: 'massAssignment',
          cite: { file, lineStart: lineNo, lineEnd: lineNo, quote },
          via: m[0].replace(/\s+/g, ' ').trim().slice(0, 80),
          taint,
          suggestedDenyFields: [...RESERVED_BODY_FIELDS],
          confidence: 'low',
        });
      }
    }
  };
  const hs = pack.handlerSnippet;
  if (hs?.snippet) scan(hs.file, hs.lineStart, hs.snippet, 'direct');
  for (const cs of pack.resolvedCallees ?? []) scan(cs.file, cs.lineStart, cs.snippet, 'wrapped');
  return out;
}
