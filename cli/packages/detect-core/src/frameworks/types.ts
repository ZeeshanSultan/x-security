// Shared contract for the deterministic route extractor (ported from the
// Python prototype at /tmp/route-extractor-proto/extract.py).
//
// Wave 0 defines ONLY the contract + shared helpers. Per-framework parsers
// (Wave 1) and pipeline wiring (Wave 3) consume these types; they live behind
// this boundary so the extractor's output shape is fixed before any parser is
// written and golden tests can compare against the prototype's JSON.

/** Where a route was discovered. The prototype's `source` field is richer
 * (e.g. `"framework:flask"`, `"protocol:soap"`); we split that into the coarse
 * provenance bucket here plus a separate `framework` / `protocol` field so the
 * provenance is queryable without string-prefix parsing. */
export type RouteSource = 'spec' | 'framework' | 'protocol';

/** Honest schema-shape signal. `declared` = the request body/args have a typed
 * contract (OpenAPI body, Pydantic model, GraphQL args). `inferred-untyped` =
 * a handler with no declared body shape. `open-unbounded` = the handler spreads
 * untrusted input into a model/constructor (mass-assignment risk). Omitted when
 * the parser can't make this determination — per Rule D-1, we do NOT default it. */
export type SchemaHint = 'declared' | 'inferred-untyped' | 'open-unbounded';

/** Non-HTTP transport for routes that aren't REST. Drives the `path#operation`
 * keying the prototype uses for SOAP/XML-RPC surfaces. */
export type Protocol = 'soap' | 'xml-rpc';

/** A single extracted API-surface entry. Mirrors the prototype's per-route dict
 * but with the source provenance normalized into discrete fields.
 *
 * Per Rule D-3, a finding without a citation is dropped upstream; `sourceFile`
 * / `sourceLine` are optional here only because spec-sourced routes cite the
 * spec file, not a code line, and protocol routes may cite a WSDL. A parser that
 * cannot cite anything must drop the route rather than emit it citation-less. */
export interface ExtractedRoute {
  /** Uppercase HTTP verb, or `ANY`/`MATCH` for catch-all framework routes,
   * or `POST` for GraphQL/SOAP/XML-RPC operations (matches the prototype). */
  method: string;
  /** Canonical path. REST paths are `norm_path`-canonicalized (`{x}`/`:x` →
   * `:x`, collapsed slashes, no trailing slash). GraphQL ops are
   * `/graphql#query.fieldName`; protocol ops are `<endpoint>#operation`. */
  path: string;
  source: RouteSource;
  /** Concrete framework that produced a `framework`-sourced route, e.g.
   * `flask`, `fastapi`, `express`, `laravel`, `graphene`, `apollo`. */
  framework?: string;
  /** Repo-relative source file the route was read from. */
  sourceFile?: string;
  /** 1-based line of the route declaration within `sourceFile`. */
  sourceLine?: number;
  /** Handler/operation name (Python def, FastAPI function, GraphQL field,
   * SOAP/XML-RPC operation). */
  handler?: string;
  schemaHint?: SchemaHint;
  /** Set only for `source: 'protocol'` routes. */
  protocol?: Protocol;
  /** Free-text parser note (e.g. the prototype's richer schema string like
   * `declared-pydantic:LoginModel`) preserved for the report layer. */
  notes?: string;
}

/** The extractor's top-level result. `warnings` surfaces parser gaps loudly
 * rather than silently degrading (Rule D-1 / D-2). */
export interface ExtractResult {
  routes: ExtractedRoute[];
  /** Frameworks detected in the repo, sorted, e.g. `['express', 'flask']`. */
  frameworksDetected: string[];
  warnings: string[];
}

/** Knobs for `extractRoutes`. Intentionally minimal in Wave 0; Wave 2 wires the
 * parser-selection / budget options through here. */
export interface ExtractOptions {
  /** Restrict to these frameworks instead of running every detected parser.
   * Empty / undefined = run all parsers for detected frameworks. */
  only?: string[];
  /** Skip the spec-first (OpenAPI/GraphQL SDL) layer. */
  skipSpecLayer?: boolean;
}
