// Public entry point for the deterministic route extractor.
//
// Wave 0 shipped the contract + shared helpers and a STUB `extractRoutes`. Wave 1
// added the per-framework parsers; Wave 2 (here) wires them into the orchestrator;
// Wave 3 hooks it into the passes/verify pipeline. Re-exporting everything from
// here lets parsers + callers import the contract from one stable module path.

export type {
  ExtractedRoute,
  ExtractResult,
  ExtractOptions,
  RouteSource,
  SchemaHint,
  Protocol,
} from './types.js';

export { normPath, routeKey, dedupeRoutes, underMount } from './dedupe.js';
export {
  listFiles,
  listFilesByExt,
  DEFAULT_SKIP_DIRS,
  OPTIONAL_SKIP_DIRS,
  ALL_DEFAULT_SKIP_DIRS,
} from './walk.js';
export type { WalkOptions } from './walk.js';
export { detectFrameworks } from './detect.js';

import type { ExtractedRoute, ExtractOptions, ExtractResult } from './types.js';
import { normPath, dedupeRoutes } from './dedupe.js';
import { detectFrameworks } from './detect.js';
import { parseOpenApiSpecs } from './spec-openapi.js';
import { parseFlask } from './flask.js';
import { parseFastapi } from './fastapi.js';
import { parseExpress } from './express.js';
import { parseNestjs } from './nestjs.js';
import { parseDjango } from './django.js';
import { parseLaravel } from './laravel.js';
import { parseRails } from './rails.js';
import { parseGraphene } from './graphene.js';
import { parseApolloSdl } from './spec-graphql.js';
import {
  parseProtocols,
  parseDynamicBlueprints,
  soapMountPaths,
} from './protocols.js';

/** True when `path` is at, or nested under, one of the SOAP `mounts`. Ports the
 * prototype's `_under_mount`: exact-match or a `<mount>/…` prefix. Mounts are
 * canonical (no trailing slash); `path` is compared after the same
 * canonicalization the dedupe layer applied. */
function underSoapMount(routePath: string, mounts: readonly string[]): boolean {
  for (const m of mounts) {
    if (routePath === m || routePath.startsWith(m + '/')) return true;
  }
  return false;
}

/**
 * Extract the API surface of a repo: detect frameworks, run every parser (each is
 * cheap and self-guards on its own framework's files), merge, suppress SOAP-mount
 * REST false-positives, then canonicalize + dedupe the union.
 *
 * Layering mirrors the Python prototype's `extract()`:
 *   1. Spec layer (OpenAPI/Swagger) — `source: 'spec'`, richest schema.
 *   2. Framework parsers (flask + dynamic blueprints, fastapi, express, laravel,
 *      graphene, apollo-sdl).
 *   3. Protocol parsers (SOAP + XML-RPC).
 *   4. `dedupeRoutes` on the union (spec wins collisions), then drop any REST
 *      route that lives under a declared SOAP mount — those are the SOAP router's
 *      internal helper endpoints, not real API surface. Dedupe-then-suppress
 *      matches the prototype byte-for-byte: suppression compares against the
 *      canonical (`normPath`-rewritten) path the dedupe pass produced.
 *
 * Per Rule D-1 the result never silently degrades: a parser that throws surfaces
 * as a `warnings` entry rather than an empty-but-clean route list, and the merged
 * set is canonicalized HERE (parsers emit raw paths) so cross-framework dedupe is
 * authoritative regardless of any per-parser normalization.
 */
export async function extractRoutes(
  repoDir: string,
  opts: ExtractOptions = {},
): Promise<ExtractResult> {
  const frameworksDetected = await detectFrameworks(repoDir);
  const warnings: string[] = [];

  // Each parser is named so a failure can be attributed in `warnings` (Rule D-1:
  // a thrown parser must be visible, not swallowed into an empty result).
  type NamedParser = readonly [name: string, run: () => Promise<ExtractedRoute[]>];
  const specParsers: NamedParser[] = opts.skipSpecLayer
    ? []
    : [['spec-openapi', () => parseOpenApiSpecs(repoDir)]];
  const parsers: NamedParser[] = [
    ...specParsers,
    ['flask', () => parseFlask(repoDir)],
    ['flask-blueprints', () => parseDynamicBlueprints(repoDir)],
    ['fastapi', () => parseFastapi(repoDir)],
    ['express', () => parseExpress(repoDir)],
    ['nestjs', () => parseNestjs(repoDir)],
    ['django', () => parseDjango(repoDir)],
    ['laravel', () => parseLaravel(repoDir)],
    ['rails', () => parseRails(repoDir)],
    ['graphene', () => parseGraphene(repoDir)],
    ['apollo-sdl', () => parseApolloSdl(repoDir)],
    ['protocols', () => parseProtocols(repoDir)],
  ];

  const settled = await Promise.all(
    parsers.map(async ([name, run]) => {
      try {
        return { name, routes: await run() };
      } catch (err) {
        warnings.push(
          `parser '${name}' failed: ${err instanceof Error ? err.message : String(err)}`,
        );
        return { name, routes: [] as ExtractedRoute[] };
      }
    }),
  );

  const merged = settled.flatMap((s) => s.routes);

  // Canonicalize + dedupe the whole union here (express returns RAW paths, flask
  // emits raw `<int:id>`; normPath unifies all param syntaxes). dedupeRoutes
  // rewrites each survivor's `path` to its canonical form, so downstream
  // suppression compares canonical-vs-canonical.
  let routes = dedupeRoutes(merged);

  // SOAP service mounts speak SOAP, not REST: drop any REST route emitted from a
  // declared SOAP-mount path (the soap router's internal helper endpoints / XPath
  // false-positives). Protocol routes themselves are never suppressed.
  const soapMounts = (await soapMountPaths(repoDir)).map((m) =>
    normPath(m).replace(/\/+$/, ''),
  );
  if (soapMounts.length > 0) {
    routes = routes.filter(
      (r) => r.protocol !== undefined || !underSoapMount(r.path, soapMounts),
    );
  }

  return { routes, frameworksDetected, warnings };
}
