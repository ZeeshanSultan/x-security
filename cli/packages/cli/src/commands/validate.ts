// `lazy validate --target <t> --gateway <url-or-path> [--format <fmt>] <spec.yaml>`
//
// Drift detection. Per-target dispatch:
//   - kong:        HTTP admin URL or exported kong.yml file
//   - coraza:      deployed Coraza YAML file
//   - bunkerweb:   deployed bunkerweb.yml file
//   - openappsec:  deployed policy.yaml file
//   - firewall:    iptables-save / .rules file, or a directory with
//                  iptables.rules + ip6tables.rules

import { loadSpec, buildResolverChain } from '@x-security/core';
import { detectAdminDrift } from '../drift/kong-admin.js';
import { detectFileDrift } from '../drift/kong-file.js';
import { detectCorazaDrift } from '../drift/coraza.js';
import { detectBunkerWebDrift } from '../drift/bunkerweb.js';
import { detectOpenAppSecDrift } from '../drift/openappsec.js';
import { detectFirewallDrift } from '../drift/firewall.js';
import { detectEnvoyDrift } from '../drift/envoy.js';
import { renderDrift } from '../reporters/human.js';
import { toJson } from '../reporters/json.js';
import { driftToSarif } from '../reporters/sarif.js';
import { driftToCsv } from '../reporters/csv.js';
import type { DriftReport, ReportFormat } from '../reporters/types.js';

export interface ValidateOptions {
  target: string;
  gateway: string;
  format?: ReportFormat;
  strict?: boolean;
  vault?: boolean;
  awsSecrets?: boolean;
  vaultKvVersion?: 1 | 2;
  /** Abort outbound gateway requests after this many ms. Unset = no timeout. */
  timeoutMs?: number;
}

export interface ValidateResult {
  report: DriftReport;
  rendered: string;
  exitCode: number;
}

const SUPPORTED_TARGETS = new Set(['kong', 'coraza', 'bunkerweb', 'openappsec', 'firewall', 'envoy']);

export async function runValidate(specPath: string, opts: ValidateOptions): Promise<ValidateResult> {
  if (!SUPPORTED_TARGETS.has(opts.target)) {
    throw new Error(
      `Drift detection is not implemented for target="${opts.target}". ` +
        `Supported: ${[...SUPPORTED_TARGETS].sort().join(', ')}.`
    );
  }

  const chainOpts: Parameters<typeof buildResolverChain>[0] = {};
  if (opts.vault) chainOpts.enableVault = true;
  if (opts.awsSecrets) chainOpts.enableAws = true;
  if (opts.vaultKvVersion) chainOpts.vaultKvVersion = opts.vaultKvVersion;
  const resolver = buildResolverChain(chainOpts);
  const spec = await loadSpec(specPath, { resolver, strict: opts.strict ?? false });

  const isHttp = /^https?:\/\//i.test(opts.gateway);
  let report: DriftReport;
  switch (opts.target) {
    case 'kong':
      report = isHttp
        ? await detectAdminDrift(spec, { gatewayUrl: opts.gateway, ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}) })
        : await detectFileDrift(spec, { filePath: opts.gateway });
      break;
    case 'coraza':
      if (isHttp) throw new Error('coraza drift is file-mode only — pass a path to the deployed YAML.');
      report = await detectCorazaDrift(spec, { filePath: opts.gateway });
      break;
    case 'bunkerweb':
      if (isHttp) throw new Error('bunkerweb drift is file-mode only — pass a path to the deployed YAML.');
      report = await detectBunkerWebDrift(spec, { filePath: opts.gateway });
      break;
    case 'openappsec':
      if (isHttp) throw new Error('openappsec drift is file-mode only — pass a path to the deployed YAML.');
      report = await detectOpenAppSecDrift(spec, { filePath: opts.gateway });
      break;
    case 'firewall':
      if (isHttp) throw new Error('firewall drift is file-mode only — pass a path to the deployed rules file or directory.');
      report = await detectFirewallDrift(spec, { filePath: opts.gateway });
      break;
    case 'envoy':
      if (isHttp) throw new Error('envoy drift is file-mode only — pass a path to the deployed envoy.yaml or a directory containing envoy.yaml + writ.lua.');
      report = await detectEnvoyDrift(spec, { filePath: opts.gateway });
      break;
    default:
      // Unreachable thanks to the guard above, but keeps the switch exhaustive.
      throw new Error(`Unhandled target "${opts.target}"`);
  }

  let rendered: string;
  switch (opts.format) {
    case 'json': rendered = toJson(report); break;
    case 'sarif': rendered = driftToSarif(report, specPath); break;
    case 'csv': rendered = driftToCsv(report); break;
    case 'table':
    default: rendered = renderDrift(report); break;
  }

  const hasCriticalOrHigh = report.issues.some(
    (i) => i.severity === 'CRITICAL' || i.severity === 'HIGH'
  );
  return { report, rendered, exitCode: hasCriticalOrHigh ? 2 : 0 };
}
