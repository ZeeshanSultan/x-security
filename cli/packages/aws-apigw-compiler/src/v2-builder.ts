import type { EndpointIR } from '@writ/core';
import type {
  ApiGatewayPolicyFragment,
  AwsScope,
  CompileError,
  CompileWarning,
  DeployMode,
  IPSetSpec,
  RegexPatternSetSpec,
  UnsupportedDirective,
  UsagePlanSpec,
  WafV2Rule
} from './types.js';

/** Shape compile.ts passes in. Avoids cross-import with the V3 module. */
export interface V2Builder {
  endpoint: EndpointIR;
  ehash: string;
  eid: string;
  ename: string;
  mode: DeployMode;
  scope: AwsScope;
  schemaVersion: string;
  prefix: string;
  enableManagedBotControl: boolean;
  warnings: CompileWarning[];
  unsupported: UnsupportedDirective[];
  errors: CompileError[];
  rules: WafV2Rule[];
  ipSets: IPSetSpec[];
  regexSets: RegexPatternSetSpec[];
  apigwPolicies: ApiGatewayPolicyFragment[];
  usagePlans: UsagePlanSpec[];
  priorityCursor: { value: number };
}
