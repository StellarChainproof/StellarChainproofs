import type { Severity } from "../types";

export const RETURNDATA_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const RETURNDATA_CONFIG_SCHEMA_VERSION = 1 as const;

export type ReturndataRuleId =
  | "CP-RTD-001" | "CP-RTD-002" | "CP-RTD-003" | "CP-RTD-004"
  | "CP-RTD-005" | "CP-RTD-006" | "CP-RTD-007" | "CP-RTD-008"
  | "CP-RTD-009" | "CP-RTD-010" | "CP-RTD-011" | "CP-RTD-012"
  | "CP-RTD-013" | "CP-RTD-014" | "CP-RTD-015" | "CP-RTD-016";

export type CallKind =
  | "call" | "callcode" | "delegatecall" | "staticcall"
  | "send" | "transfer" | "interface-call" | "unknown";

export type ReturndataVariableRole =
  | "success-flag" | "return-buffer" | "return-length" | "decoded-value"
  | "token-balance" | "allowance" | "unknown";

export type ReturndataFunctionRole =
  | "external-call" | "token-transfer" | "token-transferFrom"
  | "abi-decode" | "assembly-copy" | "multicall" | "try-catch-wrapper"
  | "safe-wrapper" | "batch-operation" | "unknown";

export type ReturndataFrameworkAdapter =
  | "safe-erc20-wrapper" | "address-utilities" | "assembly-wrapper"
  | "multicall-batch" | "try-catch-guarded" | "generic-external-call" | "none";

export interface ReturndataFrameworkAdapterDefinition {
  id: Exclude<ReturndataFrameworkAdapter, "generic-external-call" | "none">;
  displayName: string;
  requiredPatterns: string[];
  mitigations: string[];
  limitations: string[];
}

export interface ReturndataFrameworkMatch {
  adapter: ReturndataFrameworkAdapter;
  matchedPatterns: string[];
}

export interface ReturndataSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface ReturndataEvidence {
  kind:
    | "call-site" | "return-check" | "decode-site" | "guard" | "wrapper"
    | "absence" | "taint-flow" | "batch-item" | "assembly" | "adapter";
  description: string;
  location: ReturndataSourceLocation;
  snippet?: string;
}

export interface ReturndataStateVariable {
  name: string;
  typeName: string;
  role: ReturndataVariableRole;
  location: ReturndataSourceLocation;
}

export interface ReturndataOperation {
  order: number;
  kind: "call" | "assignment" | "guard" | "decode" | "assembly" | "throw";
  callKind: CallKind;
  name: string;
  expression: string;
  capturesReturn: boolean;
  checksSuccess: boolean;
  usesSafeWrapper: boolean;
  location: ReturndataSourceLocation;
}

export interface ReturndataTransition {
  name: string;
  role: ReturndataFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  operations: ReturndataOperation[];
  location: ReturndataSourceLocation;
  source: string;
  guards: string[];
}

export interface ReturndataContractModel {
  name: string;
  file: string;
  adapter: ReturndataFrameworkAdapter;
  stateVariables: ReturndataStateVariable[];
  transitions: ReturndataTransition[];
  externalCalls: ReturndataOperation[];
  assumptions: string[];
  location: ReturndataSourceLocation;
}

export interface ReturndataFinding {
  ruleId: ReturndataRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  category: string;
  contract: string;
  location: ReturndataSourceLocation;
  evidence: ReturndataEvidence[];
  assumptions: string[];
  optionalCall: boolean;
}

export interface ReturndataDiagnostic {
  code: string;
  severity: "error" | "warning" | "info";
  message: string;
  location?: ReturndataSourceLocation;
}

export interface ReturndataAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export interface ReturndataCancellationSignal { aborted?: boolean; }

export interface ReturndataAnalysisOptions {
  limits?: Partial<ReturndataAnalysisLimits>;
  includeRules?: ReturndataRuleId[];
  excludeRules?: ReturndataRuleId[];
  includeModels?: boolean;
  signal?: ReturndataCancellationSignal;
  mergeSlither?: boolean;
}

export interface ReturndataSourceInput { file: string; source: string; }

export interface ReturndataFileAnalysis {
  file: string;
  findings: ReturndataFinding[];
  diagnostics: ReturndataDiagnostic[];
  models?: ReturndataContractModel[];
}

export interface ReturndataAnalysisReport {
  schemaVersion: typeof RETURNDATA_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  files: ReturndataFileAnalysis[];
  summary: {
    files: number;
    contracts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    truncated: boolean;
  };
}

export interface ReturndataAnalysisConfigV1 {
  schemaVersion: typeof RETURNDATA_CONFIG_SCHEMA_VERSION;
  limits?: Partial<ReturndataAnalysisLimits>;
  includeModels?: boolean;
  includeRules?: ReturndataRuleId[];
  excludeRules?: ReturndataRuleId[];
  mergeSlither?: boolean;
}

export interface ReturndataAnalysisConfigV0 {
  schemaVersion?: 0;
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  detectors?: ReturndataRuleId[];
  includeModels?: boolean;
}

export type ReturndataAnalysisConfigInput = ReturndataAnalysisConfigV1 | ReturndataAnalysisConfigV0;

export interface ValidatedReturndataConfig {
  config: ReturndataAnalysisConfigV1;
  diagnostics: ReturndataDiagnostic[];
}
