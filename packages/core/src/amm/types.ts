import type { Severity } from "../types";

export const AMM_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const AMM_CONFIG_SCHEMA_VERSION = 1 as const;

export type AmmRuleId =
  | "CP-AMM-001"
  | "CP-AMM-002"
  | "CP-AMM-003"
  | "CP-AMM-004"
  | "CP-AMM-005"
  | "CP-AMM-006"
  | "CP-AMM-007"
  | "CP-AMM-008"
  | "CP-AMM-009"
  | "CP-AMM-010";

export type AmmVariableRole =
  | "reserve-token-a"
  | "reserve-token-b"
  | "reserve-balance-a"
  | "reserve-balance-b"
  | "total-supply"
  | "total-shares"
  | "liquidity-balances"
  | "fee-rate"
  | "protocol-fee"
  | "swap-fee"
  | "slippage-bound"
  | "deadline"
  | "invariant"
  | "price-bound"
  | "oracle-price"
  | "pause-state"
  | "admin"
  | "unknown";

export type AmmFunctionRole =
  | "initialize"
  | "mint-liquidity"
  | "burn-liquidity"
  | "swap"
  | "flash-swap"
  | "donate"
  | "set-fees"
  | "settle-callback"
  | "sync-reserves"
  | "update-oracle"
  | "pause"
  | "unpause"
  | "unknown";

export type AmmFrameworkAdapter =
  | "constant-product"
  | "stable-swap"
  | "weighted-pool"
  | "concentrated-liquidity"
  | "generic-amm"
  | "none";

export interface AmmFrameworkAdapterDefinition {
  id: Exclude<AmmFrameworkAdapter, "generic-amm" | "none">;
  displayName: string;
  requiredStateGroups: string[][];
  requiredFunctions: string[];
  guarantees: string[];
  limitations: string[];
}

export interface AmmFrameworkAdapterMatch {
  adapter: AmmFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

export interface AmmSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface AmmEvidence {
  kind:
    | "state-read"
    | "state-write"
    | "arithmetic"
    | "branch"
    | "call"
    | "modifier"
    | "ordering"
    | "adapter"
    | "absence";
  description: string;
  location: AmmSourceLocation;
  snippet?: string;
}

export interface AmmStateVariable {
  name: string;
  typeName: string;
  role: AmmVariableRole;
  isMapping: boolean;
  location: AmmSourceLocation;
}

export interface AmmOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard";
  name: string;
  expression: string;
  location: AmmSourceLocation;
}

export interface AmmTransition {
  name: string;
  role: AmmFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: AmmOperation[];
  location: AmmSourceLocation;
  source: string;
}

export interface AmmContractModel {
  name: string;
  file: string;
  adapter: AmmFrameworkAdapter;
  stateVariables: AmmStateVariable[];
  transitions: AmmTransition[];
  precisionScalars: string[];
  tokenPairs: string[];
  assumptions: string[];
  location: AmmSourceLocation;
}

export interface AmmFinding {
  ruleId: AmmRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Exclude<Severity, "gas">;
  confidence: "high" | "medium" | "low";
  category:
    | "reserve-accounting"
    | "liquidity"
    | "fee-accounting"
    | "slippage"
    | "precision"
    | "flash-swap"
    | "callback"
    | "invariant"
    | "configuration";
  contract: string;
  location: AmmSourceLocation;
  evidence: AmmEvidence[];
  assumptions: string[];
}

export interface AmmDiagnostic {
  code:
    | "AMM_PARSE_ERROR"
    | "AMM_SOURCE_LIMIT"
    | "AMM_CONTRACT_LIMIT"
    | "AMM_FUNCTION_LIMIT"
    | "AMM_OPERATION_LIMIT"
    | "AMM_CANCELLED"
    | "AMM_CONFIG_INVALID"
    | "AMM_FILE_UNREADABLE";
  severity: "error" | "warning" | "info";
  message: string;
  location?: AmmSourceLocation;
}

export interface AmmAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export interface AmmCancellationSignal {
  readonly aborted: boolean;
  readonly reason?: unknown;
}

export interface AmmAnalysisOptions {
  limits?: Partial<AmmAnalysisLimits>;
  signal?: AmmCancellationSignal;
  includeModels?: boolean;
  includeRules?: AmmRuleId[];
  excludeRules?: AmmRuleId[];
}

export interface AmmAnalysisConfigV1 {
  schemaVersion: 1;
  limits?: Partial<AmmAnalysisLimits>;
  includeModels?: boolean;
  includeRules?: AmmRuleId[];
  excludeRules?: AmmRuleId[];
}

export interface AmmAnalysisConfigV0 {
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  rules?: AmmRuleId[];
  includeModels?: boolean;
}

export type AmmAnalysisConfigInput =
  | AmmAnalysisConfigV1
  | AmmAnalysisConfigV0
  | Record<string, unknown>;

export interface AmmFileAnalysis {
  file: string;
  findings: AmmFinding[];
  diagnostics: AmmDiagnostic[];
  models?: AmmContractModel[];
}

export interface AmmAnalysisReport {
  schemaVersion: typeof AMM_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  files: AmmFileAnalysis[];
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

export interface AmmSourceInput {
  file: string;
  source: string;
}

export interface ValidatedAmmConfig {
  config: AmmAnalysisConfigV1;
  diagnostics: AmmDiagnostic[];
}
