import type { Severity } from "../types";

export const LENDING_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const LENDING_CONFIG_SCHEMA_VERSION = 1 as const;

export type LendingRuleId =
  | "CP-LND-001"
  | "CP-LND-002"
  | "CP-LND-003"
  | "CP-LND-004"
  | "CP-LND-005"
  | "CP-LND-006"
  | "CP-LND-007"
  | "CP-LND-008"
  | "CP-LND-009"
  | "CP-LND-010"
  | "CP-LND-011"
  | "CP-LND-012"
  | "CP-LND-013"
  | "CP-LND-014"
  | "CP-LND-015"
  | "CP-LND-016"
  | "CP-LND-017"
  | "CP-LND-018"
  | "CP-LND-019"
  | "CP-LND-020";

export type LendingVariableRole =
  | "collateral-asset"
  | "debt-asset"
  | "interest-index"
  | "debt-index"
  | "normalized-debt"
  | "debt-shares"
  | "collateral-factor"
  | "liquidation-threshold"
  | "liquidation-bonus"
  | "close-factor"
  | "reserve-factor"
  | "exchange-rate"
  | "total-supply"
  | "total-borrows"
  | "user-balance"
  | "user-borrow"
  | "utilization-rate"
  | "oracle-price"
  | "health-factor"
  | "accrual-timestamp"
  | "pause-state"
  | "isolation-flag"
  | "debt-ceiling"
  | "administrator"
  | "unknown";

export type LendingFunctionRole =
  | "deposit"
  | "supply"
  | "mint"
  | "borrow"
  | "repay"
  | "withdraw"
  | "redeem"
  | "liquidate"
  | "accrue-interest"
  | "update-index"
  | "update-oracle"
  | "calculate-health"
  | "exchange-rate"
  | "set-collateral-factor"
  | "set-liquidation-params"
  | "set-reserve-factor"
  | "pause"
  | "unpause"
  | "emergency-withdraw"
  | "unknown";

export type LendingFrameworkAdapter =
  | "compound-ctoken"
  | "aave-pool"
  | "isolated-pool"
  | "generic-lending"
  | "none";

export interface LendingFrameworkAdapterDefinition {
  id: Exclude<LendingFrameworkAdapter, "generic-lending" | "none">;
  displayName: string;
  requiredStateGroups: string[][];
  requiredFunctions: string[];
  guarantees: string[];
  limitations: string[];
}

export interface LendingFrameworkAdapterMatch {
  adapter: LendingFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

export interface LendingSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface LendingEvidence {
  kind:
    | "state-read"
    | "state-write"
    | "arithmetic"
    | "branch"
    | "call"
    | "modifier"
    | "ordering"
    | "parameter-flow"
    | "adapter"
    | "absence";
  description: string;
  location: LendingSourceLocation;
  snippet?: string;
}

export interface LendingStateVariable {
  name: string;
  typeName: string;
  role: LendingVariableRole;
  isMapping: boolean;
  location: LendingSourceLocation;
}

export interface LendingOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard";
  name: string;
  expression: string;
  parameterSources: string[];
  location: LendingSourceLocation;
}

export interface LendingTransition {
  name: string;
  role: LendingFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: LendingOperation[];
  location: LendingSourceLocation;
  source: string;
}

export interface LendingContractModel {
  name: string;
  file: string;
  adapter: LendingFrameworkAdapter;
  stateVariables: LendingStateVariable[];
  transitions: LendingTransition[];
  collateralAssets: string[];
  debtAssets: string[];
  oracleReferences: string[];
  precisionScalars: string[];
  collateralFactors: Map<string, string>;
  liquidationThresholds: Map<string, string>;
  liquidationBonuses: Map<string, string>;
  assumptions: string[];
  location: LendingSourceLocation;
}

export interface LendingFinding {
  ruleId: LendingRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Exclude<Severity, "gas">;
  confidence: "high" | "medium" | "low";
  category:
    | "collateral-health"
    | "interest-accrual"
    | "share-accounting"
    | "liquidation"
    | "state-ordering"
    | "protocol-specific";
  contract: string;
  location: LendingSourceLocation;
  evidence: LendingEvidence[];
  assumptions: string[];
}

export interface LendingAnalysisConfigV1 {
  schemaVersion: 1;
  includeModels?: boolean;
  includeRules?: LendingRuleId[];
  excludeRules?: LendingRuleId[];
  limits?: Partial<LendingAnalysisLimits>;
  protocolTerminology?: {
    deposit?: string[];
    borrow?: string[];
    repay?: string[];
    withdraw?: string[];
  };
  functionAnnotations?: {
    [functionName: string]: LendingFunctionRole;
  };
}

export interface LendingAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export const DEFAULT_LENDING_LIMITS: LendingAnalysisLimits = Object.freeze({
  maxSourceBytes: 2 * 1024 * 1024,
  maxFiles: 256,
  maxContracts: 128,
  maxFunctionsPerFile: 512,
  maxFunctionsPerContract: 512,
  maxOperationsPerFunction: 2048,
  maxFindings: 1024,
  maxEvidencePerFinding: 12,
});

export interface LendingDiagnostic {
  code:
    | "LND_PARSE_ERROR"
    | "LND_SOURCE_LIMIT"
    | "LND_CONTRACT_LIMIT"
    | "LND_FUNCTION_LIMIT"
    | "LND_OPERATION_LIMIT"
    | "LND_FINDING_LIMIT"
    | "LND_CANCELLED"
    | "LND_CONFIG_INVALID"
    | "LND_FILE_UNREADABLE";
  severity: "error" | "warning" | "info";
  message: string;
  location?: LendingSourceLocation;
}

export interface LendingCancellationSignal {
  readonly aborted: boolean;
  readonly reason?: unknown;
}

export interface LendingAnalysisOptions {
  includeModels?: boolean;
  includeRules?: LendingRuleId[];
  excludeRules?: LendingRuleId[];
  limits?: Partial<LendingAnalysisLimits>;
  signal?: LendingCancellationSignal;
  protocolTerminology?: LendingAnalysisConfigV1["protocolTerminology"];
  functionAnnotations?: LendingAnalysisConfigV1["functionAnnotations"];
}

export interface LendingAnalysisConfigV0 {
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  rules?: LendingRuleId[];
  includeModels?: boolean;
}

export type LendingAnalysisConfigInput =
  | LendingAnalysisConfigV1
  | LendingAnalysisConfigV0
  | Record<string, unknown>;

export interface LendingFileAnalysis {
  file: string;
  findings: LendingFinding[];
  diagnostics: LendingDiagnostic[];
  models?: LendingContractModel[];
}

export interface LendingAnalysisReport {
  schemaVersion: typeof LENDING_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  timestamp: string;
  files: LendingFileAnalysis[];
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
  assumptions: string[];
  config: LendingAnalysisConfigV1;
}

export interface LendingSourceInput {
  file: string;
  source: string;
}

export interface ValidatedLendingConfig {
  config: LendingAnalysisConfigV1;
  diagnostics: LendingDiagnostic[];
}
