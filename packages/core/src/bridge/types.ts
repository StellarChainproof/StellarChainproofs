import type { Severity } from "../types";

export const BRIDGE_REPORT_SCHEMA_VERSION = "1.0.0" as const;
export const BRIDGE_CONFIG_SCHEMA_VERSION = 1 as const;

export type BridgeRuleId =
  | "CP-BRG-001" | "CP-BRG-002" | "CP-BRG-003" | "CP-BRG-004"
  | "CP-BRG-005" | "CP-BRG-006" | "CP-BRG-007" | "CP-BRG-008"
  | "CP-BRG-009" | "CP-BRG-010" | "CP-BRG-011" | "CP-BRG-012"
  | "CP-BRG-013" | "CP-BRG-014" | "CP-BRG-015" | "CP-BRG-016";

export type BridgeVariableRole =
  | "source-chain" | "destination-chain" | "chain-domain" | "message-id"
  | "nonce" | "processed-messages" | "replay-map" | "validator-set"
  | "validator-threshold" | "merkle-root" | "state-root" | "finality-window"
  | "lock-amount" | "mint-amount" | "burn-amount" | "release-amount"
  | "bridge-paused" | "rate-limit" | "message-queue" | "relayer-role"
  | "upgrade-authority" | "unknown";

export type BridgeFunctionRole =
  | "send-message" | "receive-message" | "verify-proof" | "verify-signatures"
  | "lock-tokens" | "mint-tokens" | "burn-tokens" | "release-tokens"
  | "update-validator-set" | "update-threshold" | "update-root"
  | "execute-message" | "relay-message" | "pause-bridge" | "unpause-bridge"
  | "upgrade" | "unknown";

export type BridgeFrameworkAdapter =
  | "lock-mint-bridge" | "burn-release-bridge" | "optimistic-bridge"
  | "multisig-validator-bridge" | "merkle-proof-bridge" | "layerzero-style"
  | "wormhole-style" | "axelar-style" | "generic-bridge" | "none";

export interface BridgeFrameworkAdapterDefinition {
  id: Exclude<BridgeFrameworkAdapter, "generic-bridge" | "none">;
  displayName: string;
  requiredStateGroups: string[][];
  requiredFunctions: string[];
  mitigations: string[];
  limitations: string[];
}

export interface BridgeFrameworkMatch {
  adapter: BridgeFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

export interface BridgeSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface BridgeEvidence {
  kind:
    | "state-read" | "state-write" | "arithmetic" | "branch" | "call"
    | "modifier" | "ordering" | "adapter" | "absence" | "proof-loop"
    | "taint-flow" | "mitigation";
  description: string;
  location: BridgeSourceLocation;
  snippet?: string;
}

export interface BridgeStateVariable {
  name: string;
  typeName: string;
  role: BridgeVariableRole;
  isMapping: boolean;
  location: BridgeSourceLocation;
}

export interface BridgeOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard" | "loop";
  name: string;
  expression: string;
  parameterSources: string[];
  location: BridgeSourceLocation;
}

export interface BridgeTransition {
  name: string;
  role: BridgeFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: BridgeOperation[];
  location: BridgeSourceLocation;
  source: string;
  mitigations: string[];
}

export interface BridgeContractModel {
  name: string;
  file: string;
  adapter: BridgeFrameworkAdapter;
  stateVariables: BridgeStateVariable[];
  transitions: BridgeTransition[];
  privilegedCalls: BridgeOperation[];
  messageControlledCalls: BridgeOperation[];
  assumptions: string[];
  location: BridgeSourceLocation;
}

export interface BridgeFinding {
  ruleId: BridgeRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  category: string;
  contract: string;
  location: BridgeSourceLocation;
  evidence: BridgeEvidence[];
  assumptions: string[];
}

export interface BridgeDiagnostic {
  code: string;
  severity: "error" | "warning" | "info";
  message: string;
  location?: BridgeSourceLocation;
}

export interface BridgeAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export interface BridgeCancellationSignal { aborted?: boolean; }

export interface BridgeAnalysisOptions {
  limits?: Partial<BridgeAnalysisLimits>;
  includeRules?: BridgeRuleId[];
  excludeRules?: BridgeRuleId[];
  includeModels?: boolean;
  signal?: BridgeCancellationSignal;
}

export interface BridgeSourceInput { file: string; source: string; }

export interface BridgeFileAnalysis {
  file: string;
  findings: BridgeFinding[];
  diagnostics: BridgeDiagnostic[];
  models?: BridgeContractModel[];
}

export interface BridgeAnalysisReport {
  schemaVersion: typeof BRIDGE_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  files: BridgeFileAnalysis[];
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

export interface BridgeAnalysisConfigV1 {
  schemaVersion: typeof BRIDGE_CONFIG_SCHEMA_VERSION;
  limits?: Partial<BridgeAnalysisLimits>;
  includeModels?: boolean;
  includeRules?: BridgeRuleId[];
  excludeRules?: BridgeRuleId[];
}

export interface BridgeAnalysisConfigV0 {
  schemaVersion?: 0;
  version?: 0;
  maxFileSize?: number;
  maxIssues?: number;
  detectors?: BridgeRuleId[];
  includeModels?: boolean;
}

export type BridgeAnalysisConfigInput = BridgeAnalysisConfigV1 | BridgeAnalysisConfigV0;

export interface ValidatedBridgeConfig {
  config: BridgeAnalysisConfigV1;
  diagnostics: BridgeDiagnostic[];
}
