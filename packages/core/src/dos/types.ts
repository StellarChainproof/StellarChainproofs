/**
 * @packageDocumentation
 * @chainproof/core — Denial-of-Service, Gas-Griefing & Unbounded-Work Analysis Types
 */

import type { ASTNode, Finding, Severity } from "../types";

export const DOS_ANALYSIS_SCHEMA_VERSION = "1.0.0";
export const DOS_CONFIG_SCHEMA_VERSION = 1;

export type DosSeverity = Severity;
export type DosConfidence = "high" | "medium" | "low";

export type DosRuleId =
  | "CP-DOS-001" // Unbounded Loop Iteration Over Dynamic Storage Array
  | "CP-DOS-002" // Push-Payment Pattern with Unexpected Revert Risk
  | "CP-DOS-003" // External Call Fan-Out in Loop Iteration
  | "CP-DOS-004" // Return Bomb / Unbounded Returndata Memory Expansion
  | "CP-DOS-005" // Unbounded Storage Clearing / Mass Deletion
  | "CP-DOS-006" // Insufficient Gas Forwarding / 63/64th Rule Griefing
  | "CP-DOS-007" // Single-Transaction Block Gas Limit Deadlock
  | "CP-DOS-008" // Unbounded Recursion Without Depth Guard
  | "CP-DOS-009" // Attacker-Controlled Array Growth / Storage Poisoning
  | "CP-DOS-010"; // Revert Propagation in Critical Batch Operation

export type LoopBoundType =
  | "constant_bounded"
  | "parameter_bounded"
  | "storage_array_bounded"
  | "state_variable_bounded"
  | "paginated"
  | "unbounded"
  | "unknown";

export type MitigationType =
  | "pagination"
  | "pull_payment"
  | "capped_batch"
  | "failure_isolation"
  | "gas_stipend_guard"
  | "checkpoint_state_machine"
  | "rate_limited_growth"
  | "depth_guard";

export interface LoopBoundAnalysis {
  loopType: "for" | "while" | "do-while";
  line: number;
  conditionExpression: string;
  boundType: LoopBoundType;
  boundExpression?: string;
  targetVariable?: string;
  isCapped: boolean;
  maxIterationsEstimate?: number;
  uncertaintyReason?: string;
  hasExternalCalls: boolean;
  externalCallsCount: number;
  hasStateWrites: boolean;
  hasStorageDeletions: boolean;
  hasReturndataCopying: boolean;
  hasEventEmissions: boolean;
  hasBreakOrReturn: boolean;
  associatedFunction: string;
  associatedContract: string;
}

export interface CallFanOutAnalysis {
  line: number;
  callType: "value_transfer" | "high_level" | "low_level_call" | "delegatecall" | "staticcall";
  targetExpression: string;
  valueExpression?: string;
  isInsideLoop: boolean;
  loopLine?: number;
  hasRevertCheck: boolean;
  isWrappedInTryCatch: boolean;
  hasGasLimit: boolean;
  gasLimitExpression?: string;
  hasReturndataSizeCheck: boolean;
  isPushPayment: boolean;
  associatedFunction: string;
  associatedContract: string;
}

export interface ArrayGrowthAnalysis {
  line: number;
  arrayName: string;
  arrayType: string;
  pushExpression: string;
  isPublicOrExternal: boolean;
  hasAccessControl: boolean;
  hasRateLimitOrFee: boolean;
  hasLengthCap: boolean;
  associatedFunction: string;
  associatedContract: string;
  isIteratedInContract: boolean;
  iteratingFunctions: string[];
}

export interface MitigationEvidence {
  type: MitigationType;
  description: string;
  line: number;
  confidence: DosConfidence;
  contract: string;
  functionName?: string;
}

export interface DosEvidencePath {
  file: string;
  line: number;
  column?: number;
  message: string;
  snippet?: string;
}

export interface DosFinding extends Finding {
  dosRuleId: DosRuleId;
  confidence: DosConfidence;
  category: "denial_of_service" | "gas_griefing" | "unbounded_work";
  boundType?: LoopBoundType;
  evidencePaths?: DosEvidencePath[];
  mitigationsApplied?: MitigationType[];
  uncertainty?: string;
}

export interface DosContractReport {
  contractName: string;
  file: string;
  totalLoops: number;
  unboundedLoops: number;
  externalCallsInLoops: number;
  pushPaymentPatterns: number;
  returnBombRisks: number;
  growthEndpoints: number;
  loops: LoopBoundAnalysis[];
  callFanOuts: CallFanOutAnalysis[];
  arrayGrowths: ArrayGrowthAnalysis[];
  mitigations: MitigationEvidence[];
  findings: DosFinding[];
}

export interface DosFileReport {
  file: string;
  contracts: DosContractReport[];
  findings: DosFinding[];
}

export interface DosAuditSummary {
  totalFiles: number;
  totalContracts: number;
  totalLoopsAnalyzed: number;
  unboundedLoopsFound: number;
  pushPaymentsFound: number;
  returnBombRisksFound: number;
  callFanOutsFound: number;
  storageClearingFound: number;
  arrayGrowthPointsFound: number;
  mitigationsRecognized: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    gas: number;
  };
  passed: boolean;
}

export interface DosAuditReport {
  schemaVersion: string;
  createdAt: string;
  summary: DosAuditSummary;
  files: DosFileReport[];
  findings: DosFinding[];
  mitigations: MitigationEvidence[];
}

export interface DosAnalysisLimits {
  maxFiles: number;
  maxSourceBytes: number;
  maxContracts: number;
  maxLoops: number;
  maxFindings: number;
  timeoutMs: number;
}

export interface DosCancellationSignal {
  isCancelled: () => boolean;
}

export interface DosAnalysisOptions {
  config?: ValidatedDosConfig;
  limits?: Partial<DosAnalysisLimits>;
  signal?: DosCancellationSignal;
  includeRules?: DosRuleId[];
  excludeRules?: DosRuleId[];
  minSeverity?: Severity;
  minConfidence?: DosConfidence;
}

export interface DosSourceInput {
  file: string;
  content: string;
  ast?: ASTNode;
}

export interface DosConfigV0 {
  version: 0;
  maxFiles?: number;
  maxSourceSize?: number;
  includeRules?: string[];
  excludeRules?: string[];
}

export interface DosConfigV1 {
  version: 1;
  includeRules?: DosRuleId[];
  excludeRules?: DosRuleId[];
  minSeverity?: Severity;
  minConfidence?: DosConfidence;
  limits?: Partial<DosAnalysisLimits>;
}

export type DosConfigInput = DosConfigV0 | DosConfigV1;

export interface ValidatedDosConfig {
  version: 1;
  includeRules: DosRuleId[];
  excludeRules: DosRuleId[];
  minSeverity: Severity;
  minConfidence: DosConfidence;
  limits: DosAnalysisLimits;
}
