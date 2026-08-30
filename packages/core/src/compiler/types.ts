/**
 * @packageDocumentation
 * @chainproof/core — Compiler Compatibility & Diagnostic Matrix Types
 */

import type { ASTNode, Finding, Severity } from "../types";

export const COMPILER_MATRIX_SCHEMA_VERSION = "1.0.0";
export const COMPILER_CONFIG_SCHEMA_VERSION = 1;

// ─── Version & Capability Definitions ─────────────────────────────────────────

export type CompilerFamily = "0.4" | "0.5" | "0.6" | "0.7" | "0.8";

export type ABIEncoderV2Status = "unsupported" | "experimental" | "default";

export interface CompilerCapabilities {
  checkedArithmetic: boolean;
  customErrors: boolean;
  userDefinedValueTypes: boolean;
  transientStorage: boolean;
  push0Opcode: boolean;
  viaIR: boolean;
  immutableVariables: boolean;
  tryCatch: boolean;
  receiveFallbackSplit: boolean;
  abiEncoderV2: ABIEncoderV2Status;
  calldataParameters: boolean;
  constructorKeyword: boolean;
  storageLayoutOutput: boolean;
  yulOptimizer: boolean;
  payableExplicitAddress: boolean;
  virtualOverrideKeywords: boolean;
  globalImports: boolean;
}

export interface CompilerVersionMetadata {
  version: string;
  family: CompilerFamily;
  releaseDate: string;
  defaultEvmVersion: string;
  supportedEvmVersions: string[];
  isStable: boolean;
  isPrerelease: boolean;
  isDeprecated: boolean;
  capabilities: CompilerCapabilities;
  sha256Checksums?: Record<string, string>;
}

// ─── Known Compiler Bugs & Codegen Hazards ────────────────────────────────────

export type CodegenHazardSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface CompilerCodegenHazard {
  id: string;
  name: string;
  minVersion: string;
  maxVersion: string;
  affectedVersionsDescription: string;
  severity: CodegenHazardSeverity;
  conditions: string[];
  description: string;
  recommendation: string;
  cveId?: string;
  link?: string;
}

// ─── Semver & Pragma Constraints ──────────────────────────────────────────────

export type PragmaOperator = "^" | "~" | ">=" | "<=" | ">" | "<" | "=" | "!=";

export interface PragmaConstraint {
  operator: PragmaOperator;
  version: string;
  raw: string;
}

export interface ResolvedPragmas {
  file: string;
  rawPragma: string;
  constraints: PragmaConstraint[];
  isFloating: boolean;
  isOverlyBroad: boolean;
  isSecuritySensitive: boolean;
  compatibleVersions: string[];
  lowestCompatible?: string;
  highestCompatible?: string;
  hazards: CompilerCodegenHazard[];
  rangeDescription: string;
  line: number;
}

export interface ProjectPragmaResolution {
  files: ResolvedPragmas[];
  globalRange: string;
  globalCompatibleVersions: string[];
  unsatisfiable: boolean;
  conflictDetails?: string[];
  recommendedVersion?: string;
  lowestCompatibleVersion?: string;
  highestCompatibleVersion?: string;
  totalFiles: number;
  hasFloatingPragmas: boolean;
  hasBroadPragmas: boolean;
  hasSecuritySensitivePragmas: boolean;
}

// ─── Normalized Compilation Artifacts ─────────────────────────────────────────

export interface CompilerSettings {
  optimizer: {
    enabled: boolean;
    runs: number;
  };
  evmVersion?: string;
  viaIR?: boolean;
  outputSelection?: Record<string, string[]>;
}

export interface CompilerSourceInput {
  file: string;
  content: string;
  ast?: ASTNode;
}

export interface NormalizedABIParam {
  name: string;
  type: string;
  internalType?: string;
  indexed?: boolean;
  components?: NormalizedABIParam[];
}

export type ABIFunctionMutability = "pure" | "view" | "nonpayable" | "payable";
export type ABIEntryType = "function" | "constructor" | "event" | "error" | "fallback" | "receive";

export interface NormalizedABIEntry {
  type: ABIEntryType;
  name?: string;
  inputs: NormalizedABIParam[];
  outputs?: NormalizedABIParam[];
  stateMutability?: ABIFunctionMutability;
  anonymous?: boolean;
  selector?: string;
  signature?: string;
}

export interface NormalizedStorageItem {
  astId?: number;
  contract: string;
  label: string;
  offset: number;
  slot: number;
  type: string;
  numberOfBytes?: number;
}

export interface NormalizedStorageMember {
  astId?: number;
  contract: string;
  label: string;
  offset: number;
  slot: number;
  type: string;
}

export interface NormalizedStorageType {
  encoding: string;
  label: string;
  numberOfBytes: number;
  key?: string;
  value?: string;
  members?: NormalizedStorageMember[];
}

export interface NormalizedStorageLayout {
  storage: NormalizedStorageItem[];
  types: Record<string, NormalizedStorageType>;
  totalSlots: number;
  hasPacking: boolean;
  layoutHash: string;
}

export interface NormalizedBytecode {
  object: string;
  lengthBytes: number;
  opcodes?: string[];
  hasPush0: boolean;
  hasTransientStorage: boolean;
  metadataHash?: string;
  executableCodeHash: string;
}

export interface NormalizedASTSummary {
  contractCount: number;
  functionCount: number;
  hasAssembly: boolean;
  hasUncheckedBlocks: boolean;
  hasPayableFallback: boolean;
  hasReceiveFunction: boolean;
  usesCustomErrors: boolean;
  usesUserDefinedTypes: boolean;
}

export interface NormalizedContractArtifact {
  contractName: string;
  sourcePath: string;
  abi: NormalizedABIEntry[];
  storageLayout: NormalizedStorageLayout;
  bytecode: NormalizedBytecode;
  deployedBytecode: NormalizedBytecode;
  astSummary?: NormalizedASTSummary;
}

export interface NormalizedCompilerDiagnostic {
  severity: "error" | "warning" | "info";
  type: string;
  message: string;
  formattedMessage: string;
  sourceLocation?: {
    file: string;
    start: number;
    end: number;
    line?: number;
    column?: number;
  };
  errorCode?: string;
}

export interface NormalizedCompilationResult {
  version: string;
  success: boolean;
  contracts: Record<string, NormalizedContractArtifact>;
  diagnostics: NormalizedCompilerDiagnostic[];
  durationMs: number;
  evmVersion: string;
  optimizer: CompilerSettings["optimizer"];
  simulated?: boolean;
}

// ─── Differential Cross-Compiler Comparison ───────────────────────────────────

export interface ABIDiffResult {
  identical: boolean;
  addedFunctions: string[];
  removedFunctions: string[];
  mutatedSignatures: { name: string; baseSignature: string; targetSignature: string }[];
  addedEvents: string[];
  removedEvents: string[];
  addedErrors: string[];
  removedErrors: string[];
  mutabilityChanges: { name: string; from: string; to: string }[];
}

export interface StorageCollisionHazard {
  variable: string;
  severity: "critical" | "high" | "medium";
  reason: string;
  oldSlot: number;
  newSlot: number;
  oldOffset?: number;
  newOffset?: number;
}

export interface StorageLayoutDiffResult {
  identical: boolean;
  slotCollisions: StorageCollisionHazard[];
  addedVariables: string[];
  removedVariables: string[];
  shiftedSlots: { variable: string; oldSlot: number; newSlot: number }[];
  offsetChanges: { variable: string; oldOffset: number; newOffset: number }[];
  typeChanges: { variable: string; oldType: string; newType: string }[];
}

export interface BytecodeDiffResult {
  sizeDeltaBytes: number;
  sizeDeltaPercent: number;
  baseSizeBytes: number;
  targetSizeBytes: number;
  baseHasPush0: boolean;
  targetHasPush0: boolean;
  push0Hazard: boolean;
  baseHasTransient: boolean;
  targetHasTransient: boolean;
  metadataOnlyDifference: boolean;
}

export interface DiagnosticDiffResult {
  newWarnings: string[];
  resolvedWarnings: string[];
  newErrors: string[];
}

export interface FindingsDiffResult {
  introducedFindings: Finding[];
  resolvedFindings: Finding[];
  severityDelta: Record<Severity, number>;
}

export interface VersionComparisonResult {
  contractName: string;
  sourceFile: string;
  baseVersion: string;
  targetVersion: string;
  abiDiff: ABIDiffResult;
  storageLayoutDiff: StorageLayoutDiffResult;
  bytecodeDiff: BytecodeDiffResult;
  diagnosticDiff: DiagnosticDiffResult;
  findingsDiff: FindingsDiffResult;
  breakingChanges: string[];
  activeHazardsInBase: CompilerCodegenHazard[];
  activeHazardsInTarget: CompilerCodegenHazard[];
  compatibilityStatus: "compatible" | "warning" | "breaking_drift" | "hazard";
}

// ─── Matrix Grid & Audit Report ───────────────────────────────────────────────

export type MatrixCellStatus = "compatible" | "warning" | "incompatible" | "hazard";

export interface MatrixCell {
  version: string;
  status: MatrixCellStatus;
  compileSuccess: boolean;
  warningsCount: number;
  errorsCount: number;
  hazards: string[];
  bytecodeSize?: number;
  storageLayoutHash?: string;
  notes: string[];
}

export interface CompilerMatrixRow {
  file: string;
  contract: string;
  cells: Record<string, MatrixCell>;
}

export interface CompilerMatrixSummary {
  testedVersions: string[];
  supportedRange: string;
  recommendedVersion?: string;
  totalContracts: number;
  fullyCompatibleVersions: string[];
  partiallyCompatibleVersions: string[];
  incompatibleVersions: string[];
  criticalHazardsFound: number;
}

export interface CompilerMatrixGrid {
  targetVersions: string[];
  rows: CompilerMatrixRow[];
  summary: CompilerMatrixSummary;
}

export interface CompilerAuditDiagnostic {
  ruleId: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  details?: Record<string, unknown>;
}

export interface CompilerAuditSummary {
  totalFiles: number;
  totalContracts: number;
  testedVersions: string[];
  recommendedVersion?: string;
  compatibleVersionsCount: number;
  criticalHazardsCount: number;
  breakingDriftsCount: number;
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;
}

export interface CompilerAuditReport {
  version: string;
  schemaVersion: string;
  summary: CompilerAuditSummary;
  projectPragmas: ProjectPragmaResolution;
  matrix: CompilerMatrixGrid;
  comparisons: VersionComparisonResult[];
  findings: Finding[];
  diagnostics: CompilerAuditDiagnostic[];
}

// ─── Configuration & Limits ───────────────────────────────────────────────────

export type CompilerRuleId =
  | "CP-SOL-001"
  | "CP-SOL-002"
  | "CP-SOL-003"
  | "CP-SOL-004"
  | "CP-SOL-005"
  | "CP-SOL-006"
  | "CP-SOL-007"
  | "CP-SOL-008"
  | "CP-SOL-009"
  | "CP-SOL-010";

export interface CompilerAnalysisLimits {
  maxFiles: number;
  maxSourceBytes: number;
  maxContracts: number;
  maxVersionsToTest: number;
  timeoutMs: number;
  maxFindings: number;
}

export interface CompilerMatrixConfigV1 {
  version: 1;
  defaultEvmVersion?: string;
  targetVersions?: string[];
  compareVersions?: [string, string];
  optimizer?: {
    enabled: boolean;
    runs: number;
    viaIR?: boolean;
  };
  includeRules?: CompilerRuleId[];
  excludeRules?: CompilerRuleId[];
  allowedHazards?: string[];
  limits?: Partial<CompilerAnalysisLimits>;
  sandboxed?: boolean;
  compilerBinaryPath?: string;
  compilerCacheDir?: string;
}

export interface CompilerMatrixConfigV0 {
  version?: 0;
  solcVersions?: string[];
  evmVersion?: string;
  optimizer?: boolean;
  optimizerRuns?: number;
  rules?: string[];
  maxFiles?: number;
  maxSourceSize?: number;
}

export type CompilerMatrixConfigInput = CompilerMatrixConfigV0 | CompilerMatrixConfigV1;

export interface ValidatedCompilerConfig {
  version: 1;
  defaultEvmVersion: string;
  targetVersions: string[];
  compareVersions?: [string, string];
  optimizer: {
    enabled: boolean;
    runs: number;
    viaIR: boolean;
  };
  includeRules?: CompilerRuleId[];
  excludeRules?: CompilerRuleId[];
  allowedHazards: string[];
  limits: CompilerAnalysisLimits;
  sandboxed: boolean;
  compilerBinaryPath?: string;
  compilerCacheDir?: string;
}

export interface CompilerAnalysisOptions {
  config?: ValidatedCompilerConfig;
  limits?: Partial<CompilerAnalysisLimits>;
  targetVersions?: string[];
  compareVersions?: [string, string];
  evmVersion?: string;
  optimizer?: {
    enabled: boolean;
    runs: number;
    viaIR?: boolean;
  };
  includeRules?: CompilerRuleId[];
  excludeRules?: CompilerRuleId[];
  allowedHazards?: string[];
  signal?: CompilerCancellationSignal;
}

export interface CompilerCancellationSignal {
  isCancelled(): boolean;
}
