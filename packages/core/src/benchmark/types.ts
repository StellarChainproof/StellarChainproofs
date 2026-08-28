import type { Finding, Severity } from "../types";

/** Version of the benchmark corpus manifest JSON schema. */
export const BENCHMARK_CORPUS_SCHEMA_VERSION = "1.0.0" as const;

/** Version of the benchmark report JSON schema. */
export const BENCHMARK_REPORT_SCHEMA_VERSION = "1.0.0" as const;

/** Version of the threshold exceptions JSON schema. */
export const BENCHMARK_EXCEPTIONS_SCHEMA_VERSION = "1.0.0" as const;

/** Benchmark corpus case classification categories. */
export type CorpusCaseCategory =
  | "vulnerable"
  | "fixed"
  | "ambiguous"
  | "multi-file"
  | "generated"
  | "real-world";

/** Provenance and license metadata for corpus test cases. */
export interface CaseProvenance {
  author?: string;
  source?: string;
  license?: string;
  notes?: string;
}

/** An alternative acceptable match criteria for an expected finding assertion. */
export interface AllowedAlternativeFinding {
  ruleId?: string;
  severity?: Severity;
  line?: number;
  lineTolerance?: number;
}

/** Assertion on a vulnerability finding expected to be produced by scanning. */
export interface ExpectedFinding {
  ruleId: string;
  severity?: Severity | Severity[];
  file?: string;
  line?: number;
  lineEnd?: number;
  lineTolerance?: number;
  snippet?: string;
  callPath?: string[];
  evidence?: string[];
  confidence?: "high" | "medium" | "low";
  allowedAlternatives?: AllowedAlternativeFinding[];
  allowedFalsePositive?: boolean;
  fpCategory?: "unhandled-guard" | "ambiguous-ast" | "dead-code" | "complex-flow" | "other";
}

/** Single test case specification inside a corpus manifest. */
export interface CorpusTestCase {
  id: string;
  name: string;
  description?: string;
  category: CorpusCaseCategory;
  targets: string[];
  expectedFindings: ExpectedFinding[];
  expectedFindingCount?: number;
  tags?: string[];
  provenance?: CaseProvenance;
}

/** Top-level benchmark corpus manifest contract. */
export interface CorpusManifest {
  schemaVersion: typeof BENCHMARK_CORPUS_SCHEMA_VERSION;
  corpusName: string;
  description?: string;
  cases: CorpusTestCase[];
  metadata?: {
    createdAt?: string;
    updatedAt?: string;
    version?: string;
    [key: string]: unknown;
  };
}

/** Precision, recall, and diagnostic accuracy metrics for a single rule. */
export interface RuleBenchmarkMetrics {
  ruleId: string;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  coverage: {
    totalExpected: number;
    matched: number;
    coverageRatio: number;
  };
}

/** Summary of precision, recall, and counts for a metric grouping. */
export interface MetricSummary {
  cases: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
}

/** Aggregate metrics collected across an entire benchmark run. */
export interface BenchmarkMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  f2Score: number;
  f05Score: number;
  perRule: Record<string, RuleBenchmarkMetrics>;
  perCategory: Record<CorpusCaseCategory, MetricSummary>;
  falsePositiveCategories: Record<string, number>;
  runtimeMs: number;
  peakMemoryBytes: number;
}

/** Pairing of an expected finding assertion with the actual finding that satisfied it. */
export interface MatchedFindingPair {
  expected: ExpectedFinding;
  actual: Finding;
  matchedByAlternative: boolean;
  lineDelta: number;
}

/** Benchmark evaluation result for a single corpus test case. */
export interface TestCaseBenchmarkResult {
  caseId: string;
  caseName: string;
  category: CorpusCaseCategory;
  passed: boolean;
  expectedCount: number;
  actualCount: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  matchedFindings: MatchedFindingPair[];
  unmatchedActual: Finding[];
  unmatchedExpected: ExpectedFinding[];
  runtimeMs: number;
  error?: string;
  mutatedVariant?: string;
}

/** Complete benchmark execution report. */
export interface BenchmarkReport {
  schemaVersion: typeof BENCHMARK_REPORT_SCHEMA_VERSION;
  benchmarkId: string;
  timestamp: string;
  engineVersion: string;
  corpusName: string;
  corpusManifestPath?: string;
  metrics: BenchmarkMetrics;
  caseResults: TestCaseBenchmarkResult[];
  sharding?: {
    shardIndex: number;
    totalShards: number;
  };
  sampling?: {
    sampledCount: number;
    totalCount: number;
    seed: number;
  };
  mutationsApplied?: number;
}

/** Threshold exception override entry in a reviewed exceptions file. */
export interface RuleThresholdException {
  ruleId?: string;
  caseId?: string;
  minPrecision?: number;
  minRecall?: number;
  maxFalsePositives?: number;
  reason: string;
  reviewedBy?: string;
  expiresAt?: string;
}

/** Versioned reviewed threshold exceptions artifact. */
export interface ThresholdExceptionsFile {
  schemaVersion: typeof BENCHMARK_EXCEPTIONS_SCHEMA_VERSION;
  reviewedBy: string;
  reviewedAt: string;
  reason: string;
  exceptions: RuleThresholdException[];
}

/** Configuration for comparison regression gates. */
export interface GateConfig {
  minPrecision?: number;
  minRecall?: number;
  minF1?: number;
  maxPrecisionDrop?: number;
  maxRecallDrop?: number;
  maxF1Drop?: number;
  maxRuntimeRegressionPct?: number;
  allowNewFalsePositives?: boolean;
  exceptionsFile?: string;
}

/** Result for an individual check evaluated during a comparison gate. */
export interface GateCheckResult {
  name: string;
  passed: boolean;
  actual: number | string;
  threshold: number | string;
  delta?: number;
  message: string;
  waivedByException?: boolean;
}

/** Complete evaluation output from a comparison gate. */
export interface GateEvaluationResult {
  passed: boolean;
  checks: GateCheckResult[];
  summary: string;
  exceptionsApplied: RuleThresholdException[];
}

/** Diagnostic emitted during corpus validation or benchmark execution. */
export interface BenchmarkDiagnostic {
  code:
    | "CORRUPT_MANIFEST"
    | "INVALID_SCHEMA"
    | "FILE_NOT_FOUND"
    | "PARSER_FAILURE"
    | "MUTATION_ERROR"
    | "GATE_FAILED"
    | "DUPLICATE_CASE";
  severity: "error" | "warning" | "info";
  message: string;
  target?: string;
}

/** Options provided to benchmark runner. */
export interface BenchmarkRunnerOptions {
  manifestPath: string;
  baseDir?: string;
  shardIndex?: number;
  totalShards?: number;
  sampleCount?: number;
  sampleSeed?: number;
  useCache?: boolean;
  mutateVariants?: boolean;
  mutateTypes?: ("line-shift" | "comment-noise" | "format-churn")[];
  parallel?: boolean;
  useSlither?: boolean;
  useLLM?: boolean;
}
