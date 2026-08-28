import * as fs from "fs";
import * as path from "path";
import { scan } from "../scanner";
import type { Finding } from "../types";
import { parseCorpusManifest } from "./schema";
import { evaluateTestCase, calculateBenchmarkMetrics } from "./evaluator";
import { createMutatedVariant } from "./mutator";
import {
  BENCHMARK_REPORT_SCHEMA_VERSION,
  BenchmarkReport,
  BenchmarkRunnerOptions,
  CorpusTestCase,
  TestCaseBenchmarkResult,
} from "./types";

/**
 * Deterministic pseudo-random number generator for sampling reproducibility.
 */
function seededRandom(seed: number): () => number {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => {
    s = (s * 16807) % 2147483647;
    return (s - 1) / 2147483646;
  };
}

/**
 * Executes a versioned detector benchmark against a corpus manifest.
 */
export async function runBenchmark(
  options: BenchmarkRunnerOptions,
): Promise<BenchmarkReport> {
  const startTime = Date.now();
  const manifestPath = path.resolve(options.manifestPath);
  const baseDir = options.baseDir || path.dirname(manifestPath);

  const { manifest } = parseCorpusManifest(manifestPath, baseDir);

  let casesToRun: CorpusTestCase[] = [...manifest.cases];

  // 1. Sharding
  if (
    options.shardIndex !== undefined &&
    options.totalShards !== undefined &&
    options.totalShards > 1
  ) {
    const shardIdx = options.shardIndex;
    const totalShards = options.totalShards;
    casesToRun = casesToRun.filter((_, idx) => idx % totalShards === shardIdx);
  }

  // 2. Deterministic Sampling
  let samplingMetadata: BenchmarkReport["sampling"] | undefined;
  if (options.sampleCount !== undefined && options.sampleCount < casesToRun.length) {
    const seed = options.sampleSeed ?? 42;
    const rand = seededRandom(seed);
    const originalCount = casesToRun.length;

    // Shuffle deterministically
    const shuffled = [...casesToRun].sort(() => rand() - 0.5);
    casesToRun = shuffled.slice(0, options.sampleCount);

    // Sort back by ID for deterministic execution order
    casesToRun.sort((a, b) => a.id.localeCompare(b.id));

    samplingMetadata = {
      sampledCount: casesToRun.length,
      totalCount: originalCount,
      seed,
    };
  } else {
    // Standard deterministic sort by case ID
    casesToRun.sort((a, b) => a.id.localeCompare(b.id));
  }

  const caseResults: TestCaseBenchmarkResult[] = [];
  let mutationsAppliedCount = 0;

  // Execute test cases
  for (const testCase of casesToRun) {
    const caseStart = Date.now();
    let actualFindings: Finding[] = [];
    let caseError: string | undefined;
    let mutantCleanup: (() => void) | undefined;
    let mutatedVariantName: string | undefined;

    try {
      let targetPaths = testCase.targets.map((t) => {
        if (path.isAbsolute(t)) return t;
        const fromBase = path.resolve(baseDir, t);
        if (fs.existsSync(fromBase)) return fromBase;
        const fromCwd = path.resolve(process.cwd(), t);
        if (fs.existsSync(fromCwd)) return fromCwd;
        return fromBase;
      });

      // Handle fixture mutations if requested
      if (options.mutateVariants && options.mutateTypes && options.mutateTypes.length > 0) {
        const mutationType = options.mutateTypes[mutationsAppliedCount % options.mutateTypes.length];
        const mutant = createMutatedVariant(targetPaths[0], mutationType, mutationsAppliedCount + 1);
        targetPaths = [mutant.variantPath, ...targetPaths.slice(1)];
        mutantCleanup = mutant.cleanup;
        mutatedVariantName = mutationType;
        mutationsAppliedCount++;
      }

      // Run scanner engine on target files
      const scanResult = await scan({
        targets: targetPaths,
        useSlither: options.useSlither ?? false,
        useLLM: options.useLLM ?? false,
        useMetrics: false,
      });

      actualFindings = scanResult.files.flatMap((f) => f.findings);
    } catch (err) {
      caseError = err instanceof Error ? err.message : String(err);
    } finally {
      if (mutantCleanup) {
        mutantCleanup();
      }
    }

    const caseDuration = Date.now() - caseStart;
    const evaluatedResult = evaluateTestCase(
      testCase,
      actualFindings,
      caseDuration,
      caseError,
      mutatedVariantName,
    );

    caseResults.push(evaluatedResult);
  }

  const totalRuntimeMs = Date.now() - startTime;
  const peakMemoryBytes = process.memoryUsage().heapUsed;

  const metrics = calculateBenchmarkMetrics(caseResults, totalRuntimeMs, peakMemoryBytes);

  const report: BenchmarkReport = {
    schemaVersion: BENCHMARK_REPORT_SCHEMA_VERSION,
    benchmarkId: `bench_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    engineVersion: "0.1.0",
    corpusName: manifest.corpusName,
    corpusManifestPath: manifestPath,
    metrics,
    caseResults,
    sharding:
      options.shardIndex !== undefined && options.totalShards !== undefined
        ? { shardIndex: options.shardIndex, totalShards: options.totalShards }
        : undefined,
    sampling: samplingMetadata,
    mutationsApplied: mutationsAppliedCount,
  };

  return report;
}
