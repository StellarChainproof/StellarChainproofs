import * as path from "path";
import * as fs from "fs";
import {
  parseCorpusManifest,
  evaluateTestCase,
  calculateBenchmarkMetrics,
  createMutatedVariant,
  evaluateRegressionGate,
  runBenchmark,
  generateBenchmarkMarkdownReport,
  generateBenchmarkJSONReport,
  CorpusSchemaError,
  type CorpusTestCase,
  type BenchmarkReport,
  type Finding,
} from "../../index";

describe("Benchmark Corpus & Regression Engine", () => {
  const repoRoot = path.resolve(__dirname, "../../../../../");
  const manifestPath = path.join(repoRoot, "examples/benchmark-corpus/corpus.manifest.json");

  describe("Schema Parser & Validation", () => {
    test("parses a valid corpus manifest cleanly", () => {
      const { manifest, diagnostics } = parseCorpusManifest(manifestPath);
      expect(manifest.corpusName).toBe("ChainProof Official Benchmark Corpus");
      expect(manifest.cases.length).toBeGreaterThanOrEqual(3);
      expect(diagnostics.filter((d) => d.severity === "error")).toHaveLength(0);
    });

    test("throws CorpusSchemaError on non-existent manifest file", () => {
      expect(() => parseCorpusManifest("non_existent_file.json")).toThrow(CorpusSchemaError);
    });

    test("detects duplicate case IDs in manifest", () => {
      const invalidManifest = {
        schemaVersion: "1.0.0",
        corpusName: "Duplicate Test",
        cases: [
          {
            id: "CASE-DUP",
            name: "Case 1",
            category: "vulnerable",
            targets: ["examples/benchmark-corpus/contracts/VulnerableVaultBench.sol"],
            expectedFindings: [],
          },
          {
            id: "CASE-DUP",
            name: "Case 2",
            category: "fixed",
            targets: ["examples/benchmark-corpus/contracts/SecureVaultBench.sol"],
            expectedFindings: [],
          },
        ],
      };

      expect(() => parseCorpusManifest(invalidManifest as any)).toThrow(CorpusSchemaError);
    });

    test("handles malformed JSON manifest gracefully", () => {
      const tempPath = path.join(__dirname, "temp_corrupt.json");
      fs.writeFileSync(tempPath, "{ invalid json ...", "utf-8");
      try {
        expect(() => parseCorpusManifest(tempPath)).toThrow(CorpusSchemaError);
      } finally {
        if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
      }
    });
  });

  describe("Evaluator & Precision Metrics", () => {
    const testCase: CorpusTestCase = {
      id: "TEST-01",
      name: "Test Case",
      category: "vulnerable",
      targets: ["contracts/Vault.sol"],
      expectedFindings: [
        { ruleId: "CP-107", severity: "critical", line: 10, lineTolerance: 2 },
        { ruleId: "CP-115", severity: "high", line: 20, lineTolerance: 2 },
      ],
    };

    test("correctly matches exact findings and computes TP/FP/FN", () => {
      const actual: Finding[] = [
        { id: "CP-107", severity: "critical", file: "contracts/Vault.sol", line: 10, title: "Reentrancy", description: "", recommendation: "" },
        { id: "CP-115", severity: "high", file: "contracts/Vault.sol", line: 20, title: "Tx Origin", description: "", recommendation: "" },
      ];

      const res = evaluateTestCase(testCase, actual, 100);
      expect(res.passed).toBe(true);
      expect(res.truePositives).toBe(2);
      expect(res.falsePositives).toBe(0);
      expect(res.falseNegatives).toBe(0);
    });

    test("detects unmatched expected findings as False Negatives", () => {
      const actual: Finding[] = [
        { id: "CP-107", severity: "critical", file: "contracts/Vault.sol", line: 10, title: "Reentrancy", description: "", recommendation: "" },
      ];

      const res = evaluateTestCase(testCase, actual, 100);
      expect(res.passed).toBe(false);
      expect(res.truePositives).toBe(1);
      expect(res.falseNegatives).toBe(1);
    });

    test("detects unmapped extra findings as False Positives", () => {
      const actual: Finding[] = [
        { id: "CP-107", severity: "critical", file: "contracts/Vault.sol", line: 10, title: "Reentrancy", description: "", recommendation: "" },
        { id: "CP-115", severity: "high", file: "contracts/Vault.sol", line: 20, title: "Tx Origin", description: "", recommendation: "" },
        { id: "CP-101", severity: "high", file: "contracts/Vault.sol", line: 30, title: "Overflow", description: "", recommendation: "" },
      ];

      const res = evaluateTestCase(testCase, actual, 100);
      expect(res.passed).toBe(false);
      expect(res.truePositives).toBe(2);
      expect(res.falsePositives).toBe(1);
    });

    test("calculates aggregate metrics, F-scores, and per-rule coverage accurately", () => {
      const res1 = evaluateTestCase(testCase, [
        { id: "CP-107", severity: "critical", file: "contracts/Vault.sol", line: 10, title: "Reentrancy", description: "", recommendation: "" },
        { id: "CP-115", severity: "high", file: "contracts/Vault.sol", line: 20, title: "Tx Origin", description: "", recommendation: "" },
      ], 100);

      const metrics = calculateBenchmarkMetrics([res1], 100, 1024 * 1024);
      expect(metrics.precision).toBe(1.0);
      expect(metrics.recall).toBe(1.0);
      expect(metrics.f1Score).toBe(1.0);
      expect(metrics.perRule["CP-107"].coverage.coverageRatio).toBe(1.0);
    });
  });

  describe("Mutation Engine", () => {
    test("creates a valid line-shift mutated variant and cleans up", () => {
      const repoRoot = path.resolve(__dirname, "../../../../../");
      const targetFile = path.join(repoRoot, "examples/benchmark-corpus/contracts/VulnerableVaultBench.sol");
      const mutant = createMutatedVariant(targetFile, "line-shift");
      expect(fs.existsSync(mutant.variantPath)).toBe(true);

      const content = fs.readFileSync(mutant.variantPath, "utf-8");
      expect(content).toContain("BENCHMARK MUTATION VARIANT: LINE SHIFT");

      mutant.cleanup();
      expect(fs.existsSync(mutant.variantPath)).toBe(false);
    });
  });

  describe("Regression Gate Evaluator", () => {
    const candidateReport: BenchmarkReport = {
      schemaVersion: "1.0.0",
      benchmarkId: "candidate_01",
      timestamp: new Date().toISOString(),
      engineVersion: "0.1.0",
      corpusName: "Test Corpus",
      metrics: {
        truePositives: 10,
        falsePositives: 2,
        falseNegatives: 1,
        trueNegatives: 5,
        precision: 0.8333,
        recall: 0.909,
        f1Score: 0.8695,
        f2Score: 0.892,
        f05Score: 0.847,
        perRule: {},
        perCategory: {} as any,
        falsePositiveCategories: {},
        runtimeMs: 1500,
        peakMemoryBytes: 50 * 1024 * 1024,
      },
      caseResults: [],
    };

    const baselineReport: BenchmarkReport = {
      ...candidateReport,
      benchmarkId: "baseline_01",
      metrics: {
        ...candidateReport.metrics,
        precision: 0.9,
        recall: 0.95,
        f1Score: 0.924,
        runtimeMs: 1400,
      },
    };

    test("evaluates gate thresholds successfully when candidate meets requirements", () => {
      const result = evaluateRegressionGate(candidateReport, undefined, {
        minPrecision: 0.8,
        minRecall: 0.8,
        minF1: 0.8,
      });
      expect(result.passed).toBe(true);
    });

    test("fails regression gate when precision drops below baseline limit", () => {
      const result = evaluateRegressionGate(candidateReport, baselineReport, {
        minPrecision: 0.8,
        maxPrecisionDrop: 0.02, // 0.9 -> 0.8333 is a 0.0667 drop
      });
      expect(result.passed).toBe(false);
      expect(result.checks.some((c) => c.name.includes("Precision Drop") && !c.passed)).toBe(true);
    });
  });

  describe("Benchmark Runner Integration", () => {
    test("runs end-to-end benchmark against real manifest", async () => {
      const report = await runBenchmark({
        manifestPath,
        mutateVariants: false,
      });

      expect(report.schemaVersion).toBe("1.0.0");
      expect(report.caseResults.length).toBeGreaterThanOrEqual(3);
      expect(report.metrics.truePositives).toBeGreaterThan(0);

      const markdown = generateBenchmarkMarkdownReport(report);
      expect(markdown).toContain("# Detector Benchmark Report");
      expect(markdown).toContain("Precision");

      const jsonStr = generateBenchmarkJSONReport(report);
      expect(JSON.parse(jsonStr).schemaVersion).toBe("1.0.0");
    });

    test("supports sharding execution deterministically", async () => {
      const shard0 = await runBenchmark({
        manifestPath,
        shardIndex: 0,
        totalShards: 2,
      });
      const shard1 = await runBenchmark({
        manifestPath,
        shardIndex: 1,
        totalShards: 2,
      });

      expect(shard0.caseResults.length + shard1.caseResults.length).toBeGreaterThanOrEqual(3);
    });
  });
});
