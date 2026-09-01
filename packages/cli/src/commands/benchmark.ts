import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import type { Command } from "commander";
import {
  runBenchmark,
  evaluateRegressionGate,
  generateBenchmarkJSONReport,
  generateBenchmarkMarkdownReport,
  generateBenchmarkTableReport,
  generateGateMarkdownReport,
  parseCorpusManifest,
  parseThresholdExceptions,
  BENCHMARK_CORPUS_SCHEMA_VERSION,
  type BenchmarkReport,
  type CorpusManifest,
  type MutationType,
} from "@chainproof/core";

export function registerBenchmarkCommand(program: Command): void {
  const benchmarkGroup = program
    .command("benchmark")
    .description("Versioned detector benchmark corpus and precision regression framework");

  // Subcommand: run
  benchmarkGroup
    .command("run <manifestPath>")
    .description("Run a detector benchmark against a versioned corpus manifest")
    .option("--baseline <file>", "Baseline benchmark report to compare against")
    .option("--output <file>", "Output report file path")
    .option("--format <format>", "Output format: json|markdown|table", "table")
    .option("--shard <index/total>", "Shard execution (e.g. 0/4)")
    .option("--sample <count>", "Sample a subset of test cases deterministically")
    .option("--seed <number>", "Random seed for deterministic sampling", "42")
    .option("--mutate", "Run mutation variants on test fixtures")
    .option("--min-precision <val>", "Minimum precision threshold", "0.8")
    .option("--min-recall <val>", "Minimum recall threshold", "0.8")
    .option("--min-f1 <val>", "Minimum F1 score threshold", "0.8")
    .option("--exceptions <file>", "Reviewed threshold exceptions JSON file")
    .option("--slither", "Include Slither findings in scan")
    .action(async (manifestPath: string, options: Record<string, string | boolean>) => {
      try {
        let shardIndex: number | undefined;
        let totalShards: number | undefined;

        if (typeof options.shard === "string") {
          const parts = options.shard.split("/");
          if (parts.length === 2) {
            shardIndex = parseInt(parts[0], 10);
            totalShards = parseInt(parts[1], 10);
          }
        }

        const mutateTypes: MutationType[] = options.mutate
          ? ["line-shift", "comment-noise", "format-churn"]
          : [];

        const report = await runBenchmark({
          manifestPath,
          shardIndex,
          totalShards,
          sampleCount: options.sample ? parseInt(String(options.sample), 10) : undefined,
          sampleSeed: parseInt(String(options.seed), 10),
          mutateVariants: Boolean(options.mutate),
          mutateTypes,
          useSlither: Boolean(options.slither),
        });

        // Serialization
        const format = (options.format as string) || "table";
        let outputText = "";
        if (format === "json") {
          outputText = generateBenchmarkJSONReport(report);
        } else if (format === "markdown") {
          outputText = generateBenchmarkMarkdownReport(report);
        } else {
          outputText = generateBenchmarkTableReport(report);
        }

        // Evaluate regression gate if baseline or min thresholds set
        let baselineReport: BenchmarkReport | undefined;
        if (typeof options.baseline === "string" && fs.existsSync(options.baseline)) {
          baselineReport = JSON.parse(fs.readFileSync(options.baseline, "utf-8")) as BenchmarkReport;
        }

        const exceptionsFile =
          typeof options.exceptions === "string" && fs.existsSync(options.exceptions)
            ? parseThresholdExceptions(options.exceptions)
            : undefined;

        const gateResult = evaluateRegressionGate(
          report,
          baselineReport,
          {
            minPrecision: parseFloat(String(options.minPrecision)),
            minRecall: parseFloat(String(options.minRecall)),
            minF1: parseFloat(String(options.minF1)),
          },
          exceptionsFile,
        );

        if (options.output && typeof options.output === "string") {
          fs.writeFileSync(options.output, outputText, "utf-8");
          if (format !== "json") {
            console.log(chalk.green(`Benchmark report saved to ${options.output}`));
          }
        } else {
          process.stdout.write(outputText + "\n");
        }

        if (format !== "json") {
          if (!gateResult.passed) {
            console.error(chalk.red(`\n${gateResult.summary}`));
          } else {
            console.log(chalk.green(`\n${gateResult.summary}`));
          }
        }

        if (!gateResult.passed) {
          process.exitCode = 1;
        }
      } catch (err) {
        console.error(chalk.red(`Benchmark failed: ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 2;
      }
    });

  // Subcommand: compare
  benchmarkGroup
    .command("compare <baselineReport> <candidateReport>")
    .description("Compare candidate benchmark report against baseline for precision regression")
    .option("--exceptions <file>", "Reviewed threshold exceptions JSON file")
    .option("--min-precision <val>", "Minimum precision threshold", "0.8")
    .option("--min-recall <val>", "Minimum recall threshold", "0.8")
    .option("--min-f1 <val>", "Minimum F1 threshold", "0.8")
    .option("--max-prec-drop <val>", "Maximum allowed precision drop", "0.05")
    .option("--max-rec-drop <val>", "Maximum allowed recall drop", "0.05")
    .option("--max-runtime-reg <pct>", "Maximum allowed runtime regression percentage", "20")
    .option("--format <format>", "Output format: json|markdown|table", "markdown")
    .option("--output <file>", "Write gate comparison report to file")
    .action((baselinePath: string, candidatePath: string, options: Record<string, string>) => {
      try {
        const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf-8")) as BenchmarkReport;
        const candidate = JSON.parse(fs.readFileSync(candidatePath, "utf-8")) as BenchmarkReport;

        const exceptionsFile = options.exceptions ? parseThresholdExceptions(options.exceptions) : undefined;

        const gateResult = evaluateRegressionGate(
          candidate,
          baseline,
          {
            minPrecision: parseFloat(options.minPrecision),
            minRecall: parseFloat(options.minRecall),
            minF1: parseFloat(options.minF1),
            maxPrecisionDrop: parseFloat(options.maxPrecDrop),
            maxRecallDrop: parseFloat(options.maxRecDrop),
            maxRuntimeRegressionPct: parseFloat(options.maxRuntimeReg),
          },
          exceptionsFile,
        );

        const outputText =
          options.format === "json"
            ? JSON.stringify(gateResult, null, 2)
            : generateGateMarkdownReport(gateResult);

        if (options.output) {
          fs.writeFileSync(options.output, outputText, "utf-8");
          console.log(chalk.green(`Comparison gate report written to ${options.output}`));
        } else {
          console.log(outputText);
        }

        if (!gateResult.passed) {
          process.exitCode = 1;
        }
      } catch (err) {
        console.error(chalk.red(`Comparison failed: ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 2;
      }
    });

  // Subcommand: validate
  benchmarkGroup
    .command("validate <manifestPath>")
    .description("Validate schema and test fixture paths for a benchmark corpus manifest")
    .action((manifestPath: string) => {
      try {
        const { manifest, diagnostics } = parseCorpusManifest(manifestPath);
        console.log(chalk.green(`Corpus manifest '${manifest.corpusName}' is valid with ${manifest.cases.length} case(s).`));
        if (diagnostics.length > 0) {
          for (const d of diagnostics) {
            const color = d.severity === "error" ? chalk.red : chalk.yellow;
            console.log(color(`[${d.severity.toUpperCase()}] ${d.message}`));
          }
        }
      } catch (err) {
        console.error(chalk.red(`Corpus manifest validation failed: ${err instanceof Error ? err.message : String(err)}`));
        process.exitCode = 1;
      }
    });

  // Subcommand: init
  benchmarkGroup
    .command("init [outputPath]")
    .description("Scaffold a new versioned detector benchmark corpus manifest")
    .option("-f, --force", "Overwrite existing file if it exists")
    .action((outputPathArg: string | undefined, options: { force?: boolean }) => {
      const targetPath = path.resolve(outputPathArg || "corpus.manifest.json");
      if (fs.existsSync(targetPath) && !options.force) {
        console.error(chalk.red(`File already exists: ${targetPath}. Use --force to overwrite.`));
        process.exitCode = 1;
        return;
      }

      const starterManifest: CorpusManifest = {
        schemaVersion: BENCHMARK_CORPUS_SCHEMA_VERSION,
        corpusName: "ChainProof Standard Detector Benchmark Corpus",
        description: "Benchmark test cases for vulnerability detector precision and recall evaluation",
        cases: [
          {
            id: "CASE-REENTRANCY-001",
            name: "Vulnerable Vault Classic Reentrancy",
            category: "vulnerable",
            targets: ["examples/contracts/VulnerableVault.sol"],
            expectedFindings: [
              {
                ruleId: "CP-107",
                severity: "critical",
                line: 23,
                lineTolerance: 5,
                snippet: "withdraw",
                confidence: "high",
              },
            ],
            provenance: {
              author: "ChainProof Security Research",
              license: "MIT",
            },
          },
        ],
      };

      fs.writeFileSync(targetPath, JSON.stringify(starterManifest, null, 2), "utf-8");
      console.log(chalk.green(`Scaffolded benchmark corpus manifest at ${targetPath}`));
    });
}
