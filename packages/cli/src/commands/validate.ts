/**
 * `chainproof validate` — Fork-aware concrete validation CLI.
 *
 * Subcommands:
 *   plan      Translate static findings into reproduction scaffolds
 *   run       Execute scenarios against an EVM backend
 *   replay    Restore a snapshot and re-run a scenario
 *   minimize  Remove redundant calls from a scenario
 *   report    Format a saved ValidationReport as Markdown or JSON
 */

import * as fs from "fs";
import * as path from "path";
import { Command } from "commander";
import chalk from "chalk";
import {
  // Planning
  planValidation,
  serializeValidationPlan,
  parseValidationPlan,
  // Running
  runValidationPlan,
  minimizeScenario,
  // Adapters
  AnvilAdapter,
  HardhatAdapter,
  isAnvilAvailable,
  isHardhatAvailable,
  // Reports
  serializeValidationReport,
  generateValidationMarkdown,
  parseValidationReport,
  // Runner (single scenario)
  ValidationRunner,
  sanitizeScenario,
  // Errors
  ValidationError,
  CorruptBundleError,
  AdapterCrashError,
  ForkUnavailableError,
  createCancellationSignal,
} from "@chainproof/core";
import type {
  Finding,
  RunValidationOptions,
  ValidationReport,
  ValidationResult,
  ValidationScenario,
} from "@chainproof/core";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sanitizeCliError(err: unknown): string {
  if (err instanceof ValidationError) return err.message;
  if (err instanceof CorruptBundleError) return err.message;
  if (err instanceof AdapterCrashError) return err.message;
  if (err instanceof ForkUnavailableError) return err.message;
  if (err instanceof Error) {
    // Don't expose full stack or paths
    return err.message.replace(/\/[^\s"']+/g, "[path]").slice(0, 500);
  }
  return "Unexpected error during validation";
}

function writeOutput(outputPath: string | undefined, content: string): void {
  if (outputPath) {
    const dir = path.dirname(outputPath);
    if (dir && dir !== ".") {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, content, "utf8");
  } else {
    process.stdout.write(content);
    if (!content.endsWith("\n")) process.stdout.write("\n");
  }
}

function loadScanResult(file: string): Finding[] {
  const content = fs.readFileSync(file, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Could not parse scan result JSON from ${file}`);
  }
  const obj = parsed as Record<string, unknown>;
  // Support both ScanResult (with `files[].findings`) and flat `Finding[]`
  if (Array.isArray(obj)) {
    return obj as Finding[];
  }
  if (obj["files"] && Array.isArray(obj["files"])) {
    const findings: Finding[] = [];
    for (const file2 of obj["files"] as Array<Record<string, unknown>>) {
      if (Array.isArray(file2["findings"])) {
        findings.push(...(file2["findings"] as Finding[]));
      }
    }
    return findings;
  }
  throw new Error("Unrecognized scan result format");
}

function loadScenario(file: string): ValidationScenario {
  const content = fs.readFileSync(file, "utf8");
  try {
    return JSON.parse(content) as ValidationScenario;
  } catch {
    throw new CorruptBundleError(file, "Invalid JSON");
  }
}

async function detectAdapter(
  preferred: string | undefined,
  binaryPath?: string,
): Promise<"anvil" | "hardhat"> {
  if (preferred === "hardhat") return "hardhat";
  if (preferred === "anvil") return "anvil";
  // Auto-detect
  if (await isAnvilAvailable(binaryPath ?? "anvil")) return "anvil";
  if (await isHardhatAvailable("npx")) return "hardhat";
  throw new ValidationError(
    "No EVM adapter found. Install Foundry (anvil) or Hardhat (npx hardhat) and ensure they are on $PATH.",
    "ADAPTER_NOT_FOUND",
  );
}

// ─── Register command ─────────────────────────────────────────────────────────

export function registerValidateCommand(program: Command): void {
  const validate = program
    .command("validate")
    .description("Concrete validation and exploit reproduction harness");

  // ─── validate plan ──────────────────────────────────────────────────────────
  validate
    .command("plan <scan-result>")
    .description(
      "Translate static findings into reproduction scenario scaffolds. " +
        "<scan-result> is a JSON file produced by `chainproof scan --format json`.",
    )
    .option("--output <file>", "Write the validation plan to a JSON file")
    .option(
      "--min-severity <level>",
      "Only scaffold findings at or above this severity: critical|high|medium|low|info",
      "low",
    )
    .option(
      "--deduplicate-by-file",
      "Deduplicate findings by (id, file, line) rather than (id, file)",
    )
    .option("--format <format>", "Output format: json|table", "json")
    .action(async (scanResultFile: string, opts: {
      output?: string;
      minSeverity?: string;
      deduplicateByFile?: boolean;
      format?: string;
    }) => {
      try {
        const findings = loadScanResult(scanResultFile);
        const plan = planValidation(findings, {
          minSeverity: (opts.minSeverity ?? "low") as "critical" | "high" | "medium" | "low" | "info",
          deduplicateByFile: opts.deduplicateByFile ?? false,
        });

        if (opts.format === "table") {
          console.log(chalk.cyan("\n  Validation Plan\n"));
          console.log(`  Scenarios:  ${chalk.green(plan.scenarios.length)}`);
          console.log(`  Unsupported: ${chalk.yellow(plan.unsupportedFindings.length)}`);
          if (plan.scenarios.length > 0) {
            console.log("\n  Generated scenarios:");
            for (const s of plan.scenarios) {
              console.log(`    ${chalk.green("✓")} ${s.id}`);
              console.log(`      ${chalk.gray(s.title)}`);
            }
          }
          if (plan.unsupportedFindings.length > 0) {
            console.log("\n  Unsupported findings:");
            for (const u of plan.unsupportedFindings) {
              console.log(`    ${chalk.yellow("⚠")} ${u.findingId} @ ${u.findingFile}:${u.findingLine}`);
              console.log(`      ${chalk.gray(u.reason)}`);
            }
          }
        } else {
          const json = serializeValidationPlan(plan);
          if (opts.output) {
            writeOutput(opts.output, json);
            console.error(chalk.green(`Validation plan written to ${opts.output}`));
            console.error(`  ${plan.scenarios.length} scenario(s), ${plan.unsupportedFindings.length} unsupported finding(s)`);
          } else {
            writeOutput(undefined, json);
          }
        }
      } catch (err) {
        console.error(chalk.red(`validate plan failed: ${sanitizeCliError(err)}`));
        process.exit(2);
      }
    });

  // ─── validate run ───────────────────────────────────────────────────────────
  validate
    .command("run <plan-or-scenario>")
    .description(
      "Execute scenarios in a validation plan (or a single scenario JSON) against an EVM backend.",
    )
    .option("--adapter <type>", "EVM backend: anvil|hardhat (auto-detected if omitted)")
    .option("--adapter-bin <path>", "Explicit path to the adapter binary")
    .option("--fork-url <url>", "Fork RPC URL (overrides scenario chain.forkUrl)")
    .option("--fork-block <number>", "Fork block number to pin")
    .option("--chain-id <number>", "Chain ID override")
    .option("--timeout <ms>", "Per-scenario timeout in milliseconds", "30000")
    .option("--output <file>", "Write the validation report to a file")
    .option("--format <format>", "Output format: json|markdown", "json")
    .option("--fail-on-failure", "Exit 1 if any scenario fails or errors")
    .action(async (planFile: string, opts: {
      adapter?: string;
      adapterBin?: string;
      forkUrl?: string;
      forkBlock?: string;
      chainId?: string;
      timeout?: string;
      output?: string;
      format?: string;
      failOnFailure?: boolean;
    }) => {
      const { signal, cancel } = createCancellationSignal();

      // Handle Ctrl+C gracefully
      process.once("SIGINT", () => {
        console.error(chalk.yellow("\n  Cancelling..."));
        cancel();
      });

      try {
        // Load plan or single scenario
        const content = fs.readFileSync(planFile, "utf8");
        let parsed: unknown;
        try {
          parsed = JSON.parse(content);
        } catch {
          throw new CorruptBundleError(planFile, "Invalid JSON");
        }

        let scenarios: ValidationScenario[];
        const obj = parsed as Record<string, unknown>;
        if (Array.isArray(obj["scenarios"])) {
          // It's a ValidationPlan
          scenarios = obj["scenarios"] as ValidationScenario[];
        } else if (obj["id"] && obj["calls"]) {
          // Single scenario
          scenarios = [obj as unknown as ValidationScenario];
        } else {
          throw new CorruptBundleError(planFile, "Not a ValidationPlan or ValidationScenario");
        }

        if (scenarios.length === 0) {
          console.error(chalk.yellow("No scenarios to run."));
          process.exit(0);
        }

        const adapterType = await detectAdapter(opts.adapter, opts.adapterBin);
        console.error(chalk.cyan(`  Using ${adapterType} adapter`));
        console.error(chalk.cyan(`  Running ${scenarios.length} scenario(s)...\n`));

        const timeoutMs = opts.timeout ? parseInt(opts.timeout, 10) : 30_000;
        const runOpts: RunValidationOptions = {
          adapterType,
          adapterBinaryPath: opts.adapterBin,
          forkUrl: opts.forkUrl,
          forkBlockNumber: opts.forkBlock ? parseInt(opts.forkBlock, 10) : undefined,
          chainId: opts.chainId ? parseInt(opts.chainId, 10) : undefined,
          limits: { timeoutMs },
          signal,
        };

        const report = await runValidationPlan(scenarios, runOpts);

        const output = opts.format === "markdown"
          ? generateValidationMarkdown(report)
          : serializeValidationReport(report);

        if (opts.output) {
          writeOutput(opts.output, output);
          console.error(chalk.green(`\n  Report written to ${opts.output}`));
        } else {
          writeOutput(undefined, output);
        }

        console.error(
          `\n  ${chalk.green(report.passed)} passed, ` +
            `${chalk.red(report.failed)} failed, ` +
            `${chalk.yellow(report.errored)} errored ` +
            `(${report.total} total, ${report.totalDurationMs}ms)`,
        );

        if (opts.failOnFailure && (report.failed > 0 || report.errored > 0)) {
          process.exit(1);
        }
      } catch (err) {
        console.error(chalk.red(`validate run failed: ${sanitizeCliError(err)}`));
        process.exit(2);
      }
    });

  // ─── validate replay ────────────────────────────────────────────────────────
  validate
    .command("replay <result-file>")
    .description(
      "Restore a snapshot from a previous ValidationResult and replay the scenario.",
    )
    .option("--adapter <type>", "EVM backend: anvil|hardhat")
    .option("--adapter-bin <path>", "Explicit path to the adapter binary")
    .option("--fork-url <url>", "Fork RPC URL (required if scenario was forked)")
    .option("--output <file>", "Write the replay result to a file")
    .option("--format <format>", "Output format: json|markdown", "json")
    .action(async (resultFile: string, opts: {
      adapter?: string;
      adapterBin?: string;
      forkUrl?: string;
      output?: string;
      format?: string;
    }) => {
      try {
        const content = fs.readFileSync(resultFile, "utf8");
        let result: ValidationResult;
        try {
          result = JSON.parse(content) as ValidationResult;
        } catch {
          throw new CorruptBundleError(resultFile, "Invalid JSON");
        }

        if (!result.scenario) {
          throw new CorruptBundleError(resultFile, "Missing scenario in result");
        }

        const adapterType = await detectAdapter(
          opts.adapter ?? result.adapterType,
          opts.adapterBin,
        );
        console.error(chalk.cyan(`  Replaying with ${adapterType} adapter...`));

        const adapterOpts = {
          binaryPath: opts.adapterBin,
          forkUrl: opts.forkUrl ?? (result.scenario.chain?.forkUrl !== "[redacted]" ? result.scenario.chain?.forkUrl : undefined),
          forkBlockNumber: result.snapshotBlock > 0 ? result.snapshotBlock : undefined,
          chainId: result.scenario.chain?.chainId,
        };

        const adapter = adapterType === "hardhat"
          ? new HardhatAdapter(adapterOpts)
          : new AnvilAdapter(adapterOpts);

        try {
          await adapter.start();
          const runner = new ValidationRunner(adapter);
          // Re-run the scenario from scratch (snapshot from original run may be unavailable)
          const replayResult = await runner.run(result.scenario);

          const output = opts.format === "markdown"
            ? `# Replay Result\n\n${generateValidationMarkdown({
                schemaVersion: replayResult.schemaVersion,
                timestamp: new Date().toISOString(),
                total: 1,
                passed: replayResult.outcomeMatched ? 1 : 0,
                failed: replayResult.outcomeMatched ? 0 : 1,
                errored: replayResult.error ? 1 : 0,
                results: [replayResult],
                adapterType,
                totalDurationMs: replayResult.durationMs,
              })}`
            : JSON.stringify(replayResult, null, 2);

          writeOutput(opts.output, output);
          if (opts.output) {
            console.error(chalk.green(`  Replay result written to ${opts.output}`));
          }
          console.error(
            replayResult.outcomeMatched
              ? chalk.green("  ✅ Replay: PASSED")
              : chalk.red("  ❌ Replay: FAILED"),
          );
        } finally {
          await adapter.dispose().catch(() => {/* ignore */});
        }
      } catch (err) {
        console.error(chalk.red(`validate replay failed: ${sanitizeCliError(err)}`));
        process.exit(2);
      }
    });

  // ─── validate minimize ──────────────────────────────────────────────────────
  validate
    .command("minimize <scenario-file>")
    .description("Remove redundant calls from a scenario while preserving the outcome.")
    .option("--adapter <type>", "EVM backend: anvil|hardhat")
    .option("--adapter-bin <path>", "Explicit path to the adapter binary")
    .option("--fork-url <url>", "Fork RPC URL")
    .option("--max-trials <number>", "Maximum scenario re-executions", "50")
    .option("--output <file>", "Write the minimized scenario to a file")
    .action(async (scenarioFile: string, opts: {
      adapter?: string;
      adapterBin?: string;
      forkUrl?: string;
      maxTrials?: string;
      output?: string;
    }) => {
      try {
        const scenario = loadScenario(scenarioFile);
        const adapterType = await detectAdapter(opts.adapter, opts.adapterBin);
        console.error(chalk.cyan(`  Minimizing with ${adapterType} adapter...`));
        console.error(`  Original: ${scenario.calls.length} call(s)`);

        const adapterOpts = {
          binaryPath: opts.adapterBin,
          forkUrl: opts.forkUrl ?? scenario.chain.forkUrl,
          forkBlockNumber: scenario.chain.forkBlockNumber,
          chainId: scenario.chain.chainId,
        };

        const adapter = adapterType === "hardhat"
          ? new HardhatAdapter(adapterOpts)
          : new AnvilAdapter(adapterOpts);

        try {
          await adapter.start();
          const maxTrials = opts.maxTrials ? parseInt(opts.maxTrials, 10) : 50;
          const minResult = await minimizeScenario(scenario, adapter, { maxTrials });

          console.error(`  Minimized: ${minResult.minimizedCallCount} call(s) (removed ${minResult.originalCallCount - minResult.minimizedCallCount})`);
          console.error(`  Trials used: ${minResult.trialsUsed}`);
          if (minResult.budgetExceeded) {
            console.error(chalk.yellow("  ⚠ Trial budget exceeded — minimization incomplete"));
          }

          const json = JSON.stringify(minResult.minimizedScenario, null, 2);
          writeOutput(opts.output, json);
          if (opts.output) {
            console.error(chalk.green(`  Minimized scenario written to ${opts.output}`));
          }
        } finally {
          await adapter.dispose().catch(() => {/* ignore */});
        }
      } catch (err) {
        console.error(chalk.red(`validate minimize failed: ${sanitizeCliError(err)}`));
        process.exit(2);
      }
    });

  // ─── validate report ────────────────────────────────────────────────────────
  validate
    .command("report <report-file>")
    .description("Format a saved ValidationReport as Markdown or JSON.")
    .option("--format <format>", "Output format: json|markdown", "markdown")
    .option("--output <file>", "Write the report to a file")
    .option("--fail-on-failure", "Exit 1 if any scenario failed or errored")
    .action(async (reportFile: string, opts: {
      format?: string;
      output?: string;
      failOnFailure?: boolean;
    }) => {
      try {
        const content = fs.readFileSync(reportFile, "utf8");
        const report = parseValidationReport(content, reportFile);

        const output = opts.format === "json"
          ? serializeValidationReport(report)
          : generateValidationMarkdown(report);

        writeOutput(opts.output, output);
        if (opts.output) {
          console.error(chalk.green(`  Report written to ${opts.output}`));
        }

        if (opts.failOnFailure && (report.failed > 0 || report.errored > 0)) {
          process.exit(1);
        }
      } catch (err) {
        console.error(chalk.red(`validate report failed: ${sanitizeCliError(err)}`));
        process.exit(2);
      }
    });
}
