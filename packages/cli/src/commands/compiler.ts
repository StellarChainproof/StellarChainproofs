/**
 * @packageDocumentation
 * @chainproof/cli — Compiler Compatibility & Diagnostic Matrix Commands
 */

import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs";
import {
  inspectCompilerPragmas,
  buildCompilerMatrix,
  compareCompilerVersions,
  auditCompilerCompatibility,
  serializeCompilerAuditJSON,
  generateCompilerMarkdownReport,
  generateCompilerTableReport,
  generateCompilerInspectMarkdown,
  generateCompilerCompareMarkdown,
  loadCompilerConfigFile,
  stableStringify,
  CompilerConfigError,
} from "@chainproof/core";
import type {
  CompilerAnalysisOptions,
  CompilerAnalysisLimits,
  CompilerRuleId,
} from "@chainproof/core";

type OutputFormat = "table" | "json" | "markdown";
type FailSeverity = "none" | "info" | "low" | "medium" | "high" | "critical";

const SEVERITY_RANK: Record<FailSeverity, number> = {
  none: 99,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

function positiveInteger(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new CompilerConfigError("Limit option must be a positive integer.");
  }
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result <= 0) {
    throw new CompilerConfigError("Limit option must be a safe positive integer.");
  }
  return result;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function sanitize(message: string): string {
  return message.replace(/[\r\n]+/g, " ").slice(0, 500);
}

function writeReport(file: string, output: string): void {
  try {
    fs.writeFileSync(file, output, "utf-8");
  } catch (err) {
    throw new CompilerConfigError(`Report file could not be written to ${file}`);
  }
}

export function registerCompilerCommand(program: Command, printBanner: () => void): void {
  const compiler = program
    .command("compiler")
    .description("Solidity multi-compiler compatibility, diagnostic matrix, and cross-version diffs");

  // ─── compiler inspect ───────────────────────────────────────────────────────
  compiler
    .command("inspect <targets...>")
    .description("Inspect pragma constraints, resolution, floating ranges, and hazards across imports")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write inspection report to file")
    .option("--config <file>", "Load compiler configuration file")
    .action((targets: string[], opts: { format: OutputFormat; output?: string; config?: string }) => {
      if (opts.format === "table") printBanner();
      try {
        const config = opts.config ? loadCompilerConfigFile(opts.config) : undefined;
        const resolution = inspectCompilerPragmas(targets, { config });

        let outputStr: string;
        if (opts.format === "json") {
          outputStr = stableStringify(resolution);
        } else if (opts.format === "markdown") {
          outputStr = generateCompilerInspectMarkdown(resolution);
        } else {
          const lines: string[] = [];
          lines.push(chalk.bold("\n  Solidity Pragma Inspection & Compatibility Resolution\n"));
          lines.push(
            chalk.gray(
              `  Files Inspected  : ${resolution.totalFiles}\n` +
              `  Global Range     : ${chalk.cyan(resolution.globalRange)}\n` +
              `  Recommended Solc : ${chalk.green(resolution.recommendedVersion || "None")}\n` +
              `  Satisfiable      : ${resolution.unsatisfiable ? chalk.red("NO (Conflicting Pragmas)") : chalk.green("YES")}\n` +
              `  Floating Pragmas : ${resolution.hasFloatingPragmas ? chalk.yellow("Yes") : chalk.green("No")}\n` +
              `  Broad Ranges     : ${resolution.hasBroadPragmas ? chalk.yellow("Yes") : chalk.green("No")}\n` +
              `  Sensitive Pre-0.8: ${resolution.hasSecuritySensitivePragmas ? chalk.red("Yes") : chalk.green("No")}\n`,
            ),
          );

          lines.push(chalk.bold("  File Breakdown:"));
          for (const f of resolution.files) {
            const status = f.isSecuritySensitive
              ? chalk.red("[SENSITIVE]")
              : f.isFloating
              ? chalk.yellow("[FLOATING]")
              : chalk.green("[PINNED]");
            lines.push(`  ${status} ${f.file}:${f.line} -> ${chalk.cyan(f.rawPragma)} (${f.rangeDescription})`);
          }
          lines.push("");

          if (resolution.unsatisfiable && resolution.conflictDetails) {
            lines.push(chalk.red.bold("  ❌ Pairwise Pragma Conflicts:"));
            for (const conf of resolution.conflictDetails) {
              lines.push(chalk.red(`    - ${conf}`));
            }
            lines.push("");
          }

          outputStr = lines.join("\n");
        }

        if (opts.output) {
          writeReport(opts.output, outputStr);
          if (opts.format === "table") {
            console.log(chalk.green(`\n  ✅ Inspection output written to ${opts.output}`));
          }
        } else {
          console.log(outputStr);
        }

        process.exit(resolution.unsatisfiable ? 1 : 0);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`\n  Compiler inspect error: ${sanitize(msg)}`));
        process.exit(2);
      }
    });

  // ─── compiler matrix ────────────────────────────────────────────────────────
  compiler
    .command("matrix <targets...>")
    .description("Evaluate and test contracts across a matrix of Solidity compiler versions")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write matrix report to file")
    .option("--config <file>", "Load compiler configuration file")
    .option("--versions <list>", "Comma-separated compiler versions to test (e.g. 0.7.6,0.8.0,0.8.20,0.8.28)")
    .option("--evm-version <evm>", "EVM version target (e.g. paris, shanghai, cancun)")
    .option("--no-optimizer", "Disable Solidity compiler optimizer")
    .option("--optimizer-runs <n>", "Optimizer runs", positiveInteger)
    .option("--via-ir", "Enable via-IR compilation pipeline")
    .option(
      "--fail-on <severity>",
      "Exit 1 if matrix contains hazards at or above severity: none|info|low|medium|high|critical",
      "high",
    )
    .action(
      async (
        targets: string[],
        opts: {
          format: OutputFormat;
          output?: string;
          config?: string;
          versions?: string;
          evmVersion?: string;
          optimizer: boolean;
          optimizerRuns?: number;
          viaIr?: boolean;
          failOn: FailSeverity;
        },
      ) => {
        if (opts.format === "table") printBanner();
        try {
          const configured = opts.config ? loadCompilerConfigFile(opts.config) : undefined;
          const targetVersions = opts.versions
            ? opts.versions.split(",").map((v) => v.trim())
            : configured?.targetVersions;

          const options: CompilerAnalysisOptions = {
            config: configured,
            targetVersions,
            evmVersion: opts.evmVersion || configured?.defaultEvmVersion,
            optimizer: {
              enabled: opts.optimizer,
              runs: opts.optimizerRuns ?? configured?.optimizer.runs ?? 200,
              viaIR: opts.viaIr ?? configured?.optimizer.viaIR ?? false,
            },
          };

          const grid = await buildCompilerMatrix(targets, options);

          let outputStr: string;
          if (opts.format === "json") {
            outputStr = stableStringify(grid);
          } else if (opts.format === "markdown") {
            const lines: string[] = [];
            lines.push("# Solidity Compiler Compatibility Matrix");
            lines.push("");
            lines.push(`- **Supported Range:** \`${grid.summary.supportedRange}\``);
            lines.push(`- **Recommended Version:** \`${grid.summary.recommendedVersion || "N/A"}\``);
            lines.push(`- **Fully Compatible:** ${grid.summary.fullyCompatibleVersions.join(", ") || "None"}`);
            lines.push(`- **Critical Hazards:** ${grid.summary.criticalHazardsFound}`);
            lines.push("");
            lines.push("| Contract | File | " + grid.targetVersions.map((v) => `v${v}`).join(" | ") + " |");
            lines.push("| --- | --- | " + grid.targetVersions.map(() => "---").join(" | ") + " |");
            for (const row of grid.rows) {
              const cells = grid.targetVersions.map((v) => {
                const c = row.cells[v];
                if (!c) return "-";
                if (c.status === "compatible") return "🟢 PASS";
                if (c.status === "warning") return `🟡 WARN (${c.warningsCount})`;
                if (c.status === "hazard") return `🟣 HAZARD (${c.hazards.length})`;
                return "🔴 INCOMPATIBLE";
              });
              lines.push(`| \`${row.contract}\` | \`${row.file}\` | ${cells.join(" | ")} |`);
            }
            outputStr = lines.join("\n");
          } else {
            const lines: string[] = [];
            lines.push(chalk.bold("\n  Solidity Multi-Compiler Compatibility Matrix Grid\n"));
            lines.push(
              chalk.gray(
                `  Contracts Evaluated : ${grid.summary.totalContracts}\n` +
                `  Tested Versions     : ${grid.targetVersions.join(", ")}\n` +
                `  Recommended Version : ${chalk.green(grid.summary.recommendedVersion || "N/A")}\n` +
                `  Critical Hazards    : ${grid.summary.criticalHazardsFound > 0 ? chalk.red(grid.summary.criticalHazardsFound) : chalk.green("0")}\n`,
              ),
            );

            const vHeaders = grid.targetVersions.map((v) => v.padEnd(8)).join(" ");
            lines.push(chalk.gray(`  ${"Contract".padEnd(24)} ${vHeaders}`));
            lines.push(chalk.gray(`  ${"-".repeat(24 + grid.targetVersions.length * 9)}`));

            for (const row of grid.rows) {
              const cells = grid.targetVersions
                .map((v) => {
                  const c = row.cells[v];
                  if (!c) return chalk.gray("-".padEnd(8));
                  if (c.status === "compatible") return chalk.green("PASS".padEnd(8));
                  if (c.status === "warning") return chalk.yellow("WARN".padEnd(8));
                  if (c.status === "hazard") return chalk.magenta("HAZARD".padEnd(8));
                  return chalk.red("FAIL".padEnd(8));
                })
                .join(" ");

              lines.push(`  ${chalk.cyan(row.contract.slice(0, 22).padEnd(24))} ${cells}`);
            }
            lines.push("");
            outputStr = lines.join("\n");
          }

          if (opts.output) {
            writeReport(opts.output, outputStr);
            if (opts.format === "table") {
              console.log(chalk.green(`\n  ✅ Matrix output written to ${opts.output}`));
            }
          } else {
            console.log(outputStr);
          }

          const hasFailures =
            grid.summary.incompatibleVersions.length > 0 ||
            (opts.failOn !== "none" && grid.summary.criticalHazardsFound > 0);

          process.exit(hasFailures ? 1 : 0);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(chalk.red(`\n  Compiler matrix error: ${sanitize(msg)}`));
          process.exit(2);
        }
      },
    );

  // ─── compiler compare ──────────────────────────────────────────────────────
  compiler
    .command("compare <targets...>")
    .description("Compare ABI, storage layout, bytecode size, and diagnostics across two compiler versions")
    .requiredOption("--versions <v1,v2>", "Two comma-separated compiler versions to compare (e.g. 0.7.6,0.8.20)")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write comparison report to file")
    .option("--config <file>", "Load compiler configuration file")
    .option("--evm-version <evm>", "EVM target version")
    .option("--fail-on-drift", "Exit 1 if storage layout collision or ABI breaking drift is detected")
    .action(
      async (
        targets: string[],
        opts: {
          versions: string;
          format: OutputFormat;
          output?: string;
          config?: string;
          evmVersion?: string;
          failOnDrift?: boolean;
        },
      ) => {
        if (opts.format === "table") printBanner();
        try {
          const configured = opts.config ? loadCompilerConfigFile(opts.config) : undefined;
          const versionsArr = opts.versions.split(",").map((v) => v.trim());
          if (versionsArr.length !== 2) {
            throw new CompilerConfigError("--versions must specify exactly two comma-separated versions.");
          }

          const versions: [string, string] = [versionsArr[0], versionsArr[1]];
          const options: CompilerAnalysisOptions = {
            config: configured,
            evmVersion: opts.evmVersion || configured?.defaultEvmVersion,
          };

          const comparisons = await compareCompilerVersions(targets, versions, options);

          let outputStr: string;
          if (opts.format === "json") {
            outputStr = stableStringify(comparisons);
          } else if (opts.format === "markdown") {
            outputStr = generateCompilerCompareMarkdown(comparisons);
          } else {
            const lines: string[] = [];
            lines.push(
              chalk.bold(`\n  Solidity Version Differential: v${versions[0]} vs v${versions[1]}\n`),
            );

            for (const comp of comparisons) {
              const statusColor =
                comp.compatibilityStatus === "compatible"
                  ? chalk.green
                  : comp.compatibilityStatus === "warning"
                  ? chalk.yellow
                  : chalk.red;

              lines.push(
                `  Contract: ${chalk.cyan.bold(comp.contractName)} [${statusColor(comp.compatibilityStatus.toUpperCase())}]`,
              );
              lines.push(
                chalk.gray(
                  `    Bytecode Delta : ${comp.bytecodeDiff.sizeDeltaBytes > 0 ? "+" : ""}${comp.bytecodeDiff.sizeDeltaBytes} B (${comp.bytecodeDiff.sizeDeltaPercent}%)\n` +
                  `    PUSH0 Opcode   : Base=${comp.bytecodeDiff.baseHasPush0} | Target=${comp.bytecodeDiff.targetHasPush0}${comp.bytecodeDiff.push0Hazard ? chalk.red(" ⚠️ PUSH0 introduced!") : ""}\n` +
                  `    ABI Identical  : ${comp.abiDiff.identical ? chalk.green("YES") : chalk.yellow("NO (Modified)")}\n` +
                  `    Storage Layout : ${comp.storageLayoutDiff.identical ? chalk.green("IDENTICAL") : chalk.red("DRIFT DETECTED")}\n`,
                ),
              );

              if (comp.storageLayoutDiff.slotCollisions.length > 0) {
                lines.push(chalk.red.bold("    🚨 Storage Collisions / Slot Shifts:"));
                for (const col of comp.storageLayoutDiff.slotCollisions) {
                  lines.push(chalk.red(`      - ${col.variable}: ${col.reason}`));
                }
              }

              if (!comp.abiDiff.identical) {
                lines.push(chalk.yellow("    ⚠️ ABI Changes:"));
                if (comp.abiDiff.addedFunctions.length) {
                  lines.push(chalk.gray(`      Added functions: ${comp.abiDiff.addedFunctions.join(", ")}`));
                }
                if (comp.abiDiff.removedFunctions.length) {
                  lines.push(chalk.gray(`      Removed functions: ${comp.abiDiff.removedFunctions.join(", ")}`));
                }
              }
              lines.push("");
            }
            outputStr = lines.join("\n");
          }

          if (opts.output) {
            writeReport(opts.output, outputStr);
            if (opts.format === "table") {
              console.log(chalk.green(`\n  ✅ Comparison written to ${opts.output}`));
            }
          } else {
            console.log(outputStr);
          }

          const hasDrift = comparisons.some(
            (c) => c.compatibilityStatus === "breaking_drift" || c.compatibilityStatus === "hazard",
          );

          process.exit(opts.failOnDrift && hasDrift ? 1 : 0);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(chalk.red(`\n  Compiler compare error: ${sanitize(msg)}`));
          process.exit(2);
        }
      },
    );

  // ─── compiler audit ────────────────────────────────────────────────────────
  compiler
    .command("audit <targets...>")
    .description("Run a full multi-compiler compatibility audit with pragma, matrix, diff, and hazard checks")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write audit report to file")
    .option("--config <file>", "Load compiler configuration file")
    .option("--versions <list>", "Comma-separated list of compiler versions to test")
    .option("--compare-versions <v1,v2>", "Explicit two versions to compare in differential analysis")
    .option("--include-rule <id>", "Only run rule (repeatable)", collect, [])
    .option("--exclude-rule <id>", "Skip rule (repeatable)", collect, [])
    .option("--max-source-bytes <n>", "Maximum bytes per source file", positiveInteger)
    .option("--max-files <n>", "Maximum number of source files", positiveInteger)
    .option("--max-contracts <n>", "Maximum contracts to evaluate", positiveInteger)
    .option("--max-findings <n>", "Maximum findings in report", positiveInteger)
    .option(
      "--fail-on <severity>",
      "Exit 1 if findings at or above severity exist: none|info|low|medium|high|critical",
      "high",
    )
    .action(
      async (
        targets: string[],
        opts: {
          format: OutputFormat;
          output?: string;
          config?: string;
          versions?: string;
          compareVersions?: string;
          includeRule: string[];
          excludeRule: string[];
          maxSourceBytes?: number;
          maxFiles?: number;
          maxContracts?: number;
          maxFindings?: number;
          failOn: FailSeverity;
        },
      ) => {
        if (opts.format === "table") printBanner();
        try {
          const configured = opts.config ? loadCompilerConfigFile(opts.config) : undefined;
          const targetVersions = opts.versions
            ? opts.versions.split(",").map((v) => v.trim())
            : configured?.targetVersions;

          let compareVersions: [string, string] | undefined = configured?.compareVersions;
          if (opts.compareVersions) {
            const arr = opts.compareVersions.split(",").map((v) => v.trim());
            if (arr.length === 2) {
              compareVersions = [arr[0], arr[1]];
            }
          }

          const limits: Partial<CompilerAnalysisLimits> = {
            ...configured?.limits,
            ...(opts.maxSourceBytes ? { maxSourceBytes: opts.maxSourceBytes } : {}),
            ...(opts.maxFiles ? { maxFiles: opts.maxFiles } : {}),
            ...(opts.maxContracts ? { maxContracts: opts.maxContracts } : {}),
            ...(opts.maxFindings ? { maxFindings: opts.maxFindings } : {}),
          };

          const includeRules = opts.includeRule.length
            ? (opts.includeRule as CompilerRuleId[])
            : configured?.includeRules;
          const excludeRules = opts.excludeRule.length
            ? (opts.excludeRule as CompilerRuleId[])
            : configured?.excludeRules;

          const options: CompilerAnalysisOptions = {
            config: configured,
            limits,
            targetVersions,
            compareVersions,
            includeRules,
            excludeRules,
          };

          const report = await auditCompilerCompatibility(targets, options);

          let outputStr: string;
          if (opts.format === "json") {
            outputStr = serializeCompilerAuditJSON(report);
          } else if (opts.format === "markdown") {
            outputStr = generateCompilerMarkdownReport(report);
          } else {
            outputStr = generateCompilerTableReport(report);
          }

          if (opts.output) {
            writeReport(opts.output, outputStr);
            if (opts.format === "table") {
              console.log(chalk.green(`\n  ✅ Audit report written to ${opts.output}`));
            }
          } else {
            console.log(outputStr);
          }

          const minRank = SEVERITY_RANK[opts.failOn];
          const hasFailingFindings = report.findings.some(
            (f) => (SEVERITY_RANK[f.severity as FailSeverity] || 0) >= minRank,
          );

          const exitCode =
            !report.summary.passed || (opts.failOn !== "none" && hasFailingFindings) ? 1 : 0;

          process.exit(exitCode);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(chalk.red(`\n  Compiler audit error: ${sanitize(msg)}`));
          process.exit(2);
        }
      },
    );
}
