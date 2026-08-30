/**
 * @packageDocumentation
 * @chainproof/cli — Denial-of-Service, Gas-Griefing & Unbounded-Work Commands
 */

import { Command } from "commander";
import chalk from "chalk";
import * as fs from "fs";
import {
  inspectDosLoops,
  inspectDosCallFanOut,
  auditDosSafety,
  serializeDosAuditJSON,
  generateDosMarkdownReport,
  generateDosTableReport,
  generateDosLoopsMarkdown,
  generateDosFanoutMarkdown,
  loadDosConfigFile,
  stableStringify,
  DosConfigError,
} from "@chainproof/core";
import type {
  DosAnalysisOptions,
  DosAnalysisLimits,
  DosRuleId,
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
    throw new DosConfigError("Limit option must be a positive integer.");
  }
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result <= 0) {
    throw new DosConfigError("Limit option must be a safe positive integer.");
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
    throw new DosConfigError(`Report file could not be written to ${file}`);
  }
}

export function registerDosCommand(program: Command, printBanner: () => void): void {
  const dos = program
    .command("dos")
    .description("Solidity Denial-of-Service, gas-griefing, and unbounded-work analysis");

  // ─── dos inspect-loops ──────────────────────────────────────────────────────
  dos
    .command("inspect-loops <targets...>")
    .description("Inspect loop bounds, termination conditions, and storage array dependencies")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write inspection report to file")
    .option("--config <file>", "Load DoS configuration file")
    .action((targets: string[], opts: { format: OutputFormat; output?: string; config?: string }) => {
      if (opts.format === "table") printBanner();
      try {
        const config = opts.config ? loadDosConfigFile(opts.config) : undefined;
        const loops = inspectDosLoops(targets, { config });

        let outputStr: string;
        if (opts.format === "json") {
          outputStr = stableStringify(loops);
        } else if (opts.format === "markdown") {
          outputStr = generateDosLoopsMarkdown(loops);
        } else {
          const lines: string[] = [];
          lines.push(chalk.bold("\n  Solidity Loop Bounds & Complexity Inspection\n"));
          lines.push(chalk.gray(`  Total Loops Inspected: ${loops.length}\n`));

          for (const l of loops) {
            const boundColor =
              l.boundType === "storage_array_bounded" || l.boundType === "unbounded"
                ? chalk.red
                : l.isCapped
                ? chalk.green
                : chalk.yellow;

            lines.push(
              `  ${chalk.cyan.bold(l.associatedContract)}::${chalk.white(l.associatedFunction)} (line ${l.line}) [${boundColor(l.boundType)}]`,
            );
            lines.push(
              chalk.gray(
                `    Condition : ${l.conditionExpression}\n` +
                `    Capped    : ${l.isCapped ? chalk.green("YES") : chalk.red("NO")}\n` +
                `    Ext Calls : ${l.hasExternalCalls ? chalk.red(`${l.externalCallsCount} calls`) : chalk.green("0")}\n` +
                `    Deletions : ${l.hasStorageDeletions ? chalk.red("YES (Mass Deletion)") : chalk.green("No")}\n`,
              ),
            );
          }
          outputStr = lines.join("\n");
        }

        if (opts.output) {
          writeReport(opts.output, outputStr);
          if (opts.format === "table") {
            console.log(chalk.green(`\n  ✅ Loop inspection output written to ${opts.output}`));
          }
        } else {
          console.log(outputStr);
        }

        process.exit(0);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`\n  DoS loop inspection error: ${sanitize(msg)}`));
        process.exit(2);
      }
    });

  // ─── dos fanout ─────────────────────────────────────────────────────────────
  dos
    .command("fanout <targets...>")
    .description("Inspect external call fan-out, push-payment patterns, and gas forwarding")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write fanout report to file")
    .option("--config <file>", "Load DoS configuration file")
    .action((targets: string[], opts: { format: OutputFormat; output?: string; config?: string }) => {
      if (opts.format === "table") printBanner();
      try {
        const config = opts.config ? loadDosConfigFile(opts.config) : undefined;
        const calls = inspectDosCallFanOut(targets, { config });

        let outputStr: string;
        if (opts.format === "json") {
          outputStr = stableStringify(calls);
        } else if (opts.format === "markdown") {
          outputStr = generateDosFanoutMarkdown(calls);
        } else {
          const lines: string[] = [];
          lines.push(chalk.bold("\n  External Call Fan-Out & Payment Inspection\n"));
          lines.push(chalk.gray(`  Total External Calls Inspected: ${calls.length}\n`));

          for (const c of calls) {
            const riskColor = c.isInsideLoop || c.isPushPayment ? chalk.red : chalk.green;
            lines.push(
              `  ${chalk.cyan.bold(c.associatedContract)}::${chalk.white(c.associatedFunction)} (line ${c.line}) -> ${chalk.yellow(c.targetExpression)} [${riskColor(c.callType)}]`,
            );
            lines.push(
              chalk.gray(
                `    Inside Loop  : ${c.isInsideLoop ? chalk.red("YES (Fan-Out Risk)") : chalk.green("No")}\n` +
                `    Push Payment : ${c.isPushPayment ? chalk.red("YES (Revert Risk)") : chalk.green("No")}\n` +
                `    Try/Catch    : ${c.isWrappedInTryCatch ? chalk.green("YES (Isolated)") : chalk.yellow("No")}\n` +
                `    Gas Stipend  : ${c.hasGasLimit ? chalk.green(c.gasLimitExpression) : chalk.red("Full Gas (63/64)")}\n`,
              ),
            );
          }
          outputStr = lines.join("\n");
        }

        if (opts.output) {
          writeReport(opts.output, outputStr);
          if (opts.format === "table") {
            console.log(chalk.green(`\n  ✅ Fanout inspection output written to ${opts.output}`));
          }
        } else {
          console.log(outputStr);
        }

        process.exit(0);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`\n  DoS fanout inspection error: ${sanitize(msg)}`));
        process.exit(2);
      }
    });

  // ─── dos audit ──────────────────────────────────────────────────────────────
  dos
    .command("audit <targets...>")
    .description("Run a full Denial-of-Service, gas-griefing, and unbounded-work audit")
    .option("--format <format>", "Output format: table|json|markdown", "table")
    .option("--output <file>", "Write audit report to file")
    .option("--config <file>", "Load DoS configuration file")
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
          const configured = opts.config ? loadDosConfigFile(opts.config) : undefined;

          const limits: Partial<DosAnalysisLimits> = {
            ...configured?.limits,
            ...(opts.maxSourceBytes ? { maxSourceBytes: opts.maxSourceBytes } : {}),
            ...(opts.maxFiles ? { maxFiles: opts.maxFiles } : {}),
            ...(opts.maxContracts ? { maxContracts: opts.maxContracts } : {}),
            ...(opts.maxFindings ? { maxFindings: opts.maxFindings } : {}),
          };

          const includeRules = opts.includeRule.length
            ? (opts.includeRule as DosRuleId[])
            : configured?.includeRules;
          const excludeRules = opts.excludeRule.length
            ? (opts.excludeRule as DosRuleId[])
            : configured?.excludeRules;

          const options: DosAnalysisOptions = {
            config: configured,
            limits,
            includeRules,
            excludeRules,
          };

          const report = await auditDosSafety(targets, options);

          let outputStr: string;
          if (opts.format === "json") {
            outputStr = serializeDosAuditJSON(report);
          } else if (opts.format === "markdown") {
            outputStr = generateDosMarkdownReport(report);
          } else {
            outputStr = generateDosTableReport(report);
          }

          if (opts.output) {
            writeReport(opts.output, outputStr);
            if (opts.format === "table") {
              console.log(chalk.green(`\n  ✅ DoS report written to ${opts.output}`));
            }
          } else {
            console.log(outputStr);
          }

          const minRank = SEVERITY_RANK[opts.failOn];
          const hasFailingFindings =
            opts.failOn !== "none" &&
            report.findings.some(
              (f) => (SEVERITY_RANK[f.severity as FailSeverity] || 0) >= minRank,
            );

          const exitCode = hasFailingFindings ? 1 : 0;

          process.exit(exitCode);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(chalk.red(`\n  DoS audit error: ${sanitize(msg)}`));
          process.exit(2);
        }
      },
    );
}
