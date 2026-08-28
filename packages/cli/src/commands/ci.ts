import chalk from "chalk";
import ora from "ora";
import * as fs from "fs";
import * as path from "path";
import type { Command } from "commander";
import {
  scan,
  diffScans,
  generateMarkdownReport,
  generateJSONReport,
} from "@chainproof/core";
import type { ScanConfig, ScanResult, Severity } from "@chainproof/core";
import {
  buildGitLabCodeQualityReport,
  buildGitLabSASTReport,
  buildGitLabMRNote,
  buildGitLabCIReport,
  serializeGitLabCodeQualityArtifact,
  serializeGitLabSASTArtifact,
  generateGitLabCITemplate,
  GITLAB_ARTIFACT_PATHS,
  buildBitbucketCodeInsightsReport,
  buildBitbucketDiffReport,
  buildBitbucketPRSummary,
  buildBitbucketCIReport,
  serializeBitbucketCodeInsightsArtifact,
  buildBitbucketPipelineStatus,
  generateBitbucketPipelineTemplate,
  BITBUCKET_ARTIFACT_PATHS,
  applySuppressionPolicy,
  detectFork,
  extractSolFilesFromDiffOutput,
} from "@chainproof/core";
import type {
  CIIntegrationConfig,
  CIDiffConfig,
  CIReportResult,
} from "@chainproof/core";

// ─── Shared Helpers ──────────────────────────────────────────────────────────

interface BaseCIOptions {
  targets: string[];
  failSeverity: string;
  format: string;
  output: string;
  minSeverity: string;
  maxAnnotations: string;
  useSlither: boolean;
  useLLM: boolean;
  useMetrics: boolean;
  apiKey?: string;
}

function ensureReportDir(outputPath?: string): string {
  const dir = outputPath
    ? path.dirname(outputPath)
    : path.join(process.cwd(), "chainproof-reports");
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function printCIReportSummary(report: CIReportResult): void {
  const { summary, shouldFail, failThreshold } = report;
  console.log("");
  console.log(chalk.gray(`  Provider: ${report.provider}`));
  console.log(
    chalk.gray(
      `  Annotations: ${report.annotations.length} | Fail threshold: ${failThreshold}+`
    )
  );
  console.log(
    chalk.gray(
      `  Files scanned: ${report.metadata.filesScanned} | Version: ${report.metadata.scanVersion}`
    )
  );

  if (summary.critical > 0 || summary.high > 0) {
    console.log(
      chalk.red(
        `  🔴 ${summary.critical} critical, 🟠 ${summary.high} high`
      )
    );
  }

  if (shouldFail) {
    console.log(chalk.red(`  ❌ Pipeline should FAIL`));
  } else {
    console.log(chalk.green(`  ✅ Pipeline should PASS`));
  }
}

function buildScanConfig(opts: BaseCIOptions): ScanConfig {
  return {
    targets: opts.targets,
    useSlither: opts.useSlither,
    useLLM: opts.useLLM && !!opts.apiKey,
    useMetrics: opts.useMetrics,
    apiKey: opts.apiKey,
    minSeverity: opts.minSeverity as Severity,
  };
}

function parseSeverity(value: string): Severity {
  const valid: Severity[] = ["critical", "high", "medium", "low", "info", "gas"];
  if (valid.includes(value as Severity)) return value as Severity;
  return "high";
}

// ─── GitLab Subcommand ───────────────────────────────────────────────────────

export function registerGitLabCICommand(ci: Command): void {
  ci.command("gitlab")
    .description("Run ChainProof scan for GitLab CI with SAST/MR notes")
    .argument("<targets...>", "Paths to Solidity files or directories")
    .option("--fail-severity <level>", "Minimum severity to fail the pipeline", "high")
    .option("--min-severity <level>", "Minimum severity to report", "low")
    .option("--max-annotations <n>", "Maximum annotations to post", "100")
    .option("--format <format>", "Output format: json|markdown", "json")
    .option("--output <file>", "Write report to file")
    .option("--diff", "Enable diff-aware scanning against base branch")
    .option("--base-ref <ref>", "Base branch for diff-aware scanning", "origin/main")
    .option("--no-slither", "Skip Slither")
    .option("--no-llm", "Skip LLM enhancement")
    .option("--no-metrics", "Skip complexity metrics")
    .option("--api-key <key>", "LLM API key")
    .option("--no-artifacts", "Skip writing artifacts to disk")
    .option("--template", "Print GitLab CI YAML template and exit")
    .action(
      async (
        targets: string[],
        opts: {
          failSeverity: string;
          minSeverity: string;
          maxAnnotations: string;
          format: string;
          output?: string;
          diff?: boolean;
          baseRef?: string;
          slither: boolean;
          llm: boolean;
          metrics: boolean;
          apiKey?: string;
          artifacts: boolean;
          template?: boolean;
        }
      ) => {
        if (opts.template) {
          console.log(
            generateGitLabCITemplate({
              targets: targets.join(" "),
              failSeverity: opts.failSeverity,
              diffMode: opts.diff,
            })
          );
          return;
        }

        const spinner = ora("Running ChainProof GitLab CI scan...").start();
        const reportDir = ensureReportDir(opts.output);

        const scanConfig: ScanConfig = {
          targets,
          useSlither: opts.slither,
          useLLM: opts.llm && !!opts.apiKey,
          useMetrics: opts.metrics,
          apiKey: opts.apiKey,
        };

        let result: ScanResult;
        try {
          result = await scan(scanConfig);
          spinner.succeed(`Scanned ${result.files.length} file(s)`);
        } catch (err) {
          spinner.fail("Scan failed");
          console.error(chalk.red(`  Error: ${err}`));
          process.exit(1);
        }

        // Build reports
        const codeQualityReport = buildGitLabCodeQualityReport(result);
        const sastReport = buildGitLabSASTReport(result);

        if (opts.artifacts) {
          const cqPath = path.join(
            reportDir,
            "code-quality-report.json"
          );
          const sastPath = path.join(reportDir, "sast-report.json");
          fs.writeFileSync(cqPath, serializeGitLabCodeQualityArtifact(codeQualityReport), "utf-8");
          fs.writeFileSync(sastPath, serializeGitLabSASTArtifact(sastReport), "utf-8");
          console.log(chalk.gray(`  💾 Code Quality report: ${cqPath}`));
          console.log(chalk.gray(`  💾 SAST report: ${sastPath}`));
        }

        // Build CI report
        const ciConfig: CIIntegrationConfig = {
          provider: "gitlab",
          scanConfig,
          failSeverity: parseSeverity(opts.failSeverity),
          minSeverity: parseSeverity(opts.minSeverity),
          maxAnnotations: parseInt(opts.maxAnnotations, 10),
        };

        const ciReport = buildGitLabCIReport(result, ciConfig);

        // Write MR note
        if (opts.artifacts) {
          const mrNote = buildGitLabMRNote(result);
          const notePath = path.join(reportDir, "mr-note.md");
          fs.writeFileSync(notePath, mrNote, "utf-8");
          console.log(chalk.gray(`  💾 MR note: ${notePath}`));
        }

        // Write main reports
        if (opts.output) {
          const reportData =
            opts.format === "markdown"
              ? generateMarkdownReport(result)
              : generateJSONReport(result);
          fs.writeFileSync(opts.output, reportData, "utf-8");
          console.log(chalk.green(`  ✅ Report written to ${opts.output}`));
        }

        printCIReportSummary(ciReport);

        if (ciReport.shouldFail) {
          process.exit(1);
        }
      }
    );
}

// ─── Bitbucket Subcommand ────────────────────────────────────────────────────

export function registerBitbucketCICommand(ci: Command): void {
  ci.command("bitbucket")
    .description("Run ChainProof scan for Bitbucket Pipelines with Code Insights")
    .argument("<targets...>", "Paths to Solidity files or directories")
    .option("--fail-severity <level>", "Minimum severity to fail the pipeline", "high")
    .option("--min-severity <level>", "Minimum severity to report", "low")
    .option("--max-annotations <n>", "Maximum annotations to report", "100")
    .option("--format <format>", "Output format: json|markdown", "json")
    .option("--output <file>", "Write report to file")
    .option("--diff", "Enable diff-aware scanning against base branch")
    .option("--base-ref <ref>", "Base branch for diff-aware scanning", "origin/main")
    .option("--no-slither", "Skip Slither")
    .option("--no-llm", "Skip LLM enhancement")
    .option("--no-metrics", "Skip complexity metrics")
    .option("--api-key <key>", "LLM API key")
    .option("--no-artifacts", "Skip writing artifacts to disk")
    .option("--template", "Print Bitbucket Pipelines YAML template and exit")
    .action(
      async (
        targets: string[],
        opts: {
          failSeverity: string;
          minSeverity: string;
          maxAnnotations: string;
          format: string;
          output?: string;
          diff?: boolean;
          baseRef?: string;
          slither: boolean;
          llm: boolean;
          metrics: boolean;
          apiKey?: string;
          artifacts: boolean;
          template?: boolean;
        }
      ) => {
        if (opts.template) {
          console.log(
            generateBitbucketPipelineTemplate({
              targets: targets.join(" "),
              failSeverity: opts.failSeverity,
              diffMode: opts.diff,
            })
          );
          return;
        }

        const spinner = ora("Running ChainProof Bitbucket CI scan...").start();
        const reportDir = ensureReportDir(opts.output);

        const scanConfig: ScanConfig = {
          targets,
          useSlither: opts.slither,
          useLLM: opts.llm && !!opts.apiKey,
          useMetrics: opts.metrics,
          apiKey: opts.apiKey,
        };

        let result: ScanResult;
        try {
          result = await scan(scanConfig);
          spinner.succeed(`Scanned ${result.files.length} file(s)`);
        } catch (err) {
          spinner.fail("Scan failed");
          console.error(chalk.red(`  Error: ${err}`));
          process.exit(1);
        }

        // Build Code Insights report
        const insightsReport = buildBitbucketCodeInsightsReport(result, {
          failSeverity: parseSeverity(opts.failSeverity),
          maxAnnotations: parseInt(opts.maxAnnotations, 10),
        });

        if (opts.artifacts) {
          const insightsPath = path.join(
            reportDir,
            "code-insights-report.json"
          );
          fs.writeFileSync(
            insightsPath,
            serializeBitbucketCodeInsightsArtifact(insightsReport),
            "utf-8"
          );
          console.log(chalk.gray(`  💾 Code Insights report: ${insightsPath}`));
        }

        // Build PR summary
        if (opts.artifacts) {
          const prSummary = buildBitbucketPRSummary(result);
          const summaryPath = path.join(reportDir, "pr-summary.md");
          fs.writeFileSync(summaryPath, prSummary, "utf-8");
          console.log(chalk.gray(`  💾 PR summary: ${summaryPath}`));
        }

        // Build pipeline status
        const pipelineStatus = buildBitbucketPipelineStatus(result, {
          commitSha: process.env.BB_COMMIT || undefined,
          branch: process.env.BB_BRANCH || undefined,
        });

        if (opts.artifacts) {
          const statusPath = path.join(
            reportDir,
            "pipeline-status.json"
          );
          fs.writeFileSync(statusPath, JSON.stringify(pipelineStatus, null, 2), "utf-8");
          console.log(chalk.gray(`  💾 Pipeline status: ${statusPath}`));
        }

        // Build CI report
        const ciConfig: CIIntegrationConfig = {
          provider: "bitbucket",
          scanConfig,
          failSeverity: parseSeverity(opts.failSeverity),
          minSeverity: parseSeverity(opts.minSeverity),
          maxAnnotations: parseInt(opts.maxAnnotations, 10),
        };

        const ciReport = buildBitbucketCIReport(result, ciConfig);

        // Write main reports
        if (opts.output) {
          const reportData =
            opts.format === "markdown"
              ? generateMarkdownReport(result)
              : generateJSONReport(result);
          fs.writeFileSync(opts.output, reportData, "utf-8");
          console.log(chalk.green(`  ✅ Report written to ${opts.output}`));
        }

        printCIReportSummary(ciReport);

        if (ciReport.shouldFail) {
          process.exit(1);
        }
      }
    );
}

// ─── Register All CI Commands ────────────────────────────────────────────────

export function registerCICommands(program: Command, printBanner: () => void): void {
  const ci = program
    .command("ci")
    .description("CI provider integrations (GitLab, Bitbucket)");

  registerGitLabCICommand(ci);
  registerBitbucketCICommand(ci);
}
