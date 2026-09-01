/**
 * @packageDocumentation
 * @chainproof/core — Deterministic Serialization & Reports for DoS Analysis
 */

import chalk from "chalk";
import type {
  DosAuditReport,
  LoopBoundAnalysis,
  CallFanOutAnalysis,
} from "./types";

export function stableStringify(obj: unknown, space: number = 2): string {
  function sortKeys(value: unknown): unknown {
    if (value === null || typeof value !== "object") {
      return value;
    }
    if (Array.isArray(value)) {
      return value.map(sortKeys);
    }
    const sortedObj: Record<string, unknown> = {};
    const keys = Object.keys(value as Record<string, unknown>).sort();
    for (const key of keys) {
      sortedObj[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sortedObj;
  }

  return JSON.stringify(sortKeys(obj), null, space);
}

export function serializeDosAuditJSON(report: DosAuditReport): string {
  return stableStringify(report, 2);
}

export function generateDosMarkdownReport(report: DosAuditReport): string {
  const lines: string[] = [];

  lines.push("# ChainProof Denial-of-Service, Gas-Griefing & Unbounded-Work Report");
  lines.push("");
  lines.push(`**Generated at:** ${report.createdAt}  `);
  lines.push(`**Schema Version:** \`${report.schemaVersion}\`  `);
  lines.push(`**Audit Result:** ${report.summary.passed ? "✅ **PASSED**" : "❌ **FAILED (DoS Hazards Detected)**"}  `);
  lines.push("");

  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`- **Files Analyzed:** ${report.summary.totalFiles}`);
  lines.push(`- **Contracts Evaluated:** ${report.summary.totalContracts}`);
  lines.push(`- **Loops Inspected:** ${report.summary.totalLoopsAnalyzed}`);
  lines.push(`- **Unbounded Loops Found:** ${report.summary.unboundedLoopsFound}`);
  lines.push(`- **Push-Payment Risks:** ${report.summary.pushPaymentsFound}`);
  lines.push(`- **Return Bomb Risks:** ${report.summary.returnBombRisksFound}`);
  lines.push(`- **Call Fan-Out Hazards:** ${report.summary.callFanOutsFound}`);
  lines.push(`- **Mass Storage Deletions:** ${report.summary.storageClearingFound}`);
  lines.push(`- **Array Poisoning Endpoints:** ${report.summary.arrayGrowthPointsFound}`);
  lines.push(`- **Mitigations Recognized:** ${report.summary.mitigationsRecognized}`);
  lines.push("");

  lines.push("### Severity Breakdown");
  lines.push("");
  lines.push(`- 🔴 **Critical:** ${report.summary.findingsCount.critical}`);
  lines.push(`- 🟠 **High:** ${report.summary.findingsCount.high}`);
  lines.push(`- 🟡 **Medium:** ${report.summary.findingsCount.medium}`);
  lines.push(`- 🔵 **Low:** ${report.summary.findingsCount.low}`);
  lines.push(`- ⚪ **Info:** ${report.summary.findingsCount.info}`);
  lines.push("");

  if (report.mitigations.length > 0) {
    lines.push("## Mitigations Recognized");
    lines.push("");
    lines.push("| Pattern | Contract | Function | Line | Description |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const m of report.mitigations) {
      lines.push(`| \`${m.type}\` | \`${m.contract}\` | \`${m.functionName || "N/A"}\` | ${m.line} | ${m.description} |`);
    }
    lines.push("");
  }

  lines.push("## Findings Catalog");
  lines.push("");
  if (report.findings.length === 0) {
    lines.push("✅ *No Denial-of-Service or Gas-Griefing vulnerabilities detected.*");
  } else {
    for (const f of report.findings) {
      const icon =
        f.severity === "critical" || f.severity === "high"
          ? "🚨"
          : f.severity === "medium"
          ? "⚠️"
          : "ℹ️";

      lines.push(`### ${icon} [${f.severity.toUpperCase()}] ${f.id} — ${f.title}`);
      lines.push("");
      lines.push(`- **Location:** \`${f.file}:${f.line}\``);
      lines.push(`- **Category:** \`${f.category}\``);
      lines.push(`- **Confidence:** \`${f.confidence}\``);
      if (f.boundType) {
        lines.push(`- **Bound Type:** \`${f.boundType}\``);
      }
      lines.push("");
      lines.push(`**Description:** ${f.description}`);
      lines.push("");
      lines.push(`**Recommendation:** ${f.recommendation}`);
      lines.push("");
      if (f.snippet) {
        lines.push("```solidity");
        lines.push(f.snippet);
        lines.push("```");
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}

export function generateDosTableReport(report: DosAuditReport): string {
  const lines: string[] = [];

  lines.push(chalk.bold("\n  ChainProof Denial-of-Service & Unbounded-Work Report\n"));
  lines.push(
    chalk.gray(
      `  Files: ${report.summary.totalFiles} | Contracts: ${report.summary.totalContracts} | Loops: ${report.summary.totalLoopsAnalyzed}\n` +
      `  Unbounded Loops: ${report.summary.unboundedLoopsFound} | Push Payments: ${report.summary.pushPaymentsFound} | Return Bombs: ${report.summary.returnBombRisksFound}\n` +
      `  Mitigations Recognized: ${chalk.green(report.summary.mitigationsRecognized)}\n`,
    ),
  );

  if (report.findings.length === 0) {
    lines.push(chalk.green.bold("  ✅ PASS — No DoS or gas-griefing hazards detected.\n"));
  } else {
    lines.push(chalk.bold("  Findings Summary:"));
    for (const f of report.findings) {
      const color =
        f.severity === "critical" || f.severity === "high"
          ? chalk.red
          : f.severity === "medium"
          ? chalk.yellow
          : chalk.blue;
      lines.push(`  ${color(`[${f.severity.toUpperCase()}]`)} ${chalk.cyan(f.id)} ${f.file}:${f.line} — ${f.title}`);
    }
    lines.push("");
    if (report.summary.passed) {
      lines.push(chalk.green.bold(`  ✅ PASS (No critical/high hazards) — ${report.findings.length} finding(s).\n`));
    } else {
      lines.push(chalk.red.bold(`  ❌ FAIL — ${report.findings.length} DoS hazard(s) detected.\n`));
    }
  }

  return lines.join("\n");
}

export function generateDosLoopsMarkdown(loops: LoopBoundAnalysis[]): string {
  const lines: string[] = [];
  lines.push("# Loop Bounds and Complexity Inspection");
  lines.push("");
  lines.push("| Contract | Function | Line | Loop Type | Bound Type | Capped | Ext Calls | Writes | Deletions |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");

  for (const l of loops) {
    lines.push(
      `| \`${l.associatedContract}\` | \`${l.associatedFunction}\` | ${l.line} | \`${l.loopType}\` | \`${l.boundType}\` | ${l.isCapped ? "✅ Yes" : "❌ No"} | ${l.hasExternalCalls ? `⚠️ ${l.externalCallsCount}` : "0"} | ${l.hasStateWrites ? "Yes" : "No"} | ${l.hasStorageDeletions ? "⚠️ Yes" : "No"} |`,
    );
  }

  return lines.join("\n");
}

export function generateDosFanoutMarkdown(calls: CallFanOutAnalysis[]): string {
  const lines: string[] = [];
  lines.push("# External Call Fan-Out & Payment Inspection");
  lines.push("");
  lines.push("| Contract | Function | Line | Call Type | In Loop | Push Payment | Try/Catch | Gas Limit |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");

  for (const c of calls) {
    lines.push(
      `| \`${c.associatedContract}\` | \`${c.associatedFunction}\` | ${c.line} | \`${c.callType}\` | ${c.isInsideLoop ? "⚠️ Yes" : "No"} | ${c.isPushPayment ? "⚠️ Yes" : "No"} | ${c.isWrappedInTryCatch ? "✅ Yes" : "No"} | ${c.hasGasLimit ? `✅ ${c.gasLimitExpression}` : "❌ Full (63/64)"} |`,
    );
  }

  return lines.join("\n");
}
