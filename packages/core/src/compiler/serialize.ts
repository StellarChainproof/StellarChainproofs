/**
 * @packageDocumentation
 * @chainproof/core — Deterministic Serialization & Report Generators (JSON, Markdown & Table)
 */

import chalk from "chalk";
import type {
  CompilerAuditReport,
  ProjectPragmaResolution,
  VersionComparisonResult,
} from "./types";

/**
 * Deterministically stringifies an object by sorting object keys recursively.
 */
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

/**
 * Serializes a compiler audit report into schema-versioned deterministic JSON.
 */
export function serializeCompilerAuditJSON(report: CompilerAuditReport): string {
  return stableStringify(report);
}

/**
 * Generates a comprehensive Markdown report for a compiler audit.
 */
export function generateCompilerMarkdownReport(report: CompilerAuditReport): string {
  const { summary, projectPragmas, matrix, comparisons, findings } = report;

  const lines: string[] = [];

  lines.push("# ChainProof Multi-Compiler Compatibility & Diagnostic Report");
  lines.push("");
  lines.push(`**Status:** ${summary.passed ? "✅ PASSED" : "❌ FAILED"}`);
  lines.push(`**Schema Version:** \`${report.schemaVersion}\``);
  lines.push(`**Recommended Compiler:** \`${summary.recommendedVersion || "N/A"}\``);
  lines.push(`**Global Supported Range:** \`${projectPragmas.globalRange}\``);
  lines.push("");

  // Executive Summary Table
  lines.push("## Executive Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Total Source Files | ${summary.totalFiles} |`);
  lines.push(`| Total Contracts Evaluated | ${summary.totalContracts} |`);
  lines.push(`| Compatible Compiler Versions | ${summary.compatibleVersionsCount} |`);
  lines.push(`| Critical Codegen Hazards Found | ${summary.criticalHazardsCount} |`);
  lines.push(`| Breaking Interface/Storage Drifts | ${summary.breakingDriftsCount} |`);
  lines.push(`| Security Findings (Critical/High) | ${summary.findingsSummary.critical} critical, ${summary.findingsSummary.high} high |`);
  lines.push("");

  // Pragma Resolution Table
  lines.push("## Pragma Constraints & Resolution");
  lines.push("");
  lines.push("| File | Declared Pragma | Compatible Range | Floating? | Broad? | Sensitive? |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const f of projectPragmas.files) {
    const floating = f.isFloating ? "⚠️ Yes" : "✅ No";
    const broad = f.isOverlyBroad ? "⚠️ Yes" : "✅ No";
    const sensitive = f.isSecuritySensitive ? "🚨 Yes" : "✅ No";
    lines.push(
      `| \`${f.file}\` | \`${f.rawPragma}\` | \`${f.rangeDescription}\` | ${floating} | ${broad} | ${sensitive} |`,
    );
  }
  lines.push("");

  if (projectPragmas.unsatisfiable) {
    lines.push("> [!CAUTION]");
    lines.push("> **Unsatisfiable Pragma Intersection Detected!**");
    lines.push("> Imported files have mutually incompatible compiler version requirements:");
    if (projectPragmas.conflictDetails) {
      for (const conf of projectPragmas.conflictDetails) {
        lines.push(`> - ${conf}`);
      }
    }
    lines.push("");
  }

  // Matrix Grid
  lines.push("## Compiler Diagnostic Matrix");
  lines.push("");
  if (matrix.targetVersions.length > 0 && matrix.rows.length > 0) {
    const headers = ["Contract", "File", ...matrix.targetVersions.map((v) => `v${v}`)];
    lines.push(`| ${headers.join(" | ")} |`);
    lines.push(`| ${headers.map(() => "---").join(" | ")} |`);

    for (const row of matrix.rows) {
      const rowCells = [
        `\`${row.contract}\``,
        `\`${row.file}\``,
        ...matrix.targetVersions.map((v) => {
          const cell = row.cells[v];
          if (!cell) return "⚪ -";
          if (cell.status === "compatible") return "🟢 Pass";
          if (cell.status === "warning") return `🟡 Warn (${cell.warningsCount})`;
          if (cell.status === "hazard") return `🟣 Hazard (${cell.hazards.length})`;
          return "🔴 Incompatible";
        }),
      ];
      lines.push(`| ${rowCells.join(" | ")} |`);
    }
    lines.push("");
  }

  // Cross-Version Comparisons
  if (comparisons.length > 0) {
    lines.push("## Version Drift & Differential Analysis");
    lines.push("");

    for (const comp of comparisons) {
      lines.push(`### \`${comp.contractName}\` (${comp.baseVersion} vs ${comp.targetVersion})`);
      lines.push("");
      lines.push(`- **Compatibility Status:** \`${comp.compatibilityStatus.toUpperCase()}\``);
      lines.push(`- **Bytecode Delta:** ${comp.bytecodeDiff.sizeDeltaBytes > 0 ? "+" : ""}${comp.bytecodeDiff.sizeDeltaBytes} bytes (${comp.bytecodeDiff.sizeDeltaPercent}%)`);
      lines.push(`- **PUSH0 Opcode:** Base: \`${comp.bytecodeDiff.baseHasPush0}\` | Target: \`${comp.bytecodeDiff.targetHasPush0}\`${comp.bytecodeDiff.push0Hazard ? " ⚠️ **(PUSH0 introduced)**" : ""}`);
      lines.push(`- **Transient Storage:** Base: \`${comp.bytecodeDiff.baseHasTransient}\` | Target: \`${comp.bytecodeDiff.targetHasTransient}\``);
      lines.push("");

      // Storage Collisions
      if (comp.storageLayoutDiff.slotCollisions.length > 0) {
        lines.push("> [!CAUTION]");
        lines.push("> **Storage Layout Collisions / Slot Drift Detected!**");
        for (const col of comp.storageLayoutDiff.slotCollisions) {
          lines.push(`> - **${col.variable}**: ${col.reason}`);
        }
        lines.push("");
      }

      // ABI Diffs
      if (!comp.abiDiff.identical) {
        lines.push("**ABI Interface Modifications:**");
        if (comp.abiDiff.addedFunctions.length > 0) {
          lines.push(`- Added functions: ${comp.abiDiff.addedFunctions.map((f) => `\`${f}\``).join(", ")}`);
        }
        if (comp.abiDiff.removedFunctions.length > 0) {
          lines.push(`- Removed functions: ${comp.abiDiff.removedFunctions.map((f) => `\`${f}\``).join(", ")}`);
        }
        if (comp.abiDiff.mutatedSignatures.length > 0) {
          for (const mut of comp.abiDiff.mutatedSignatures) {
            lines.push(`- Mutated signature \`${mut.name}\`: \`${mut.baseSignature}\` -> \`${mut.targetSignature}\``);
          }
        }
        lines.push("");
      }

      // Breaking Syntax Changes
      if (comp.breakingChanges.length > 0) {
        lines.push("**Syntax & Semantic Transitions:**");
        for (const brk of comp.breakingChanges) {
          lines.push(`- ${brk}`);
        }
        lines.push("");
      }
    }
  }

  // Findings List
  if (findings.length > 0) {
    lines.push("## Compiler Findings & Diagnostics");
    lines.push("");
    for (const f of findings) {
      const icon =
        f.severity === "critical"
          ? "🚨"
          : f.severity === "high"
          ? "❌"
          : f.severity === "medium"
          ? "⚠️"
          : "ℹ️";
      lines.push(`### ${icon} [${f.severity.toUpperCase()}] ${f.id}: ${f.title}`);
      lines.push(`**File:** \`${f.file}:${f.line}\``);
      lines.push("");
      lines.push(f.description);
      lines.push("");
      lines.push(`**Recommendation:** ${f.recommendation}`);
      if (f.snippet) {
        lines.push("");
        lines.push("```solidity");
        lines.push(f.snippet);
        lines.push("```");
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Generates an ANSI-styled table report for terminal CLI output.
 */
export function generateCompilerTableReport(report: CompilerAuditReport): string {
  const { summary, projectPragmas, matrix, findings } = report;
  const out: string[] = [];

  out.push(chalk.bold("\n  ChainProof Multi-Compiler Diagnostic Matrix\n"));
  out.push(
    chalk.gray(
      `  Files: ${summary.totalFiles} | Contracts: ${summary.totalContracts} | Tested: ${summary.testedVersions.join(", ")}\n` +
      `  Global Range: ${chalk.cyan(projectPragmas.globalRange)} | Recommended: ${chalk.green(summary.recommendedVersion || "N/A")}\n`,
    ),
  );

  // Matrix Grid
  if (matrix.targetVersions.length > 0 && matrix.rows.length > 0) {
    out.push(chalk.bold("  Matrix Overview:"));
    const versionHeader = matrix.targetVersions.map((v) => v.padEnd(8)).join(" ");
    out.push(chalk.gray(`  ${"Contract".padEnd(24)} ${versionHeader}`));
    out.push(chalk.gray(`  ${"-".repeat(24 + matrix.targetVersions.length * 9)}`));

    for (const row of matrix.rows) {
      const cells = matrix.targetVersions
        .map((v) => {
          const c = row.cells[v];
          if (!c) return chalk.gray("-".padEnd(8));
          if (c.status === "compatible") return chalk.green("PASS".padEnd(8));
          if (c.status === "warning") return chalk.yellow("WARN".padEnd(8));
          if (c.status === "hazard") return chalk.magenta("HAZARD".padEnd(8));
          return chalk.red("FAIL".padEnd(8));
        })
        .join(" ");

      out.push(`  ${chalk.cyan(row.contract.slice(0, 22).padEnd(24))} ${cells}`);
    }
    out.push("");
  }

  // Findings
  if (findings.length > 0) {
    out.push(chalk.bold("  Findings Summary:"));
    for (const f of findings) {
      const color =
        f.severity === "critical"
          ? chalk.red
          : f.severity === "high"
          ? chalk.red
          : f.severity === "medium"
          ? chalk.yellow
          : chalk.blue;

      out.push(
        `  ${color(`[${f.severity.toUpperCase()}]`)} ${chalk.bold(f.id)} ${f.file}:${f.line} — ${f.title}`,
      );
    }
    out.push("");
  }

  const passColor = summary.passed ? chalk.green : chalk.red;
  out.push(
    passColor(
      `  ${summary.passed ? "✅ PASS" : "❌ FAIL"} — ${summary.criticalHazardsCount} critical hazards, ${summary.breakingDriftsCount} breaking drifts, ${findings.length} findings.\n`,
    ),
  );

  return out.join("\n");
}

/**
 * Generates inspection-specific Markdown.
 */
export function generateCompilerInspectMarkdown(inspection: ProjectPragmaResolution): string {
  const lines: string[] = [];
  lines.push("# Solidity Pragma & Compiler Inspection Report");
  lines.push("");
  lines.push(`- **Global Satisfiable Range:** \`${inspection.globalRange}\``);
  lines.push(`- **Recommended Version:** \`${inspection.recommendedVersion || "None"}\``);
  lines.push(`- **Satisfiable:** ${inspection.unsatisfiable ? "❌ NO" : "✅ YES"}`);
  lines.push(`- **Floating Pragmas:** ${inspection.hasFloatingPragmas ? "⚠️ Yes" : "No"}`);
  lines.push(`- **Overly Broad Pragmas:** ${inspection.hasBroadPragmas ? "⚠️ Yes" : "No"}`);
  lines.push(`- **Security-Sensitive Pragmas:** ${inspection.hasSecuritySensitivePragmas ? "🚨 Yes" : "No"}`);
  lines.push("");

  lines.push("## Files");
  lines.push("");
  lines.push("| File | Raw Pragma | Compatible Versions | Floating? | Broad? |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const f of inspection.files) {
    lines.push(
      `| \`${f.file}\` | \`${f.rawPragma}\` | \`${f.rangeDescription}\` | ${f.isFloating ? "⚠️" : "✅"} | ${f.isOverlyBroad ? "⚠️" : "✅"} |`,
    );
  }
  lines.push("");

  if (inspection.unsatisfiable && inspection.conflictDetails) {
    lines.push("## Conflicts");
    for (const c of inspection.conflictDetails) {
      lines.push(`- ❌ ${c}`);
    }
  }

  return lines.join("\n");
}

/**
 * Generates comparison-specific Markdown.
 */
export function generateCompilerCompareMarkdown(comparisons: VersionComparisonResult[]): string {
  const lines: string[] = [];
  lines.push("# Solidity Multi-Compiler Version Comparison");
  lines.push("");

  for (const comp of comparisons) {
    lines.push(`## \`${comp.contractName}\` (${comp.baseVersion} -> ${comp.targetVersion})`);
    lines.push("");
    lines.push(`- **Status:** \`${comp.compatibilityStatus.toUpperCase()}\``);
    lines.push(`- **Bytecode Delta:** ${comp.bytecodeDiff.sizeDeltaBytes} bytes (${comp.bytecodeDiff.sizeDeltaPercent}%)`);
    lines.push(`- **PUSH0 Opcode:** ${comp.bytecodeDiff.targetHasPush0 ? "Yes" : "No"}`);
    lines.push("");

    if (comp.storageLayoutDiff.slotCollisions.length > 0) {
      lines.push("### 🚨 Storage Layout Collisions");
      for (const col of comp.storageLayoutDiff.slotCollisions) {
        lines.push(`- \`${col.variable}\`: ${col.reason}`);
      }
      lines.push("");
    }

    if (!comp.abiDiff.identical) {
      lines.push("### ⚠️ ABI Differences");
      if (comp.abiDiff.addedFunctions.length) lines.push(`- Added: ${comp.abiDiff.addedFunctions.join(", ")}`);
      if (comp.abiDiff.removedFunctions.length) lines.push(`- Removed: ${comp.abiDiff.removedFunctions.join(", ")}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}
