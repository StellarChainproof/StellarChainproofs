import type { LendingAnalysisReport, LendingFinding } from "./types";

export function serializeLendingReportJSON(report: LendingAnalysisReport, pretty = true): string {
  return `${JSON.stringify(sortValue(report), null, pretty ? 2 : 0)}\n`;
}

export function serializeLendingReportMarkdown(report: LendingAnalysisReport): string {
  const lines: string[] = [
    "# Lending Protocol Invariant Analysis",
    "",
    `Report schema: \`${report.schemaVersion}\``,
    `Engine version: \`${report.engineVersion}\``,
    "",
    "## Summary",
    "",
    "| Files | Contracts | Critical | High | Medium | Low | Info | Total | Truncated |",
    "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |",
    `| ${report.summary.files} | ${report.summary.contracts} | ${report.summary.critical} | ${report.summary.high} | ${report.summary.medium} | ${report.summary.low} | ${report.summary.info} | ${report.summary.total} | ${report.summary.truncated ? "yes" : "no"} |`,
    "",
  ];

  for (const file of report.files) {
    lines.push(`## ${escapeMarkdown(file.file)}`, "");
    if (file.findings.length === 0) {
      lines.push("No provable lending invariant findings.", "");
    }
    for (const finding of file.findings) renderFinding(lines, finding);
    if (file.diagnostics.length > 0) {
      lines.push("### Diagnostics", "");
      for (const diagnostic of file.diagnostics) {
        const line = diagnostic.location?.line ? `:${diagnostic.location.line}` : "";
        lines.push(`- **${diagnostic.code}** (${diagnostic.severity})${line}: ${escapeMarkdown(diagnostic.message)}`);
      }
      lines.push("");
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}

function renderFinding(lines: string[], finding: LendingFinding): void {
  lines.push(
    `### ${finding.ruleId}: ${escapeMarkdown(finding.title)}`,
    "",
    `- **Severity:** ${finding.severity}`,
    `- **Confidence:** ${finding.confidence}`,
    `- **Category:** ${finding.category}`,
    `- **Contract:** \`${escapeCode(finding.contract)}\``,
    `- **Location:** \`${escapeCode(finding.location.file)}:${finding.location.line}:${finding.location.column}\``,
    "",
    escapeMarkdown(finding.description),
    "",
    `**Recommendation:** ${escapeMarkdown(finding.recommendation)}`,
    "",
    "**Evidence path:**",
    "",
  );
  for (const evidence of finding.evidence) {
    lines.push(
      `1. ${escapeMarkdown(evidence.description)} ` +
        `(\`${escapeCode(evidence.location.file)}:${evidence.location.line}:${evidence.location.column}\`)`,
    );
    if (evidence.snippet) lines.push(`   - \`${escapeCode(evidence.snippet)}\``);
  }
  if (finding.assumptions.length > 0) {
    lines.push("", "**Assumptions:**", "");
    for (const assumption of finding.assumptions) lines.push(`- ${escapeMarkdown(assumption)}`);
  }
  lines.push("");
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) sorted[key] = sortValue(record[key]);
    return sorted;
  }
  return value;
}

function escapeMarkdown(value: string): string {
  return value.replace(/([\\`*_{}[\]()<>#+.!|-])/g, "\\$1");
}

function escapeCode(value: string): string {
  return value.replace(/`/g, "\\`").replace(/\s+/g, " ").trim();
}
