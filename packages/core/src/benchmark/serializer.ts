import type { BenchmarkReport, GateEvaluationResult } from "./types";

/**
 * Serializes a BenchmarkReport into a formatted JSON string.
 */
export function generateBenchmarkJSONReport(report: BenchmarkReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Serializes a BenchmarkReport into a human-readable Markdown document.
 */
export function generateBenchmarkMarkdownReport(report: BenchmarkReport): string {
  const m = report.metrics;
  const lines: string[] = [];

  lines.push(`# Detector Benchmark Report: ${report.corpusName}`);
  lines.push("");
  lines.push(`- **Engine Version:** \`${report.engineVersion}\``);
  lines.push(`- **Timestamp:** \`${report.timestamp}\``);
  lines.push(`- **Benchmark ID:** \`${report.benchmarkId}\``);
  if (report.sharding) {
    lines.push(`- **Shard:** ${report.sharding.shardIndex + 1} of ${report.sharding.totalShards}`);
  }
  if (report.sampling) {
    lines.push(`- **Sampling:** ${report.sampling.sampledCount} of ${report.sampling.totalCount} cases (seed: ${report.sampling.seed})`);
  }
  lines.push("");

  lines.push("## Summary Metrics");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| **Precision** | **${(m.precision * 100).toFixed(2)}%** |`);
  lines.push(`| **Recall** | **${(m.recall * 100).toFixed(2)}%** |`);
  lines.push(`| **F1 Score** | **${m.f1Score.toFixed(4)}** |`);
  lines.push(`| **F0.5 Score** | ${m.f05Score.toFixed(4)} |`);
  lines.push(`| **F2 Score** | ${m.f2Score.toFixed(4)} |`);
  lines.push(`| True Positives (TP) | ${m.truePositives} |`);
  lines.push(`| False Positives (FP) | ${m.falsePositives} |`);
  lines.push(`| False Negatives (FN) | ${m.falseNegatives} |`);
  lines.push(`| True Negatives (TN) | ${m.trueNegatives} |`);
  lines.push(`| Runtime | ${m.runtimeMs} ms |`);
  lines.push(`| Peak Memory | ${(m.peakMemoryBytes / (1024 * 1024)).toFixed(2)} MB |`);
  lines.push("");

  lines.push("## Metrics by Category");
  lines.push("");
  lines.push("| Category | Cases | TP | FP | FN | Precision | Recall | F1 Score |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");

  for (const [cat, summary] of Object.entries(m.perCategory)) {
    if (summary.cases === 0) continue;
    lines.push(
      `| \`${cat}\` | ${summary.cases} | ${summary.truePositives} | ${summary.falsePositives} | ${summary.falseNegatives} | ${(summary.precision * 100).toFixed(1)}% | ${(summary.recall * 100).toFixed(1)}% | ${summary.f1Score.toFixed(3)} |`,
    );
  }
  lines.push("");

  lines.push("## Metrics by Detector Rule");
  lines.push("");
  lines.push("| Rule ID | Total Expected | Matched | FP | FN | Precision | Recall | F1 Score | Coverage |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");

  const rules = Object.values(m.perRule).sort((a, b) => a.ruleId.localeCompare(b.ruleId));
  if (rules.length === 0) {
    lines.push("| _No rule metrics recorded_ | - | - | - | - | - | - | - | - |");
  } else {
    for (const r of rules) {
      lines.push(
        `| \`${r.ruleId}\` | ${r.coverage.totalExpected} | ${r.coverage.matched} | ${r.falsePositives} | ${r.falseNegatives} | ${(r.precision * 100).toFixed(1)}% | ${(r.recall * 100).toFixed(1)}% | ${r.f1Score.toFixed(3)} | ${(r.coverage.coverageRatio * 100).toFixed(1)}% |`,
      );
    }
  }
  lines.push("");

  if (Object.keys(m.falsePositiveCategories).length > 0) {
    lines.push("## False Positive Breakdown");
    lines.push("");
    lines.push("| Category | Count |");
    lines.push("| --- | --- |");
    for (const [fpCat, count] of Object.entries(m.falsePositiveCategories)) {
      lines.push(`| \`${fpCat}\` | ${count} |`);
    }
    lines.push("");
  }

  lines.push("## Individual Test Case Results");
  lines.push("");
  lines.push("| Status | Case ID | Category | Expected | Actual | TP | FP | FN | Runtime |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");

  for (const res of report.caseResults) {
    const status = res.passed ? "✅ PASS" : "❌ FAIL";
    lines.push(
      `| ${status} | \`${res.caseId}\` | \`${res.category}\` | ${res.expectedCount} | ${res.actualCount} | ${res.truePositives} | ${res.falsePositives} | ${res.falseNegatives} | ${res.runtimeMs}ms |`,
    );
  }
  lines.push("");

  return lines.join("\n");
}

/**
 * Serializes a BenchmarkReport into a terminal table representation.
 */
export function generateBenchmarkTableReport(report: BenchmarkReport): string {
  const m = report.metrics;
  const lines: string[] = [];

  lines.push(`=== BENCHMARK REPORT: ${report.corpusName} ===`);
  lines.push(`Precision: ${(m.precision * 100).toFixed(1)}%  |  Recall: ${(m.recall * 100).toFixed(1)}%  |  F1: ${m.f1Score.toFixed(3)}`);
  lines.push(`TP: ${m.truePositives}  FP: ${m.falsePositives}  FN: ${m.falseNegatives}  TN: ${m.trueNegatives}  Runtime: ${m.runtimeMs}ms`);
  lines.push("");
  lines.push("Cases Summary:");
  for (const res of report.caseResults) {
    const status = res.passed ? "[PASS]" : "[FAIL]";
    lines.push(`  ${status.padEnd(7)} ${res.caseId.padEnd(25)} (TP: ${res.truePositives}, FP: ${res.falsePositives}, FN: ${res.falseNegatives})`);
  }

  return lines.join("\n");
}

/**
 * Serializes a GateEvaluationResult into Markdown format.
 */
export function generateGateMarkdownReport(gate: GateEvaluationResult): string {
  const lines: string[] = [];
  lines.push(`# Regression Gate Evaluation Result`);
  lines.push("");
  lines.push(`**Overall Status:** ${gate.passed ? "🟢 PASSED" : "🔴 FAILED"}`);
  lines.push(`**Summary:** ${gate.summary}`);
  lines.push("");
  lines.push("## Comparison Checks");
  lines.push("");
  lines.push("| Status | Check Name | Actual | Threshold | Delta | Details |");
  lines.push("| --- | --- | --- | --- | --- | --- |");

  for (const c of gate.checks) {
    const status = c.passed ? "✅ PASS" : "❌ FAIL";
    const deltaStr = c.delta !== undefined ? String(c.delta) : "-";
    const waivedNote = c.waivedByException ? " (Waived)" : "";
    lines.push(`| ${status}${waivedNote} | ${c.name} | ${c.actual} | ${c.threshold} | ${deltaStr} | ${c.message} |`);
  }
  lines.push("");

  if (gate.exceptionsApplied.length > 0) {
    lines.push("## Exceptions Applied");
    lines.push("");
    lines.push("| Rule / Case | Reason | Reviewed By |");
    lines.push("| --- | --- | --- |");
    for (const exc of gate.exceptionsApplied) {
      const target = exc.ruleId || exc.caseId || "General";
      lines.push(`| \`${target}\` | ${exc.reason} | ${exc.reviewedBy || "Maintainer"} |`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
