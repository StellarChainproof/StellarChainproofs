/**
 * Validation report generators.
 *
 * Produces portable, versioned JSON and human-readable Markdown reports
 * from {@link ValidationReport} and {@link ValidationResult} objects.
 *
 * @remarks
 * JSON reports use deterministic key ordering and are suitable for diffing.
 * Markdown reports are designed for terminal output and pull-request comments.
 * No sensitive information (private keys, fork URLs, local paths) is emitted.
 */

import type { CallResult, ValidationReport, ValidationResult } from "./types";

// ─── JSON report ──────────────────────────────────────────────────────────────

/**
 * Serialize a {@link ValidationReport} to pretty-printed JSON.
 * Keys are ordered deterministically.
 */
export function serializeValidationReport(report: ValidationReport): string {
  return JSON.stringify(report, deterministicReplacer, 2);
}

/**
 * Serialize a single {@link ValidationResult} to JSON.
 */
export function serializeValidationResult(result: ValidationResult): string {
  return JSON.stringify(result, deterministicReplacer, 2);
}

/** @internal */
function deterministicReplacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)),
    );
  }
  return value;
}

// ─── Markdown report ──────────────────────────────────────────────────────────

/**
 * Generate a Markdown validation report suitable for PR comments or terminal display.
 */
export function generateValidationMarkdown(report: ValidationReport): string {
  const lines: string[] = [];

  lines.push("# ChainProof Validation Report\n");
  lines.push(`**Schema:** ${report.schemaVersion}  `);
  lines.push(`**Timestamp:** ${report.timestamp}  `);
  lines.push(`**Adapter:** ${report.adapterType}  `);
  lines.push(`**Duration:** ${formatDuration(report.totalDurationMs)}\n`);

  // Summary table
  lines.push("## Summary\n");
  lines.push("| Result | Count |");
  lines.push("|--------|-------|");
  lines.push(`| ✅ Passed | ${report.passed} |`);
  lines.push(`| ❌ Failed | ${report.failed} |`);
  lines.push(`| 🔴 Errored | ${report.errored} |`);
  lines.push(`| **Total** | **${report.total}** |`);
  lines.push("");

  if (report.total === 0) {
    lines.push("_No scenarios were executed._\n");
    return lines.join("\n");
  }

  // Per-scenario results
  lines.push("## Scenario Results\n");

  for (const result of report.results) {
    lines.push(...generateResultSection(result));
  }

  return lines.join("\n");
}

function generateResultSection(result: ValidationResult): string[] {
  const lines: string[] = [];
  const icon = result.error ? "🔴" : result.outcomeMatched ? "✅" : "❌";
  const status = result.error ? "ERROR" : result.outcomeMatched ? "PASSED" : "FAILED";

  lines.push(`### ${icon} ${escapeMarkdown(result.scenario.title)}`);
  lines.push("");
  lines.push(`**Scenario ID:** \`${result.scenario.id}\`  `);
  lines.push(`**Status:** ${status}  `);
  lines.push(`**Adapter:** ${result.adapterType} ${result.adapterVersion}  `);
  lines.push(`**Duration:** ${formatDuration(result.durationMs)}  `);
  lines.push(`**Total Gas:** ${result.totalGasUsed.toLocaleString()}  `);

  if (result.scenario.findingId) {
    lines.push(`**Finding:** ${result.scenario.findingId} — ${result.scenario.findingFile ?? ""}:${result.scenario.findingLine ?? "?"}`);
  }
  lines.push("");

  lines.push(`**Outcome:** ${escapeMarkdown(result.outcomeSummary)}\n`);

  // Error
  if (result.error) {
    lines.push(`> ⚠️ **Infrastructure Error:** ${escapeMarkdown(result.error)}\n`);
  }

  // Call results summary
  if (result.callResults.length > 0) {
    lines.push("#### Call Execution\n");
    lines.push("| # | Description | Reverted | Gas |");
    lines.push("|---|-------------|----------|-----|");
    for (const cr of result.callResults) {
      const call = result.scenario.calls[cr.callIndex];
      const desc = call?.description ?? call?.signature ?? `call[${cr.callIndex}]`;
      const revert = cr.reverted
        ? `⛔ ${escapeMarkdown(cr.revertReason?.slice(0, 60) ?? "reverted")}`
        : "✓";
      lines.push(`| ${cr.callIndex + 1} | ${escapeMarkdown(desc.slice(0, 60))} | ${revert} | ${cr.gasUsed.toLocaleString()} |`);
    }
    lines.push("");
  }

  // Assertion results
  if (result.storageAssertionResults.length > 0) {
    lines.push("#### Storage Assertions\n");
    for (const ar of result.storageAssertionResults) {
      const icon2 = ar.passed ? "✅" : "❌";
      lines.push(
        `${icon2} Slot \`${ar.assertion.slot}\` on \`${ar.assertion.contract}\`: ` +
          `expected \`${ar.assertion.expected}\`, got \`${ar.actual}\``,
      );
    }
    lines.push("");
  }

  if (result.balanceAssertionResults.length > 0) {
    lines.push("#### Balance Assertions\n");
    for (const ar of result.balanceAssertionResults) {
      const icon2 = ar.passed ? "✅" : "❌";
      lines.push(
        `${icon2} \`${ar.assertion.account}\` balance ${ar.assertion.op} \`${ar.assertion.value}\` wei: ` +
          `actual \`${ar.actual}\` wei`,
      );
    }
    lines.push("");
  }

  if (result.eventAssertionResults.length > 0) {
    lines.push("#### Event Assertions\n");
    for (const ar of result.eventAssertionResults) {
      const icon2 = ar.passed ? "✅" : "❌";
      const neg = ar.assertion.negate ? "NOT " : "";
      lines.push(
        `${icon2} Event \`${ar.assertion.eventSignature}\` ${neg}emitted by \`${ar.assertion.contract}\`: ` +
          `found=${ar.found}`,
      );
    }
    lines.push("");
  }

  // Warnings
  if (result.warnings.length > 0) {
    lines.push("#### Warnings\n");
    for (const w of result.warnings) {
      lines.push(`- ⚠️ ${escapeMarkdown(w)}`);
    }
    lines.push("");
  }

  lines.push("---\n");
  return lines;
}

// ─── Single result Markdown ───────────────────────────────────────────────────

/**
 * Generate a Markdown summary for a single {@link ValidationResult}.
 */
export function generateValidationResultMarkdown(result: ValidationResult): string {
  const lines: string[] = [];
  lines.push("# Validation Result\n");
  lines.push(...generateResultSection(result));
  return lines.join("\n");
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  if (ms < 1_000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.floor((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

function escapeMarkdown(text: string): string {
  return text.replace(/[<>|`*_[\]]/g, "\\$&");
}

/**
 * Parse a validation report from JSON.
 * Throws on schema mismatch.
 */
export function parseValidationReport(json: string, filePath = "<string>"): ValidationReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`Invalid JSON in validation report at ${filePath}`);
  }
  const obj = parsed as Record<string, unknown>;
  if (!obj || typeof obj !== "object") {
    throw new Error("Validation report must be an object");
  }
  if (typeof obj["schemaVersion"] !== "string") {
    throw new Error("Validation report missing schemaVersion");
  }
  if (!Array.isArray(obj["results"])) {
    throw new Error("Validation report missing results array");
  }
  return obj as unknown as ValidationReport;
}
