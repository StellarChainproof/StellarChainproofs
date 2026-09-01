import type { Finding } from "../types";
import type { ReturndataFinding } from "./types";

/** Slither detector IDs related to unchecked return values. */
const SLITHER_RETURN_DETECTORS = new Set([
  "unchecked-transfer",
  "unchecked-lowlevel",
  "unchecked-send",
  "return-value",
  "unused-return",
]);

export interface SlitherReturnFinding {
  id: string;
  check: string;
  impact: string;
  confidence: string;
  line: number;
}

/** Merge equivalent Slither findings while preserving ChainProof evidence. */
export function mergeSlitherReturnFindings(
  chainproofFindings: ReturndataFinding[],
  slitherFindings: SlitherReturnFinding[],
): ReturndataFinding[] {
  const merged = [...chainproofFindings];
  const coveredLines = new Set(chainproofFindings.map((f) => f.location.line));

  for (const slither of slitherFindings) {
    if (!SLITHER_RETURN_DETECTORS.has(slither.check) && !/return|transfer|lowlevel|send/i.test(slither.check)) {
      continue;
    }
    if (coveredLines.has(slither.line)) continue;
    merged.push({
      ruleId: "CP-RTD-004",
      title: `Slither: ${slither.check}`,
      description: slither.impact,
      recommendation: "Check the return value or use a SafeERC20/Address wrapper.",
      severity: slither.impact.toLowerCase().includes("high") ? "high" : "medium",
      confidence: slither.confidence === "High" ? "high" : "medium",
      category: "slither-merge",
      contract: "<slither>",
      location: { file: "<slither>", line: slither.line, column: 1 },
      evidence: [{ kind: "adapter", description: `Slither detector: ${slither.check}`, location: { file: "<slither>", line: slither.line, column: 1 } }],
      assumptions: ["Slither static analysis is available"],
      optionalCall: false,
    });
    coveredLines.add(slither.line);
  }
  return merged.sort((a, b) => a.location.line - b.location.line || a.ruleId.localeCompare(b.ruleId));
}

/** Convert ChainProof Finding to check for Slither overlap. */
export function isSlitherEquivalent(cp: ReturndataFinding, slither: SlitherReturnFinding): boolean {
  return Math.abs(cp.location.line - slither.line) <= 2 &&
    /return|transfer|call|send/i.test(slither.check);
}

export function toScanFinding(finding: ReturndataFinding, filePath: string): Finding {
  return {
    id: finding.ruleId,
    title: finding.title,
    description: finding.description,
    recommendation: finding.recommendation,
    severity: finding.severity,
    file: filePath,
    line: finding.location.line,
    lineEnd: finding.location.lineEnd,
    confidence: finding.confidence,
    assumptions: finding.assumptions,
    evidence: finding.evidence.map((e) => ({
      description: e.description + (finding.optionalCall ? " (optional call)" : ""),
      file: e.location.file,
      line: e.location.line,
    })),
  };
}
