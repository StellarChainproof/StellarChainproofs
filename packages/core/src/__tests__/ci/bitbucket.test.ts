import type { Finding, ScanResult, Severity } from "../../types";
import {
  mapSeverityToBitbucket,
  mapFindingTypeToBitbucket,
  findingToBitbucketAnnotation,
  buildBitbucketCodeInsightsReport,
  buildBitbucketDiffReport,
  buildBitbucketPRSummary,
  findingsToBitbucketAnnotations,
  buildBitbucketCIReport,
  serializeBitbucketCodeInsightsArtifact,
  buildBitbucketPipelineStatus,
  BITBUCKET_ARTIFACT_PATHS,
} from "../../ci/bitbucket";
import type { CIIntegrationConfig } from "../../ci/types";

// ─── Test Fixtures ───────────────────────────────────────────────────────────

function createMockFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: "CP-107",
    title: "Reentrancy vulnerability",
    description: "Reentrancy vulnerability detected in withdraw function",
    recommendation: "Use ReentrancyGuard",
    severity: "critical",
    file: "contracts/Vault.sol",
    line: 42,
    lineEnd: 50,
    snippet: "(bool ok,) = msg.sender.call{value: amount}(\"\")",
    swcId: "SWC-107",
    ...overrides,
  };
}

function createMockScanResult(findings: Finding[]): ScanResult {
  const fileMap = new Map<string, Finding[]>();
  findings.forEach((f) => {
    if (!fileMap.has(f.file)) fileMap.set(f.file, []);
    fileMap.get(f.file)!.push(f);
  });

  const files = Array.from(fileMap.entries()).map(([file, fileFindings]) => ({
    file,
    findings: fileFindings,
    gasHints: [],
    slitherRan: false,
  }));

  return {
    version: "0.1.0",
    timestamp: "2026-08-28T12:00:00.000Z",
    files,
    summary: {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
      gas: 0,
      total: findings.length,
    },
  };
}

// ─── Severity Mapping Tests ──────────────────────────────────────────────────

describe("Bitbucket severity mapping", () => {
  it("maps critical to BLOCKER", () => {
    expect(mapSeverityToBitbucket("critical")).toBe("BLOCKER");
  });

  it("maps high to CRITICAL", () => {
    expect(mapSeverityToBitbucket("high")).toBe("CRITICAL");
  });

  it("maps medium to MAJOR", () => {
    expect(mapSeverityToBitbucket("medium")).toBe("MAJOR");
  });

  it("maps low to MINOR", () => {
    expect(mapSeverityToBitbucket("low")).toBe("MINOR");
  });

  it("maps info to INFO", () => {
    expect(mapSeverityToBitbucket("info")).toBe("INFO");
  });

  it("maps gas to INFO", () => {
    expect(mapSeverityToBitbucket("gas")).toBe("INFO");
  });

  it("maps finding types correctly", () => {
    expect(mapFindingTypeToBitbucket("critical")).toBe("VULNERABILITY");
    expect(mapFindingTypeToBitbucket("high")).toBe("VULNERABILITY");
    expect(mapFindingTypeToBitbucket("medium")).toBe("SECURITY");
    expect(mapFindingTypeToBitbucket("low")).toBe("CODE_SMELL");
    expect(mapFindingTypeToBitbucket("info")).toBe("ISSUE");
  });
});

// ─── Finding Conversion Tests ────────────────────────────────────────────────

describe("findingToBitbucketAnnotation", () => {
  it("converts a finding to Bitbucket annotation format", () => {
    const finding = createMockFinding();
    const annotation = findingToBitbucketAnnotation(finding);

    expect(annotation.external_id).toContain("chainproof-CP-107");
    expect(annotation.external_id).toContain("Vault.sol");
    expect(annotation.annotation_type).toBe("VULNERABILITY");
    expect(annotation.summary).toContain("[CP-107]");
    expect(annotation.summary).toContain("Reentrancy vulnerability");
    expect(annotation.severity).toBe("BLOCKER");
    expect(annotation.path).toBe("contracts/Vault.sol");
    expect(annotation.line).toBe(42);
    expect(annotation.rule).toEqual({
      type: "chainproof",
      name: "CP-107",
    });
  });

  it("truncates long summaries", () => {
    const finding = createMockFinding({
      title: "A".repeat(2000),
    });
    const annotation = findingToBitbucketAnnotation(finding);
    expect(annotation.summary.length).toBeLessThanOrEqual(1024);
    expect(annotation.summary.endsWith("...")).toBe(true);
  });

  it("truncates long details", () => {
    const finding = createMockFinding({
      description: "B".repeat(2000),
    });
    const annotation = findingToBitbucketAnnotation(finding);
    expect(annotation.details.length).toBeLessThanOrEqual(1024);
  });
});

// ─── Code Insights Report Tests ──────────────────────────────────────────────

describe("buildBitbucketCodeInsightsReport", () => {
  it("builds a report with PASS when no high/critical findings", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "low", id: "LOW-1" }),
    ]);
    const report = buildBitbucketCodeInsightsReport(result);

    expect(report.result).toBe("PASS");
    expect(report.reporter).toBe("chainproof");
    expect(report.title).toBe("ChainProof Security Scan");
    expect(report.annotations).toHaveLength(1);
    expect(report.data.properties.criticalCount).toBe(0);
  });

  it("builds a report with FAIL when critical findings exist", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const report = buildBitbucketCodeInsightsReport(result);

    expect(report.result).toBe("FAIL");
    expect(report.annotations).toHaveLength(1);
  });

  it("respects custom fail severity threshold", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "medium", id: "MED-1" }),
    ]);
    const report = buildBitbucketCodeInsightsReport(result, {
      failSeverity: "medium",
    });

    expect(report.result).toBe("FAIL");
  });

  it("does not fail when findings are below threshold", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "low", id: "LOW-1" }),
    ]);
    const report = buildBitbucketCodeInsightsReport(result, {
      failSeverity: "high",
    });

    expect(report.result).toBe("PASS");
  });

  it("applies maxAnnotations limit", () => {
    const findings = Array.from({ length: 50 }).map((_, i) =>
      createMockFinding({ id: `CP-${i}`, file: `F${i}.sol`, line: i })
    );
    const result = createMockScanResult(findings);
    const report = buildBitbucketCodeInsightsReport(result, {
      maxAnnotations: 5,
    });

    expect(report.annotations).toHaveLength(5);
  });

  it("includes summary details with file count", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildBitbucketCodeInsightsReport(result);

    expect(report.details).toContain("Files scanned: 1");
    expect(report.details).toContain("Total: 1");
  });
});

// ─── Diff Report Tests ───────────────────────────────────────────────────────

describe("buildBitbucketDiffReport", () => {
  it("builds a diff report with PASS when no introduced high/critical findings", () => {
    const result = createMockScanResult([createMockFinding()]);
    const diff = {
      introduced: [createMockFinding({ severity: "low", id: "NEW-1" })],
      resolved: [createMockFinding({ id: "OLD-1", file: "Old.sol", line: 10 })],
      persisted: [createMockFinding({ id: "CP-107" })],
    };

    const report = buildBitbucketDiffReport(result, diff);

    expect(report.result).toBe("PASS");
    expect(report.title).toBe("ChainProof Diff Security Scan");
    expect(report.annotations).toHaveLength(1);
  });

  it("builds a diff report with FAIL when critical findings are introduced", () => {
    const result = createMockScanResult([createMockFinding()]);
    const diff = {
      introduced: [createMockFinding({ id: "NEW-CRIT", severity: "critical" })],
      resolved: [],
      persisted: [],
    };

    const report = buildBitbucketDiffReport(result, diff);

    expect(report.result).toBe("FAIL");
    expect(report.data.properties.introducedCount).toBe(1);
  });

  it("includes diff summary in details", () => {
    const result = createMockScanResult([]);
    const diff = {
      introduced: [createMockFinding({ id: "N1" }), createMockFinding({ id: "N2" })],
      resolved: [createMockFinding({ id: "R1" })],
      persisted: [createMockFinding({ id: "P1" })],
    };

    const report = buildBitbucketDiffReport(result, diff);

    expect(report.details).toContain("Introduced: 2");
    expect(report.details).toContain("Resolved: 1");
    expect(report.details).toContain("Persisted: 1");
  });
});

// ─── PR Summary Tests ────────────────────────────────────────────────────────

describe("buildBitbucketPRSummary", () => {
  it("generates a clean PR summary for no findings", () => {
    const result = createMockScanResult([]);
    const summary = buildBitbucketPRSummary(result);

    expect(summary).toContain("## ✅ ChainProof Security Scan");
    expect(summary).toContain("| **Total** | **0** |");
  });

  it("shows critical alert for blocking findings", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const summary = buildBitbucketPRSummary(result);

    expect(summary).toContain("## 🚨 ChainProof Security Scan");
    expect(summary).toContain("Critical or high severity issues found");
  });

  it("shows diff-aware mode when diff is provided", () => {
    const result = createMockScanResult([]);
    const diff = {
      introduced: [createMockFinding({ id: "NEW-1", severity: "critical" })],
      resolved: [],
    };
    const summary = buildBitbucketPRSummary(result, diff);

    expect(summary).toContain("Diff-aware");
    expect(summary).toContain("Newly Introduced Findings");
    expect(summary).toContain("🔴");
  });

  it("shows resolved findings when diff is provided", () => {
    const result = createMockScanResult([]);
    const diff = {
      introduced: [],
      resolved: [createMockFinding({ id: "OLD-1", title: "Fixed bug" })],
    };
    const summary = buildBitbucketPRSummary(result, diff);

    expect(summary).toContain("Resolved (1)");
    expect(summary).toContain("Fixed bug");
  });

  it("shows top findings in full scan mode", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
      createMockFinding({ severity: "high", id: "CP-115", file: "Auth.sol", line: 18 }),
    ]);
    const summary = buildBitbucketPRSummary(result);

    expect(summary).toContain("### Top Findings");
    expect(summary).toContain("🔴");
    expect(summary).toContain("🟠");
  });
});

// ─── Annotations Tests ───────────────────────────────────────────────────────

describe("findingsToBitbucketAnnotations", () => {
  it("converts findings to annotations", () => {
    const findings = [
      createMockFinding({ severity: "critical" }),
      createMockFinding({ severity: "high", id: "CP-115", file: "Auth.sol", line: 18 }),
    ];
    const annotations = findingsToBitbucketAnnotations(findings);

    expect(annotations).toHaveLength(2);
    expect(annotations[0].severity).toBe("BLOCKER");
    expect(annotations[1].severity).toBe("CRITICAL");
  });

  it("filters by minSeverity", () => {
    const findings = [
      createMockFinding({ severity: "critical" }),
      createMockFinding({ severity: "medium", id: "MED-1", file: "M.sol", line: 5 }),
      createMockFinding({ severity: "info", id: "INF-1", file: "I.sol", line: 1 }),
    ];
    const annotations = findingsToBitbucketAnnotations(findings, {
      minSeverity: "high",
    });

    expect(annotations).toHaveLength(1);
    expect(annotations[0].ruleId).toBe("CP-107");
  });

  it("applies maxAnnotations limit", () => {
    const findings = Array.from({ length: 30 }).map((_, i) =>
      createMockFinding({ id: `CP-${i}`, file: `F${i}.sol`, line: i })
    );
    const annotations = findingsToBitbucketAnnotations(findings, {
      maxAnnotations: 3,
    });

    expect(annotations).toHaveLength(3);
  });

  it("applies suppression policy", () => {
    const findings = [
      createMockFinding({ id: "CP-107", severity: "critical" }),
      createMockFinding({ id: "CP-115", severity: "high", file: "Auth.sol", line: 18 }),
    ];
    const annotations = findingsToBitbucketAnnotations(findings, {
      suppressPolicy: {
        suppressedRuleIds: ["CP-107"],
        suppressedSeverities: [],
        suppressedFiles: [],
      },
    });

    expect(annotations).toHaveLength(1);
    expect(annotations[0].ruleId).toBe("CP-115");
  });
});

// ─── Full CI Report Tests ────────────────────────────────────────────────────

describe("buildBitbucketCIReport", () => {
  it("builds a complete CI report with correct provider", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "bitbucket",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildBitbucketCIReport(result, config);

    expect(report.provider).toBe("bitbucket");
    expect(report.shouldFail).toBe(true);
    expect(report.summary.critical).toBe(1);
    expect(report.metadata.filesScanned).toBe(1);
  });

  it("does not fail when only low findings exist", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "low", id: "LOW-1" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "bitbucket",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildBitbucketCIReport(result, config);
    expect(report.shouldFail).toBe(false);
  });

  it("does not fail when running from a fork", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "bitbucket",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildBitbucketCIReport(result, config, undefined, {
      isFork: true,
      skipPosting: true,
    });
    expect(report.shouldFail).toBe(false);
  });
});

// ─── Pipeline Status Tests ───────────────────────────────────────────────────

describe("buildBitbucketPipelineStatus", () => {
  it("returns FAILED when critical/high findings exist", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const status = buildBitbucketPipelineStatus(result);

    expect(status.state).toBe("FAILED");
    expect(status.key).toBe("chainproof-security-scan");
    expect(status.name).toBe("ChainProof Security Scan");
    expect(status.description).toContain("1 critical");
  });

  it("returns SUCCESSFUL when no critical/high findings", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "low", id: "LOW-1" }),
    ]);
    const status = buildBitbucketPipelineStatus(result);

    expect(status.state).toBe("SUCCESSFUL");
    expect(status.description).toContain("none critical/high");
  });

  it("includes optional metadata", () => {
    const result = createMockScanResult([]);
    const status = buildBitbucketPipelineStatus(result, {
      commitSha: "abc123",
      branch: "feature/test",
      pipelineUrl: "https://bitbucket.org/build/123",
    });

    expect(status.commit).toBe("abc123");
    expect(status.refname).toBe("feature/test");
    expect(status.url).toBe("https://bitbucket.org/build/123");
  });
});

// ─── Artifact Serialization Tests ────────────────────────────────────────────

describe("Bitbucket artifact serialization", () => {
  it("serializeBitbucketCodeInsightsArtifact produces valid JSON", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildBitbucketCodeInsightsReport(result);
    const json = serializeBitbucketCodeInsightsArtifact(report);
    const parsed = JSON.parse(json);

    expect(parsed.reporter).toBe("chainproof");
    expect(parsed.annotations).toHaveLength(1);
  });

  it("serializes artifact paths correctly", () => {
    expect(BITBUCKET_ARTIFACT_PATHS).toContain("chainproof-reports/code-insights-report.json");
    expect(BITBUCKET_ARTIFACT_PATHS).toContain("chainproof-reports/audit-report.json");
  });
});
