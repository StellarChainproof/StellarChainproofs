import type { Finding, ScanResult, Severity } from "../../types";
import {
  mapSeverityToGitLab,
  mapSeverityToGitLabSAST,
  findingToGitLabCodeQuality,
  findingToGitLabSAST,
  buildGitLabCodeQualityReport,
  buildGitLabSASTReport,
  buildGitLabMRNote,
  findingsToGitLabAnnotations,
  buildGitLabCIReport,
  serializeGitLabCodeQualityArtifact,
  serializeGitLabSASTArtifact,
  GITLAB_ARTIFACT_PATHS,
  GITLAB_JOB_NAMES,
} from "../../ci/gitlab";
import type { CIIntegrationConfig } from "../../ci/types";

// ─── Test Fixtures ───────────────────────────────────────────────────────────

function createMockFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: "CP-107",
    title: "Reentrancy vulnerability",
    description: "Reentrancy vulnerability detected in withdraw function",
    recommendation: "Use ReentrancyGuard or Checks-Effects-Interactions pattern",
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

describe("GitLab severity mapping", () => {
  it("maps critical to blocker", () => {
    expect(mapSeverityToGitLab("critical")).toBe("blocker");
  });

  it("maps high to critical", () => {
    expect(mapSeverityToGitLab("high")).toBe("critical");
  });

  it("maps medium to major", () => {
    expect(mapSeverityToGitLab("medium")).toBe("major");
  });

  it("maps low to minor", () => {
    expect(mapSeverityToGitLab("low")).toBe("minor");
  });

  it("maps info to info", () => {
    expect(mapSeverityToGitLab("info")).toBe("info");
  });

  it("maps gas to info", () => {
    expect(mapSeverityToGitLab("gas")).toBe("info");
  });

  it("maps SAST severities correctly", () => {
    expect(mapSeverityToGitLabSAST("critical")).toBe("CRITICAL");
    expect(mapSeverityToGitLabSAST("high")).toBe("HIGH");
    expect(mapSeverityToGitLabSAST("medium")).toBe("MEDIUM");
    expect(mapSeverityToGitLabSAST("low")).toBe("LOW");
    expect(mapSeverityToGitLabSAST("info")).toBe("INFO");
    expect(mapSeverityToGitLabSAST("gas")).toBe("INFO");
  });
});

// ─── Finding Conversion Tests ────────────────────────────────────────────────

describe("findingToGitLabCodeQuality", () => {
  it("converts a finding to Code Quality issue format", () => {
    const finding = createMockFinding();
    const issue = findingToGitLabCodeQuality(finding);

    expect(issue.description).toContain("[CRITICAL]");
    expect(issue.description).toContain("Reentrancy vulnerability");
    expect(issue.severity).toBe("blocker");
    expect(issue.location.path).toBe("contracts/Vault.sol");
    expect(issue.location.lines.begin).toBe(42);
    expect(issue.fingerprint).toHaveLength(64); // SHA-256 hex
    expect(issue.identifiers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "swc", value: "SWC-107" }),
        expect.objectContaining({ type: "chainproof", value: "CP-107" }),
      ])
    );
  });

  it("omits swcId identifier when not present", () => {
    const finding = createMockFinding({ swcId: undefined });
    const issue = findingToGitLabCodeQuality(finding);
    expect(issue.identifiers).toHaveLength(1);
    expect(issue.identifiers[0].type).toBe("chainproof");
  });

  it("truncates long descriptions", () => {
    const finding = createMockFinding({
      description: "A".repeat(2000),
    });
    const issue = findingToGitLabCodeQuality(finding);
    expect(issue.description.length).toBeLessThanOrEqual(1024);
    expect(issue.description.endsWith("...")).toBe(true);
  });
});

describe("findingToGitLabSAST", () => {
  it("converts a finding to SAST vulnerability format", () => {
    const finding = createMockFinding();
    const vuln = findingToGitLabSAST(finding);

    expect(vuln.id).toContain("chainproof");
    expect(vuln.id).toContain("CP-107");
    expect(vuln.category).toBe("sast");
    expect(vuln.name).toBe("Reentrancy vulnerability");
    expect(vuln.severity).toBe("CRITICAL");
    expect(vuln.location.file).toBe("contracts/Vault.sol");
    expect(vuln.location.start_line).toBe(42);
    expect(vuln.location.end_line).toBe(50);
    expect(vuln.solution).toBe("Use ReentrancyGuard or Checks-Effects-Interactions pattern");
  });

  it("includes swc_id identifier when present", () => {
    const finding = createMockFinding({ swcId: "SWC-107" });
    const vuln = findingToGitLabSAST(finding);
    const swcIdent = vuln.identifiers.find((i) => i.type === "swc_id");
    expect(swcIdent).toBeDefined();
    expect(swcIdent!.value).toBe("SWC-107");
  });

  it("omits solution when recommendation is empty", () => {
    const finding = createMockFinding({ recommendation: "" });
    const vuln = findingToGitLabSAST(finding);
    expect(vuln.solution).toBeUndefined();
  });
});

// ─── Report Builder Tests ────────────────────────────────────────────────────

describe("buildGitLabCodeQualityReport", () => {
  it("builds a report with correct version and schema", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildGitLabCodeQualityReport(result);

    expect(report.version).toBe("15.1.6");
    expect(report.schema).toContain("code-quality-schema");
    expect(report.issues).toHaveLength(1);
  });

  it("converts all findings to issues", () => {
    const findings = [
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
      createMockFinding({ id: "CP-115", file: "B.sol", line: 20, severity: "high" }),
      createMockFinding({ id: "CP-101", file: "C.sol", line: 30, severity: "medium" }),
    ];
    const result = createMockScanResult(findings);
    const report = buildGitLabCodeQualityReport(result);

    expect(report.issues).toHaveLength(3);
  });

  it("returns empty issues for clean scan", () => {
    const result = createMockScanResult([]);
    const report = buildGitLabCodeQualityReport(result);
    expect(report.issues).toHaveLength(0);
  });
});

describe("buildGitLabSASTReport", () => {
  it("builds a SAST report with correct metadata", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildGitLabSASTReport(result);

    expect(report.version).toBe("15.1.6");
    expect(report.scan.analyzer.id).toBe("chainproof-core");
    expect(report.scan.scanner.id).toBe("chainproof-scanner");
    expect(report.scan.analyzer.version).toBe("0.1.0");
    expect(report.vulnerabilities).toHaveLength(1);
  });

  it("converts all findings to vulnerabilities", () => {
    const findings = [
      createMockFinding({ id: "CP-107" }),
      createMockFinding({ id: "CP-115", severity: "high" }),
    ];
    const result = createMockScanResult(findings);
    const report = buildGitLabSASTReport(result);

    expect(report.vulnerabilities).toHaveLength(2);
  });
});

// ─── MR Note Builder Tests ───────────────────────────────────────────────────

describe("buildGitLabMRNote", () => {
  it("generates a clean report for no findings", () => {
    const result = createMockScanResult([]);
    const note = buildGitLabMRNote(result);

    expect(note).toContain("## ✅ ChainProof Security Scan");
    expect(note).toContain("| **Total** | **0** |");
    expect(note).toContain("No vulnerability findings detected");
  });

  it("shows critical/high alert for blocking findings", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const note = buildGitLabMRNote(result);

    expect(note).toContain("## 🚨 ChainProof Security Scan");
    expect(note).toContain("Critical or high severity issues found");
    expect(note).toContain("| 🔴 Critical | 1 |");
  });

  it("shows diff mode when diff is provided", () => {
    const result = createMockScanResult([createMockFinding()]);
    const diff = {
      introduced: [createMockFinding({ id: "NEW-1", file: "New.sol", line: 10 })],
      resolved: [createMockFinding({ id: "OLD-1", file: "Old.sol", line: 20 })],
    };
    const note = buildGitLabMRNote(result, diff);

    expect(note).toContain("Diff-aware");
    expect(note).toContain("Newly Introduced (1)");
    expect(note).toContain("Resolved (1)");
  });

  it("respects maxFindings limit", () => {
    const findings = Array.from({ length: 100 }).map((_, i) =>
      createMockFinding({ id: `CP-${i}`, file: `F${i}.sol`, line: i })
    );
    const result = createMockScanResult(findings);
    const note = buildGitLabMRNote(result, undefined, 5);

    expect(note).toContain("+95 more");
  });
});

// ─── Annotations Tests ───────────────────────────────────────────────────────

describe("findingsToGitLabAnnotations", () => {
  it("converts findings to annotations", () => {
    const findings = [
      createMockFinding({ id: "CP-107", severity: "critical" }),
      createMockFinding({ id: "CP-115", severity: "high", file: "Auth.sol", line: 18 }),
    ];
    const annotations = findingsToGitLabAnnotations(findings);

    expect(annotations).toHaveLength(2);
    expect(annotations[0].severity).toBe("blocker");
    expect(annotations[1].severity).toBe("critical");
  });

  it("filters by minSeverity", () => {
    const findings = [
      createMockFinding({ id: "CP-107", severity: "critical" }),
      createMockFinding({ id: "CP-104", severity: "medium", file: "T.sol", line: 5 }),
      createMockFinding({ id: "INFO-1", severity: "info", file: "I.sol", line: 1 }),
    ];
    const annotations = findingsToGitLabAnnotations(findings, {
      minSeverity: "high",
    });

    expect(annotations).toHaveLength(1);
    expect(annotations[0].ruleId).toBe("CP-107");
  });

  it("applies maxAnnotations limit", () => {
    const findings = Array.from({ length: 50 }).map((_, i) =>
      createMockFinding({ id: `CP-${i}`, file: `F${i}.sol`, line: i })
    );
    const annotations = findingsToGitLabAnnotations(findings, {
      maxAnnotations: 5,
    });

    expect(annotations).toHaveLength(5);
  });

  it("applies suppression policy to filter out suppressed rules", () => {
    const findings = [
      createMockFinding({ id: "CP-107", severity: "critical" }),
      createMockFinding({ id: "CP-115", severity: "high", file: "Auth.sol", line: 18 }),
    ];
    const annotations = findingsToGitLabAnnotations(findings, {
      suppressPolicy: {
        suppressedRuleIds: ["CP-107"],
        suppressedSeverities: [],
        suppressedFiles: [],
      },
    });

    expect(annotations).toHaveLength(1);
    expect(annotations[0].ruleId).toBe("CP-115");
  });

  it("applies file-based suppression", () => {
    const findings = [
      createMockFinding({ id: "CP-107", file: "contracts/test/Vault.sol", line: 42 }),
      createMockFinding({ id: "CP-115", file: "contracts/Auth.sol", line: 18 }),
    ];
    const annotations = findingsToGitLabAnnotations(findings, {
      suppressPolicy: {
        suppressedRuleIds: [],
        suppressedSeverities: [],
        suppressedFiles: ["contracts/test/**"],
      },
    });

    expect(annotations).toHaveLength(1);
    expect(annotations[0].file).toBe("contracts/Auth.sol");
  });
});

// ─── Full CI Report Tests ────────────────────────────────────────────────────

describe("buildGitLabCIReport", () => {
  it("builds a complete CI report with correct provider", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "gitlab",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildGitLabCIReport(result, config);

    expect(report.provider).toBe("gitlab");
    expect(report.shouldFail).toBe(true);
    expect(report.summary.critical).toBe(1);
    expect(report.metadata.filesScanned).toBe(1);
    expect(report.annotations.length).toBeGreaterThan(0);
  });

  it("does not fail when only low-severity findings exist", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "low", id: "LOW-1" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "gitlab",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildGitLabCIReport(result, config);
    expect(report.shouldFail).toBe(false);
  });

  it("does not fail when running from a fork", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "gitlab",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
      failSeverity: "high",
    };

    const report = buildGitLabCIReport(result, config, undefined, {
      isFork: true,
      skipPosting: true,
    });
    expect(report.shouldFail).toBe(false);
  });

  it("includes diff metadata when diff is provided", () => {
    const result = createMockScanResult([
      createMockFinding({ severity: "critical" }),
    ]);
    const config: CIIntegrationConfig = {
      provider: "gitlab",
      scanConfig: {
        targets: ["contracts/"],
        useSlither: false,
        useLLM: false,
        useMetrics: false,
      },
    };
    const diff = {
      introduced: [createMockFinding({ id: "NEW-1" })],
      resolved: [],
      persisted: [createMockFinding({ id: "CP-107" })],
    };

    const report = buildGitLabCIReport(result, config, diff);
    expect(report.metadata.introducedCount).toBe(1);
    expect(report.metadata.resolvedCount).toBe(0);
  });
});

// ─── Artifact Serialization Tests ────────────────────────────────────────────

describe("GitLab artifact serialization", () => {
  it("serializeGitLabCodeQualityArtifact produces valid JSON", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildGitLabCodeQualityReport(result);
    const json = serializeGitLabCodeQualityArtifact(report);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe("15.1.6");
    expect(parsed.issues).toHaveLength(1);
  });

  it("serializeGitLabSASTArtifact produces valid JSON", () => {
    const result = createMockScanResult([createMockFinding()]);
    const report = buildGitLabSASTReport(result);
    const json = serializeGitLabSASTArtifact(report);
    const parsed = JSON.parse(json);

    expect(parsed.vulnerabilities).toHaveLength(1);
  });

  it("serializes artifact paths correctly", () => {
    expect(GITLAB_ARTIFACT_PATHS).toContain("chainproof-reports/code-quality-report.json");
    expect(GITLAB_ARTIFACT_PATHS).toContain("chainproof-reports/sast-report.json");
    expect(GITLAB_ARTIFACT_PATHS).toContain("chainproof-reports/audit-report.json");
  });

  it("has correct job names", () => {
    expect(GITLAB_JOB_NAMES.scan).toBe("chainproof-scan");
    expect(GITLAB_JOB_NAMES.diffScan).toBe("chainproof-diff-scan");
  });
});
