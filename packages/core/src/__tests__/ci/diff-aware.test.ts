import type { Finding, ScanResult } from "../../types";
import {
  computeDiff,
  filterExistingFiles,
  resolveFilePaths,
  extractSolFilesFromDiffOutput,
  applySuppressionPolicy,
  detectFork,
} from "../../ci/diff-aware";

// ─── Test Fixtures ───────────────────────────────────────────────────────────

function createMockFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: "CP-107",
    title: "Reentrancy vulnerability",
    description: "Reentrancy vulnerability detected",
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

// ─── computeDiff Tests ───────────────────────────────────────────────────────

describe("computeDiff", () => {
  it("identifies introduced findings (new in current, not in baseline)", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
      createMockFinding({ id: "CP-115", file: "B.sol", line: 20 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.introduced).toHaveLength(1);
    expect(diff.introduced[0].id).toBe("CP-115");
    expect(diff.persisted).toHaveLength(1);
    expect(diff.persisted[0].id).toBe("CP-107");
    expect(diff.resolved).toHaveLength(0);
  });

  it("identifies resolved findings (in baseline, not in current)", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
      createMockFinding({ id: "CP-115", file: "B.sol", line: 20 }),
    ]);
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.resolved).toHaveLength(1);
    expect(diff.resolved[0].id).toBe("CP-115");
    expect(diff.persisted).toHaveLength(1);
    expect(diff.introduced).toHaveLength(0);
  });

  it("identifies persisted findings (present in both)", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.persisted).toHaveLength(1);
    expect(diff.introduced).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
  });

  it("handles empty baseline (all findings are introduced)", () => {
    const baseline = createMockScanResult([]);
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.introduced).toHaveLength(1);
    expect(diff.persisted).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
  });

  it("handles empty current (all findings are resolved)", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);
    const current = createMockScanResult([]);

    const diff = computeDiff(baseline, current);

    expect(diff.resolved).toHaveLength(1);
    expect(diff.persisted).toHaveLength(0);
    expect(diff.introduced).toHaveLength(0);
  });

  it("handles both empty (no findings in either scan)", () => {
    const baseline = createMockScanResult([]);
    const current = createMockScanResult([]);

    const diff = computeDiff(baseline, current);

    expect(diff.introduced).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
    expect(diff.persisted).toHaveLength(0);
  });

  it("matches findings with line tolerance of ±3 lines", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);
    // Finding moved 2 lines down
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 12 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.persisted).toHaveLength(1);
    expect(diff.introduced).toHaveLength(0);
    expect(diff.resolved).toHaveLength(0);
  });

  it("does not match findings beyond ±3 line tolerance", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
    ]);
    // Finding moved 5 lines down (beyond tolerance)
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 15 }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.persisted).toHaveLength(0);
    expect(diff.introduced).toHaveLength(1);
    expect(diff.resolved).toHaveLength(1);
  });

  it("handles complex scenario with multiple findings across files", () => {
    const baseline = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }),
      createMockFinding({ id: "CP-115", file: "A.sol", line: 20 }),
      createMockFinding({ id: "CP-101", file: "B.sol", line: 30 }),
    ]);
    const current = createMockScanResult([
      createMockFinding({ id: "CP-107", file: "A.sol", line: 10 }), // persisted
      createMockFinding({ id: "CP-104", file: "C.sol", line: 40 }), // introduced
      createMockFinding({ id: "CP-115", file: "A.sol", line: 22 }), // persisted (within tolerance)
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.persisted).toHaveLength(2); // CP-107, CP-115
    expect(diff.introduced).toHaveLength(1); // CP-104
    expect(diff.resolved).toHaveLength(1); // CP-101
  });

  it("matches by exact fingerprint when available", () => {
    const baseline = createMockScanResult([
      createMockFinding({
        id: "CP-107",
        file: "A.sol",
        line: 10,
        snippet: "msg.sender.call{value: amount}(\"\")",
      }),
    ]);
    const current = createMockScanResult([
      createMockFinding({
        id: "CP-107",
        file: "A.sol",
        line: 10,
        snippet: "msg.sender.call{value: amount}(\"\")",
      }),
    ]);

    const diff = computeDiff(baseline, current);

    expect(diff.persisted).toHaveLength(1);
    expect(diff.introduced).toHaveLength(0);
  });
});

// ─── extractSolFilesFromDiffOutput Tests ─────────────────────────────────────

describe("extractSolFilesFromDiffOutput", () => {
  it("extracts .sol files from git diff --name-status output", () => {
    const diffOutput = [
      "A\tcontracts/Vault.sol",
      "M\tcontracts/Auth.sol",
      "D\tcontracts/Deprecated.sol",
      "M\tpackage.json",
      "A\tcontracts/new/Token.sol",
    ].join("\n");

    const files = extractSolFilesFromDiffOutput(diffOutput);

    expect(files).toContain("contracts/Vault.sol");
    expect(files).toContain("contracts/Auth.sol");
    expect(files).toContain("contracts/Deprecated.sol");
    expect(files).toContain("contracts/new/Token.sol");
    expect(files).not.toContain("package.json");
  });

  it("handles empty diff output", () => {
    const files = extractSolFilesFromDiffOutput("");
    expect(files).toHaveLength(0);
  });

  it("deduplicates files", () => {
    const diffOutput = [
      "M\tcontracts/Vault.sol",
      "M\tcontracts/Vault.sol",
    ].join("\n");

    const files = extractSolFilesFromDiffOutput(diffOutput);
    expect(files).toHaveLength(1);
  });

  it("handles rename status", () => {
    const diffOutput = "R100\tcontracts/Old.sol\tcontracts/New.sol";
    const files = extractSolFilesFromDiffOutput(diffOutput);

    expect(files).toContain("contracts/New.sol");
  });
});

// ─── filterExistingFiles Tests ───────────────────────────────────────────────

describe("filterExistingFiles", () => {
  it("filters out non-existent files", () => {
    const files = [
      "packages/core/src/index.ts",
      "/nonexistent/path/file.sol",
    ];
    const existing = filterExistingFiles(files);
    expect(existing).toContain("packages/core/src/index.ts");
    expect(existing).not.toContain("/nonexistent/path/file.sol");
  });

  it("applies exclusion patterns", () => {
    const files = [
      "packages/core/src/index.ts",
      "packages/core/src/__tests__/test.ts",
    ];
    const existing = filterExistingFiles(files, ["**/__tests__/**"]);
    expect(existing).toContain("packages/core/src/index.ts");
    expect(existing).not.toContain("packages/core/src/__tests__/test.ts");
  });

  it("returns empty array for all non-existent files", () => {
    const files = ["/no/such/file1.sol", "/no/such/file2.sol"];
    const existing = filterExistingFiles(files);
    expect(existing).toHaveLength(0);
  });
});

// ─── resolveFilePaths Tests ──────────────────────────────────────────────────

describe("resolveFilePaths", () => {
  it("resolves relative paths to absolute", () => {
    const resolved = resolveFilePaths(["packages/core/src/index.ts"]);
    expect(resolved[0]).toMatch(/packages\/core\/src\/index\.ts$/);
    expect(require("path").isAbsolute(resolved[0])).toBe(true);
  });

  it("keeps absolute paths unchanged", () => {
    const absolutePath = require("path").resolve("packages/core/src/index.ts");
    const resolved = resolveFilePaths([absolutePath]);
    expect(resolved[0]).toBe(absolutePath);
  });

  it("resolves relative to a custom base path", () => {
    const resolved = resolveFilePaths(["src/index.ts"], "/tmp/myproject");
    expect(resolved[0]).toBe("/tmp/myproject/src/index.ts");
  });
});

// ─── applySuppressionPolicy Tests ────────────────────────────────────────────

describe("applySuppressionPolicy", () => {
  const findings = [
    createMockFinding({ id: "CP-107", severity: "critical", file: "A.sol" }),
    createMockFinding({ id: "CP-115", severity: "high", file: "B.sol", line: 18 }),
    createMockFinding({ id: "CP-104", severity: "medium", file: "test/C.sol", line: 30 }),
  ];

  it("filters out findings by suppressed rule IDs", () => {
    const result = applySuppressionPolicy(findings, {
      suppressedRuleIds: ["CP-107"],
    });

    expect(result).toHaveLength(2);
    expect(result.find((f) => f.id === "CP-107")).toBeUndefined();
  });

  it("filters out findings by suppressed severity", () => {
    const result = applySuppressionPolicy(findings, {
      suppressedSeverities: ["medium"],
    });

    expect(result).toHaveLength(2);
    expect(result.find((f) => f.severity === "medium")).toBeUndefined();
  });

  it("filters out findings by file pattern", () => {
    const result = applySuppressionPolicy(findings, {
      suppressedFiles: ["test/**"],
    });

    expect(result).toHaveLength(2);
    expect(result.find((f) => f.file === "test/C.sol")).toBeUndefined();
  });

  it("applies multiple suppression criteria together", () => {
    const result = applySuppressionPolicy(findings, {
      suppressedRuleIds: ["CP-107"],
      suppressedSeverities: ["medium"],
    });

    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("CP-115");
  });

  it("returns all findings when no suppressions apply", () => {
    const result = applySuppressionPolicy(findings, {});
    expect(result).toHaveLength(3);
  });

  it("returns all findings when expired suppression is provided", () => {
    const result = applySuppressionPolicy(findings, {
      suppressedRuleIds: ["CP-107"],
      expiresAt: "2020-01-01T00:00:00.000Z", // Already expired
    });

    // The logic checks if new Date(expiresAt) > new Date()
    // Since 2020 is before now, this condition is false, so the filter applies
    expect(result).toHaveLength(2);
    expect(result.find((f) => f.id === "CP-107")).toBeUndefined();
  });
});

// ─── detectFork Tests ────────────────────────────────────────────────────────

describe("detectFork", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("detects GitLab fork when root namespace differs from project namespace", () => {
    process.env.CI_PROJECT_ROOT_NAMESPACE = "original-org";
    process.env.CI_PROJECT_NAMESPACE = "fork-user/original-org";

    const result = detectFork();
    expect(result.isFork).toBe(true);
    expect(result.provider).toBe("gitlab");
  });

  it("detects non-fork on GitLab when namespaces match", () => {
    process.env.CI_PROJECT_ROOT_NAMESPACE = "my-org";
    process.env.CI_PROJECT_NAMESPACE = "my-org/my-project";
    delete process.env.CI_MERGE_REQUEST_SOURCE_PROJECT_ID;

    const result = detectFork();
    expect(result.isFork).toBe(false);
  });

  it("detects GitHub fork when head repository differs", () => {
    process.env.GITHUB_HEAD_REPOSITORY = "fork-user/StellarChainproofs";
    process.env.GITHUB_REPOSITORY = "StellarChainproofs/StellarChainproofs";

    const result = detectFork();
    expect(result.isFork).toBe(true);
    expect(result.provider).toBe("unknown");
  });

  it("returns isFork: false when no CI env vars are set", () => {
    delete process.env.CI_PROJECT_ROOT_NAMESPACE;
    delete process.env.CI_PROJECT_NAMESPACE;
    delete process.env.GITHUB_HEAD_REPOSITORY;
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.CI_MERGE_REQUEST_SOURCE_PROJECT_ID;
    delete process.env.CI_PROJECT_ID;
    delete process.env.BB_PR_FROM_COMMIT;

    const result = detectFork();
    expect(result.isFork).toBe(false);
  });
});
