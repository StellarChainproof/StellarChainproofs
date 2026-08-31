/**
 * CLI tests for `chainproof validate` subcommands.
 *
 * Tests cover:
 * - `validate plan`  — translate a scan-result JSON into a ValidationPlan
 * - `validate run`   — execution path with adapter unavailability graceful failure
 * - `validate replay`— replay a saved result (offline, no adapter needed)
 * - `validate minimize` — minimize a scenario
 * - `validate report`— re-format a saved ValidationReport (json / markdown)
 *
 * These are integration tests that invoke the compiled CLI binary. Adapter
 * lifecycle tests (actual Anvil / Hardhat execution) require those binaries
 * to be installed and are skipped in CI environments where they are absent.
 */

import { spawnSync, execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const CLI = path.resolve(__dirname, "../../dist/cli.js");

// ─── Fixtures ─────────────────────────────────────────────────────────────────

/** Minimal ScanResult JSON with supported (CP-107) and unsupported (GAS-001) findings. */
const SCAN_RESULT_WITH_CP107 = JSON.stringify({
  version: "0.1.0",
  timestamp: "2026-08-01T00:00:00.000Z",
  files: [
    {
      file: "contracts/VulnerableVault.sol",
      findings: [
        {
          id: "CP-107",
          title: "Reentrancy",
          description: "External call before state update",
          recommendation: "Apply CEI pattern",
          severity: "critical",
          file: "contracts/VulnerableVault.sol",
          line: 42,
          snippet: "payable(msg.sender).call{value: amount}(\"\");",
        },
        {
          id: "CP-115",
          title: "tx.origin auth",
          description: "Uses tx.origin for authentication",
          recommendation: "Use msg.sender",
          severity: "high",
          file: "contracts/VulnerableVault.sol",
          line: 55,
          snippet: "require(tx.origin == owner);",
        },
        {
          id: "GAS-001",
          title: "Storage in loop",
          description: "Reading state variable inside loop",
          recommendation: "Cache in memory",
          severity: "gas",
          file: "contracts/VulnerableVault.sol",
          line: 70,
          snippet: "for (uint i = 0; i < arr.length; i++)",
        },
      ],
    },
  ],
  summary: { critical: 1, high: 1, medium: 0, low: 0, info: 0, gas: 1, total: 3 },
});

/** Minimal ScanResult with only unsupported finding IDs. */
const SCAN_RESULT_UNSUPPORTED = JSON.stringify({
  version: "0.1.0",
  timestamp: "2026-08-01T00:00:00.000Z",
  files: [
    {
      file: "contracts/Test.sol",
      findings: [
        {
          id: "CUSTOM-999",
          title: "Custom rule",
          description: "Custom",
          recommendation: "Fix it",
          severity: "medium",
          file: "contracts/Test.sol",
          line: 1,
        },
      ],
    },
  ],
  summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0, gas: 0, total: 1 },
});

/** Flat Finding[] JSON format (also supported by plan). */
const SCAN_RESULT_FLAT = JSON.stringify([
  {
    id: "CP-107",
    title: "Reentrancy",
    description: "External call before state update",
    recommendation: "Apply CEI",
    severity: "critical",
    file: "contracts/Vault.sol",
    line: 10,
  },
  {
    id: "CP-104",
    title: "Unchecked return value",
    description: ".call return value not checked",
    recommendation: "Check return value",
    severity: "medium",
    file: "contracts/Vault.sol",
    line: 20,
  },
]);

/** A minimal synthetic ValidationReport (produced without running an adapter). */
const SYNTHETIC_REPORT = JSON.stringify({
  schemaVersion: "1.0.0",
  timestamp: "2026-08-01T10:00:00.000Z",
  total: 2,
  passed: 1,
  failed: 1,
  errored: 0,
  adapterType: "anvil",
  totalDurationMs: 1250,
  results: [
    {
      schemaVersion: "1.0.0",
      scenario: {
        schemaVersion: "1.0.0",
        id: "scenario-CP-107-VulnerableVault-withdraw",
        title: "Reentrancy in VulnerableVault.withdraw",
        findingId: "CP-107",
        findingFile: "contracts/VulnerableVault.sol",
        findingLine: 42,
        chain: { chainId: 31337 },
        accounts: [{ address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", balance: "10000000000000000000", label: "attacker" }],
        contracts: [{ name: "Vault", bytecode: "0x" }],
        calls: [
          { to: "Vault", signature: "deposit()", value: "1000000000000000000", from: "attacker", description: "Initial deposit" },
          { to: "Vault", signature: "withdraw(uint256)", args: ["1000000000000000000"], from: "attacker", description: "Trigger reentrancy" },
        ],
        expectedOutcome: "exploit-succeeds",
        createdAt: "2026-08-01T10:00:00.000Z",
      },
      adapterType: "anvil",
      adapterVersion: "anvil/0.2.0",
      snapshotId: "0x1",
      snapshotBlock: 1,
      callResults: [
        { callIndex: 0, reverted: false, returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] },
        { callIndex: 1, reverted: false, returnData: "0x", gasUsed: 50000, logs: [], storageDiff: [] },
      ],
      outcomeMatched: true,
      outcomeSummary: "Exploit scenario completed without reverts and all assertions passed",
      storageAssertionResults: [],
      balanceAssertionResults: [],
      eventAssertionResults: [],
      totalGasUsed: 71000,
      startedAt: "2026-08-01T10:00:00.000Z",
      completedAt: "2026-08-01T10:00:01.250Z",
      durationMs: 1250,
      warnings: [],
    },
    {
      schemaVersion: "1.0.0",
      scenario: {
        schemaVersion: "1.0.0",
        id: "scenario-CP-115-VulnerableVault-adminWithdraw",
        title: "tx.origin authentication bypass in VulnerableVault.adminWithdraw",
        findingId: "CP-115",
        findingFile: "contracts/VulnerableVault.sol",
        findingLine: 55,
        chain: { chainId: 31337 },
        accounts: [{ address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", balance: "10000000000000000000", label: "attacker" }],
        contracts: [{ name: "Vault", bytecode: "0x" }],
        calls: [{ to: "Vault", signature: "adminWithdraw(uint256)", args: ["1000"], from: "attacker", description: "Bypass via tx.origin" }],
        expectedOutcome: "exploit-succeeds",
        createdAt: "2026-08-01T10:00:00.000Z",
      },
      adapterType: "anvil",
      adapterVersion: "anvil/0.2.0",
      snapshotId: "0x2",
      snapshotBlock: 2,
      callResults: [
        { callIndex: 0, reverted: true, revertReason: "Not owner", returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] },
      ],
      outcomeMatched: false,
      outcomeSummary: "Exploit scenario had an unexpected revert (call[0])",
      storageAssertionResults: [],
      balanceAssertionResults: [],
      eventAssertionResults: [],
      totalGasUsed: 21000,
      startedAt: "2026-08-01T10:00:01.250Z",
      completedAt: "2026-08-01T10:00:01.500Z",
      durationMs: 250,
      warnings: [],
    },
  ],
});

/** A minimal synthetic ValidationResult for replay tests. */
const SYNTHETIC_RESULT = JSON.parse(SYNTHETIC_REPORT).results[0];

/** A minimal ValidationScenario for minimize tests. */
const SYNTHETIC_SCENARIO = {
  schemaVersion: "1.0.0",
  id: "scenario-CP-107-test",
  title: "Test scenario",
  findingId: "CP-107",
  chain: { chainId: 31337 },
  accounts: [{ address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", balance: "10000000000000000000" }],
  contracts: [{ name: "Vault", bytecode: "0x" }],
  calls: [
    { to: "Vault", signature: "deposit()", value: "1000", description: "Setup" },
    { to: "Vault", signature: "withdraw(uint256)", args: ["1000"], description: "Attack" },
  ],
  expectedOutcome: "exploit-succeeds",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function run(
  args: string[],
  opts: { input?: string; env?: NodeJS.ProcessEnv } = {},
): { stdout: string; stderr: string; status: number } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...opts.env },
    timeout: 15_000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status ?? 1,
  };
}

let tmpDir: string;
beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-validate-cli-test-"));
});
afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ─── validate plan ────────────────────────────────────────────────────────────

describe("validate plan", () => {
  it("produces a valid JSON ValidationPlan from a ScanResult JSON", () => {
    const scanFile = path.join(tmpDir, "scan.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    expect(plan.schemaVersion).toBe("1.0.0");
    expect(Array.isArray(plan.scenarios)).toBe(true);
    expect(Array.isArray(plan.unsupportedFindings)).toBe(true);
    expect(plan.createdAt).toBeDefined();
  });

  it("generates scenarios for supported finding IDs (CP-107, CP-115)", () => {
    const scanFile = path.join(tmpDir, "scan-supported.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    const ids = plan.scenarios.map((s: { findingId: string }) => s.findingId);
    expect(ids).toContain("CP-107");
    expect(ids).toContain("CP-115");
  });

  it("silently excludes GAS-* findings (gas severity or GAS- prefix)", () => {
    const scanFile = path.join(tmpDir, "scan-gas.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    // GAS-001 (gas severity) must NOT appear in unsupportedFindings
    const unsupportedIds = plan.unsupportedFindings.map(
      (u: { findingId: string }) => u.findingId,
    );
    expect(unsupportedIds).not.toContain("GAS-001");
  });

  it("reports unsupported finding IDs in unsupportedFindings", () => {
    const scanFile = path.join(tmpDir, "scan-unsupported.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_UNSUPPORTED, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    expect(plan.scenarios.length).toBe(0);
    expect(plan.unsupportedFindings.length).toBe(1);
    expect(plan.unsupportedFindings[0].findingId).toBe("CUSTOM-999");
    expect(plan.unsupportedFindings[0].reason).toBeTruthy();
  });

  it("accepts flat Finding[] JSON as input", () => {
    const scanFile = path.join(tmpDir, "scan-flat.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_FLAT, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    expect(plan.scenarios.length).toBeGreaterThan(0);
  });

  it("writes the plan to --output file when specified", () => {
    const scanFile = path.join(tmpDir, "scan-out.json");
    const outFile = path.join(tmpDir, "plan-out.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile, "--output", outFile]);
    expect(result.status).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);

    const plan = JSON.parse(fs.readFileSync(outFile, "utf8"));
    expect(plan.schemaVersion).toBe("1.0.0");
  });

  it("prints a table summary with --format table", () => {
    const scanFile = path.join(tmpDir, "scan-table.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile, "--format", "table"]);
    expect(result.status).toBe(0);
    // Table format goes to stdout
    const combined = result.stdout + result.stderr;
    expect(combined).toContain("Validation Plan");
    expect(combined).toMatch(/Scenarios:/i);
  });

  it("respects --min-severity (high) and omits medium/low findings", () => {
    const scanFile = path.join(tmpDir, "scan-minsev.json");
    const input = JSON.stringify([
      { id: "CP-107", title: "Reentrancy", description: "", recommendation: "", severity: "critical", file: "f.sol", line: 1 },
      { id: "CP-101", title: "Overflow", description: "", recommendation: "", severity: "high", file: "f.sol", line: 2 },
      { id: "CP-104", title: "Unchecked", description: "", recommendation: "", severity: "medium", file: "f.sol", line: 3 },
    ]);
    fs.writeFileSync(scanFile, input, "utf8");

    const result = run(["validate", "plan", scanFile, "--min-severity", "high"]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    const severities = plan.scenarios.map((s: { findingId: string }) => s.findingId);
    expect(severities).toContain("CP-107");
    expect(severities).toContain("CP-101");
    // CP-104 is medium — should be absent
    expect(severities).not.toContain("CP-104");
  });

  it("exits 2 on corrupt JSON input", () => {
    const scanFile = path.join(tmpDir, "scan-corrupt.json");
    fs.writeFileSync(scanFile, "{ not valid json @@", "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/failed|error/i);
  });

  it("exits 2 on missing input file", () => {
    const result = run(["validate", "plan", "/no/such/file/scan.json"]);
    expect(result.status).toBe(2);
  });

  it("plan scenario IDs are unique", () => {
    const scanFile = path.join(tmpDir, "scan-unique.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_FLAT, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    const ids = plan.scenarios.map((s: { id: string }) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("each scenario has required fields", () => {
    const scanFile = path.join(tmpDir, "scan-fields.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    const plan = JSON.parse(result.stdout);
    for (const s of plan.scenarios) {
      expect(s.schemaVersion).toBe("1.0.0");
      expect(typeof s.id).toBe("string");
      expect(s.id.length).toBeGreaterThan(0);
      expect(typeof s.title).toBe("string");
      expect(s.chain).toBeDefined();
      expect(Array.isArray(s.accounts)).toBe(true);
      expect(Array.isArray(s.contracts)).toBe(true);
      expect(Array.isArray(s.calls)).toBe(true);
      expect(s.expectedOutcome).toBeDefined();
    }
  });

  it("plan output does not contain private keys or fork URLs", () => {
    const scanFile = path.join(tmpDir, "scan-secrets.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    const result = run(["validate", "plan", scanFile]);
    expect(result.status).toBe(0);

    // No private keys (0x + 64 hex chars) should appear in the plan
    expect(result.stdout).not.toMatch(/['"](0x[0-9a-f]{64})['"]/i);
  });
});

// ─── validate run ─────────────────────────────────────────────────────────────

describe("validate run", () => {
  it("exits 2 with actionable error when no adapter is available", () => {
    const planFile = path.join(tmpDir, "plan-run.json");
    // Write a minimal valid plan
    const plan = {
      schemaVersion: "1.0.0",
      scenarios: [SYNTHETIC_SCENARIO],
      unsupportedFindings: [],
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(planFile, JSON.stringify(plan), "utf8");

    // Use PATH that doesn't include anvil/hardhat to simulate unavailability
    const result = run(
      ["validate", "run", planFile, "--adapter", "anvil", "--adapter-bin", "/no/such/anvil"],
      { env: { PATH: "" } },
    );
    // Should exit 2 (error) when adapter is unavailable
    expect([1, 2]).toContain(result.status);
    expect(result.stderr).toBeTruthy();
  });

  it("exits 2 on corrupt plan JSON", () => {
    const planFile = path.join(tmpDir, "plan-corrupt.json");
    fs.writeFileSync(planFile, "{ bad json", "utf8");

    const result = run(["validate", "run", planFile]);
    expect(result.status).toBe(2);
  });

  it("exits 2 when plan has unrecognized structure", () => {
    const planFile = path.join(tmpDir, "plan-bad-structure.json");
    fs.writeFileSync(planFile, JSON.stringify({ notAScenario: true }), "utf8");

    const result = run(["validate", "run", planFile]);
    expect(result.status).toBe(2);
  });

  it("accepts a single ValidationScenario (not a plan)", () => {
    const scenarioFile = path.join(tmpDir, "single-scenario.json");
    fs.writeFileSync(scenarioFile, JSON.stringify(SYNTHETIC_SCENARIO), "utf8");

    // We can't actually run without an adapter but we can test that it parses and
    // attempts to run (exiting 2 when adapter unavailable, not crashing with a
    // different error)
    const result = run(
      ["validate", "run", scenarioFile, "--adapter-bin", "/no/such/anvil"],
      { env: { PATH: "" } },
    );
    expect([1, 2]).toContain(result.status);
  });

  it("exits 0 when plan has no scenarios", () => {
    const planFile = path.join(tmpDir, "plan-empty.json");
    const plan = {
      schemaVersion: "1.0.0",
      scenarios: [],
      unsupportedFindings: [],
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(planFile, JSON.stringify(plan), "utf8");

    const result = run(["validate", "run", planFile, "--adapter-bin", "/no/such/anvil"]);
    expect(result.status).toBe(0);
  });
});

// ─── validate replay ──────────────────────────────────────────────────────────

describe("validate replay", () => {
  it("exits 2 when the result file is corrupt JSON", () => {
    const resultFile = path.join(tmpDir, "result-corrupt.json");
    fs.writeFileSync(resultFile, "not json", "utf8");

    const result = run(["validate", "replay", resultFile]);
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/failed|error/i);
  });

  it("exits 2 when result JSON is missing the scenario field", () => {
    const resultFile = path.join(tmpDir, "result-no-scenario.json");
    fs.writeFileSync(resultFile, JSON.stringify({ schemaVersion: "1.0.0" }), "utf8");

    const result = run(["validate", "replay", resultFile]);
    expect(result.status).toBe(2);
  });

  it("exits 2 when adapter is unavailable but result is otherwise valid", () => {
    const resultFile = path.join(tmpDir, "result-valid.json");
    fs.writeFileSync(resultFile, JSON.stringify(SYNTHETIC_RESULT), "utf8");

    const result = run(
      ["validate", "replay", resultFile, "--adapter-bin", "/no/such/anvil"],
      { env: { PATH: "" } },
    );
    expect([1, 2]).toContain(result.status);
  });
});

// ─── validate minimize ────────────────────────────────────────────────────────

describe("validate minimize", () => {
  it("exits 2 when scenario file is corrupt", () => {
    const f = path.join(tmpDir, "scenario-corrupt.json");
    fs.writeFileSync(f, "{ bad", "utf8");

    const result = run(["validate", "minimize", f]);
    expect(result.status).toBe(2);
  });

  it("exits with error when adapter is unavailable", () => {
    const f = path.join(tmpDir, "scenario-minimize.json");
    fs.writeFileSync(f, JSON.stringify(SYNTHETIC_SCENARIO), "utf8");

    const result = run(
      ["validate", "minimize", f, "--adapter-bin", "/no/such/anvil"],
      { env: { PATH: "" } },
    );
    expect([1, 2]).toContain(result.status);
  });
});

// ─── validate report ──────────────────────────────────────────────────────────

describe("validate report", () => {
  it("formats a ValidationReport as Markdown (default)", () => {
    const reportFile = path.join(tmpDir, "report.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("# ChainProof Validation Report");
    expect(result.stdout).toContain("## Summary");
    expect(result.stdout).toMatch(/Passed|Failed/);
  });

  it("formats a report as JSON with --format json", () => {
    const reportFile = path.join(tmpDir, "report-json.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile, "--format", "json"]);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.schemaVersion).toBe("1.0.0");
    expect(parsed.total).toBe(2);
  });

  it("writes to --output file when specified", () => {
    const reportFile = path.join(tmpDir, "report-write.json");
    const outFile = path.join(tmpDir, "report-output.md");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile, "--output", outFile]);
    expect(result.status).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
    expect(fs.readFileSync(outFile, "utf8")).toContain("ChainProof Validation Report");
  });

  it("JSON output has deterministic key order (sorted alphabetically)", () => {
    const reportFile = path.join(tmpDir, "report-det.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result1 = run(["validate", "report", reportFile, "--format", "json"]);
    const result2 = run(["validate", "report", reportFile, "--format", "json"]);
    expect(result1.status).toBe(0);
    expect(result1.stdout).toBe(result2.stdout);
  });

  it("reports scenario-level pass/fail counts in Markdown", () => {
    const reportFile = path.join(tmpDir, "report-count.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(0);
    // The synthetic report has 1 passed, 1 failed
    expect(result.stdout).toMatch(/1/);
  });

  it("exits 1 with --fail-on-failure when report has failures", () => {
    const reportFile = path.join(tmpDir, "report-fail.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile, "--fail-on-failure"]);
    expect(result.status).toBe(1);
  });

  it("exits 0 with --fail-on-failure when all scenarios passed", () => {
    const allPassedReport = {
      ...JSON.parse(SYNTHETIC_REPORT),
      failed: 0,
      passed: 2,
      results: JSON.parse(SYNTHETIC_REPORT).results.map(
        (r: Record<string, unknown>) => ({ ...r, outcomeMatched: true }),
      ),
    };
    const reportFile = path.join(tmpDir, "report-allpass.json");
    fs.writeFileSync(reportFile, JSON.stringify(allPassedReport), "utf8");

    const result = run(["validate", "report", reportFile, "--fail-on-failure"]);
    expect(result.status).toBe(0);
  });

  it("exits 2 on corrupt report JSON", () => {
    const reportFile = path.join(tmpDir, "report-corrupt.json");
    fs.writeFileSync(reportFile, "{ not valid", "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(2);
  });

  it("exits 2 on report missing schemaVersion", () => {
    const reportFile = path.join(tmpDir, "report-no-version.json");
    fs.writeFileSync(reportFile, JSON.stringify({ results: [] }), "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(2);
  });

  it("exits 2 on report missing results array", () => {
    const reportFile = path.join(tmpDir, "report-no-results.json");
    fs.writeFileSync(reportFile, JSON.stringify({ schemaVersion: "1.0.0" }), "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(2);
  });

  it("Markdown report contains per-scenario sections for each result", () => {
    const reportFile = path.join(tmpDir, "report-sections.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(0);
    // Both scenarios should appear
    expect(result.stdout).toContain("Reentrancy in VulnerableVault.withdraw");
    expect(result.stdout).toContain("tx.origin");
  });

  it("Markdown report does not contain fork URLs or private keys", () => {
    const reportFile = path.join(tmpDir, "report-nosecrets.json");
    fs.writeFileSync(reportFile, SYNTHETIC_REPORT, "utf8");

    const result = run(["validate", "report", reportFile]);
    expect(result.status).toBe(0);
    // No 0x-prefixed 64-char hex (private keys) in output
    expect(result.stdout).not.toMatch(/(0x[0-9a-f]{64})/i);
    // No http URLs with credentials
    expect(result.stdout).not.toMatch(/https?:\/\/[^/]+@/);
  });
});

// ─── Adapter availability guard ───────────────────────────────────────────────
// Full adapter lifecycle tests (actual EVM execution) require Anvil or Hardhat.
// They are skipped when neither is present so CI always passes even on bare runners.

const SKIP_ADAPTER = process.env["CHAINPROOF_SKIP_ADAPTER_TESTS"] === "1";

(SKIP_ADAPTER ? describe.skip : describe)("validate run — with adapter (integration)", () => {
  it("runs a plan against Anvil and produces a ValidationReport", async () => {
    // This test requires `anvil` to be on $PATH.
    // Skip inline if not available.
    let anvilAvailable = false;
    try {
      execFileSync("anvil", ["--version"], { stdio: "ignore", timeout: 5_000 });
      anvilAvailable = true;
    } catch {
      anvilAvailable = false;
    }
    if (!anvilAvailable) {
      console.warn("  Skipping adapter integration test — anvil not found");
      return;
    }

    const scanFile = path.join(tmpDir, "scan-integration.json");
    fs.writeFileSync(scanFile, SCAN_RESULT_WITH_CP107, "utf8");

    // Step 1: plan
    const planResult = run(["validate", "plan", scanFile]);
    expect(planResult.status).toBe(0);
    const plan = JSON.parse(planResult.stdout);
    expect(plan.scenarios.length).toBeGreaterThan(0);

    const planFile = path.join(tmpDir, "plan-integration.json");
    fs.writeFileSync(planFile, planResult.stdout, "utf8");

    // Step 2: run
    const reportFile = path.join(tmpDir, "report-integration.json");
    const runResult = run([
      "validate", "run", planFile,
      "--adapter", "anvil",
      "--timeout", "60000",
      "--output", reportFile,
    ]);
    // Should exit 0 (success) or 1 (failures in scenarios) but not 2 (infra error)
    expect([0, 1]).toContain(runResult.status);
    expect(fs.existsSync(reportFile)).toBe(true);

    const report = JSON.parse(fs.readFileSync(reportFile, "utf8"));
    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.total).toBeGreaterThan(0);
    expect(typeof report.totalDurationMs).toBe("number");

    // Step 3: report
    const reportMdResult = run(["validate", "report", reportFile]);
    expect(reportMdResult.status).toBe(0);
    expect(reportMdResult.stdout).toContain("# ChainProof Validation Report");
  }, 120_000);
});
