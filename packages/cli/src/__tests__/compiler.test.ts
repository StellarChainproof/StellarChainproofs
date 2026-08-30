import { execFileSync, spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const CLI = path.resolve(__dirname, "../../dist/cli.js");
const FIXTURES = path.resolve(__dirname, "../../../../examples/contracts/compiler");

describe("compiler CLI commands", () => {
  beforeAll(() => {
    execFileSync("npm", ["run", "build", "--workspace=packages/core"], {
      cwd: path.resolve(__dirname, "../../../.."),
    });
    execFileSync("npm", ["run", "build", "--workspace=packages/server"], {
      cwd: path.resolve(__dirname, "../../../.."),
    });
    execFileSync("npm", ["run", "build", "--workspace=packages/cli"], {
      cwd: path.resolve(__dirname, "../../../.."),
    });
  }, 60_000);

  describe("chainproof compiler inspect", () => {
    it("outputs machine-readable JSON pragma resolution", () => {
      const target = path.join(FIXTURES, "SecurePinnedVault.sol");
      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "inspect", target, "--format", "json"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(0);
      const json = JSON.parse(result.stdout);
      expect(json.totalFiles).toBe(1);
      expect(json.unsatisfiable).toBe(false);
      expect(json.globalRange).toBe("=0.8.28");
    });

    it("detects unsatisfiable pragma imports and exits with code 1", () => {
      const fileA = path.join(FIXTURES, "IncompatibleA.sol");
      const fileB = path.join(FIXTURES, "IncompatibleB.sol");
      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "inspect", fileA, fileB, "--format", "json"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(1);
      const json = JSON.parse(result.stdout);
      expect(json.unsatisfiable).toBe(true);
      expect(json.conflictDetails.length).toBeGreaterThan(0);
    });
  });

  describe("chainproof compiler matrix", () => {
    it("evaluates matrix grid across compiler versions in JSON format", () => {
      const target = path.join(FIXTURES, "SecurePinnedVault.sol");
      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "matrix", target, "--versions", "0.8.20,0.8.28", "--format", "json", "--fail-on", "none"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(0);
      const json = JSON.parse(result.stdout);
      expect(json.targetVersions).toEqual(["0.8.20", "0.8.28"]);
      expect(json.rows.length).toBe(1);
      expect(json.rows[0].contract).toBe("SecurePinnedVault");
    });
  });

  describe("chainproof compiler compare", () => {
    it("compares two compiler versions and detects storage layout drift", () => {
      const targetV1 = path.join(FIXTURES, "StorageDriftV1.sol");
      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "compare", targetV1, "--versions", "0.8.20,0.8.28", "--format", "json"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(0);
      const json = JSON.parse(result.stdout);
      expect(Array.isArray(json)).toBe(true);
      expect(json[0].contractName).toBe("StorageDrift");
    });
  });

  describe("chainproof compiler audit", () => {
    it("runs complete compiler audit and writes Markdown artifact", () => {
      const target = path.join(FIXTURES, "SecurePinnedVault.sol");
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "compiler-audit-"));
      const outputFile = path.join(tmpDir, "report.md");

      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "audit", target, "--format", "markdown", "--output", outputFile, "--fail-on", "none"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(0);
      expect(fs.existsSync(outputFile)).toBe(true);
      const mdContent = fs.readFileSync(outputFile, "utf8");
      expect(mdContent).toContain("Multi-Compiler Compatibility");

      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it("fails with exit code 1 when fail-on threshold is breached", () => {
      const target = path.join(FIXTURES, "LegacyMathVault.sol");
      const result = spawnSync(
        process.execPath,
        [CLI, "compiler", "audit", target, "--format", "json", "--fail-on", "high"],
        { encoding: "utf8" },
      );

      expect(result.status).toBe(1);
      const json = JSON.parse(result.stdout);
      expect(json.findings.length).toBeGreaterThan(0);
      expect(json.findings.some((f: any) => f.id === "CP-SOL-004")).toBe(true);
    });
  });
});
