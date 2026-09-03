import {
  inspectCompilerPragmas,
  buildCompilerMatrix,
  compareCompilerVersions,
  auditCompilerCompatibility,
} from "../api";
import {
  serializeCompilerAuditJSON,
  generateCompilerMarkdownReport,
  generateCompilerTableReport,
} from "../serialize";

describe("Public Compiler Matrix API", () => {
  const sampleSource = `
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.28;

    contract Vault {
        address public owner;
        uint256 public total;

        constructor() {
            owner = msg.sender;
        }

        function deposit() external payable {
            total += msg.value;
        }
    }
  `;

  it("inspectCompilerPragmas returns structured resolution", () => {
    const res = inspectCompilerPragmas([
      { file: "Vault.sol", content: sampleSource },
    ]);
    expect(res.totalFiles).toBe(1);
    expect(res.globalRange).toBe("=0.8.28");
    expect(res.hasFloatingPragmas).toBe(false);
  });

  it("buildCompilerMatrix builds grid across target versions", async () => {
    const grid = await buildCompilerMatrix(
      [{ file: "Vault.sol", content: sampleSource }],
      { targetVersions: ["0.8.20", "0.8.28"] },
    );
    expect(grid.targetVersions).toEqual(["0.8.20", "0.8.28"]);
    expect(grid.rows.length).toBe(1);
    expect(grid.rows[0].contract).toBe("Vault");
    expect(grid.rows[0].cells["0.8.28"].status).toBe("compatible");
  });

  it("compareCompilerVersions performs differential comparison", async () => {
    const comps = await compareCompilerVersions(
      [{ file: "Vault.sol", content: sampleSource }],
      ["0.8.20", "0.8.28"],
    );
    expect(comps.length).toBe(1);
    expect(comps[0].contractName).toBe("Vault");
    expect(comps[0].abiDiff.identical).toBe(true);
    expect(comps[0].storageLayoutDiff.identical).toBe(true);
  });

  it("auditCompilerCompatibility produces full deterministic report and serializes to JSON / Markdown", async () => {
    const report = await auditCompilerCompatibility([
      { file: "Vault.sol", content: sampleSource },
    ]);

    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.summary.passed).toBe(true);

    const json = serializeCompilerAuditJSON(report);
    expect(typeof json).toBe("string");
    const parsed = JSON.parse(json);
    expect(parsed.schemaVersion).toBe("1.0.0");

    const markdown = generateCompilerMarkdownReport(report);
    expect(markdown).toContain("# ChainProof Multi-Compiler Compatibility");
    expect(markdown).toContain("✅ PASSED");

    const table = generateCompilerTableReport(report);
    expect(table).toContain("ChainProof Multi-Compiler Diagnostic Matrix");
  });
});
