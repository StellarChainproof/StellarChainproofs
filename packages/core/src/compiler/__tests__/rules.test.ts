import { parseSolidity } from "../../ast/parser";
import {
  detectCompilerCompatibility,
  checkFloatingPragma,
  checkOverlyBroadPragma,
  checkOutdatedCompilerVersion,
  checkPush0Hazard,
  checkTransientStorageHazard,
} from "../rules";

describe("Compiler Compatibility Rules (CP-SOL-001 to CP-SOL-010)", () => {
  it("detects floating pragma (CP-SOL-001)", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;
      contract Test {}
    `;
    const { ast } = parseSolidity(source, "Test.sol");
    const findings = checkFloatingPragma(ast!, source, "Test.sol");
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("CP-SOL-001");
    expect(findings[0].severity).toBe("low");
  });

  it("detects overly broad pragma range (CP-SOL-003)", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity >=0.7.0 <0.9.0;
      contract Test {}
    `;
    const { ast } = parseSolidity(source, "Test.sol");
    const findings = checkOverlyBroadPragma(ast!, source, "Test.sol");
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("CP-SOL-003");
    expect(findings[0].severity).toBe("medium");
  });

  it("detects outdated compiler version <0.8.0 (CP-SOL-004)", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.7.6;
      contract Legacy {}
    `;
    const { ast } = parseSolidity(source, "Legacy.sol");
    const findings = checkOutdatedCompilerVersion(ast!, source, "Legacy.sol");
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("CP-SOL-004");
    expect(findings[0].severity).toBe("high");
  });

  it("detects PUSH0 opcode hazard (CP-SOL-006)", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity 0.8.20;
      contract Modern {}
    `;
    const { ast } = parseSolidity(source, "Modern.sol");
    const findings = checkPush0Hazard(ast!, source, "Modern.sol");
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("CP-SOL-006");
  });

  it("detects transient storage usage (CP-SOL-009)", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity 0.8.24;
      contract Transient {
          function test() external {
              assembly {
                  tstore(0, 1)
              }
          }
      }
    `;
    const { ast } = parseSolidity(source, "Transient.sol");
    const findings = checkTransientStorageHazard(ast!, source, "Transient.sol");
    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe("CP-SOL-009");
  });

  it("filters rules with includeRules and excludeRules", () => {
    const source = `
      // SPDX-License-Identifier: MIT
      pragma solidity ^0.7.0;
      contract MultiIssue {}
    `;
    const { ast } = parseSolidity(source, "MultiIssue.sol");

    const onlyFloating = detectCompilerCompatibility(ast!, source, "MultiIssue.sol", {
      includeRules: ["CP-SOL-001"],
    });
    expect(onlyFloating.every((f) => f.id === "CP-SOL-001")).toBe(true);

    const noFloating = detectCompilerCompatibility(ast!, source, "MultiIssue.sol", {
      excludeRules: ["CP-SOL-001"],
    });
    expect(noFloating.some((f) => f.id === "CP-SOL-001")).toBe(false);
  });
});
