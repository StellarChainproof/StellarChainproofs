import {
  extractPragmas,
  parsePragmaConstraints,
  isFloatingPragma,
  isOverlyBroadPragma,
  isSecuritySensitivePragma,
  analyzeFilePragma,
  resolveProjectPragmas,
} from "../pragma";

describe("Pragma Analysis & Constraint Resolution", () => {
  describe("extractPragmas", () => {
    it("extracts pragma from Solidity source with comments", () => {
      const source = `
        // SPDX-License-Identifier: MIT
        /* Header block */
        pragma solidity ^0.8.20;

        contract Test {}
      `;
      const extracted = extractPragmas(source);
      expect(extracted.length).toBe(1);
      expect(extracted[0].value).toBe("^0.8.20");
      expect(extracted[0].line).toBe(4);
    });

    it("extracts complex multi-constraint pragma", () => {
      const source = `pragma solidity >=0.7.0 <0.9.0 !=0.8.13;`;
      const extracted = extractPragmas(source);
      expect(extracted.length).toBe(1);
      expect(extracted[0].value).toBe(">=0.7.0 <0.9.0 !=0.8.13");
    });
  });

  describe("Floating & Broad Pragma Detection", () => {
    it("detects floating pragmas (^ and >=)", () => {
      expect(isFloatingPragma("^0.8.20")).toBe(true);
      expect(isFloatingPragma(">=0.8.0")).toBe(true);
      expect(isFloatingPragma("~0.8.20")).toBe(true);
      expect(isFloatingPragma("0.8.28")).toBe(false);
      expect(isFloatingPragma("=0.8.28")).toBe(false);
    });

    it("detects overly broad pragmas spanning multiple minor families", () => {
      expect(isOverlyBroadPragma(["0.7.0", "0.7.6", "0.8.0", "0.8.20"])).toBe(true);
      expect(isOverlyBroadPragma(["0.8.0", "0.8.4", "0.8.20"])).toBe(false);
    });

    it("detects security sensitive pragmas allowing pre-0.8.0 versions", () => {
      expect(isSecuritySensitivePragma(["0.7.6", "0.8.0"])).toBe(true);
      expect(isSecuritySensitivePragma(["0.8.20", "0.8.28"])).toBe(false);
    });
  });

  describe("resolveProjectPragmas", () => {
    it("resolves compatible intersection across matching files", () => {
      const files = [
        { file: "Vault.sol", source: "pragma solidity ^0.8.0;" },
        { file: "Token.sol", source: "pragma solidity >=0.8.10 <0.8.25;" },
        { file: "Math.sol", source: "pragma solidity 0.8.20;" },
      ];

      const res = resolveProjectPragmas(files);
      expect(res.unsatisfiable).toBe(false);
      expect(res.globalCompatibleVersions).toContain("0.8.20");
      expect(res.globalCompatibleVersions.length).toBe(1);
      expect(res.recommendedVersion).toBe("0.8.20");
    });

    it("detects unsatisfiable pragma intersection across incompatible imports", () => {
      const files = [
        { file: "IncompatibleA.sol", source: "pragma solidity ^0.7.0;" },
        { file: "IncompatibleB.sol", source: "pragma solidity ^0.8.0;" },
      ];

      const res = resolveProjectPragmas(files);
      expect(res.unsatisfiable).toBe(true);
      expect(res.globalCompatibleVersions.length).toBe(0);
      expect(res.conflictDetails).toBeDefined();
      expect(res.conflictDetails!.length).toBeGreaterThan(0);
      expect(res.conflictDetails![0]).toContain("IncompatibleA.sol");
      expect(res.conflictDetails![0]).toContain("IncompatibleB.sol");
    });

    it("handles files with unspecified pragma", () => {
      const files = [{ file: "NoPragma.sol", source: "contract NoPragma {}" }];
      const res = resolveProjectPragmas(files);
      expect(res.unsatisfiable).toBe(false);
      expect(res.hasFloatingPragmas).toBe(true);
    });
  });
});
