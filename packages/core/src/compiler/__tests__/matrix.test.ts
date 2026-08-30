import {
  getSupportedCompilerVersions,
  getCompilerVersionMetadata,
  isVersionSupported,
  getBreakingChangesBetween,
  getHazardsForVersion,
  getCompatibleCompilerVersions,
  getRecommendedCompilerVersion,
  SOL_CODEGEN_BUGS,
  BREAKING_CHANGES_REGISTRY,
} from "../matrix";

describe("Supported Compiler Matrix & Codegen Hazards Database", () => {
  describe("Matrix metadata and query functions", () => {
    it("returns supported compiler versions spanning 0.4 to 0.8", () => {
      const versions = getSupportedCompilerVersions();
      expect(versions.length).toBeGreaterThanOrEqual(25);
      expect(versions).toContain("0.4.24");
      expect(versions).toContain("0.5.16");
      expect(versions).toContain("0.6.12");
      expect(versions).toContain("0.7.6");
      expect(versions).toContain("0.8.0");
      expect(versions).toContain("0.8.20");
      expect(versions).toContain("0.8.28");
    });

    it("returns detailed metadata for supported version", () => {
      const meta = getCompilerVersionMetadata("0.8.28");
      expect(meta).not.toBeNull();
      expect(meta?.version).toBe("0.8.28");
      expect(meta?.family).toBe("0.8");
      expect(meta?.isStable).toBe(true);
      expect(meta?.capabilities.checkedArithmetic).toBe(true);
      expect(meta?.capabilities.customErrors).toBe(true);
      expect(meta?.capabilities.transientStorage).toBe(true);
      expect(meta?.capabilities.push0Opcode).toBe(true);
    });

    it("verifies capabilities across major compiler evolution", () => {
      const meta04 = getCompilerVersionMetadata("0.4.24");
      expect(meta04?.capabilities.checkedArithmetic).toBe(false);
      expect(meta04?.capabilities.customErrors).toBe(false);
      expect(meta04?.capabilities.abiEncoderV2).toBe("experimental");

      const meta07 = getCompilerVersionMetadata("0.7.6");
      expect(meta07?.capabilities.checkedArithmetic).toBe(false);
      expect(meta07?.capabilities.tryCatch).toBe(true);
      expect(meta07?.capabilities.receiveFallbackSplit).toBe(true);

      const meta08 = getCompilerVersionMetadata("0.8.4");
      expect(meta08?.capabilities.checkedArithmetic).toBe(true);
      expect(meta08?.capabilities.customErrors).toBe(true);
      expect(meta08?.capabilities.abiEncoderV2).toBe("default");
    });
  });

  describe("Breaking changes registry", () => {
    it("returns breaking syntax changes between compiler families", () => {
      const changes07to08 = getBreakingChangesBetween("0.7.6", "0.8.20");
      expect(changes07to08.length).toBe(1);
      expect(changes07to08[0].fromFamily).toBe("0.7");
      expect(changes07to08[0].toFamily).toBe("0.8");
      expect(changes07to08[0].summary).toContain("checked arithmetic");

      const changes04to08 = getBreakingChangesBetween("0.4.24", "0.8.20");
      expect(changes04to08.length).toBe(4); // 0.4->0.5, 0.5->0.6, 0.6->0.7, 0.7->0.8
    });
  });

  describe("Codegen hazards database", () => {
    it("returns dirty bytes bug for <=0.8.6", () => {
      const hazards = getHazardsForVersion("0.8.4");
      expect(hazards.some((h) => h.id === "SOL-BUG-2021-3")).toBe(true);

      const hazardsClean = getHazardsForVersion("0.8.28");
      expect(hazardsClean.some((h) => h.id === "SOL-BUG-2021-3")).toBe(false);
    });

    it("returns PUSH0 hazard for 0.8.20+ when targeting non-Shanghai EVM", () => {
      const hazards = getHazardsForVersion("0.8.20", { targetEvmLacksPush0: true });
      expect(hazards.some((h) => h.id === "SOL-BUG-2023-1")).toBe(true);
    });

    it("returns transient storage bug for 0.8.24-0.8.25", () => {
      const hazards = getHazardsForVersion("0.8.24", { hasTransientStorage: true });
      expect(hazards.some((h) => h.id === "SOL-BUG-2024-1")).toBe(true);

      const hazards26 = getHazardsForVersion("0.8.26", { hasTransientStorage: true });
      expect(hazards26.some((h) => h.id === "SOL-BUG-2024-1")).toBe(false);
    });
  });

  describe("Compatible and recommended version resolution", () => {
    it("finds compatible versions for range", () => {
      const compatible = getCompatibleCompilerVersions(">=0.8.20 <=0.8.26");
      expect(compatible).toEqual(["0.8.20", "0.8.21", "0.8.23", "0.8.24", "0.8.25", "0.8.26"]);
    });

    it("chooses recommended version for range", () => {
      expect(getRecommendedCompilerVersion("^0.8.0")).toBe("0.8.28");
      expect(getRecommendedCompilerVersion("^0.7.0")).toBe("0.7.6");
    });
  });
});
