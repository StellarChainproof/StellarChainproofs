import {
  parseSemVer,
  formatSemVer,
  compareSemVer,
  semverEq,
  semverGt,
  semverGte,
  semverLt,
  semverLte,
  parseSemVerRange,
  satisfiesSemVer,
  intersectSemVerRanges,
  findMaxSatisfyingVersion,
  findMinSatisfyingVersion,
  sortSemVerList,
} from "../semver";

describe("SemVer and Solidity Range Parser", () => {
  describe("parseSemVer & formatSemVer", () => {
    it("parses standard SemVer versions", () => {
      const v = parseSemVer("0.8.28");
      expect(v).not.toBeNull();
      expect(v?.major).toBe(0);
      expect(v?.minor).toBe(8);
      expect(v?.patch).toBe(28);
      expect(v?.prerelease).toEqual([]);
      expect(formatSemVer(v!)).toBe("0.8.28");
    });

    it("parses versions with 'v' prefix and prerelease/build", () => {
      const v = parseSemVer("v0.8.20-nightly.2024.1.1+commit.abc");
      expect(v).not.toBeNull();
      expect(v?.major).toBe(0);
      expect(v?.minor).toBe(8);
      expect(v?.patch).toBe(20);
      expect(v?.prerelease).toEqual(["nightly", "2024", "1", "1"]);
      expect(v?.build).toEqual(["commit", "abc"]);
    });

    it("returns null for invalid semver strings", () => {
      expect(parseSemVer("invalid")).toBeNull();
      expect(parseSemVer("1.2")).toBeNull();
      expect(parseSemVer("")).toBeNull();
    });
  });

  describe("compareSemVer & comparisons", () => {
    it("compares major, minor, patch correctly", () => {
      expect(compareSemVer("0.8.20", "0.8.28")).toBe(-1);
      expect(compareSemVer("0.8.28", "0.8.20")).toBe(1);
      expect(compareSemVer("0.8.20", "0.8.20")).toBe(0);

      expect(compareSemVer("0.7.6", "0.8.0")).toBe(-1);
      expect(compareSemVer("1.0.0", "0.8.28")).toBe(1);
    });

    it("evaluates comparator helpers", () => {
      expect(semverEq("0.8.20", "0.8.20")).toBe(true);
      expect(semverGt("0.8.28", "0.8.20")).toBe(true);
      expect(semverGte("0.8.20", "0.8.20")).toBe(true);
      expect(semverLt("0.7.6", "0.8.0")).toBe(true);
      expect(semverLte("0.8.0", "0.8.0")).toBe(true);
    });

    it("handles prerelease comparisons", () => {
      expect(compareSemVer("0.8.20-beta.1", "0.8.20")).toBe(-1);
      expect(compareSemVer("0.8.20", "0.8.20-beta.1")).toBe(1);
      expect(compareSemVer("0.8.20-alpha.1", "0.8.20-beta.1")).toBe(-1);
    });
  });

  describe("Range evaluation & satisfiesSemVer", () => {
    it("evaluates caret ranges (^0.8.0)", () => {
      expect(satisfiesSemVer("0.8.0", "^0.8.0")).toBe(true);
      expect(satisfiesSemVer("0.8.28", "^0.8.0")).toBe(true);
      expect(satisfiesSemVer("0.9.0", "^0.8.0")).toBe(false);
      expect(satisfiesSemVer("0.7.6", "^0.8.0")).toBe(false);
    });

    it("evaluates caret ranges for 0.4.x (^0.4.24)", () => {
      expect(satisfiesSemVer("0.4.24", "^0.4.24")).toBe(true);
      expect(satisfiesSemVer("0.4.26", "^0.4.24")).toBe(true);
      expect(satisfiesSemVer("0.5.0", "^0.4.24")).toBe(false);
      expect(satisfiesSemVer("0.4.23", "^0.4.24")).toBe(false);
    });

    it("evaluates tilde ranges (~0.8.20)", () => {
      expect(satisfiesSemVer("0.8.20", "~0.8.20")).toBe(true);
      expect(satisfiesSemVer("0.8.21", "~0.8.20")).toBe(true);
      expect(satisfiesSemVer("0.9.0", "~0.8.20")).toBe(false);
    });

    it("evaluates hyphen ranges (0.7.0 - 0.8.20)", () => {
      expect(satisfiesSemVer("0.7.0", "0.7.0 - 0.8.20")).toBe(true);
      expect(satisfiesSemVer("0.7.6", "0.7.0 - 0.8.20")).toBe(true);
      expect(satisfiesSemVer("0.8.20", "0.7.0 - 0.8.20")).toBe(true);
      expect(satisfiesSemVer("0.8.21", "0.7.0 - 0.8.20")).toBe(false);
      expect(satisfiesSemVer("0.6.12", "0.7.0 - 0.8.20")).toBe(false);
    });

    it("evaluates compound ranges (>=0.7.0 <0.9.0 !=0.8.13)", () => {
      expect(satisfiesSemVer("0.7.6", ">=0.7.0 <0.9.0 !=0.8.13")).toBe(true);
      expect(satisfiesSemVer("0.8.20", ">=0.7.0 <0.9.0 !=0.8.13")).toBe(true);
      expect(satisfiesSemVer("0.8.13", ">=0.7.0 <0.9.0 !=0.8.13")).toBe(false);
      expect(satisfiesSemVer("0.6.12", ">=0.7.0 <0.9.0 !=0.8.13")).toBe(false);
    });

    it("evaluates disjunctions (||)", () => {
      const range = "^0.7.0 || ^0.8.0";
      expect(satisfiesSemVer("0.7.6", range)).toBe(true);
      expect(satisfiesSemVer("0.8.20", range)).toBe(true);
      expect(satisfiesSemVer("0.6.12", range)).toBe(false);
      expect(satisfiesSemVer("0.9.0", range)).toBe(false);
    });
  });

  describe("intersectSemVerRanges & sorting", () => {
    const versions = ["0.7.0", "0.7.6", "0.8.0", "0.8.4", "0.8.13", "0.8.20", "0.8.28"];

    it("calculates range intersection when compatible", () => {
      const res = intersectSemVerRanges(["^0.8.0", ">=0.8.4"], versions);
      expect(res.satisfiable).toBe(true);
      expect(res.satisfyingVersions).toEqual(["0.8.4", "0.8.13", "0.8.20", "0.8.28"]);
      expect(res.lowestVersion).toBe("0.8.4");
      expect(res.highestVersion).toBe("0.8.28");
    });

    it("detects unsatisfiable range intersection", () => {
      const res = intersectSemVerRanges(["^0.7.0", "^0.8.0"], versions);
      expect(res.satisfiable).toBe(false);
      expect(res.satisfyingVersions).toEqual([]);
    });

    it("finds max and min satisfying versions", () => {
      expect(findMaxSatisfyingVersion(versions, "^0.8.0")).toBe("0.8.28");
      expect(findMinSatisfyingVersion(versions, "^0.8.0")).toBe("0.8.0");
      expect(findMaxSatisfyingVersion(versions, "^0.6.0")).toBeNull();
    });

    it("sorts semver lists properly", () => {
      const unsorted = ["0.8.20", "0.7.6", "0.8.4", "0.8.28", "0.4.24"];
      expect(sortSemVerList(unsorted, "asc")).toEqual(["0.4.24", "0.7.6", "0.8.4", "0.8.20", "0.8.28"]);
      expect(sortSemVerList(unsorted, "desc")).toEqual(["0.8.28", "0.8.20", "0.8.4", "0.7.6", "0.4.24"]);
    });
  });
});
