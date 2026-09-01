import * as fs from "fs";
import * as path from "path";
import { analyzeAmmSource } from "../api";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/amm");

function analyzeFixture(name: string) {
  const file = path.join(FIXTURES, name);
  return analyzeAmmSource({ file, source: fs.readFileSync(file, "utf8") }, { includeModels: true });
}

describe("AMM invariant and liquidity analyzer", () => {
  it("detects reserve drift, slippage, and liquidity accounting issues in vulnerable fixtures", () => {
    const report = analyzeFixture("VulnerableAMMProtocol.sol");
    const ids = report.files[0].findings.map((finding) => finding.ruleId);
    expect(ids).toEqual(expect.arrayContaining([
      "CP-AMM-001",
      "CP-AMM-002",
      "CP-AMM-003",
      "CP-AMM-004",
      "CP-AMM-005",
      "CP-AMM-006",
      "CP-AMM-007",
      "CP-AMM-008",
      "CP-AMM-009",
      "CP-AMM-010",
    ]));
  });

  it("accepts a secure AMM implementation with no findings", () => {
    const report = analyzeFixture("SecureAMMProtocol.sol");
    expect(report.files[0].findings).toEqual([]);
  });

  it("supports rule inclusion and exclusion", () => {
    const file = path.join(FIXTURES, "VulnerableAMMProtocol.sol");
    const source = fs.readFileSync(file, "utf8");
    const included = analyzeAmmSource({ file, source }, { includeRules: ["CP-AMM-006"] });
    const excluded = analyzeAmmSource({ file, source }, { excludeRules: ["CP-AMM-006"] });
    expect(included.files[0].findings.map((finding) => finding.ruleId)).toEqual(["CP-AMM-006"]);
    expect(excluded.files[0].findings.some((finding) => finding.ruleId === "CP-AMM-006")).toBe(false);
  });
});
