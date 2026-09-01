import * as fs from "fs";
import * as path from "path";
import { analyzeReturndataFiles, analyzeReturndataSource } from "../api";
import type { ReturndataRuleId } from "../types";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/returndata");

function fixture(name: string) {
  return analyzeReturndataFiles([path.join(FIXTURES, `${name}.sol`)], { includeModels: true });
}

function rules(name: string): ReturndataRuleId[] {
  return fixture(name).files.flatMap((file) => file.findings.map((finding) => finding.ruleId));
}

describe("returndata safety analyzer", () => {
  it("detects ignored returns, unchecked token transfers, and unsafe decode", () => {
    const ids = new Set(rules("VulnerableReturndata"));
    expect(ids.size).toBeGreaterThan(0);
    for (const expected of [
      "CP-RTD-003", "CP-RTD-004", "CP-RTD-005", "CP-RTD-007",
    ] satisfies ReturndataRuleId[]) {
      expect(ids).toContain(expected);
    }
  });

  it("recognizes SafeERC20 and Address utility patterns", () => {
    const report = fixture("SecureReturndata");
    expect(report.files[0].findings).toEqual([]);
    expect(report.files[0].models?.[0].adapter).toBe("safe-erc20-wrapper");
  });

  it("attaches evidence, assumptions, and precise locations", () => {
    const finding = fixture("VulnerableReturndata").files[0].findings[0];
    expect(finding.evidence.length).toBeGreaterThan(0);
    expect(finding.location.line).toBeGreaterThan(0);
  });

  it("supports deterministic include/exclude selection", () => {
    const file = path.join(FIXTURES, "VulnerableReturndata.sol");
    const source = fs.readFileSync(file, "utf8");
    const filtered = analyzeReturndataSource(source, file, { includeRules: ["CP-RTD-003"] }).files[0].findings;
    expect(filtered.every((f) => f.ruleId === "CP-RTD-003")).toBe(true);
  });

  it("returns empty findings for unrelated contracts", () => {
    const report = analyzeReturndataSource(
      "pragma solidity ^0.8.20; contract X { uint256 public y; }",
      "X.sol",
    );
    expect(report.files[0].findings).toEqual([]);
  });
});
