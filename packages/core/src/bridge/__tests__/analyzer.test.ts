import * as fs from "fs";
import * as path from "path";
import { analyzeBridgeFiles, analyzeBridgeSource } from "../api";
import type { BridgeRuleId } from "../types";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/bridge");

function fixture(name: string) {
  return analyzeBridgeFiles([path.join(FIXTURES, `${name}.sol`)], { includeModels: true });
}

function rules(name: string): BridgeRuleId[] {
  return fixture(name).files.flatMap((file) => file.findings.map((finding) => finding.ruleId));
}

describe("bridge safety analyzer", () => {
  it("detects replay, verification bypass, mint-without-lock, and payload execution risks", () => {
    const ids = new Set(rules("VulnerableLockMintBridge"));
    expect(ids.size).toBeGreaterThan(0);
    for (const expected of [
      "CP-BRG-001", "CP-BRG-003", "CP-BRG-006", "CP-BRG-012", "CP-BRG-013",
    ] satisfies BridgeRuleId[]) {
      expect(ids).toContain(expected);
    }
  });

  it("recognizes secure lock-mint bridge with domain binding and replay protection", () => {
    const report = fixture("SecureLockMintBridge");
    expect(report.files[0].findings).toEqual([]);
    const model = report.files[0].models?.find((item) => item.name === "SecureLockMintBridge");
    expect(model?.adapter).toBe("lock-mint-bridge");
  });

  it("detects burn-release and validator loop weaknesses", () => {
    const ids = new Set(rules("VulnerableBurnReleaseBridge"));
    expect(ids.size).toBeGreaterThan(0);
  });

  it("recognizes secure burn-release bridge with finality window", () => {
    const report = fixture("SecureBurnReleaseBridge");
    expect(report.files[0].findings).toEqual([]);
  });

  it("attaches evidence, assumptions, confidence, and precise locations", () => {
    const finding = fixture("VulnerableLockMintBridge").files[0].findings[0];
    expect(finding.evidence.length).toBeGreaterThan(0);
    expect(finding.assumptions.length).toBeGreaterThan(0);
    expect(finding.location.line).toBeGreaterThan(0);
  });

  it("supports deterministic include/exclude selection", () => {
    const file = path.join(FIXTURES, "VulnerableLockMintBridge.sol");
    const source = fs.readFileSync(file, "utf8");
    const all = analyzeBridgeSource(source, file).files[0].findings;
    const filtered = analyzeBridgeSource(source, file, { includeRules: ["CP-BRG-003"] }).files[0].findings;
    expect(filtered.every((f) => f.ruleId === "CP-BRG-003")).toBe(true);
    expect(filtered.length).toBeLessThanOrEqual(all.length);
  });

  it("returns empty findings for unrelated contracts", () => {
    const report = analyzeBridgeSource(
      "pragma solidity ^0.8.20; contract Token { uint256 public x; }",
      "Token.sol",
    );
    expect(report.files[0].findings).toEqual([]);
  });
});
