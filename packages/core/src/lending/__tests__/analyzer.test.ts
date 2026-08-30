import * as fs from "fs";
import * as path from "path";
import { analyzeLendingSource } from "../api";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/lending");

function analyzeFixture(name: string) {
  const file = path.join(FIXTURES, name);
  return analyzeLendingSource({ file, source: fs.readFileSync(file, "utf8") }, { includeModels: true });
}

describe("lending invariant analyzer", () => {
  it("detects health, interest, and liquidation issues in vulnerable fixtures", () => {
    const report = analyzeFixture("VulnerableLendingProtocol.sol");
    const ids = report.files[0].findings.map((finding) => finding.ruleId);

    expect(ids).toEqual(expect.arrayContaining([
      "CP-LND-001",
      "CP-LND-004",
      "CP-LND-007",
      "CP-LND-010",
      "CP-LND-011",
      "CP-LND-014",
      "CP-LND-016",
    ]));
    expect(report.files[0].models?.[0]).toMatchObject({
      name: "VulnerableLendingProtocol",
      adapter: expect.any(String),
    });
    expect(report.files[0].findings.every((finding) => finding.evidence.length > 0)).toBe(true);
  });

  it("accepts a secure protocol implementation with no findings", () => {
    const report = analyzeFixture("SecureLendingProtocol.sol");
    expect(report.files[0].findings).toEqual([]);
  });

  it("supports include and exclude rule filtering", () => {
    const file = path.join(FIXTURES, "VulnerableLendingProtocol.sol");
    const input = { file, source: fs.readFileSync(file, "utf8") };
    const included = analyzeLendingSource(input, { includeRules: ["CP-LND-010"] });
    const excluded = analyzeLendingSource(input, { excludeRules: ["CP-LND-010"] });
    expect(included.files[0].findings.map((finding) => finding.ruleId)).toEqual(["CP-LND-010"]);
    expect(excluded.files[0].findings.some((finding) => finding.ruleId === "CP-LND-010")).toBe(false);
  });
});
