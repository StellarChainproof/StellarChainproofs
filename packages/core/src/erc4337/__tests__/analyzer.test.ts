import * as fs from "fs";
import * as path from "path";
import { parseSolidity } from "../../ast/parser";
import { analyzeERC4337, detectERC4337 } from "../analyzer";

const FIXTURES = path.resolve(__dirname, "../../../../../examples/contracts/erc4337");

function readFixture(name: string): { source: string; file: string; ast: any } {
  const file = path.join(FIXTURES, name);
  const source = fs.readFileSync(file, "utf8");
  const parsed = parseSolidity(source, file);
  expect(parsed.ast).not.toBeNull();
  return { source, file, ast: parsed.ast };
}

describe("ERC-4337 analyzer", () => {
  it("models versioned UserOperations and detects vulnerable paymaster paths", () => {
    const fixture = readFixture("VulnerableAccount4337.sol");
    const analysis = analyzeERC4337(fixture.ast, fixture.source, fixture.file);
    expect(analysis.protocol).toBe("erc-4337");
    expect(analysis.schemaVersion).toBe("erc4337-analysis-1");
    expect(analysis.version).toBe("0.8");
    expect(analysis.userOperation?.fields.length).toBeGreaterThan(10);
    expect(analysis.diagnostics.map((item) => item.code)).toEqual(
      expect.arrayContaining(["AA003_NONCE_REPLAY", "AA007_PAYMASTER_DEPOSIT", "AA008_PAYMASTER_POSTOP"]),
    );
  });

  it("keeps secure validation free of nonce and paymaster findings", () => {
    const fixture = readFixture("SecureAccount4337.sol");
    const findings = detectERC4337(fixture.ast, fixture.source, fixture.file);
    expect(findings.map((finding) => finding.id)).not.toEqual(
      expect.arrayContaining(["CP-4337-NONCE_REPLAY", "CP-4337-PAYMASTER_LIMIT", "CP-4337-PAYMASTER_POSTOP"]),
    );
  });

  it("is deterministic and honors diagnostic bounds", () => {
    const fixture = readFixture("VulnerableAccount4337.sol");
    const options = { limits: { maxDiagnostics: 2, maxEvidenceItems: 1 } };
    const first = analyzeERC4337(fixture.ast, fixture.source, fixture.file, options);
    const second = analyzeERC4337(fixture.ast, fixture.source, fixture.file, options);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first.diagnostics).toHaveLength(2);
    expect(first.truncated).toBe(true);
    expect(first.diagnostics.every((item) => item.evidence.length <= 1)).toBe(true);
  });
});
