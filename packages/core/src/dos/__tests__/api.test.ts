import { auditDosSafety, inspectDosLoops, inspectDosCallFanOut, DosAnalysisCancelledError } from "../api";

describe("DoS Public High-Level APIs", () => {
  const sampleSource = `
    pragma solidity 0.8.20;
    contract Vault {
      address[] public users;
      function payAll() public {
        for (uint256 i = 0; i < users.length; i++) {
          payable(users[i]).transfer(1 ether);
        }
      }
    }
  `;

  it("audits Solidity sources and returns structured audit report", async () => {
    const report = await auditDosSafety([
      {
        file: "Vault.sol",
        content: sampleSource,
      },
    ]);

    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.summary.totalFiles).toBe(1);
    expect(report.summary.totalContracts).toBe(1);
    expect(report.summary.totalLoopsAnalyzed).toBe(1);
    expect(report.summary.unboundedLoopsFound).toBe(1);
    expect(report.summary.pushPaymentsFound).toBe(1);
    expect(report.summary.passed).toBe(false);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("inspects loop bounds across sources", () => {
    const loops = inspectDosLoops([
      {
        file: "Vault.sol",
        content: sampleSource,
      },
    ]);

    expect(loops.length).toBe(1);
    expect(loops[0].associatedContract).toBe("Vault");
    expect(loops[0].associatedFunction).toBe("payAll");
  });

  it("inspects call fanouts across sources", () => {
    const calls = inspectDosCallFanOut([
      {
        file: "Vault.sol",
        content: sampleSource,
      },
    ]);

    expect(calls.length).toBe(1);
    expect(calls[0].isPushPayment).toBe(true);
    expect(calls[0].isInsideLoop).toBe(true);
  });

  it("aborts audit when cancellation signal is triggered", async () => {
    let cancelled = false;
    const signal = {
      isCancelled: () => cancelled,
    };

    cancelled = true;
    await expect(
      auditDosSafety(
        [
          {
            file: "Vault.sol",
            content: sampleSource,
          },
        ],
        { signal },
      ),
    ).rejects.toThrow(DosAnalysisCancelledError);
  });
});
