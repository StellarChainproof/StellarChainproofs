import { auditDosSafety, inspectDosLoops } from "../api";
import { DosConfigError } from "../config";

describe("DoS Adversarial and Edge Case Handling", () => {
  it("handles malformed Solidity syntax gracefully without crashing", async () => {
    const malformed = "contract { broken syntax ;;; for (;;;) ";
    const report = await auditDosSafety([
      {
        file: "Broken.sol",
        content: malformed,
      },
    ]);

    expect(report.schemaVersion).toBe("1.0.0");
    expect(report.summary.totalFiles).toBe(1);
    expect(report.summary.passed).toBe(true);
  });

  it("enforces maxSourceBytes limit", async () => {
    const largeContent = "contract Big {}\n".repeat(5000);
    await expect(
      auditDosSafety(
        [
          {
            file: "Big.sol",
            content: largeContent,
          },
        ],
        {
          limits: { maxSourceBytes: 100 },
        },
      ),
    ).rejects.toThrow(DosConfigError);
  });

  it("enforces maxFiles limit", async () => {
    const files = [
      { file: "A.sol", content: "contract A {}" },
      { file: "B.sol", content: "contract B {}" },
    ];
    await expect(
      auditDosSafety(files, {
        limits: { maxFiles: 1 },
      }),
    ).rejects.toThrow(DosConfigError);
  });

  it("handles deeply nested loops without stack overflow", () => {
    let nested = "pragma solidity 0.8.20; contract Deep { function run() public { ";
    for (let i = 0; i < 20; i++) {
      nested += `for (uint256 i${i} = 0; i${i} < 10; i${i}++) { `;
    }
    for (let i = 0; i < 20; i++) {
      nested += "} ";
    }
    nested += "} }";

    const loops = inspectDosLoops([
      {
        file: "Deep.sol",
        content: nested,
      },
    ]);

    expect(loops.length).toBe(20);
  });
});
