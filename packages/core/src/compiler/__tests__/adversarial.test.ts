import {
  inspectCompilerPragmas,
  buildCompilerMatrix,
  auditCompilerCompatibility,
  CompilerAnalysisCancelledError,
} from "../api";
import { CompilerConfigError } from "../config";

describe("Adversarial Inputs, Bounds & Cancellation", () => {
  it("enforces maxSourceBytes limit gracefully", () => {
    const hugeContent = "pragma solidity 0.8.28;\n" + "// padding\n".repeat(20000);
    expect(() =>
      inspectCompilerPragmas([{ file: "Huge.sol", content: hugeContent }], {
        limits: { maxSourceBytes: 1000 },
      }),
    ).toThrow(CompilerConfigError);
  });

  it("enforces maxFiles limit gracefully", () => {
    const files = Array.from({ length: 15 }, (_, i) => ({
      file: `Contract_${i}.sol`,
      content: "pragma solidity 0.8.28; contract C {}",
    }));

    expect(() =>
      inspectCompilerPragmas(files, {
        limits: { maxFiles: 5 },
      }),
    ).toThrow(CompilerConfigError);
  });

  it("honors cooperative cancellation signal", async () => {
    let cancelled = false;
    const signal = {
      isCancelled: () => cancelled,
    };

    cancelled = true;
    await expect(
      auditCompilerCompatibility(
        [{ file: "Test.sol", content: "pragma solidity 0.8.28; contract Test {}" }],
        { signal },
      ),
    ).rejects.toThrow(CompilerAnalysisCancelledError);
  });

  it("handles malformed Solidity gracefully without crashing", async () => {
    const malformed = `
      pragma solidity 0.8.28;
      contract Corrupt {
          function invalid( syntax error {{{
      }
    `;

    const report = await auditCompilerCompatibility([
      { file: "Corrupt.sol", content: malformed },
    ]);

    expect(report).toBeDefined();
    expect(report.summary.totalFiles).toBe(1);
  });
});
