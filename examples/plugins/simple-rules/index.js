/**
 * Example ChainProof Plugin
 *
 * Demonstrates custom rule detection for team-specific patterns.
 * Export a ChainProofPlugin object with an array of PluginRule implementations.
 */

const plugin = {
  name: "example-rules",
  version: "1.0.0",
  rules: [
    {
      id: "EXAMPLE-001",
      title: "Deprecated console.log usage",
      severity: "medium",
      description:
        "The contract uses console.log which should be removed before production. " +
        "In Solidity, console.log is typically for testing/debugging with hardhat.",
      recommendation:
        "Remove all console.log statements or use them only in test files.",
      detect(ast, source, filePath) {
        const findings = [];
        const lines = source.split("\n");

        lines.forEach((line, index) => {
          if (line.includes("console.log")) {
            findings.push({
              id: "EXAMPLE-001",
              title: "Deprecated console.log usage",
              severity: "medium",
              description:
                "Found console.log call. This should be removed before mainnet deployment.",
              recommendation:
                "Remove the console.log line or move it to a test file.",
              file: filePath,
              line: index + 1,
              snippet: line.trim(),
            });
          }
        });

        return findings;
      },
    },

    {
      id: "EXAMPLE-002",
      title: "Unchecked external call result",
      severity: "high",
      description:
        "External calls (to addresses or contracts) should have their return value checked. " +
        "Ignoring return values can lead to unexpected behavior.",
      recommendation:
        "Check the return value of external calls or use try-catch for proper error handling.",
      detect(ast, source, filePath) {
        const findings = [];
        const lines = source.split("\n");

        // Simple heuristic: detect lines with external calls that might not check return
        const callPatterns = [
          /\.call\{/.test(source),
          /\.delegatecall/.test(source),
        ];

        if (callPatterns.some(Boolean)) {
          lines.forEach((line, index) => {
            if (
              (line.includes(".call{") || line.includes(".delegatecall")) &&
              !line.includes("require(") &&
              !line.includes("try")
            ) {
              findings.push({
                id: "EXAMPLE-002",
                title: "Unchecked external call result",
                severity: "high",
                description:
                  "This external call result is not checked. An attacker could cause it to fail silently.",
                recommendation:
                  "Use require() to check the return value or wrap in try-catch.",
                file: filePath,
                line: index + 1,
                snippet: line.trim(),
              });
            }
          });
        }

        return findings;
      },
    },
  ],
};

module.exports = plugin;
