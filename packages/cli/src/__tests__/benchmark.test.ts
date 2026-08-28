import * as path from "path";
import * as fs from "fs";
import { execSync } from "child_process";

const CLI_BIN = path.resolve(__dirname, "../../dist/cli.js");
const MANIFEST_PATH = path.resolve(__dirname, "../../../../examples/benchmark-corpus/corpus.manifest.json");

function runCli(cmd: string, opts: { allowFailure?: boolean } = {}): string {
  try {
    return execSync(`node ${CLI_BIN} ${cmd}`, { encoding: "utf-8" });
  } catch (err) {
    if (opts.allowFailure) {
      return (err as { stdout?: string }).stdout || (err as { stderr?: string }).stderr || "";
    }
    throw err;
  }
}

describe("CLI Benchmark Commands", () => {
  test("benchmark validate: succeeds for valid manifest", () => {
    const output = runCli(`benchmark validate ${MANIFEST_PATH}`);
    expect(output).toContain("is valid");
  });

  test("benchmark validate: fails for invalid manifest path", () => {
    const output = runCli("benchmark validate non_existent_manifest.json", { allowFailure: true });
    expect(output).toContain("validation failed");
  });

  test("benchmark run: executes benchmark and outputs table report", () => {
    const output = runCli(`benchmark run ${MANIFEST_PATH} --min-precision 0.5 --min-recall 0.5`);
    expect(output).toContain("BENCHMARK REPORT");
    expect(output).toContain("Precision");
  });

  test("benchmark run: outputs JSON format when requested", () => {
    const output = runCli(`benchmark run ${MANIFEST_PATH} --format json --min-precision 0.5 --min-recall 0.5`);
    const parsed = JSON.parse(output);
    expect(parsed.schemaVersion).toBe("1.0.0");
    expect(parsed.metrics.truePositives).toBeDefined();
  });

  test("benchmark init: scaffolds starter corpus manifest", () => {
    const tempManifest = path.join(__dirname, "temp_scaffold_corpus.json");
    try {
      const output = runCli(`benchmark init ${tempManifest}`);
      expect(output).toContain("Scaffolded benchmark corpus manifest");
      expect(fs.existsSync(tempManifest)).toBe(true);

      const parsed = JSON.parse(fs.readFileSync(tempManifest, "utf-8"));
      expect(parsed.schemaVersion).toBe("1.0.0");
      expect(parsed.corpusName).toBeDefined();
    } finally {
      if (fs.existsSync(tempManifest)) fs.unlinkSync(tempManifest);
    }
  });

  test("benchmark compare: evaluates regression gate between reports", () => {
    const baseReportPath = path.join(__dirname, "temp_base_report.json");
    const candReportPath = path.join(__dirname, "temp_cand_report.json");

    try {
      runCli(`benchmark run ${MANIFEST_PATH} --format json --output ${baseReportPath} --min-precision 0.1`);
      runCli(`benchmark run ${MANIFEST_PATH} --format json --output ${candReportPath} --min-precision 0.1`);

      const output = runCli(`benchmark compare ${baseReportPath} ${candReportPath} --format markdown`);
      expect(output).toContain("Regression Gate Evaluation Result");
      expect(output).toContain("Minimum Precision");
    } finally {
      if (fs.existsSync(baseReportPath)) fs.unlinkSync(baseReportPath);
      if (fs.existsSync(candReportPath)) fs.unlinkSync(candReportPath);
    }
  });
});
