import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

describe("CLI chainproof dos commands", () => {
  const cliPath = path.resolve(__dirname, "../../dist/cli.js");
  const fixturePath = path.resolve(__dirname, "../../../../examples/contracts/dos/UnboundedDividendVault.sol");
  const secureFixturePath = path.resolve(__dirname, "../../../../examples/contracts/dos/PullPaymentAuction.sol");

  it("runs chainproof dos inspect-loops --format json", () => {
    const cmd = `node ${cliPath} dos inspect-loops ${fixturePath} --format json`;
    const output = execSync(cmd, { encoding: "utf-8" });
    const parsed = JSON.parse(output);

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed[0].boundType).toBe("storage_array_bounded");
  });

  it("runs chainproof dos fanout --format json", () => {
    const cmd = `node ${cliPath} dos fanout ${fixturePath} --format json`;
    const output = execSync(cmd, { encoding: "utf-8" });
    const parsed = JSON.parse(output);

    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed[0].isPushPayment).toBe(true);
  });

  it("runs chainproof dos audit --format json on secure contract with exit 0", () => {
    const cmd = `node ${cliPath} dos audit ${secureFixturePath} --format json`;
    const output = execSync(cmd, { encoding: "utf-8" });
    const parsed = JSON.parse(output);

    expect(parsed.schemaVersion).toBe("1.0.0");
    expect(parsed.summary.passed).toBe(true);
  });

  it("runs chainproof dos audit with --output file", () => {
    const tmpOut = path.resolve(__dirname, "../../temp_dos_out.json");
    try {
      const cmd = `node ${cliPath} dos audit ${fixturePath} --format json --output ${tmpOut} --fail-on none`;
      execSync(cmd, { encoding: "utf-8" });

      expect(fs.existsSync(tmpOut)).toBe(true);
      const content = JSON.parse(fs.readFileSync(tmpOut, "utf-8"));
      expect(content.summary.totalFiles).toBe(1);
    } finally {
      if (fs.existsSync(tmpOut)) {
        fs.unlinkSync(tmpOut);
      }
    }
  });
});
