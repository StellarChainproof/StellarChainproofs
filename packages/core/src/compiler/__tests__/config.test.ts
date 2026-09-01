import {
  validateCompilerConfig,
  migrateCompilerConfig,
  loadCompilerConfigFile,
  CompilerConfigError,
} from "../config";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

describe("Compiler Configuration Validation & Migration", () => {
  describe("validateCompilerConfig", () => {
    it("validates valid v1 configuration", () => {
      const valid = {
        version: 1,
        defaultEvmVersion: "cancun",
        targetVersions: ["0.8.20", "0.8.28"],
        includeRules: ["CP-SOL-001", "CP-SOL-006"],
        limits: {
          maxFiles: 50,
          timeoutMs: 10000,
        },
      };

      const res = validateCompilerConfig(valid);
      expect(res.version).toBe(1);
      expect(res.defaultEvmVersion).toBe("cancun");
      expect(res.targetVersions).toEqual(["0.8.20", "0.8.28"]);
      expect(res.limits.maxFiles).toBe(50);
      expect(res.limits.timeoutMs).toBe(10000);
    });

    it("rejects invalid EVM version", () => {
      expect(() =>
        validateCompilerConfig({
          version: 1,
          defaultEvmVersion: "nonexistent_evm",
        }),
      ).toThrow(CompilerConfigError);
    });

    it("rejects overlap between includeRules and excludeRules", () => {
      expect(() =>
        validateCompilerConfig({
          version: 1,
          includeRules: ["CP-SOL-001"],
          excludeRules: ["CP-SOL-001"],
        }),
      ).toThrow("overlap");
    });

    it("rejects negative limits", () => {
      expect(() =>
        validateCompilerConfig({
          version: 1,
          limits: { maxFiles: -5 },
        }),
      ).toThrow(CompilerConfigError);
    });
  });

  describe("migrateCompilerConfig (v0 -> v1)", () => {
    it("migrates legacy v0 fields to v1 schema", () => {
      const v0 = {
        version: 0 as const,
        solcVersions: ["0.8.20"],
        evmVersion: "shanghai",
        maxFiles: 20,
        maxSourceSize: 100000,
      };

      const v1 = migrateCompilerConfig(v0);
      expect(v1.version).toBe(1);
      expect(v1.defaultEvmVersion).toBe("shanghai");
      expect(v1.targetVersions).toEqual(["0.8.20"]);
      expect(v1.limits.maxFiles).toBe(20);
      expect(v1.limits.maxSourceBytes).toBe(100000);
    });
  });

  describe("loadCompilerConfigFile", () => {
    it("loads and parses config file from disk", () => {
      const tempPath = path.join(os.tmpdir(), "chainproof-compiler-config.json");
      fs.writeFileSync(
        tempPath,
        JSON.stringify({
          version: 1,
          targetVersions: ["0.8.28"],
        }),
      );

      const config = loadCompilerConfigFile(tempPath);
      expect(config.targetVersions).toEqual(["0.8.28"]);

      fs.unlinkSync(tempPath);
    });

    it("throws on missing file", () => {
      expect(() => loadCompilerConfigFile("/nonexistent/file.json")).toThrow(CompilerConfigError);
    });
  });
});
