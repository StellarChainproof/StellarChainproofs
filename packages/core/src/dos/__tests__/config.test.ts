import {
  validateDosConfig,
  migrateDosConfig,
  DosConfigError,
  DEFAULT_DOS_LIMITS,
} from "../config";

describe("DoS Config Validation and Migration", () => {
  it("validates default v1 config", () => {
    const config = validateDosConfig({ version: 1 });
    expect(config.version).toBe(1);
    expect(config.limits.maxFiles).toBe(DEFAULT_DOS_LIMITS.maxFiles);
  });

  it("migrates v0 config to v1", () => {
    const v0 = {
      version: 0,
      maxFiles: 50,
      includeRules: ["CP-DOS-001"],
    };
    const migrated = migrateDosConfig(v0 as any);
    expect(migrated.version).toBe(1);
    expect(migrated.limits.maxFiles).toBe(50);
    expect(migrated.includeRules).toContain("CP-DOS-001");
  });

  it("throws error for non-object config", () => {
    expect(() => validateDosConfig(null)).toThrow(DosConfigError);
    expect(() => validateDosConfig("invalid")).toThrow(DosConfigError);
  });

  it("throws error for invalid rule ID", () => {
    expect(() =>
      validateDosConfig({
        version: 1,
        includeRules: ["INVALID-RULE"],
      }),
    ).toThrow(DosConfigError);
  });

  it("throws error when rule is in both include and exclude", () => {
    expect(() =>
      validateDosConfig({
        version: 1,
        includeRules: ["CP-DOS-001"],
        excludeRules: ["CP-DOS-001"],
      }),
    ).toThrow(DosConfigError);
  });

  it("throws error for non-positive limits", () => {
    expect(() =>
      validateDosConfig({
        version: 1,
        limits: { maxFiles: -5 },
      }),
    ).toThrow(DosConfigError);
  });
});
