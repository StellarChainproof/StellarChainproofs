import { isSlitherAvailable, runSlither } from "../slither";

describe("isSlitherAvailable", () => {
  it("returns a boolean without throwing", () => {
    const result = isSlitherAvailable();
    expect(typeof result).toBe("boolean");
  });
});

describe("runSlither", () => {
  it("returns an empty array for a non-existent file", () => {
    const findings = runSlither("/tmp/does-not-exist-chainproof.sol");
    expect(Array.isArray(findings)).toBe(true);
    expect(findings).toHaveLength(0);
  });

  it("returns an empty array when slither is unavailable", () => {
    if (isSlitherAvailable()) {
      // Skip — slither is actually present in this environment
      return;
    }
    const findings = runSlither("any.sol");
    expect(findings).toEqual([]);
  });
});
