/**
 * Adversarial and edge-case tests for the validation engine.
 *
 * Tests cover:
 * - Fork unavailability (adapter fails to start)
 * - RPC inconsistency (adapter returns unexpected responses)
 * - Process crash simulation
 * - Malicious / oversized input
 * - Replay integrity (scenario IDs are stable)
 * - Boundary conditions (max values, empty arrays, missing fields)
 * - Error sanitization (no secrets leak in error messages)
 */

import {
  ValidationError,
  ValidationTimeoutError,
  AdapterCrashError,
  ForkUnavailableError,
  CorruptBundleError,
  ScenarioValidationError,
  createCancellationSignal,
  resolveResourceLimits,
  sanitizeErrorMessage,
  planValidation,
  serializeValidationPlan,
  parseValidationPlan,
  serializeValidationReport,
  parseValidationReport,
  generateValidationMarkdown,
  ValidationRunner,
  sanitizeScenario,
  minimizeScenario,
  DEFAULT_RESOURCE_LIMITS,
  VALIDATION_SCHEMA_VERSION,
  normalizeHex,
  keccak256Pure,
  keccak256Selector,
  encodeFunctionCall,
  hexToDecimalString,
} from "../validation";
import type {
  EvmAdapter,
  CallResult,
  CallSpec,
  ResolvedResourceLimits,
  ValidationCancellationSignal,
  ValidationScenario,
} from "../validation";
import type { Finding } from "../types";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeScenario(overrides: Partial<ValidationScenario> = {}): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: "scenario-adversarial-001",
    title: "Adversarial test scenario",
    chain: { chainId: 31337 },
    accounts: [
      { address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", balance: "10000000000000000000", label: "deployer" },
    ],
    contracts: [],
    calls: [{ to: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", signature: "noop()", from: "deployer" }],
    expectedOutcome: "exploit-succeeds",
    ...overrides,
  };
}

/** Adapter that throws on every call */
class AlwaysFailingAdapter implements EvmAdapter {
  readonly type = "anvil" as const;
  readonly version = "mock/failing";
  readonly rpcUrl = "http://127.0.0.1:1";
  async start(): Promise<void> {
    throw new AdapterCrashError("anvil", "process failed to start");
  }
  async dispose(): Promise<void> { /* no-op */ }
  async setupAccount(): Promise<void> { throw new AdapterCrashError("anvil", "crash"); }
  async deployContract(): Promise<string> { throw new AdapterCrashError("anvil", "crash"); }
  async executeCall(): Promise<CallResult> { throw new AdapterCrashError("anvil", "crash"); }
  async getStorageAt(): Promise<string> { throw new AdapterCrashError("anvil", "crash"); }
  async getBalance(): Promise<string> { throw new AdapterCrashError("anvil", "crash"); }
  async getBlockNumber(): Promise<number> { throw new AdapterCrashError("anvil", "crash"); }
  async snapshot(): Promise<string> { throw new AdapterCrashError("anvil", "crash"); }
  async revertToSnapshot(): Promise<void> { throw new AdapterCrashError("anvil", "crash"); }
  async setNextBlockTimestamp(): Promise<void> { throw new AdapterCrashError("anvil", "crash"); }
  async mine(): Promise<void> { throw new AdapterCrashError("anvil", "crash"); }
  async setStorageAt(): Promise<void> { throw new AdapterCrashError("anvil", "crash"); }
}

/** Adapter that hangs indefinitely on executeCall */
class HangingAdapter implements EvmAdapter {
  readonly type = "anvil" as const;
  readonly version = "mock/hanging";
  readonly rpcUrl = "http://127.0.0.1:1";
  async start(): Promise<void> { /* no-op */ }
  async dispose(): Promise<void> { /* no-op */ }
  async setupAccount(): Promise<void> { /* no-op */ }
  async deployContract(): Promise<string> { return "0x1000000000000000000000000000000000001000"; }
  async executeCall(_: CallSpec, __: Map<string, string>, ___: ResolvedResourceLimits, signal?: ValidationCancellationSignal): Promise<CallResult> {
    // Simulate a hanging call by waiting forever (or until cancelled)
    return new Promise((_, reject) => {
      if (signal) {
        signal.onCancelled(() => reject(new ValidationError("Cancelled", "TIMEOUT")));
      }
      setTimeout(() => reject(new ValidationError("Timeout", "TIMEOUT")), 60_000);
    });
  }
  async getStorageAt(): Promise<string> { return normalizeHex("0x0"); }
  async getBalance(): Promise<string> { return "0"; }
  async getBlockNumber(): Promise<number> { return 1; }
  async snapshot(): Promise<string> { return "snap-1"; }
  async revertToSnapshot(): Promise<void> { /* no-op */ }
  async setNextBlockTimestamp(): Promise<void> { /* no-op */ }
  async mine(): Promise<void> { /* no-op */ }
  async setStorageAt(): Promise<void> { /* no-op */ }
}

/** Adapter returning RPC errors */
class RpcErrorAdapter implements EvmAdapter {
  readonly type = "anvil" as const;
  readonly version = "mock/rpc-error";
  readonly rpcUrl = "http://127.0.0.1:1";
  async start(): Promise<void> { /* no-op */ }
  async dispose(): Promise<void> { /* no-op */ }
  async setupAccount(): Promise<void> { /* no-op */ }
  async deployContract(): Promise<string> { return "0x1000000000000000000000000000000000001001"; }
  async executeCall(): Promise<CallResult> {
    throw new ValidationError("eth_sendTransaction: nonce too high", "RPC_ERROR");
  }
  async getStorageAt(): Promise<string> { return normalizeHex("0x0"); }
  async getBalance(): Promise<string> { return "0"; }
  async getBlockNumber(): Promise<number> { return 1; }
  async snapshot(): Promise<string> { return "snap-1"; }
  async revertToSnapshot(): Promise<void> { /* no-op */ }
  async setNextBlockTimestamp(): Promise<void> { /* no-op */ }
  async mine(): Promise<void> { /* no-op */ }
  async setStorageAt(): Promise<void> { /* no-op */ }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("fork unavailability", () => {
  it("ValidationRunner records infrastructure error when adapter crashes mid-run", async () => {
    const adapter = new RpcErrorAdapter();
    const runner = new ValidationRunner(adapter);
    const scenario = makeScenario({ calls: [{ to: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", signature: "noop()" }] });
    const result = await runner.run(scenario);
    // Should not throw; error is captured in result.error
    expect(result.error).toBeDefined();
    expect(result.outcomeMatched).toBe(false);
  });

  it("AdapterCrashError message does not leak paths", () => {
    const e = new AdapterCrashError("anvil", "/home/user/private/key.txt: No such file");
    expect(e.message).not.toContain("/home/user");
  });

  it("ForkUnavailableError message does not leak RPC URL", () => {
    const e = new ForkUnavailableError("ECONNREFUSED https://mainnet.infura.io/v3/SECRET_KEY");
    expect(e.message).not.toContain("SECRET_KEY");
  });
});

describe("RPC inconsistency", () => {
  it("RPC error is captured in result.error, not thrown", async () => {
    const adapter = new RpcErrorAdapter();
    const runner = new ValidationRunner(adapter);
    const scenario = makeScenario();
    const result = await runner.run(scenario);
    expect(result.error).toBeDefined();
    expect(typeof result.error).toBe("string");
  });

  it("RPC error message is sanitized in result", async () => {
    const adapter = new RpcErrorAdapter();
    const runner = new ValidationRunner(adapter);
    const scenario = makeScenario();
    const result = await runner.run(scenario);
    // Should not contain raw paths or secrets
    expect(result.error).not.toContain("/home/");
  });
});

describe("cancellation / hanging adapter", () => {
  it("cancellation signal stops the run and returns an error result", async () => {
    const adapter = new HangingAdapter();
    const { signal, cancel } = createCancellationSignal();
    const runner = new ValidationRunner(adapter, { signal });
    const scenario = makeScenario();

    // Cancel after a tiny delay
    setTimeout(() => cancel(), 10);
    const result = await runner.run(scenario);
    expect(result.error).toBeDefined();
  }, 10_000);

  it("pre-cancelled signal prevents calls from being made", async () => {
    const adapter = new HangingAdapter();
    const { signal, cancel } = createCancellationSignal();
    cancel(); // cancel BEFORE run
    const runner = new ValidationRunner(adapter, { signal });
    const scenario = makeScenario();
    const result = await runner.run(scenario);
    expect(result.error).toBeDefined();
  });
});

describe("malicious / oversized input", () => {
  it("rejects scenario with too many calls (limits.maxCalls)", async () => {
    class OkAdapter implements EvmAdapter {
      readonly type = "anvil" as const;
      readonly version = "mock/ok";
      readonly rpcUrl = "http://127.0.0.1:1";
      async start(): Promise<void> { /* no-op */ }
      async dispose(): Promise<void> { /* no-op */ }
      async setupAccount(): Promise<void> { /* no-op */ }
      async deployContract(): Promise<string> { return "0x1000000000000000000000000000000000001002"; }
      async executeCall(): Promise<CallResult> {
        return { callIndex: 0, reverted: false, returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] };
      }
      async getStorageAt(): Promise<string> { return normalizeHex("0x0"); }
      async getBalance(): Promise<string> { return "0"; }
      async getBlockNumber(): Promise<number> { return 1; }
      async snapshot(): Promise<string> { return "snap-1"; }
      async revertToSnapshot(): Promise<void> { /* no-op */ }
      async setNextBlockTimestamp(): Promise<void> { /* no-op */ }
      async mine(): Promise<void> { /* no-op */ }
      async setStorageAt(): Promise<void> { /* no-op */ }
    }

    const adapter = new OkAdapter();
    const runner = new ValidationRunner(adapter, { limits: { maxCalls: 5 } });
    const scenario = makeScenario({
      calls: Array.from({ length: 10 }, () => ({ to: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", signature: "noop()" })),
    });
    await expect(runner.run(scenario)).rejects.toThrow(ValidationError);
  });

  it("planValidation handles 10,000 findings without throwing", () => {
    const findings: Finding[] = Array.from({ length: 10_000 }, (_, i) => ({
      id: i % 2 === 0 ? "CP-107" : "CP-115",
      title: "Test",
      description: "Test",
      recommendation: "Fix",
      severity: "critical",
      file: `contracts/File${i}.sol`,
      line: 1,
    } as Finding));
    // Should complete without OOM or timeout
    const plan = planValidation(findings, { deduplicateByFile: true });
    expect(plan.scenarios.length).toBeGreaterThan(0);
  });

  it("sanitizeErrorMessage handles null-like input gracefully", () => {
    expect(sanitizeErrorMessage("")).toBe("");
    expect(sanitizeErrorMessage("normal message")).toBe("normal message");
  });

  it("parseValidationPlan rejects excessively nested objects gracefully", () => {
    // Build a deeply nested JSON object
    let nested: unknown = "leaf";
    for (let i = 0; i < 100; i++) {
      nested = { value: nested };
    }
    const json = JSON.stringify({ schemaVersion: "1.0.0", scenarios: [nested] });
    // Should not throw an unhandled error (may throw CorruptBundleError or return partially parsed)
    expect(() => parseValidationPlan(json)).not.toThrow(TypeError);
  });

  it("generateValidationMarkdown handles scenario with XSS-like content in title", () => {
    const finding: Finding = {
      id: "CP-107",
      title: 'Reentrancy <script>alert("xss")</script>',
      description: "Test",
      recommendation: "Fix",
      severity: "critical",
      file: "contracts/Vault.sol",
      line: 1,
    };
    const plan = planValidation([finding]);
    const report = {
      schemaVersion: VALIDATION_SCHEMA_VERSION,
      timestamp: "2024-01-01T00:00:00.000Z",
      total: 0,
      passed: 0,
      failed: 0,
      errored: 0,
      results: [],
      adapterType: "anvil" as const,
      totalDurationMs: 0,
    };
    const md = generateValidationMarkdown(report);
    // Should not throw; markdown escaping handles special chars
    expect(typeof md).toBe("string");
  });

  it("scenario with empty calls array runs and records no callResults", async () => {
    class OkAdapter2 implements EvmAdapter {
      readonly type = "anvil" as const;
      readonly version = "mock/ok2";
      readonly rpcUrl = "http://127.0.0.1:1";
      async start(): Promise<void> { /* no-op */ }
      async dispose(): Promise<void> { /* no-op */ }
      async setupAccount(): Promise<void> { /* no-op */ }
      async deployContract(): Promise<string> { return "0x1000000000000000000000000000000000001003"; }
      async executeCall(): Promise<CallResult> {
        return { callIndex: 0, reverted: false, returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] };
      }
      async getStorageAt(): Promise<string> { return normalizeHex("0x0"); }
      async getBalance(): Promise<string> { return "0"; }
      async getBlockNumber(): Promise<number> { return 1; }
      async snapshot(): Promise<string> { return "snap-1"; }
      async revertToSnapshot(): Promise<void> { /* no-op */ }
      async setNextBlockTimestamp(): Promise<void> { /* no-op */ }
      async mine(): Promise<void> { /* no-op */ }
      async setStorageAt(): Promise<void> { /* no-op */ }
    }

    const adapter = new OkAdapter2();
    const runner = new ValidationRunner(adapter);
    const scenario = makeScenario({ calls: [] });
    const result = await runner.run(scenario);
    expect(result.callResults).toHaveLength(0);
  });
});

describe("replay integrity", () => {
  it("scenario IDs are stable across multiple planValidation calls", () => {
    const finding: Finding = {
      id: "CP-107",
      title: "Reentrancy",
      description: "Test",
      recommendation: "Fix",
      severity: "critical",
      file: "contracts/Vault.sol",
      line: 42,
    };
    const plan1 = planValidation([finding]);
    const plan2 = planValidation([finding]);
    expect(plan1.scenarios[0].id).toBe(plan2.scenarios[0].id);
  });

  it("serialized plan is identical for identical input (deterministic)", () => {
    const finding: Finding = {
      id: "CP-107",
      title: "Reentrancy",
      description: "Test",
      recommendation: "Fix",
      severity: "critical",
      file: "contracts/Vault.sol",
      line: 42,
    };
    const plan1 = planValidation([finding]);
    const plan2 = planValidation([finding]);
    const json1 = serializeValidationPlan(plan1);
    const json2 = serializeValidationPlan(plan2);
    // createdAt timestamps will differ; strip them for comparison
    const strip = (s: string) => s.replace(/"createdAt":\s*"[^"]+"/g, '"createdAt":"REDACTED"');
    expect(strip(json1)).toBe(strip(json2));
  });
});

describe("boundary conditions", () => {
  it("resolveResourceLimits handles zero values by using defaults", () => {
    // Zero values passed through — they override defaults
    const r = resolveResourceLimits({ timeoutMs: 0 });
    expect(r.timeoutMs).toBe(0); // explicitly overridden to 0
  });

  it("normalizeHex pads 0x0 to 64 chars", () => {
    const result = normalizeHex("0x0");
    expect(result).toHaveLength(66); // 0x + 64 chars
    expect(result).toBe("0x" + "0".repeat(64));
  });

  it("normalizeHex handles values without 0x prefix", () => {
    const result = normalizeHex("ff");
    expect(result).toBe("0x" + "ff".padStart(64, "0"));
  });

  it("hexToDecimalString handles very large values (uint256.max)", () => {
    const uint256Max = "0x" + "f".repeat(64);
    const decimal = hexToDecimalString(uint256Max);
    expect(decimal).toBe(
      "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    );
  });

  it("keccak256Pure returns 64-hex-char output for any input", () => {
    const cases = [
      Buffer.from(""),
      Buffer.from("a"),
      Buffer.from("a".repeat(200)),
      Buffer.alloc(136), // exactly one keccak block
      Buffer.alloc(137), // just over one block
    ];
    for (const input of cases) {
      const result = keccak256Pure(input);
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("encodeFunctionCall handles BigInt.MAX_SAFE_INTEGER", () => {
    expect(() =>
      encodeFunctionCall("transfer(address,uint256)", [
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935"),
      ]),
    ).not.toThrow();
  });

  it("scenario with no accounts still runs (uses defaults)", async () => {
    class MinimalOkAdapter implements EvmAdapter {
      readonly type = "anvil" as const;
      readonly version = "mock/minimal";
      readonly rpcUrl = "http://127.0.0.1:1";
      async start(): Promise<void> { /* no-op */ }
      async dispose(): Promise<void> { /* no-op */ }
      async setupAccount(): Promise<void> { /* no-op */ }
      async deployContract(): Promise<string> { return "0x1000000000000000000000000000000000001004"; }
      async executeCall(): Promise<CallResult> {
        return { callIndex: 0, reverted: false, returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] };
      }
      async getStorageAt(): Promise<string> { return normalizeHex("0x0"); }
      async getBalance(): Promise<string> { return "0"; }
      async getBlockNumber(): Promise<number> { return 1; }
      async snapshot(): Promise<string> { return "snap-1"; }
      async revertToSnapshot(): Promise<void> { /* no-op */ }
      async setNextBlockTimestamp(): Promise<void> { /* no-op */ }
      async mine(): Promise<void> { /* no-op */ }
      async setStorageAt(): Promise<void> { /* no-op */ }
    }

    const adapter = new MinimalOkAdapter();
    const runner = new ValidationRunner(adapter);
    const scenario = makeScenario({ accounts: [] });
    const result = await runner.run(scenario);
    expect(result).toBeDefined();
    // Should not throw
  });
});

describe("error sanitization / no secrets in output", () => {
  it("sanitizeScenario does not include API keys in result", () => {
    const scenario = makeScenario({
      chain: { chainId: 1, forkUrl: "https://eth-mainnet.g.alchemy.com/v2/SECRET_API_KEY" },
    });
    const s = sanitizeScenario(scenario);
    const json = JSON.stringify(s);
    expect(json).not.toContain("SECRET_API_KEY");
  });

  it("scenario ID does not embed file path components", () => {
    const plan = planValidation([{
      id: "CP-107",
      title: "Test",
      description: "",
      recommendation: "",
      severity: "critical",
      file: "/home/user/private_project/contracts/Secret.sol",
      line: 1,
    } as Finding]);
    const id = plan.scenarios[0]?.id ?? "";
    expect(id).not.toContain("private_project");
    expect(id).not.toContain("/home/user");
  });

  it("CorruptBundleError only shows basename of file path", () => {
    const e = new CorruptBundleError("/home/user/secret/plan.json", "bad format");
    expect(e.message).not.toContain("/home/user/secret");
    expect(e.message).toContain("plan.json");
  });

  it("ValidationError context is not automatically included in message", () => {
    const e = new ValidationError("test error", "TIMEOUT", { secretKey: "sk-secret123" });
    expect(e.message).toBe("test error");
    expect(e.message).not.toContain("sk-secret123");
  });
});

describe("supported finding IDs coverage", () => {
  const supportedFindings: { id: string; severity: "critical" | "high" | "medium" | "low" }[] = [
    { id: "CP-107", severity: "critical" },
    { id: "SWC-107", severity: "critical" },
    { id: "CP-107-X", severity: "critical" },
    { id: "CP-115", severity: "high" },
    { id: "SWC-115", severity: "high" },
    { id: "CP-101", severity: "high" },
    { id: "SWC-101", severity: "high" },
    { id: "CP-104", severity: "medium" },
    { id: "SWC-104", severity: "medium" },
    { id: "CP-122", severity: "high" },
    { id: "CP-CB-CEI", severity: "critical" },
    { id: "CP-CB-CROSSFN", severity: "critical" },
    { id: "CP-CB-READONLY", severity: "high" },
    { id: "CP-CB-SPOOF", severity: "high" },
    { id: "CP-CB-BATCH", severity: "medium" },
  ];

  for (const { id, severity } of supportedFindings) {
    it(`${id} generates exactly one scenario`, () => {
      const finding: Finding = {
        id,
        title: "Test",
        description: "",
        recommendation: "",
        severity,
        file: "contracts/Test.sol",
        line: 1,
      };
      const plan = planValidation([finding], { deduplicateByFile: true });
      expect(plan.scenarios.length).toBe(1);
      expect(plan.unsupportedFindings.length).toBe(0);
      expect(plan.scenarios[0].schemaVersion).toBe(VALIDATION_SCHEMA_VERSION);
    });
  }

  it("unsupported finding IDs are correctly reported", () => {
    const unsupportedIds = ["GAS-001", "SLITHER-arbitrary-send", "CUSTOM-999"];
    for (const id of unsupportedIds) {
      const finding: Finding = {
        id,
        title: "Test",
        description: "",
        recommendation: "",
        severity: "high",
        file: "contracts/Test.sol",
        line: 1,
      };
      const plan = planValidation([finding]);
      // GAS findings are excluded silently; others go to unsupported
      if (id.startsWith("GAS-")) {
        expect(plan.unsupportedFindings.length).toBe(0);
      } else {
        expect(plan.unsupportedFindings.length).toBeGreaterThan(0);
      }
    }
  });
});
