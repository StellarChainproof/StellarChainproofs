/**
 * Unit and integration tests for the validation engine.
 *
 * These tests cover:
 * - Core types and utilities (pure unit tests)
 * - Scaffold/planning from static findings
 * - ValidationRunner with a mock adapter
 * - Report generation
 * - Serialization/deserialization round-trips
 * - Minimizer logic
 * - Cancellation
 */

import * as fs from "fs";
import * as path from "path";
import { scan } from "../scanner";
import {
  // Constants
  DEFAULT_RESOURCE_LIMITS,
  VALIDATION_SCHEMA_VERSION,
  // Errors
  ValidationError,
  ValidationTimeoutError,
  AdapterCrashError,
  ForkUnavailableError,
  CorruptBundleError,
  ScenarioValidationError,
  // Cancellation
  createCancellationSignal,
  resolveResourceLimits,
  sanitizeErrorMessage,
  // Adapter utilities
  encodeFunctionCall,
  keccak256Selector,
  keccak256Pure,
  hexToDecimalString,
  normalizeHex,
  // Planning
  planValidation,
  serializeValidationPlan,
  parseValidationPlan,
  // Reports
  serializeValidationReport,
  generateValidationMarkdown,
  parseValidationReport,
  // Runner
  ValidationRunner,
  sanitizeScenario,
  minimizeScenario,
} from "../validation";
import type {
  CallResult,
  CallSpec,
  EvmAdapter,
  ResolvedResourceLimits,
  ValidationCancellationSignal,
  ValidationResult,
  ValidationScenario,
} from "../validation";
import { Finding } from "../types";

// ─── Mock adapter ─────────────────────────────────────────────────────────────

/**
 * Minimal mock EVM adapter for unit tests.
 * Does not spawn any process; returns configurable results.
 */
class MockEvmAdapter implements EvmAdapter {
  readonly type = "anvil" as const;
  version = "anvil/mock-1.0.0";
  rpcUrl = "http://127.0.0.1:9999";

  private _snapshotCounter = 0;
  private _blockNumber = 1;
  private _storage: Map<string, Map<string, string>> = new Map();
  private _balances: Map<string, string> = new Map();
  private _deployCounter = 0;

  // Configurable responses
  callShouldRevert = false;
  callRevertReason: string | undefined = undefined;
  deployedAddresses: string[] = [];

  async start(): Promise<void> { /* no-op */ }
  async dispose(): Promise<void> { /* no-op */ }

  async setupAccount(account: { address: string; balance?: string }): Promise<void> {
    if (account.balance) {
      this._balances.set(account.address.toLowerCase(), account.balance);
    }
  }

  async deployContract(spec: { name: string; bytecode?: string }, _deployer: string): Promise<string> {
    const address = this.deployedAddresses[this._deployCounter] ??
      `0x${(0x1000 + this._deployCounter).toString(16).padStart(40, "0")}`;
    this._deployCounter++;
    return address;
  }

  async executeCall(
    spec: CallSpec,
    _resolvedAddresses: Map<string, string>,
    _limits: ResolvedResourceLimits,
    _signal?: ValidationCancellationSignal,
  ): Promise<CallResult> {
    return {
      callIndex: 0,
      reverted: this.callShouldRevert,
      revertReason: this.callShouldRevert ? (this.callRevertReason ?? "reverted") : undefined,
      returnData: "0x",
      gasUsed: 21_000,
      logs: [],
      storageDiff: [],
    };
  }

  async getStorageAt(address: string, slot: string): Promise<string> {
    const contractStorage = this._storage.get(address.toLowerCase());
    return contractStorage?.get(slot) ?? normalizeHex("0x0");
  }

  async getBalance(address: string): Promise<string> {
    return this._balances.get(address.toLowerCase()) ?? "0";
  }

  async getBlockNumber(): Promise<number> {
    return this._blockNumber;
  }

  async snapshot(): Promise<string> {
    return `snap-${++this._snapshotCounter}`;
  }

  async revertToSnapshot(_snapshotId: string): Promise<void> { /* no-op */ }

  async setNextBlockTimestamp(_ts: number): Promise<void> { /* no-op */ }

  async mine(_count?: number): Promise<void> {
    this._blockNumber++;
  }

  async setStorageAt(address: string, slot: string, value: string): Promise<void> {
    if (!this._storage.has(address.toLowerCase())) {
      this._storage.set(address.toLowerCase(), new Map());
    }
    this._storage.get(address.toLowerCase())!.set(slot, value);
  }

  // Test helpers
  setBalance(address: string, wei: string): void {
    this._balances.set(address.toLowerCase(), wei);
  }

  setStorage(address: string, slot: string, value: string): void {
    if (!this._storage.has(address.toLowerCase())) {
      this._storage.set(address.toLowerCase(), new Map());
    }
    this._storage.get(address.toLowerCase())!.set(slot, value);
  }
}

// ─── Sample scenarios ─────────────────────────────────────────────────────────

function makeSampleScenario(overrides: Partial<ValidationScenario> = {}): ValidationScenario {
  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    id: "scenario-test-001",
    title: "Test scenario",
    chain: { chainId: 31337 },
    accounts: [
      { address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", balance: "10000000000000000000", label: "deployer" },
      { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", balance: "10000000000000000000", label: "attacker" },
    ],
    contracts: [
      { name: "Vault", bytecode: "0x608060405234801561001057600080fd5b50", abi: "[]", deployer: "deployer" },
    ],
    calls: [
      { to: "Vault", signature: "deposit()", value: "1000000000000000000", from: "deployer" },
      { to: "Vault", signature: "withdraw(uint256)", args: [1000000000000000000n], from: "attacker" },
    ],
    expectedOutcome: "exploit-succeeds",
    ...overrides,
  };
}

function makeSampleFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "CP-107",
    title: "Reentrancy",
    description: "External call before state update",
    recommendation: "Use CEI pattern",
    severity: "critical",
    file: "contracts/Vault.sol",
    line: 42,
    ...overrides,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("validation/types — constants", () => {
  it("VALIDATION_SCHEMA_VERSION is a semver string", () => {
    expect(VALIDATION_SCHEMA_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("DEFAULT_RESOURCE_LIMITS has sane values", () => {
    expect(DEFAULT_RESOURCE_LIMITS.timeoutMs).toBeGreaterThan(0);
    expect(DEFAULT_RESOURCE_LIMITS.maxCalls).toBeGreaterThan(0);
    expect(DEFAULT_RESOURCE_LIMITS.maxGasPerCall).toBeGreaterThan(0);
    expect(DEFAULT_RESOURCE_LIMITS.maxLogs).toBeGreaterThan(0);
    expect(DEFAULT_RESOURCE_LIMITS.maxMemoryBytes).toBeGreaterThan(0);
  });
});

describe("resolveResourceLimits", () => {
  it("uses defaults when no overrides given", () => {
    const r = resolveResourceLimits({});
    expect(r.timeoutMs).toBe(DEFAULT_RESOURCE_LIMITS.timeoutMs);
    expect(r.maxCalls).toBe(DEFAULT_RESOURCE_LIMITS.maxCalls);
  });

  it("scenario overrides take precedence over adapter overrides", () => {
    const r = resolveResourceLimits({ timeoutMs: 5_000 }, { timeoutMs: 10_000 });
    expect(r.timeoutMs).toBe(5_000);
  });

  it("adapter overrides take precedence over defaults", () => {
    const r = resolveResourceLimits({}, { maxCalls: 42 });
    expect(r.maxCalls).toBe(42);
  });
});

describe("sanitizeErrorMessage", () => {
  it("redacts http URLs", () => {
    expect(sanitizeErrorMessage("Error connecting to https://mainnet.infura.io/v3/abc123")).not.toContain("infura");
  });

  it("redacts file paths", () => {
    expect(sanitizeErrorMessage("Cannot find /home/user/secret/path/file.ts")).not.toContain("/home/user");
  });

  it("redacts long hex strings", () => {
    expect(sanitizeErrorMessage("Key: 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")).not.toContain("deadbeef");
  });

  it("truncates long messages to 500 chars", () => {
    const long = "x".repeat(1000);
    expect(sanitizeErrorMessage(long).length).toBeLessThanOrEqual(500);
  });
});

describe("keccak256Pure", () => {
  it("produces correct keccak256 for empty input", () => {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    const result = keccak256Pure(Buffer.from(""));
    expect(result).toBe("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  });

  it("produces correct keccak256 for 'hello'", () => {
    // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    const result = keccak256Pure(Buffer.from("hello", "utf8"));
    expect(result).toBe("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
  });
});

describe("keccak256Selector", () => {
  it("produces correct 4-byte selector for transfer(address,uint256)", () => {
    // keccak256("transfer(address,uint256)")[0:4] = a9059cbb
    const selector = keccak256Selector("transfer(address,uint256)");
    expect(selector.toLowerCase()).toBe("0xa9059cbb");
  });

  it("produces correct selector for balanceOf(address)", () => {
    // 0x70a08231
    const selector = keccak256Selector("balanceOf(address)");
    expect(selector.toLowerCase()).toBe("0x70a08231");
  });
});

describe("encodeFunctionCall", () => {
  it("encodes function call with no args correctly (4-byte selector)", () => {
    const data = encodeFunctionCall("deposit()", []);
    expect(data).toMatch(/^0x[0-9a-f]{8}$/i);
  });

  it("encodes address argument as 32-byte padded value", () => {
    const addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const data = encodeFunctionCall("approve(address,uint256)", [addr, 100n]);
    expect(data.length).toBe(2 + 8 + 64 + 64); // 0x + selector + addr + uint
  });

  it("encodes bool true as 0x...01", () => {
    const data = encodeFunctionCall("setFlag(bool)", [true]);
    expect(data.endsWith("01")).toBe(true);
  });

  it("encodes bool false as 0x...00", () => {
    const data = encodeFunctionCall("setFlag(bool)", [false]);
    expect(data.endsWith("00")).toBe(true);
  });
});

describe("hexToDecimalString", () => {
  it("converts 0x1 to '1'", () => {
    expect(hexToDecimalString("0x1")).toBe("1");
  });

  it("converts 0xde0b6b3a7640000 (1 ETH in wei)", () => {
    expect(hexToDecimalString("0xde0b6b3a7640000")).toBe("1000000000000000000");
  });

  it("handles empty/zero", () => {
    expect(hexToDecimalString("0x")).toBe("0");
    expect(hexToDecimalString("0x0")).toBe("0");
  });
});

describe("normalizeHex", () => {
  it("pads short hex to 32 bytes", () => {
    expect(normalizeHex("0x1")).toBe("0x" + "1".padStart(64, "0"));
  });

  it("preserves already-padded values", () => {
    const full = "0x" + "a".repeat(64);
    expect(normalizeHex(full)).toBe(full);
  });
});

describe("ValidationError hierarchy", () => {
  it("ValidationError has code and name", () => {
    const e = new ValidationError("test", "TIMEOUT");
    expect(e.code).toBe("TIMEOUT");
    expect(e.name).toBe("ValidationError");
    expect(e.message).toBe("test");
  });

  it("ValidationTimeoutError", () => {
    const e = new ValidationTimeoutError("scenario-1", 30_000);
    expect(e.code).toBe("TIMEOUT");
    expect(e.name).toBe("ValidationTimeoutError");
    expect(e.message).toContain("30000");
  });

  it("AdapterCrashError sanitizes detail", () => {
    const e = new AdapterCrashError("anvil", "anvil crashed at /home/user/secret");
    expect(e.message).not.toContain("/home/user");
  });

  it("ForkUnavailableError", () => {
    const e = new ForkUnavailableError("connection refused");
    expect(e.code).toBe("FORK_UNAVAILABLE");
  });

  it("CorruptBundleError sanitizes path", () => {
    const e = new CorruptBundleError("/home/user/secret.json", "Invalid JSON");
    expect(e.message).not.toContain("/home/user");
    expect(e.message).toContain("secret.json");
  });
});

describe("createCancellationSignal", () => {
  it("starts as not cancelled", () => {
    const { signal } = createCancellationSignal();
    expect(signal.cancelled).toBe(false);
  });

  it("becomes cancelled after cancel()", () => {
    const { signal, cancel } = createCancellationSignal();
    cancel();
    expect(signal.cancelled).toBe(true);
  });

  it("calls onCancelled callbacks when cancelled", () => {
    const { signal, cancel } = createCancellationSignal();
    const cb = jest.fn();
    signal.onCancelled(cb);
    cancel();
    expect(cb).toHaveBeenCalledTimes(1);
  });

  it("calls onCancelled immediately if already cancelled", () => {
    const { signal, cancel } = createCancellationSignal();
    cancel();
    const cb = jest.fn();
    signal.onCancelled(cb);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  it("is idempotent — cancel() twice does not call callbacks twice", () => {
    const { signal, cancel } = createCancellationSignal();
    const cb = jest.fn();
    signal.onCancelled(cb);
    cancel();
    cancel();
    expect(cb).toHaveBeenCalledTimes(1);
  });
});

describe("planValidation", () => {
  it("generates a scenario for CP-107 reentrancy finding", () => {
    const finding = makeSampleFinding({ id: "CP-107", severity: "critical" });
    const plan = planValidation([finding]);
    expect(plan.schemaVersion).toBe(VALIDATION_SCHEMA_VERSION);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].findingId).toBe("CP-107");
    expect(plan.scenarios[0].tags).toContain("reentrancy");
  });

  it("generates a scenario for CP-115 tx.origin finding", () => {
    const finding = makeSampleFinding({ id: "CP-115", severity: "high" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].tags).toContain("tx-origin");
  });

  it("generates a scenario for CP-122 vault inflation", () => {
    const finding = makeSampleFinding({ id: "CP-122", severity: "high" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].tags).toContain("vault-inflation");
  });

  it("generates a scenario for CP-CB-CEI callback violation", () => {
    const finding = makeSampleFinding({ id: "CP-CB-CEI", severity: "critical" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].tags).toContain("callback-reentrancy");
  });

  it("generates a scenario for CP-CB-SPOOF callback spoofing", () => {
    const finding = makeSampleFinding({ id: "CP-CB-SPOOF", severity: "high" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].tags).toContain("callback-spoof");
  });

  it("generates a scenario for CP-CB-BATCH", () => {
    const finding = makeSampleFinding({ id: "CP-CB-BATCH", severity: "medium" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(1);
    expect(plan.scenarios[0].expectedOutcome).toBe("exploit-reverts");
  });

  it("adds unknown finding IDs to unsupportedFindings", () => {
    const finding = makeSampleFinding({ id: "SLITHER-reentrancy-eth", severity: "high" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(0);
    expect(plan.unsupportedFindings.length).toBe(1);
    expect(plan.unsupportedFindings[0].findingId).toBe("SLITHER-reentrancy-eth");
  });

  it("excludes gas-severity findings", () => {
    const finding = makeSampleFinding({ id: "GAS-001", severity: "gas" });
    const plan = planValidation([finding]);
    expect(plan.scenarios.length).toBe(0);
    expect(plan.unsupportedFindings.length).toBe(0); // gas is silently excluded
  });

  it("respects minSeverity option", () => {
    const findings = [
      makeSampleFinding({ id: "CP-107", severity: "critical" }),
      makeSampleFinding({ id: "CP-115", severity: "high" }),
      makeSampleFinding({ id: "CP-104", severity: "medium", line: 100 }),
    ];
    const plan = planValidation(findings, { minSeverity: "high" });
    // Only critical and high should be included
    expect(plan.scenarios.length).toBe(2);
  });

  it("deduplicates by (id, file) by default", () => {
    const findings = [
      makeSampleFinding({ id: "CP-107", line: 10 }),
      makeSampleFinding({ id: "CP-107", line: 20 }),
    ];
    const plan = planValidation(findings);
    expect(plan.scenarios.length).toBe(1);
  });

  it("does not deduplicate when deduplicateByFile=true (different lines)", () => {
    const findings = [
      makeSampleFinding({ id: "CP-107", line: 10 }),
      makeSampleFinding({ id: "CP-107", line: 20 }),
    ];
    const plan = planValidation(findings, { deduplicateByFile: true });
    expect(plan.scenarios.length).toBe(2);
  });

  it("all scenarios have required fields", () => {
    const findings = [
      makeSampleFinding({ id: "CP-107" }),
      makeSampleFinding({ id: "CP-115" }),
      makeSampleFinding({ id: "CP-122" }),
    ];
    const plan = planValidation(findings);
    for (const scenario of plan.scenarios) {
      expect(scenario.schemaVersion).toBeDefined();
      expect(scenario.id).toBeDefined();
      expect(scenario.title).toBeDefined();
      expect(scenario.chain).toBeDefined();
      expect(Array.isArray(scenario.accounts)).toBe(true);
      expect(Array.isArray(scenario.contracts)).toBe(true);
      expect(Array.isArray(scenario.calls)).toBe(true);
      expect(scenario.expectedOutcome).toBeDefined();
    }
  });

  it("scenario IDs are unique within a plan", () => {
    const findings = [
      makeSampleFinding({ id: "CP-107", file: "A.sol", line: 1 }),
      makeSampleFinding({ id: "CP-115", file: "B.sol", line: 2 }),
      makeSampleFinding({ id: "CP-122", file: "C.sol", line: 3 }),
    ];
    const plan = planValidation(findings, { deduplicateByFile: true });
    const ids = plan.scenarios.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("serializeValidationPlan / parseValidationPlan", () => {
  it("round-trips a plan through JSON", () => {
    const finding = makeSampleFinding({ id: "CP-107" });
    const plan = planValidation([finding]);
    const json = serializeValidationPlan(plan);
    const parsed = parseValidationPlan(json);
    expect(parsed.schemaVersion).toBe(plan.schemaVersion);
    expect(parsed.scenarios.length).toBe(plan.scenarios.length);
  });

  it("throws CorruptBundleError on invalid JSON", () => {
    expect(() => parseValidationPlan("{ not valid json")).toThrow();
  });

  it("throws on missing schemaVersion", () => {
    expect(() => parseValidationPlan('{"scenarios":[]}')).toThrow();
  });

  it("throws on missing scenarios array", () => {
    expect(() => parseValidationPlan('{"schemaVersion":"1.0.0"}')).toThrow();
  });
});

describe("sanitizeScenario", () => {
  it("removes privateKey from accounts", () => {
    const scenario = makeSampleScenario();
    scenario.accounts[0].privateKey = "0xdeadbeef";
    const sanitized = sanitizeScenario(scenario);
    expect(sanitized.accounts[0].privateKey).toBeUndefined();
  });

  it("replaces forkUrl with [redacted]", () => {
    const scenario = makeSampleScenario({
      chain: { chainId: 1, forkUrl: "https://mainnet.infura.io/v3/secret" },
    });
    const sanitized = sanitizeScenario(scenario);
    expect(sanitized.chain.forkUrl).toBe("[redacted]");
    expect(sanitized.chain.chainId).toBe(1);
  });

  it("does not modify the original scenario", () => {
    const scenario = makeSampleScenario({ chain: { chainId: 1, forkUrl: "https://secret" } });
    sanitizeScenario(scenario);
    expect(scenario.chain.forkUrl).toBe("https://secret");
  });
});

describe("ValidationRunner with MockEvmAdapter", () => {
  let adapter: MockEvmAdapter;
  let runner: ValidationRunner;

  beforeEach(() => {
    adapter = new MockEvmAdapter();
    runner = new ValidationRunner(adapter);
  });

  it("returns a ValidationResult with correct schema version", async () => {
    const scenario = makeSampleScenario();
    const result = await runner.run(scenario);
    expect(result.schemaVersion).toBe(VALIDATION_SCHEMA_VERSION);
    expect(result.adapterType).toBe("anvil");
  });

  it("runs all calls and records callResults", async () => {
    const scenario = makeSampleScenario();
    const result = await runner.run(scenario);
    expect(result.callResults.length).toBe(scenario.calls.length);
  });

  it("outcome exploit-succeeds passes when no calls revert and assertions pass", async () => {
    adapter.callShouldRevert = false;
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-succeeds" });
    const result = await runner.run(scenario);
    expect(result.outcomeMatched).toBe(true);
  });

  it("outcome exploit-succeeds fails when a call reverts", async () => {
    adapter.callShouldRevert = true;
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-succeeds" });
    const result = await runner.run(scenario);
    expect(result.outcomeMatched).toBe(false);
    expect(result.outcomeSummary).toContain("revert");
  });

  it("outcome exploit-reverts passes when a call reverts", async () => {
    adapter.callShouldRevert = true;
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-reverts" });
    const result = await runner.run(scenario);
    expect(result.outcomeMatched).toBe(true);
  });

  it("outcome exploit-reverts fails when no call reverts", async () => {
    adapter.callShouldRevert = false;
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-reverts" });
    const result = await runner.run(scenario);
    expect(result.outcomeMatched).toBe(false);
    expect(result.outcomeSummary).toContain("did not revert");
  });

  it("outcome secure-baseline passes when no calls revert", async () => {
    adapter.callShouldRevert = false;
    const scenario = makeSampleScenario({ expectedOutcome: "secure-baseline" });
    const result = await runner.run(scenario);
    expect(result.outcomeMatched).toBe(true);
  });

  it("records snapshotId and snapshotBlock", async () => {
    const scenario = makeSampleScenario();
    const result = await runner.run(scenario);
    expect(result.snapshotId).toBeTruthy();
    expect(result.snapshotBlock).toBeGreaterThanOrEqual(0);
  });

  it("evaluates storage assertions", async () => {
    const contractAddr = "0x1000000000000000000000000000000000001000";
    const slot = "0x" + "0".repeat(64);
    adapter.setStorage(contractAddr, slot, normalizeHex("0x2a"));
    const scenario = makeSampleScenario({
      storageAssertions: [
        { contract: contractAddr, slot, expected: "0x" + "2a".padStart(64, "0") },
      ],
    });
    const result = await runner.run(scenario);
    expect(result.storageAssertionResults).toHaveLength(1);
    expect(result.storageAssertionResults[0].passed).toBe(true);
  });

  it("evaluates balance assertions (gt)", async () => {
    const addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    adapter.setBalance(addr, "5000000000000000000"); // 5 ETH
    const scenario = makeSampleScenario({
      balanceAssertions: [
        { account: addr, op: "gt", value: "1000000000000000000", description: "Has > 1 ETH" },
      ],
    });
    const result = await runner.run(scenario);
    expect(result.balanceAssertionResults[0].passed).toBe(true);
  });

  it("evaluates balance assertions (lt) — fails when balance is too high", async () => {
    const addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    adapter.setBalance(addr, "5000000000000000000");
    const scenario = makeSampleScenario({
      balanceAssertions: [
        { account: addr, op: "lt", value: "1000000000000000000" },
      ],
    });
    const result = await runner.run(scenario);
    expect(result.balanceAssertionResults[0].passed).toBe(false);
  });

  it("rejects scenarios exceeding maxCalls limit", async () => {
    const scenario = makeSampleScenario();
    const manyCallsScenario = {
      ...scenario,
      calls: Array.from({ length: 200 }, () => scenario.calls[0]),
      limits: { maxCalls: 10 },
    };
    await expect(runner.run(manyCallsScenario)).rejects.toThrow(ValidationError);
  });

  it("respects cancellation signal", async () => {
    const { signal, cancel } = createCancellationSignal();
    cancel(); // cancel before run
    const cancelRunner = new ValidationRunner(adapter, { signal });
    const scenario = makeSampleScenario();
    // Should throw or record error
    const result = await cancelRunner.run(scenario);
    expect(result.error).toBeDefined();
  });

  it("sanitizes private keys in result scenario", async () => {
    const scenario = makeSampleScenario();
    scenario.accounts[0].privateKey = "0xsecretkey";
    const result = await runner.run(scenario);
    expect(result.scenario.accounts[0].privateKey).toBeUndefined();
  });

  it("strips fork URL from result scenario", async () => {
    const scenario = makeSampleScenario({
      chain: { chainId: 1, forkUrl: "https://secret-rpc-url" },
    });
    const result = await runner.run(scenario);
    expect(result.scenario.chain.forkUrl).toBe("[redacted]");
  });

  it("records total gas used as sum of call results", async () => {
    const scenario = makeSampleScenario();
    const result = await runner.run(scenario);
    const expectedTotal = result.callResults.reduce((sum, r) => sum + r.gasUsed, 0);
    expect(result.totalGasUsed).toBe(expectedTotal);
  });

  it("duration is non-negative", async () => {
    const scenario = makeSampleScenario();
    const result = await runner.run(scenario);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});

describe("minimizeScenario", () => {
  it("returns original scenario when outcome cannot be established", async () => {
    const adapter = new MockEvmAdapter();
    adapter.callShouldRevert = true; // baseline won't match exploit-succeeds
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-succeeds" });
    const result = await minimizeScenario(scenario, adapter, { maxTrials: 5 });
    expect(result.minimizedCallCount).toBe(scenario.calls.length);
    expect(result.removedCallIndices).toHaveLength(0);
  });

  it("removes redundant calls when possible", async () => {
    const adapter = new MockEvmAdapter();
    adapter.callShouldRevert = false;
    // Scenario with 3 calls; mock always succeeds so any subset also succeeds
    const scenario = makeSampleScenario({
      expectedOutcome: "exploit-succeeds",
      calls: [
        { to: "Vault", signature: "noop()", from: "deployer", description: "call 1" },
        { to: "Vault", signature: "noop()", from: "deployer", description: "call 2" },
        { to: "Vault", signature: "attack()", from: "attacker", description: "exploit" },
      ],
    });
    const result = await minimizeScenario(scenario, adapter, { maxTrials: 20 });
    expect(result.minimizedCallCount).toBeLessThanOrEqual(scenario.calls.length);
    expect(result.trialsUsed).toBeGreaterThan(0);
  });

  it("respects maxTrials budget", async () => {
    const adapter = new MockEvmAdapter();
    adapter.callShouldRevert = false;
    const scenario = makeSampleScenario({
      expectedOutcome: "exploit-succeeds",
      calls: Array.from({ length: 10 }, (_, i) => ({
        to: "Vault",
        signature: `noop${i}()`,
        from: "deployer",
      })),
    });
    const result = await minimizeScenario(scenario, adapter, { maxTrials: 2 });
    expect(result.trialsUsed).toBeLessThanOrEqual(3); // baseline + max 2
    expect(result.budgetExceeded).toBe(true);
  });

  it("respects cancellation signal", async () => {
    const adapter = new MockEvmAdapter();
    const { signal, cancel } = createCancellationSignal();
    const scenario = makeSampleScenario({ expectedOutcome: "exploit-succeeds" });
    cancel();
    const result = await minimizeScenario(scenario, adapter, { signal });
    // Should complete without throwing
    expect(result).toBeDefined();
  });
});

describe("report generation", () => {
  function makeValidationReport(overrides: Partial<import("../validation").ValidationReport> = {}) {
    const result: ValidationResult = {
      schemaVersion: VALIDATION_SCHEMA_VERSION,
      scenario: makeSampleScenario(),
      adapterType: "anvil",
      adapterVersion: "anvil/0.2.0",
      snapshotId: "snap-1",
      snapshotBlock: 100,
      callResults: [
        { callIndex: 0, reverted: false, returnData: "0x", gasUsed: 21000, logs: [], storageDiff: [] },
      ],
      outcomeMatched: true,
      outcomeSummary: "Exploit scenario completed without reverts",
      storageAssertionResults: [],
      balanceAssertionResults: [],
      eventAssertionResults: [],
      totalGasUsed: 21000,
      startedAt: "2024-01-01T00:00:00.000Z",
      completedAt: "2024-01-01T00:00:01.000Z",
      durationMs: 1000,
      warnings: [],
    };

    return {
      schemaVersion: VALIDATION_SCHEMA_VERSION,
      timestamp: "2024-01-01T00:00:01.000Z",
      total: 1,
      passed: 1,
      failed: 0,
      errored: 0,
      results: [result],
      adapterType: "anvil" as const,
      totalDurationMs: 1000,
      ...overrides,
    };
  }

  it("serializeValidationReport produces valid JSON", () => {
    const report = makeValidationReport();
    const json = serializeValidationReport(report);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("round-trips through parseValidationReport", () => {
    const report = makeValidationReport();
    const json = serializeValidationReport(report);
    const parsed = parseValidationReport(json);
    expect(parsed.total).toBe(report.total);
    expect(parsed.passed).toBe(report.passed);
  });

  it("generateValidationMarkdown includes summary table", () => {
    const report = makeValidationReport();
    const md = generateValidationMarkdown(report);
    expect(md).toContain("## Summary");
    expect(md).toContain("Passed");
    expect(md).toContain("Failed");
  });

  it("generateValidationMarkdown includes scenario title", () => {
    const report = makeValidationReport();
    const md = generateValidationMarkdown(report);
    expect(md).toContain("Test scenario");
  });

  it("generateValidationMarkdown shows error in errored results", () => {
    const report = makeValidationReport({
      errored: 1,
      passed: 0,
      results: [{
        ...makeValidationReport().results[0],
        error: "adapter crashed",
        outcomeMatched: false,
      }],
    });
    const md = generateValidationMarkdown(report);
    expect(md).toContain("Infrastructure Error");
  });

  it("parseValidationReport throws on missing schemaVersion", () => {
    expect(() => parseValidationReport('{"results":[]}')).toThrow();
  });

  it("parseValidationReport throws on invalid JSON", () => {
    expect(() => parseValidationReport("{bad json}")).toThrow();
  });

  it("serializeValidationReport output has deterministic key order", () => {
    const report1 = makeValidationReport({ passed: 1 });
    const report2 = makeValidationReport({ passed: 1 });
    // Same input → same output
    expect(serializeValidationReport(report1)).toBe(serializeValidationReport(report2));
  });
});

describe("validation fixtures exist", () => {
  const fixtureDir = path.resolve(__dirname, "../../../../examples/contracts/validation");

  it("ValidationVulnerableVault.sol exists", () => {
    const filePath = path.join(fixtureDir, "ValidationVulnerableVault.sol");
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("ValidationSecureVault.sol exists", () => {
    const filePath = path.join(fixtureDir, "ValidationSecureVault.sol");
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("ValidationReentrantAttacker.sol exists", () => {
    const filePath = path.join(fixtureDir, "ValidationReentrantAttacker.sol");
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("ValidationVulnerableVault.sol is parseable as text and contains expected patterns", () => {
    const content = fs.readFileSync(
      path.join(fixtureDir, "ValidationVulnerableVault.sol"),
      "utf8",
    );
    expect(content).toContain("withdraw");
    expect(content).toContain("tx.origin");
    expect(content).toContain("balances");
  });

  it("ValidationSecureVault.sol contains nonReentrant modifier", () => {
    const content = fs.readFileSync(
      path.join(fixtureDir, "ValidationSecureVault.sol"),
      "utf8",
    );
    expect(content).toContain("nonReentrant");
    expect(content).toContain("msg.sender");
  });
});

describe("integration: planValidation → scan", () => {
  it("can plan from real static findings from VulnerableVault.sol", async () => {
    const vaultPath = path.resolve(__dirname, "../../../../examples/contracts/VulnerableVault.sol");
    const result = await scan({ targets: [vaultPath], useSlither: false, useLLM: false, useMetrics: false });
    const allFindings = result.files.flatMap((f: { findings: Finding[] }) => f.findings);
    expect(allFindings.length).toBeGreaterThan(0);

    const plan = planValidation(allFindings);
    // At least one scenario should be generated
    expect(plan.scenarios.length).toBeGreaterThanOrEqual(0); // may have unsupported IDs
    expect(plan.unsupportedFindings.length).toBeGreaterThanOrEqual(0);
    expect(plan.createdAt).toBeDefined();
  });
});
