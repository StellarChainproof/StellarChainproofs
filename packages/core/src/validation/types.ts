/**
 * @packageDocumentation
 * Core types for the fork-aware concrete validation and exploit reproduction harness.
 *
 * Scenarios describe the EVM state needed to reproduce a finding. Adapters
 * encapsulate process-isolated EVM backends (Anvil, Hardhat Network).
 * ValidationBundles are the portable, versioned output of a validation run.
 *
 * @remarks
 * All types are versioned. When the schema changes in a breaking way,
 * VALIDATION_SCHEMA_VERSION is bumped and migration helpers must be provided.
 * Serialized bundles carry a `schemaVersion` field so offline replay tools
 * can reject incompatible files without crashing.
 *
 * Security boundaries: adapters run external processes with bounded resources
 * (time, memory, fds). No secrets, local paths beyond the project root, or
 * provider credentials are persisted into bundles. Scenario sources are
 * embedded as sanitized bytecode or constructor arguments, not file paths.
 */

/** Schema version for serialized validation scenarios and bundles. */
export const VALIDATION_SCHEMA_VERSION = "1.0.0";

// ─── Chain / block context ────────────────────────────────────────────────────

/**
 * Identifies the chain and block context for a validation scenario.
 *
 * When `forkUrl` is provided the adapter forks at `forkBlockNumber`
 * (or latest, if omitted) and replays the scenario against real state.
 * When both are absent the adapter starts a fresh in-process devnet.
 */
export interface ChainContext {
  /** EIP-155 chain id. Defaults to 31337 (Hardhat/Anvil devnet). */
  chainId?: number;
  /**
   * Remote JSON-RPC URL to fork from.
   * MUST NOT be serialized into a bundle; replaced with `forkBlockNumber`
   * and a redacted placeholder when bundles are written.
   */
  forkUrl?: string;
  /**
   * Block number to pin the fork. Required for deterministic replay
   * when `forkUrl` is set. If absent, the adapter fetches and pins latest.
   */
  forkBlockNumber?: number;
  /**
   * Unix timestamp (seconds) to use for the first block.
   * Deterministic replay requires this to be pinned.
   */
  timestamp?: number;
  /** Base fee per gas in wei for the first block. */
  baseFeePerGas?: string;
}

// ─── Accounts ────────────────────────────────────────────────────────────────

/** A funded account with an optional private key for transaction signing. */
export interface AccountSpec {
  /** Hex address (0x-prefixed, EIP-55 or lowercase). */
  address: string;
  /** Initial balance in wei (decimal or 0x-prefixed hex string). */
  balance?: string;
  /**
   * Private key for signing (0x-prefixed hex).
   * Absent for read-only or externally owned accounts.
   * MUST NOT be emitted in bundles; adapters accept it transiently.
   */
  privateKey?: string;
  /** Human-readable role label for report generation. */
  label?: string;
}

// ─── Deployed contracts ───────────────────────────────────────────────────────

/**
 * A contract to deploy or alias at a fixed address before the scenario runs.
 */
export interface ContractSpec {
  /** Symbolic name used in call specs (e.g. "Vault"). */
  name: string;
  /**
   * Pre-computed deployment bytecode (0x-prefixed hex).
   * Either `bytecode` or `address` must be provided.
   */
  bytecode?: string;
  /** ABI as a JSON string (array of ABI items). */
  abi?: string;
  /**
   * ABI-encoded constructor arguments (0x-prefixed hex, no "0x" function selector).
   * Appended to `bytecode` at deploy time.
   */
  constructorArgs?: string;
  /**
   * Pre-existing contract address. When set, no deployment happens;
   * the symbolic name is simply aliased to this address.
   * Requires `forkUrl` in the chain context.
   */
  address?: string;
  /**
   * Storage slots to pre-set before any calls.
   * Keys are 0x-prefixed 32-byte slot indices; values are 0x-prefixed 32-byte values.
   */
  storageOverrides?: Record<string, string>;
  /** Deployer account label (must match an AccountSpec label or address). */
  deployer?: string;
}

// ─── Transactions / calls ─────────────────────────────────────────────────────

/** A single EVM call or state-mutating transaction in the scenario. */
export interface CallSpec {
  /** Target contract name (from ContractSpec.name) or raw hex address. */
  to: string;
  /**
   * ABI function signature, e.g. `"withdraw(uint256)"`.
   * Used to encode calldata when `calldata` is absent.
   */
  signature?: string;
  /** ABI-decoded arguments as JSON-serializable values. */
  args?: unknown[];
  /**
   * Raw calldata (0x-prefixed hex). Takes precedence over `signature`+`args`.
   */
  calldata?: string;
  /** Sender account label or address. Defaults to the first AccountSpec. */
  from?: string;
  /** Value in wei (decimal or 0x-prefixed hex). */
  value?: string;
  /** Gas limit override. */
  gasLimit?: number;
  /**
   * Whether to treat a revert as expected (scenario assertion).
   * When true, the call is considered passing if and only if it reverts.
   */
  expectRevert?: boolean;
  /** Human-readable description for report generation. */
  description?: string;
}

// ─── Storage / outcome assumptions ───────────────────────────────────────────

/** A storage slot expected to hold a particular value after the scenario. */
export interface StorageAssertion {
  /** Contract name or address. */
  contract: string;
  /** Slot index (0x-prefixed 32-byte hex). */
  slot: string;
  /** Expected value (0x-prefixed 32-byte hex). */
  expected: string;
  /** Human-readable description. */
  description?: string;
}

/** An account balance assertion after the scenario. */
export interface BalanceAssertion {
  /** Account label or address. */
  account: string;
  /** Comparison operator. */
  op: "eq" | "gt" | "gte" | "lt" | "lte";
  /** Value in wei (decimal or 0x-prefixed hex). */
  value: string;
  /** Human-readable description. */
  description?: string;
}

/** A log/event emission assertion. */
export interface EventAssertion {
  /** Contract name or address that emitted the event. */
  contract: string;
  /** Event signature, e.g. `"Transfer(address,address,uint256)"`. */
  eventSignature: string;
  /** Whether the event must NOT have been emitted. */
  negate?: boolean;
  /** Human-readable description. */
  description?: string;
}

// ─── The Validation Scenario ──────────────────────────────────────────────────

/**
 * A fully self-contained description of a validation experiment.
 *
 * Scenarios are produced either by the scaffold translator (from static
 * findings) or hand-authored by security researchers. They are versioned,
 * deterministic by default, and reproducible offline.
 *
 * @example Reentrancy reproduction scaffold
 * ```json
 * {
 *   "schemaVersion": "1.0.0",
 *   "id": "scenario-CP-107-VulnerableVault-withdraw",
 *   "title": "Reentrancy in VulnerableVault.withdraw",
 *   "findingId": "CP-107",
 *   "findingFile": "contracts/VulnerableVault.sol",
 *   "findingLine": 42,
 *   "chain": { "chainId": 31337 },
 *   "accounts": [
 *     { "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "balance": "10000000000000000000", "label": "attacker" }
 *   ],
 *   "contracts": [
 *     { "name": "Vault", "bytecode": "0x...", "abi": "[...]" }
 *   ],
 *   "calls": [
 *     { "to": "Vault", "signature": "deposit()", "value": "1000000000000000000", "from": "attacker" },
 *     { "to": "Vault", "signature": "withdraw(uint256)", "args": ["1000000000000000000"], "from": "attacker" }
 *   ],
 *   "expectedOutcome": "exploit-succeeds"
 * }
 * ```
 */
export interface ValidationScenario {
  /** Schema version for migration and compatibility checks. */
  schemaVersion: string;
  /**
   * Stable unique identifier.
   * Convention: `scenario-{findingId}-{contractName}-{functionName}`.
   */
  id: string;
  /** Human-readable title. */
  title: string;
  /** Short explanation of what this scenario tests. */
  description?: string;
  /**
   * Finding ID this scenario was generated from (e.g. "CP-107").
   * Absent for hand-authored scenarios.
   */
  findingId?: string;
  /** Source file the finding was detected in. */
  findingFile?: string;
  /** 1-indexed line number of the finding. */
  findingLine?: number;
  /** Chain context (devnet or fork). */
  chain: ChainContext;
  /** Accounts to pre-fund. */
  accounts: AccountSpec[];
  /** Contracts to deploy or alias. */
  contracts: ContractSpec[];
  /**
   * Ordered list of calls. They execute in sequence.
   * A snapshot is taken before call[0] and is available for replay.
   */
  calls: CallSpec[];
  /**
   * Storage assertions checked after all calls complete.
   */
  storageAssertions?: StorageAssertion[];
  /** Balance assertions checked after all calls complete. */
  balanceAssertions?: BalanceAssertion[];
  /** Event assertions checked after all calls complete. */
  eventAssertions?: EventAssertion[];
  /**
   * What outcome this scenario is designed to demonstrate.
   *
   * - `exploit-succeeds` — the calls execute without reverting and demonstrate the vulnerability.
   * - `exploit-reverts` — the calls revert, suggesting a guard is in place.
   * - `secure-baseline` — the equivalent hardened variant; used for false-positive controls.
   * - `custom` — researcher-defined outcome; `outcomeDescription` is mandatory.
   */
  expectedOutcome: "exploit-succeeds" | "exploit-reverts" | "secure-baseline" | "custom";
  /**
   * Required when `expectedOutcome` is `"custom"`.
   */
  outcomeDescription?: string;
  /**
   * Resource limits for this scenario (overrides adapter defaults).
   */
  limits?: ScenarioResourceLimits;
  /**
   * Tags for filtering and grouping (e.g. `["reentrancy", "erc20"]`).
   */
  tags?: string[];
  /** ISO-8601 creation timestamp. */
  createdAt?: string;
}

// ─── Resource limits ──────────────────────────────────────────────────────────

/** Resource bounds for a single validation run. */
export interface ScenarioResourceLimits {
  /** Maximum wall-clock time in milliseconds for the entire scenario (default: 30_000). */
  timeoutMs?: number;
  /** Maximum memory in bytes for the adapter process (default: 512 * 1024 * 1024). */
  maxMemoryBytes?: number;
  /** Maximum number of calls in the scenario (default: 100). */
  maxCalls?: number;
  /** Maximum gas per call (default: 30_000_000). */
  maxGasPerCall?: number;
  /** Maximum number of log entries captured (default: 1000). */
  maxLogs?: number;
}

/** Resolved resource limits with all defaults applied. */
export interface ResolvedResourceLimits {
  timeoutMs: number;
  maxMemoryBytes: number;
  maxCalls: number;
  maxGasPerCall: number;
  maxLogs: number;
}

export const DEFAULT_RESOURCE_LIMITS: ResolvedResourceLimits = {
  timeoutMs: 30_000,
  maxMemoryBytes: 512 * 1024 * 1024,
  maxCalls: 100,
  maxGasPerCall: 30_000_000,
  maxLogs: 1_000,
};

// ─── Execution trace / results ────────────────────────────────────────────────

/** A single emitted log entry from an EVM call. */
export interface LogEntry {
  /** Emitting contract address. */
  address: string;
  /** Log topics (0x-prefixed 32-byte hex strings). */
  topics: string[];
  /** ABI-decoded event name, if available. */
  eventName?: string;
  /** Log data (0x-prefixed hex). */
  data: string;
}

/** Storage diff for a single contract from a single call. */
export interface StorageDiff {
  /** Contract address. */
  address: string;
  /** Map from slot (0x-prefixed 32-byte hex) to { before, after } values. */
  slots: Record<string, { before: string; after: string }>;
}

/** Result of executing a single {@link CallSpec}. */
export interface CallResult {
  /** Zero-based index into the scenario's calls array. */
  callIndex: number;
  /** Whether the call reverted. */
  reverted: boolean;
  /** Revert reason (ABI-decoded if possible, raw hex otherwise). */
  revertReason?: string;
  /** Return data (0x-prefixed hex). */
  returnData?: string;
  /** Gas used by this call. */
  gasUsed: number;
  /** Emitted logs. */
  logs: LogEntry[];
  /** Storage changes. */
  storageDiff: StorageDiff[];
  /** Call trace in a human-readable format (optional, adapter-dependent). */
  callTrace?: string;
}

/** Outcome of a storage assertion check. */
export interface StorageAssertionResult {
  assertion: StorageAssertion;
  actual: string;
  passed: boolean;
}

/** Outcome of a balance assertion check. */
export interface BalanceAssertionResult {
  assertion: BalanceAssertion;
  actual: string;
  passed: boolean;
}

/** Outcome of an event assertion check. */
export interface EventAssertionResult {
  assertion: EventAssertion;
  found: boolean;
  passed: boolean;
}

/**
 * The complete result of executing a {@link ValidationScenario}.
 *
 * Portable and serializable. Contains enough information to replay or
 * minimize the scenario offline without a live network.
 */
export interface ValidationResult {
  /** Schema version for compatibility checks. */
  schemaVersion: string;
  /** The scenario that was executed (without private keys or fork URLs). */
  scenario: ValidationScenario;
  /** Which adapter backend was used. */
  adapterType: AdapterType;
  /** Adapter version string (e.g. "anvil/0.2.0"). */
  adapterVersion: string;
  /**
   * The EVM snapshot ID recorded before the first call.
   * Used by replay and minimize operations.
   */
  snapshotId: string;
  /** Block number at which the snapshot was taken. */
  snapshotBlock: number;
  /** Results for each call in execution order. */
  callResults: CallResult[];
  /**
   * Whether the scenario's `expectedOutcome` was met.
   */
  outcomeMatched: boolean;
  /**
   * Detailed outcome description (what actually happened vs. what was expected).
   */
  outcomeSummary: string;
  /** Storage assertion results. */
  storageAssertionResults: StorageAssertionResult[];
  /** Balance assertion results. */
  balanceAssertionResults: BalanceAssertionResult[];
  /** Event assertion results. */
  eventAssertionResults: EventAssertionResult[];
  /** Total gas used across all calls. */
  totalGasUsed: number;
  /** ISO-8601 timestamp when the run started. */
  startedAt: string;
  /** ISO-8601 timestamp when the run completed. */
  completedAt: string;
  /** Wall-clock duration in milliseconds. */
  durationMs: number;
  /**
   * Any non-fatal warnings generated during the run
   * (e.g. fork block older than 256 blocks, unresolved ABI).
   */
  warnings: string[];
  /**
   * Error message if the run failed due to an infrastructure error
   * (adapter crash, timeout, OOM) rather than a revert.
   */
  error?: string;
}

// ─── Adapter types ────────────────────────────────────────────────────────────

/** Which EVM backend this adapter wraps. */
export type AdapterType = "anvil" | "hardhat";

/** Options for constructing an EVM adapter. */
export interface AdapterOptions {
  type: AdapterType;
  /** Explicit binary path. Defaults to searching $PATH. */
  binaryPath?: string;
  /** Override adapter-level resource limits (merged with per-scenario limits). */
  limits?: Partial<ScenarioResourceLimits>;
  /** JSON-RPC port to bind (0 = random ephemeral). */
  port?: number;
  /**
   * Verbosity level for the adapter process.
   * 0 = silent, 1 = errors only, 2 = full (useful for debugging).
   */
  verbosity?: 0 | 1 | 2;
}

// ─── Snapshot / replay ────────────────────────────────────────────────────────

/**
 * A named snapshot that can be restored to replay a scenario from
 * a deterministic starting state.
 */
export interface SnapshotEntry {
  /** Unique snapshot identifier (adapter-assigned). */
  snapshotId: string;
  /** Scenario ID this snapshot belongs to. */
  scenarioId: string;
  /** Block number at snapshot. */
  blockNumber: number;
  /** ISO-8601 when the snapshot was taken. */
  takenAt: string;
}

// ─── Minimizer ────────────────────────────────────────────────────────────────

/**
 * The result of the scenario minimizer.
 *
 * The minimizer attempts to remove calls that are not needed to reproduce
 * the finding, without changing the outcome.
 */
export interface MinimizationResult {
  /** Original number of calls. */
  originalCallCount: number;
  /** Minimized scenario with redundant calls removed. */
  minimizedScenario: ValidationScenario;
  /** Minimized number of calls. */
  minimizedCallCount: number;
  /** Indices of calls that were removed. */
  removedCallIndices: number[];
  /** Number of EVM executions used during minimization. */
  trialsUsed: number;
  /** Whether minimization completed within its trial budget. */
  budgetExceeded: boolean;
}

// ─── Plan output ─────────────────────────────────────────────────────────────

/** The result of `chainproof validate plan`. */
export interface ValidationPlan {
  /** Schema version. */
  schemaVersion: string;
  /** Scenarios generated from the provided findings. */
  scenarios: ValidationScenario[];
  /**
   * Findings that could not be translated to a scenario
   * (unsupported rule, missing bytecode, etc.).
   */
  unsupportedFindings: UnsupportedFinding[];
  /** ISO-8601 creation timestamp. */
  createdAt: string;
}

/** A finding that the scaffold translator could not handle. */
export interface UnsupportedFinding {
  findingId: string;
  findingFile: string;
  findingLine: number;
  reason: string;
}

// ─── Report ───────────────────────────────────────────────────────────────────

/** Aggregate validation report covering multiple scenario results. */
export interface ValidationReport {
  /** Schema version. */
  schemaVersion: string;
  /** ISO-8601 timestamp. */
  timestamp: string;
  /** Total number of scenarios executed. */
  total: number;
  /** Scenarios where `outcomeMatched` is true. */
  passed: number;
  /** Scenarios where `outcomeMatched` is false. */
  failed: number;
  /** Scenarios that errored due to infrastructure failures. */
  errored: number;
  /** Individual results. */
  results: ValidationResult[];
  /** Adapter type used. */
  adapterType: AdapterType;
  /** Total wall-clock time in milliseconds. */
  totalDurationMs: number;
}

// ─── Errors ───────────────────────────────────────────────────────────────────

/** Base class for all validation-subsystem errors. */
export class ValidationError extends Error {
  constructor(
    message: string,
    /** Machine-readable error code. */
    public readonly code: ValidationErrorCode,
    /** Optional additional context (sanitized, no secrets). */
    public readonly context?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

/** Thrown when a scenario exceeds its configured resource limits. */
export class ValidationTimeoutError extends ValidationError {
  constructor(scenarioId: string, limitMs: number) {
    super(
      `Scenario "${scenarioId}" exceeded time limit of ${limitMs}ms`,
      "TIMEOUT",
      { scenarioId, limitMs },
    );
    this.name = "ValidationTimeoutError";
  }
}

/** Thrown when the EVM adapter process crashes or becomes unreachable. */
export class AdapterCrashError extends ValidationError {
  constructor(adapterType: AdapterType, detail: string) {
    super(
      `EVM adapter "${adapterType}" crashed or became unreachable: ${sanitizeErrorMessage(detail)}`,
      "ADAPTER_CRASH",
      { adapterType },
    );
    this.name = "AdapterCrashError";
  }
}

/** Thrown when the fork RPC is unavailable or returns an unexpected response. */
export class ForkUnavailableError extends ValidationError {
  constructor(detail: string) {
    super(
      `Fork RPC unavailable: ${sanitizeErrorMessage(detail)}`,
      "FORK_UNAVAILABLE",
    );
    this.name = "ForkUnavailableError";
  }
}

/** Thrown when a validation bundle file is corrupt or has an unsupported version. */
export class CorruptBundleError extends ValidationError {
  constructor(filePath: string, detail: string) {
    super(
      `Validation bundle at "${sanitizePath(filePath)}" is corrupt or unsupported: ${sanitizeErrorMessage(detail)}`,
      "CORRUPT_BUNDLE",
    );
    this.name = "CorruptBundleError";
  }
}

/** Thrown when a scenario fails schema validation. */
export class ScenarioValidationError extends ValidationError {
  constructor(detail: string) {
    super(`Scenario validation failed: ${detail}`, "SCENARIO_INVALID");
    this.name = "ScenarioValidationError";
  }
}

export type ValidationErrorCode =
  | "TIMEOUT"
  | "ADAPTER_CRASH"
  | "FORK_UNAVAILABLE"
  | "CORRUPT_BUNDLE"
  | "SCENARIO_INVALID"
  | "UNSUPPORTED_FINDING"
  | "ADAPTER_NOT_FOUND"
  | "RPC_ERROR"
  | "RESOURCE_EXCEEDED"
  | "SNAPSHOT_NOT_FOUND"
  | "DEPLOY_FAILED";

// ─── Cancellation ────────────────────────────────────────────────────────────

/** A cooperative cancellation signal for long-running validation runs. */
export interface ValidationCancellationSignal {
  /** Whether cancellation has been requested. */
  readonly cancelled: boolean;
  /** Callback called when cancellation is requested. */
  onCancelled(callback: () => void): void;
}

/** Creates a cancellation signal/controller pair. */
export function createCancellationSignal(): {
  signal: ValidationCancellationSignal;
  cancel: () => void;
} {
  let cancelled = false;
  const callbacks: Array<() => void> = [];
  const signal: ValidationCancellationSignal = {
    get cancelled() {
      return cancelled;
    },
    onCancelled(cb) {
      if (cancelled) {
        cb();
      } else {
        callbacks.push(cb);
      }
    },
  };
  return {
    signal,
    cancel() {
      if (cancelled) return;
      cancelled = true;
      for (const cb of callbacks) {
        try {
          cb();
        } catch {
          // ignore
        }
      }
    },
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Sanitize an error message to remove potential sensitive information
 * (file paths, hostnames, API keys) before persisting in bundles or logs.
 * @internal
 */
export function sanitizeErrorMessage(message: string): string {
  return message
    .replace(/https?:\/\/[^\s"']*/gi, "[redacted-url]")
    .replace(/\/[^\s"']+/g, "[redacted-path]")
    .replace(/0x[0-9a-f]{40,}/gi, "[redacted-hex]")
    .slice(0, 500);
}

/**
 * Sanitize a file path for inclusion in error messages.
 * @internal
 */
export function sanitizePath(filePath: string): string {
  // Only show the basename to avoid leaking directory structure
  return filePath.replace(/.*[\\/]/, "");
}

/**
 * Resolve scenario resource limits, merging scenario-level overrides
 * with global defaults.
 * @internal
 */
export function resolveResourceLimits(
  scenario: Partial<ScenarioResourceLimits>,
  adapter: Partial<ScenarioResourceLimits> = {},
): ResolvedResourceLimits {
  return {
    timeoutMs: scenario.timeoutMs ?? adapter.timeoutMs ?? DEFAULT_RESOURCE_LIMITS.timeoutMs,
    maxMemoryBytes: scenario.maxMemoryBytes ?? adapter.maxMemoryBytes ?? DEFAULT_RESOURCE_LIMITS.maxMemoryBytes,
    maxCalls: scenario.maxCalls ?? adapter.maxCalls ?? DEFAULT_RESOURCE_LIMITS.maxCalls,
    maxGasPerCall: scenario.maxGasPerCall ?? adapter.maxGasPerCall ?? DEFAULT_RESOURCE_LIMITS.maxGasPerCall,
    maxLogs: scenario.maxLogs ?? adapter.maxLogs ?? DEFAULT_RESOURCE_LIMITS.maxLogs,
  };
}
