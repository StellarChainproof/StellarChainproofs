/**
 * Validation Runner.
 *
 * Orchestrates the execution of {@link ValidationScenario} objects against an
 * {@link EvmAdapter}. Handles:
 * - Account setup and contract deployment
 * - Ordered call execution with cancellation support
 * - Snapshot/restore for deterministic replay
 * - Assertion evaluation (storage, balance, events)
 * - Resource limit enforcement
 * - Error isolation (infrastructure failures vs. revert-as-expected)
 */

import type { EvmAdapter } from "./adapter";
import type {
  AccountSpec,
  BalanceAssertionResult,
  CallResult,
  ContractSpec,
  EventAssertionResult,
  LogEntry,
  ResolvedResourceLimits,
  ScenarioResourceLimits,
  StorageAssertionResult,
  ValidationCancellationSignal,
  ValidationResult,
  ValidationScenario,
} from "./types";
import {
  VALIDATION_SCHEMA_VERSION,
  ValidationError,
  ValidationTimeoutError,
  resolveResourceLimits,
  sanitizeErrorMessage,
} from "./types";
import { normalizeHex, keccak256Pure } from "./adapter";

// ─── Runner options ───────────────────────────────────────────────────────────

export interface RunnerOptions {
  /** Global resource limit overrides (per-scenario limits take precedence). */
  limits?: Partial<ScenarioResourceLimits>;
  /** Cancellation signal. */
  signal?: ValidationCancellationSignal;
}

// ─── ValidationRunner ─────────────────────────────────────────────────────────

/**
 * Executes a single {@link ValidationScenario} against an {@link EvmAdapter}.
 *
 * The adapter must already be started before calling `run()`.
 */
export class ValidationRunner {
  constructor(
    private readonly adapter: EvmAdapter,
    private readonly opts: RunnerOptions = {},
  ) {}

  /**
   * Execute a scenario and return a portable {@link ValidationResult}.
   *
   * The adapter state after the run is the state at the end of the scenario
   * (not reverted). The snapshot taken before call[0] can be replayed with
   * `replay()`.
   */
  async run(scenario: ValidationScenario): Promise<ValidationResult> {
    const startedAt = new Date().toISOString();
    const startMs = Date.now();
    const warnings: string[] = [];

    const limits = resolveResourceLimits(
      scenario.limits ?? {},
      this.opts.limits ?? {},
    );

    // Enforce call count
    if (scenario.calls.length > limits.maxCalls) {
      throw new ValidationError(
        `Scenario "${scenario.id}" has ${scenario.calls.length} calls, ` +
          `which exceeds the limit of ${limits.maxCalls}`,
        "RESOURCE_EXCEEDED",
      );
    }

    let snapshotId = "";
    let snapshotBlock = 0;
    const callResults: CallResult[] = [];
    let error: string | undefined;
    const resolvedAddresses = new Map<string, string>();

    try {
      // 1. Setup accounts
      for (const account of scenario.accounts) {
        this.#checkCancelled(limits);
        await this.adapter.setupAccount(account);
        if (account.label) {
          resolvedAddresses.set(account.label, account.address);
        }
        resolvedAddresses.set(account.address, account.address);
      }

      // 2. Deploy contracts (in order; later specs may reference earlier ones)
      for (const contractSpec of scenario.contracts) {
        this.#checkCancelled(limits);
        const deployedAddress = await this.#deployOrAlias(
          contractSpec,
          resolvedAddresses,
          scenario.accounts,
        );
        resolvedAddresses.set(contractSpec.name, deployedAddress);
        // Apply storage overrides after deployment
        if (contractSpec.storageOverrides) {
          for (const [slot, value] of Object.entries(contractSpec.storageOverrides)) {
            await this.adapter.setStorageAt(deployedAddress, slot, value);
          }
        }
      }

      // 3. Take snapshot before first call
      snapshotBlock = await this.adapter.getBlockNumber();
      snapshotId = await this.adapter.snapshot();

      // 4. Execute calls in order
      for (let i = 0; i < scenario.calls.length; i++) {
        this.#checkCancelled(limits);
        this.#checkTimeout(startMs, limits, scenario.id);

        const callSpec = scenario.calls[i];
        const result = await this.adapter.executeCall(
          callSpec,
          resolvedAddresses,
          limits,
          this.opts.signal,
        );
        result.callIndex = i;

        // Validate expectRevert
        if (callSpec.expectRevert === true && !result.reverted) {
          warnings.push(
            `Call[${i}] "${callSpec.description ?? callSpec.signature ?? "unknown"}" ` +
              `was expected to revert but did not`,
          );
        }
        if (callSpec.expectRevert === false && result.reverted) {
          warnings.push(
            `Call[${i}] "${callSpec.description ?? callSpec.signature ?? "unknown"}" ` +
              `reverted unexpectedly: ${result.revertReason ?? "unknown reason"}`,
          );
        }

        callResults.push(result);
      }
    } catch (err) {
      if (err instanceof ValidationError) {
        error = sanitizeErrorMessage(err.message);
      } else if (err instanceof Error) {
        error = sanitizeErrorMessage(err.message);
      } else {
        error = "Unknown error during validation run";
      }
    }

    // 5. Evaluate assertions
    const storageAssertionResults = await this.#evaluateStorageAssertions(
      scenario,
      resolvedAddresses,
      warnings,
    );
    const balanceAssertionResults = await this.#evaluateBalanceAssertions(
      scenario,
      resolvedAddresses,
      warnings,
    );
    const eventAssertionResults = this.#evaluateEventAssertions(
      scenario,
      callResults,
      warnings,
    );

    // 6. Determine outcome
    const { outcomeMatched, outcomeSummary } = this.#determineOutcome(
      scenario,
      callResults,
      storageAssertionResults,
      balanceAssertionResults,
      eventAssertionResults,
      error,
    );

    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startMs;
    const totalGasUsed = callResults.reduce((sum, r) => sum + r.gasUsed, 0);

    // Strip private keys and fork URLs from the scenario before persisting
    const sanitizedScenario = sanitizeScenario(scenario);

    return {
      schemaVersion: VALIDATION_SCHEMA_VERSION,
      scenario: sanitizedScenario,
      adapterType: this.adapter.type,
      adapterVersion: this.adapter.version,
      snapshotId,
      snapshotBlock,
      callResults,
      outcomeMatched,
      outcomeSummary,
      storageAssertionResults,
      balanceAssertionResults,
      eventAssertionResults,
      totalGasUsed,
      startedAt,
      completedAt,
      durationMs,
      warnings,
      error,
    };
  }

  /**
   * Replay a scenario from a previously taken snapshot.
   *
   * The adapter must still be running and the snapshotId must be valid.
   */
  async replay(
    snapshotId: string,
    scenario: ValidationScenario,
  ): Promise<ValidationResult> {
    // Restore to the snapshot (note: evm_revert consumes the snapshot in most implementations)
    await this.adapter.revertToSnapshot(snapshotId);
    // Re-snapshot so we can replay again
    const newSnapshotId = await this.adapter.snapshot();
    // Run with the new snapshot
    const result = await this.run(scenario);
    return { ...result, snapshotId: newSnapshotId };
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  async #deployOrAlias(
    spec: ContractSpec,
    resolvedAddresses: Map<string, string>,
    accounts: AccountSpec[],
  ): Promise<string> {
    if (spec.address) {
      // Alias to existing address (fork mode)
      return spec.address;
    }
    if (!spec.bytecode || spec.bytecode === "0x") {
      // Scaffold placeholder — cannot actually deploy
      return "0x0000000000000000000000000000000000000001";
    }

    // Determine deployer address
    let deployerAddress: string;
    if (spec.deployer) {
      const found = resolvedAddresses.get(spec.deployer);
      if (found) {
        deployerAddress = found;
      } else {
        // Try to match as an address
        deployerAddress = spec.deployer;
      }
    } else {
      // Default to first account
      deployerAddress = accounts[0]?.address ?? "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    }

    return this.adapter.deployContract(spec, deployerAddress);
  }

  async #evaluateStorageAssertions(
    scenario: ValidationScenario,
    resolvedAddresses: Map<string, string>,
    warnings: string[],
  ): Promise<StorageAssertionResult[]> {
    if (!scenario.storageAssertions?.length) return [];
    const results: StorageAssertionResult[] = [];
    for (const assertion of scenario.storageAssertions) {
      try {
        const contractAddress = resolvedAddresses.get(assertion.contract) ?? assertion.contract;
        const actual = await this.adapter.getStorageAt(contractAddress, assertion.slot);
        const expected = normalizeHex(assertion.expected);
        results.push({ assertion, actual, passed: actual === expected });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Storage assertion failed to evaluate: ${sanitizeErrorMessage(msg)}`);
        results.push({ assertion, actual: "0x0", passed: false });
      }
    }
    return results;
  }

  async #evaluateBalanceAssertions(
    scenario: ValidationScenario,
    resolvedAddresses: Map<string, string>,
    warnings: string[],
  ): Promise<BalanceAssertionResult[]> {
    if (!scenario.balanceAssertions?.length) return [];
    const results: BalanceAssertionResult[] = [];
    for (const assertion of scenario.balanceAssertions) {
      try {
        const address = resolvedAddresses.get(assertion.account) ?? assertion.account;
        const actual = await this.adapter.getBalance(address);
        const actualBig = BigInt(actual);
        const expectedBig = BigInt(assertion.value);
        let passed: boolean;
        switch (assertion.op) {
          case "eq": passed = actualBig === expectedBig; break;
          case "gt": passed = actualBig > expectedBig; break;
          case "gte": passed = actualBig >= expectedBig; break;
          case "lt": passed = actualBig < expectedBig; break;
          case "lte": passed = actualBig <= expectedBig; break;
          default: passed = false;
        }
        results.push({ assertion, actual, passed });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Balance assertion failed to evaluate: ${sanitizeErrorMessage(msg)}`);
        results.push({ assertion, actual: "0", passed: false });
      }
    }
    return results;
  }

  #evaluateEventAssertions(
    scenario: ValidationScenario,
    callResults: CallResult[],
    warnings: string[],
  ): EventAssertionResult[] {
    if (!scenario.eventAssertions?.length) return [];
    // Flatten all logs from all call results
    const allLogs: LogEntry[] = callResults.flatMap((r) => r.logs);
    return scenario.eventAssertions.map((assertion) => {
      // Compute topic0 from eventSignature using keccak256
      try {
        const topic0 = "0x" + keccak256Pure(Buffer.from(assertion.eventSignature, "utf8"));
        const found = allLogs.some(
          (log) =>
            log.address.toLowerCase() ===
              (assertion.contract.startsWith("0x")
                ? assertion.contract.toLowerCase()
                : assertion.contract.toLowerCase()) &&
            log.topics[0]?.toLowerCase() === topic0.toLowerCase(),
        );
        const passed = assertion.negate ? !found : found;
        return { assertion, found, passed };
      } catch {
        warnings.push(`Event assertion for ${assertion.eventSignature} could not be evaluated`);
        return { assertion, found: false, passed: false };
      }
    });
  }

  #determineOutcome(
    scenario: ValidationScenario,
    callResults: CallResult[],
    storageResults: StorageAssertionResult[],
    balanceResults: BalanceAssertionResult[],
    eventResults: EventAssertionResult[],
    error: string | undefined,
  ): { outcomeMatched: boolean; outcomeSummary: string } {
    if (error) {
      return {
        outcomeMatched: false,
        outcomeSummary: `Infrastructure error: ${error}`,
      };
    }

    const anyCallReverted = callResults.some((r) => r.reverted);
    const allAssertionsPassed =
      storageResults.every((r) => r.passed) &&
      balanceResults.every((r) => r.passed) &&
      eventResults.every((r) => r.passed);

    switch (scenario.expectedOutcome) {
      case "exploit-succeeds": {
        const matched = !anyCallReverted && allAssertionsPassed;
        return {
          outcomeMatched: matched,
          outcomeSummary: matched
            ? "Exploit scenario completed without reverts and all assertions passed"
            : anyCallReverted
              ? `Exploit scenario had an unexpected revert (call[${callResults.findIndex((r) => r.reverted)}])`
              : "One or more assertions failed",
        };
      }
      case "exploit-reverts": {
        const matched = anyCallReverted;
        return {
          outcomeMatched: matched,
          outcomeSummary: matched
            ? "Exploit scenario reverted as expected (defensive mechanism present)"
            : "Exploit scenario did not revert — potential vulnerability confirmed",
        };
      }
      case "secure-baseline": {
        const matched = !anyCallReverted && allAssertionsPassed;
        return {
          outcomeMatched: matched,
          outcomeSummary: matched
            ? "Secure baseline executed cleanly"
            : "Secure baseline had unexpected behavior",
        };
      }
      case "custom": {
        return {
          outcomeMatched: allAssertionsPassed && !anyCallReverted,
          outcomeSummary: scenario.outcomeDescription ?? "Custom outcome — check assertions",
        };
      }
    }
  }

  #checkCancelled(_limits: ResolvedResourceLimits): void {
    if (this.opts.signal?.cancelled) {
      throw new ValidationError("Validation cancelled by signal", "TIMEOUT");
    }
  }

  #checkTimeout(startMs: number, limits: ResolvedResourceLimits, scenarioId: string): void {
    if (Date.now() - startMs > limits.timeoutMs) {
      throw new ValidationTimeoutError(scenarioId, limits.timeoutMs);
    }
  }
}

// ─── Minimizer ────────────────────────────────────────────────────────────────

import type { MinimizationResult } from "./types";

export interface MinimizerOptions {
  /** Maximum number of scenario re-executions (default: 50). */
  maxTrials?: number;
  /** Resource limits for each trial execution. */
  limits?: Partial<ScenarioResourceLimits>;
  signal?: ValidationCancellationSignal;
}

/**
 * Attempt to remove redundant calls from a scenario while preserving the outcome.
 *
 * Uses a greedy backward-elimination strategy: try removing each call from the
 * end of the list first (since setup calls at the start are usually necessary).
 */
export async function minimizeScenario(
  scenario: ValidationScenario,
  adapter: EvmAdapter,
  opts: MinimizerOptions = {},
): Promise<MinimizationResult> {
  const maxTrials = opts.maxTrials ?? 50;
  let trialsUsed = 0;
  let budgetExceeded = false;
  const removedIndices: number[] = [];
  let current = { ...scenario, calls: [...scenario.calls] };
  const runner = new ValidationRunner(adapter, {
    limits: opts.limits,
    signal: opts.signal,
  });

  // First establish baseline outcome
  const baseline = await runner.run(current);
  trialsUsed++;

  if (!baseline.outcomeMatched) {
    // Can't minimize if baseline doesn't match outcome
    return {
      originalCallCount: scenario.calls.length,
      minimizedScenario: scenario,
      minimizedCallCount: scenario.calls.length,
      removedCallIndices: [],
      trialsUsed,
      budgetExceeded: false,
    };
  }

  // Try removing each call (backward iteration for greedy)
  for (let i = current.calls.length - 1; i >= 0; i--) {
    if (opts.signal?.cancelled) break;
    if (trialsUsed >= maxTrials) {
      budgetExceeded = true;
      break;
    }

    const candidate = {
      ...current,
      calls: current.calls.filter((_, idx) => idx !== i),
    };

    if (candidate.calls.length === 0) continue;

    try {
      const result = await runner.run(candidate);
      trialsUsed++;
      if (result.outcomeMatched) {
        // Removal preserved outcome — keep it
        removedIndices.push(i);
        current = candidate;
        // Adjust indices for next iteration
        i = Math.min(i, current.calls.length - 1) + 1;
      }
    } catch {
      trialsUsed++;
      // Assume this removal broke something
    }
  }

  return {
    originalCallCount: scenario.calls.length,
    minimizedScenario: current,
    minimizedCallCount: current.calls.length,
    removedCallIndices: removedIndices.sort((a, b) => a - b),
    trialsUsed,
    budgetExceeded,
  };
}

// ─── Sanitize scenario (strip secrets before persisting) ─────────────────────

/**
 * Return a copy of the scenario with private keys and fork URLs removed.
 * @internal
 */
export function sanitizeScenario(scenario: ValidationScenario): ValidationScenario {
  return {
    ...scenario,
    chain: {
      ...scenario.chain,
      forkUrl: scenario.chain.forkUrl ? "[redacted]" : undefined,
    },
    accounts: scenario.accounts.map((a) => ({
      ...a,
      privateKey: undefined,
    })),
  };
}

// ─── Batch runner ─────────────────────────────────────────────────────────────

import type { ValidationReport } from "./types";
import { AnvilAdapter } from "./anvil-adapter";
import { HardhatAdapter } from "./hardhat-adapter";

export interface RunValidationOptions {
  adapterType?: "anvil" | "hardhat";
  adapterBinaryPath?: string;
  limits?: Partial<ScenarioResourceLimits>;
  signal?: ValidationCancellationSignal;
  forkUrl?: string;
  forkBlockNumber?: number;
  chainId?: number;
  verbosity?: 0 | 1 | 2;
}

/**
 * Run all scenarios in a plan and return a {@link ValidationReport}.
 *
 * Creates and manages the adapter lifecycle automatically.
 */
export async function runValidationPlan(
  scenarios: ValidationScenario[],
  opts: RunValidationOptions = {},
): Promise<ValidationReport> {
  const startMs = Date.now();
  const adapterType = opts.adapterType ?? "anvil";

  // Build adapter for each scenario independently (process isolation)
  const results: ValidationResult[] = [];

  for (const scenario of scenarios) {
    if (opts.signal?.cancelled) break;

    let adapter: EvmAdapter;
    if (adapterType === "hardhat") {
      adapter = new HardhatAdapter({
        binaryPath: opts.adapterBinaryPath,
        limits: opts.limits,
        forkUrl: opts.forkUrl ?? scenario.chain.forkUrl,
        forkBlockNumber: opts.forkBlockNumber ?? scenario.chain.forkBlockNumber,
        chainId: opts.chainId ?? scenario.chain.chainId,
        verbosity: opts.verbosity ?? 0,
      });
    } else {
      adapter = new AnvilAdapter({
        binaryPath: opts.adapterBinaryPath,
        limits: opts.limits,
        forkUrl: opts.forkUrl ?? scenario.chain.forkUrl,
        forkBlockNumber: opts.forkBlockNumber ?? scenario.chain.forkBlockNumber,
        chainId: opts.chainId ?? scenario.chain.chainId,
        verbosity: opts.verbosity ?? 0,
      });
    }

    try {
      await adapter.start(opts.limits);
      const runner = new ValidationRunner(adapter, {
        limits: opts.limits,
        signal: opts.signal,
      });
      const result = await runner.run(scenario);
      results.push(result);
    } catch (err) {
      // Infrastructure failure — record as errored
      const errMsg =
        err instanceof Error
          ? sanitizeErrorMessage(err.message)
          : "Unknown infrastructure error";
      results.push({
        schemaVersion: VALIDATION_SCHEMA_VERSION,
        scenario: sanitizeScenario(scenario),
        adapterType,
        adapterVersion: "unknown",
        snapshotId: "",
        snapshotBlock: 0,
        callResults: [],
        outcomeMatched: false,
        outcomeSummary: `Infrastructure error: ${errMsg}`,
        storageAssertionResults: [],
        balanceAssertionResults: [],
        eventAssertionResults: [],
        totalGasUsed: 0,
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 0,
        warnings: [],
        error: errMsg,
      });
    } finally {
      await adapter.dispose().catch(() => {/* ignore */});
    }
  }

  const passed = results.filter((r) => r.outcomeMatched && !r.error).length;
  const errored = results.filter((r) => !!r.error).length;
  const failed = results.length - passed - errored;

  return {
    schemaVersion: VALIDATION_SCHEMA_VERSION,
    timestamp: new Date().toISOString(),
    total: results.length,
    passed,
    failed,
    errored,
    results,
    adapterType,
    totalDurationMs: Date.now() - startMs,
  };
}
