/**
 * @packageDocumentation
 * Fork-aware concrete validation and exploit reproduction harness.
 *
 * This module bridges ChainProof's static analysis pipeline to concrete EVM
 * execution experiments. It translates static {@link Finding} objects into
 * parameterized {@link ValidationScenario} scaffolds, executes them against
 * process-isolated EVM backends (Anvil, Hardhat Network), and produces
 * portable {@link ValidationReport} bundles.
 *
 * @remarks
 * **Security assumptions:**
 * - Adapter processes are spawned with standard OS resource limits; they do
 *   NOT have network access restrictions. Use a network namespace / sandbox
 *   when running against untrusted scenarios in CI.
 * - Fork URLs are never serialized into bundles; they must be re-supplied at
 *   replay time.
 * - Scenario bytecode is embedded verbatim; review before execution.
 *
 * @example
 * ```typescript
 * import { planValidation, runValidationPlan, generateValidationMarkdown } from '@chainproof/core';
 *
 * const plan = planValidation(findings);
 * const report = await runValidationPlan(plan.scenarios, { adapterType: 'anvil' });
 * console.log(generateValidationMarkdown(report));
 * ```
 */

// ─── Types ────────────────────────────────────────────────────────────────────
export type {
  AccountSpec,
  AdapterOptions,
  AdapterType,
  BalanceAssertion,
  BalanceAssertionResult,
  CallResult,
  CallSpec,
  ChainContext,
  ContractSpec,
  EventAssertion,
  EventAssertionResult,
  LogEntry,
  MinimizationResult,
  ResolvedResourceLimits,
  ScenarioResourceLimits,
  SnapshotEntry,
  StorageAssertion,
  StorageAssertionResult,
  StorageDiff,
  UnsupportedFinding,
  ValidationCancellationSignal,
  ValidationPlan,
  ValidationReport,
  ValidationResult,
  ValidationScenario,
} from "./types";

export {
  DEFAULT_RESOURCE_LIMITS,
  VALIDATION_SCHEMA_VERSION,
  ValidationError,
  ValidationTimeoutError,
  AdapterCrashError,
  ForkUnavailableError,
  CorruptBundleError,
  ScenarioValidationError,
  createCancellationSignal,
  resolveResourceLimits,
  sanitizeErrorMessage,
} from "./types";

// ─── Adapter ──────────────────────────────────────────────────────────────────
export type { EvmAdapter } from "./adapter";
export {
  jsonRpcCall,
  waitForRpc,
  encodeFunctionCall,
  keccak256Selector,
  keccak256Pure,
  decodeLogEntries,
  hexToDecimalString,
  normalizeHex,
} from "./adapter";

// ─── Anvil adapter ────────────────────────────────────────────────────────────
export { AnvilAdapter, isAnvilAvailable } from "./anvil-adapter";

// ─── Hardhat adapter ──────────────────────────────────────────────────────────
export { HardhatAdapter, isHardhatAvailable } from "./hardhat-adapter";

// ─── Scaffold / planning ──────────────────────────────────────────────────────
export {
  planValidation,
  serializeValidationPlan,
  parseValidationPlan,
} from "./scaffold";
export type { PlanValidationOptions } from "./scaffold";

// ─── Runner ───────────────────────────────────────────────────────────────────
export {
  ValidationRunner,
  minimizeScenario,
  runValidationPlan,
  sanitizeScenario,
} from "./runner";
export type { RunnerOptions, MinimizerOptions, RunValidationOptions } from "./runner";

// ─── Reports ─────────────────────────────────────────────────────────────────
export {
  serializeValidationReport,
  serializeValidationResult,
  generateValidationMarkdown,
  generateValidationResultMarkdown,
  parseValidationReport,
} from "./report";
