# ChainProof Concrete Validation Guide

Fork-aware concrete validation and exploit reproduction harness for ChainProof.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Threat Model](#threat-model)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [Validation Scenarios](#validation-scenarios)
- [EVM Adapters](#evm-adapters)
- [Report Format](#report-format)
- [Security Boundaries](#security-boundaries)
- [Limitations](#limitations)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Compatibility](#compatibility)
- [Migration](#migration)

---

## Overview

ChainProof's static analysis pipeline produces `Finding` objects with severity, file, and line information. The validation engine bridges the gap between a static finding and concrete EVM execution:

1. **Plan** — translate static findings into parameterized `ValidationScenario` scaffolds
2. **Run** — execute scenarios against a process-isolated EVM backend (Anvil or Hardhat Network)
3. **Replay** — restore a snapshot and re-execute deterministically
4. **Minimize** — remove redundant calls while preserving the outcome
5. **Report** — produce structured JSON or Markdown output

This is **finding validation**, not coverage correlation or AI-generated testing. The engine does not claim a finding is automatically exploitable — it provides a reproducible scaffold for a researcher to confirm or refute.

---

## Architecture

```
Static Findings (Finding[])
         │
         ▼
    planValidation()         ← scaffold.ts
         │
         ▼
  ValidationScenario[]       ← types.ts
         │
         ▼
 runValidationPlan()         ← runner.ts
    │         │
    ▼         ▼
AnvilAdapter  HardhatAdapter ← anvil-adapter.ts / hardhat-adapter.ts
    │         │
    ▼         ▼
   JSON-RPC (eth_sendTransaction, evm_snapshot, ...)
         │
         ▼
  ValidationResult[]
         │
         ▼
  ValidationReport           ← types.ts
         │
         ▼
  JSON / Markdown             ← report.ts
```

### Key design decisions

- **Process isolation**: each scenario runs in a fresh EVM process that is killed after completion. No state leaks between scenarios.
- **No external dependencies**: the JSON-RPC client is implemented using Node's built-in `http` module. The keccak-256 implementation is pure JavaScript. No ethers.js or web3.js is required.
- **Determinism**: scenarios pin `chainId`, `forkBlockNumber`, and optionally `timestamp`. The same scenario produces byte-identical results on the same adapter version.
- **Bounded execution**: adapters enforce `timeoutMs`, `maxCalls`, and `maxGasPerCall`. Exceeding these limits produces a `ValidationTimeoutError` or `RESOURCE_EXCEEDED` error, never a hang.
- **Portable bundles**: `ValidationResult` and `ValidationReport` contain everything needed to understand the run. Private keys and fork URLs are never serialized.

---

## Threat Model

### Assets

| Asset | Description |
|-------|-------------|
| Fork URL / RPC credentials | Passed transiently to the adapter; never persisted |
| Private keys | Accepted for devnet accounts; never serialized into bundles |
| Local file paths | Scenario sources reference relative paths; sanitized in error messages |
| Deployed bytecode | Embedded verbatim in scenarios; treat as untrusted if sourced externally |

### Adversary capabilities

The threat model considers two adversaries:

1. **Malicious scenario file** — A user is tricked into running a crafted `ValidationScenario` JSON that contains adversarial bytecode or calls targeting the researcher's machine. **Mitigation**: the EVM adapter runs as an isolated child process. Bytecode execution is sandboxed within the EVM. The adapter has no ability to read host files.

2. **Malicious RPC endpoint** — A fork URL resolves to an adversarially-controlled server that returns crafted responses. **Mitigation**: the JSON-RPC client only makes outbound HTTP POST requests. It does not follow redirects. RPC responses are parsed as JSON; no eval or exec paths are taken.

### Assumptions

- The researcher controls the `forkUrl` they supply. ChainProof does not validate or denylist RPC endpoints.
- Adapter binaries (`anvil`, `npx hardhat`) are trusted; they must be sourced from trusted package managers.
- The EVM adapter process runs with the same OS user privileges as the ChainProof process. Scenarios should not be run as root.
- Network isolation (network namespaces, `iptables`) is the responsibility of the CI operator, not ChainProof.

### What is NOT in scope

- Cross-contract reentrancy tracing across separately-deployed protocols
- Symbolic execution or formal verification
- Automated exploitation — scenarios are scaffolds, not exploits
- Live mainnet state beyond the pinned fork block

---

## Quick Start

### 1. Scan and save findings as JSON

```bash
chainproof scan contracts/ --format json --output findings.json
```

### 2. Generate validation scaffolds

```bash
chainproof validate plan findings.json --output validation-plan.json
```

### 3. Run scenarios (requires Anvil or Hardhat Network)

```bash
# With Anvil (Foundry)
chainproof validate run validation-plan.json --adapter anvil --output report.json

# With Hardhat Network
chainproof validate run validation-plan.json --adapter hardhat --output report.json
```

### 4. Format the report

```bash
chainproof validate report report.json --format markdown
```

### 5. Programmatic usage

```typescript
import { scan } from '@chainproof/core';
import {
  planValidation,
  runValidationPlan,
  generateValidationMarkdown,
} from '@chainproof/core';

const scanResult = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false });
const findings = scanResult.files.flatMap(f => f.findings);

const plan = planValidation(findings, { minSeverity: 'high' });
const report = await runValidationPlan(plan.scenarios, { adapterType: 'anvil' });
console.log(generateValidationMarkdown(report));
```

---

## CLI Reference

### `chainproof validate plan <scan-result>`

Translate static findings from a JSON scan result into reproduction scenario scaffolds.

| Option | Default | Description |
|--------|---------|-------------|
| `--output <file>` | stdout | Write the `ValidationPlan` JSON to a file |
| `--min-severity <level>` | `low` | Only scaffold findings at or above this severity |
| `--deduplicate-by-file` | off | Deduplicate by `(id, file, line)` instead of `(id, file)` |
| `--format <format>` | `json` | Output format: `json` or `table` |

**Output**: a `ValidationPlan` JSON object containing `scenarios[]` and `unsupportedFindings[]`.

**Notes**:
- Gas findings are always excluded.
- Findings with unsupported IDs appear in `unsupportedFindings` with an explanation.
- Scenario scaffolds contain placeholder bytecode (`0x`). You must supply real compiled bytecode before running.

---

### `chainproof validate run <plan-or-scenario>`

Execute scenarios against an EVM backend. Accepts a `ValidationPlan` JSON file or a single `ValidationScenario` JSON file.

| Option | Default | Description |
|--------|---------|-------------|
| `--adapter <type>` | auto | `anvil` or `hardhat`; auto-detected if omitted |
| `--adapter-bin <path>` | `$PATH` | Explicit binary path |
| `--fork-url <url>` | scenario chain | Fork RPC URL |
| `--fork-block <number>` | latest | Fork block number |
| `--chain-id <number>` | scenario chain | Chain ID |
| `--timeout <ms>` | `30000` | Per-scenario timeout in milliseconds |
| `--output <file>` | stdout | Write `ValidationReport` JSON to file |
| `--format <format>` | `json` | `json` or `markdown` |
| `--fail-on-failure` | off | Exit 1 if any scenario fails or errors |

**Exit codes**:
- `0` — all scenarios passed (or `--fail-on-failure` not set)
- `1` — one or more scenarios failed/errored (with `--fail-on-failure`)
- `2` — infrastructure error (adapter not found, corrupt plan file)

---

### `chainproof validate replay <result-file>`

Restore state from a previous result and re-run the scenario from scratch.

| Option | Default | Description |
|--------|---------|-------------|
| `--adapter <type>` | from result | `anvil` or `hardhat` |
| `--adapter-bin <path>` | `$PATH` | Explicit binary path |
| `--fork-url <url>` | — | Required if the original scenario used a fork |
| `--output <file>` | stdout | Write the replay result |
| `--format <format>` | `json` | `json` or `markdown` |

**Note**: `forkUrl` is not persisted in results (it is replaced with `[redacted]`). You must re-supply it with `--fork-url` to replay a forked scenario.

---

### `chainproof validate minimize <scenario-file>`

Remove redundant calls from a scenario while preserving the outcome.

| Option | Default | Description |
|--------|---------|-------------|
| `--adapter <type>` | auto | `anvil` or `hardhat` |
| `--adapter-bin <path>` | `$PATH` | Explicit binary path |
| `--fork-url <url>` | scenario | Fork RPC URL |
| `--max-trials <number>` | `50` | Maximum EVM re-executions |
| `--output <file>` | stdout | Write the minimized scenario |

**Algorithm**: greedy backward elimination. Tries removing each call from the end of the list first; keeps the removal if the outcome still matches. Stops when the trial budget is exhausted.

---

### `chainproof validate report <report-file>`

Format a saved `ValidationReport` as Markdown or JSON.

| Option | Default | Description |
|--------|---------|-------------|
| `--format <format>` | `markdown` | `json` or `markdown` |
| `--output <file>` | stdout | Write to file |
| `--fail-on-failure` | off | Exit 1 if any scenario failed |

---

## API Reference

### Types

#### `ValidationScenario`

The core unit of work. Describes the full EVM state needed to reproduce a finding.

```typescript
interface ValidationScenario {
  schemaVersion: string;         // e.g. "1.0.0"
  id: string;                    // e.g. "scenario-CP-107-Vault-withdraw-a1b2c3d4"
  title: string;
  description?: string;
  findingId?: string;            // e.g. "CP-107"
  findingFile?: string;
  findingLine?: number;
  chain: ChainContext;           // chainId, forkUrl, forkBlockNumber, timestamp
  accounts: AccountSpec[];       // funded accounts
  contracts: ContractSpec[];     // contracts to deploy
  calls: CallSpec[];             // ordered transactions
  storageAssertions?: StorageAssertion[];
  balanceAssertions?: BalanceAssertion[];
  eventAssertions?: EventAssertion[];
  expectedOutcome: "exploit-succeeds" | "exploit-reverts" | "secure-baseline" | "custom";
  limits?: ScenarioResourceLimits;
  tags?: string[];
  createdAt?: string;
}
```

#### `ValidationResult`

The complete result of executing one `ValidationScenario`. Safe to serialize.

#### `ValidationReport`

Aggregate report covering multiple results.

### Functions

#### `planValidation(findings, opts?)`

```typescript
function planValidation(findings: Finding[], opts?: PlanValidationOptions): ValidationPlan
```

Translates static findings into scenario scaffolds.

#### `runValidationPlan(scenarios, opts?)`

```typescript
async function runValidationPlan(
  scenarios: ValidationScenario[],
  opts?: RunValidationOptions,
): Promise<ValidationReport>
```

Runs scenarios, managing adapter lifecycle automatically. Each scenario gets a fresh adapter process.

#### `minimizeScenario(scenario, adapter, opts?)`

```typescript
async function minimizeScenario(
  scenario: ValidationScenario,
  adapter: EvmAdapter,
  opts?: MinimizerOptions,
): Promise<MinimizationResult>
```

#### `generateValidationMarkdown(report)`

```typescript
function generateValidationMarkdown(report: ValidationReport): string
```

#### `serializeValidationReport(report)`

```typescript
function serializeValidationReport(report: ValidationReport): string
```

Deterministic JSON serialization.

### Errors

| Class | Code | When thrown |
|-------|------|-------------|
| `ValidationError` | various | Base class |
| `ValidationTimeoutError` | `TIMEOUT` | Scenario exceeded time limit |
| `AdapterCrashError` | `ADAPTER_CRASH` | EVM process crashed |
| `ForkUnavailableError` | `FORK_UNAVAILABLE` | Fork RPC unreachable |
| `CorruptBundleError` | `CORRUPT_BUNDLE` | Invalid/unsupported JSON file |
| `ScenarioValidationError` | `SCENARIO_INVALID` | Schema validation failure |

All errors sanitize their messages to remove file paths, URLs, and long hex strings.

---

## Validation Scenarios

### Scenario schema

```json
{
  "schemaVersion": "1.0.0",
  "id": "scenario-CP-107-Vault-withdraw-a1b2c3d4",
  "title": "Reentrancy scaffold: Vault.sol L42",
  "findingId": "CP-107",
  "findingFile": "contracts/Vault.sol",
  "findingLine": 42,
  "chain": { "chainId": 31337 },
  "accounts": [
    { "address": "0xf39...", "balance": "10000000000000000000", "label": "deployer" },
    { "address": "0x709...", "balance": "10000000000000000000", "label": "attacker" }
  ],
  "contracts": [
    {
      "name": "Vault",
      "bytecode": "0x608060405234801561001...",
      "abi": "[{\"type\":\"function\",\"name\":\"deposit\"...}]",
      "deployer": "deployer"
    },
    {
      "name": "Attacker",
      "bytecode": "0x608060405234801561001...",
      "abi": "[...]",
      "deployer": "attacker"
    }
  ],
  "calls": [
    {
      "to": "Vault",
      "signature": "deposit()",
      "value": "1000000000000000000",
      "from": "deployer",
      "description": "Victim deposits 1 ETH"
    },
    {
      "to": "Attacker",
      "signature": "attack()",
      "from": "attacker",
      "description": "Attacker triggers reentrancy"
    }
  ],
  "balanceAssertions": [
    {
      "account": "Attacker",
      "op": "gt",
      "value": "1000000000000000000",
      "description": "Attacker gained ETH"
    }
  ],
  "expectedOutcome": "exploit-succeeds"
}
```

### Supplying bytecode

Scaffold scenarios contain placeholder bytecode (`0x`). To execute them:

1. Compile the contract with `solc` or Foundry/Hardhat
2. Extract the deployment bytecode from the artifact
3. Replace `"bytecode": "0x"` with the actual bytecode in the scenario JSON

```bash
# Using solc
solc --bin contracts/Vault.sol | grep -A1 "Binary:" | tail -1
```

```bash
# Using Foundry
forge build && cat out/Vault.sol/Vault.json | jq -r '.bytecode.object'
```

### Storage overrides (fork mode)

When using a fork, you can pre-set storage slots to bypass initialization or set up specific state:

```json
{
  "contracts": [
    {
      "name": "Vault",
      "address": "0x1234...existing_vault...",
      "storageOverrides": {
        "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
      }
    }
  ]
}
```

---

## EVM Adapters

### Anvil (Foundry)

Anvil is the preferred adapter. It is faster, supports `debug_traceTransaction` for detailed call traces, and provides `anvil_setStorageAt` for precise state manipulation.

**Install**:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
anvil --version
```

**Fork mode**:
```bash
chainproof validate run plan.json \
  --adapter anvil \
  --fork-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --fork-block 19000000
```

### Hardhat Network

Hardhat Network is available whenever Hardhat is installed. It is slightly slower to start but requires no additional install if the project already uses Hardhat.

**Install**:
```bash
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
```

**Use**:
```bash
chainproof validate run plan.json --adapter hardhat
```

### Adapter availability detection

The CLI auto-detects adapters in order: Anvil first, then Hardhat. To force a specific adapter:

```bash
chainproof validate run plan.json --adapter anvil
chainproof validate run plan.json --adapter hardhat
```

---

## Report Format

### JSON report (`ValidationReport`)

```json
{
  "schemaVersion": "1.0.0",
  "timestamp": "2024-01-15T12:00:00.000Z",
  "total": 3,
  "passed": 2,
  "failed": 1,
  "errored": 0,
  "adapterType": "anvil",
  "totalDurationMs": 45000,
  "results": [
    {
      "schemaVersion": "1.0.0",
      "scenario": { ... },
      "adapterType": "anvil",
      "adapterVersion": "anvil/0.2.0",
      "snapshotId": "snap-1",
      "snapshotBlock": 100,
      "callResults": [
        {
          "callIndex": 0,
          "reverted": false,
          "returnData": "0x",
          "gasUsed": 21000,
          "logs": [],
          "storageDiff": []
        }
      ],
      "outcomeMatched": true,
      "outcomeSummary": "Exploit scenario completed without reverts and all assertions passed",
      "storageAssertionResults": [],
      "balanceAssertionResults": [],
      "eventAssertionResults": [],
      "totalGasUsed": 21000,
      "startedAt": "2024-01-15T12:00:00.000Z",
      "completedAt": "2024-01-15T12:00:15.000Z",
      "durationMs": 15000,
      "warnings": []
    }
  ]
}
```

---

## Security Boundaries

### What is safe to share

- Serialized `ValidationPlan` files (no secrets; bytecode is researcher-supplied)
- Serialized `ValidationReport` files (no secrets; fork URLs are redacted)
- Minimized scenarios

### What is NOT safe to share

- Scenarios with real private keys in `accounts[].privateKey` (use labels instead)
- Fork URLs embedded in scenario `chain.forkUrl` (redacted automatically on serialization)

### Input validation

- Scenario call counts are bounded by `maxCalls` (default: 100)
- Gas per call is bounded by `maxGasPerCall` (default: 30M)
- Log entries captured per call are bounded by `maxLogs` (default: 1,000)
- Total execution time is bounded by `timeoutMs` (default: 30s)

### Process isolation

Each scenario runs in a fresh EVM process. The process is killed (SIGTERM then SIGKILL) when the scenario completes or times out. No EVM state persists between scenarios.

---

## Limitations

1. **Scaffold placeholders**: generated scenarios contain `bytecode: "0x"`. You must compile and supply real bytecode. ChainProof does not have a Solidity compiler dependency.

2. **No multi-hop cross-contract analysis**: the runner executes the calls you provide. It does not automatically trace reentrancy across separately-deployed contracts not listed in `scenario.contracts`.

3. **No symbolic execution**: the engine executes concrete inputs. It does not search for inputs that trigger a vulnerability.

4. **Fork determinism**: fork mode is only deterministic if `forkBlockNumber` is pinned. Without it, the adapter fetches latest, which changes between runs.

5. **Gas estimation**: `gasUsed` values are EVM measurements. They depend on the adapter implementation and may differ between Anvil and Hardhat for the same scenario.

6. **ABI encoding**: the built-in encoder supports `uint256`, `int256`, `address`, `bool`, `bytes`, `bytes32`, and `string` value types. For complex types (arrays, tuples, structs), supply pre-encoded `calldata` directly.

7. **Snapshot consumption**: `evm_revert` consumes the snapshot in most EVM implementations. The runner re-takes a snapshot after revert so that replays work, but the original `snapshotId` in a `ValidationResult` is not guaranteed to be reusable after the adapter process restarts.

8. **Windows compatibility**: the adapter process management uses POSIX signals (`SIGTERM`, `SIGKILL`). On Windows, process termination uses `process.kill()` which may behave differently.

---

## Configuration

### Per-scenario resource limits

```json
{
  "schemaVersion": "1.0.0",
  "id": "...",
  "limits": {
    "timeoutMs": 60000,
    "maxCalls": 20,
    "maxGasPerCall": 15000000,
    "maxLogs": 500,
    "maxMemoryBytes": 268435456
  },
  ...
}
```

### Global limits via CLI

```bash
chainproof validate run plan.json --timeout 60000
```

### Default limits

| Limit | Default |
|-------|---------|
| `timeoutMs` | 30,000 ms |
| `maxCalls` | 100 |
| `maxGasPerCall` | 30,000,000 |
| `maxLogs` | 1,000 |
| `maxMemoryBytes` | 512 MB |

---

## Troubleshooting

### `No EVM adapter found`

Install Foundry or Hardhat:

```bash
# Foundry (Anvil)
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Hardhat
npm install --save-dev hardhat
```

Or specify the binary path explicitly:

```bash
chainproof validate run plan.json --adapter-bin /usr/local/bin/anvil
```

### `Fork RPC unavailable`

- Verify the RPC URL is correct and the provider is up
- Use `--fork-url` to supply the URL (it is not stored in plan files)
- Check that the RPC endpoint allows `eth_getBlockByNumber` and `eth_getStorageAt`

### `Adapter crashed`

- Check that no other process is using the same port
- Increase the timeout: `--timeout 60000`
- Enable verbose output: `--verbosity 2` (if supported by the adapter CLI)

### `Scenario exceeded time limit`

- Increase `--timeout` for complex scenarios
- Use `chainproof validate minimize` to reduce the number of calls

### `Transaction not mined within Xms`

Anvil is configured in `--no-mining` mode for determinism. The adapter mines a block after each transaction. If mining fails, check that the adapter process is still running (not killed by the watchdog timer).

### `Deployment of X produced no contractAddress`

The bytecode is invalid or the deployment reverted. Check:
1. The bytecode is correct (0x-prefixed, non-empty)
2. The deployer has sufficient balance
3. The constructor arguments are ABI-encoded correctly

---

## Compatibility

| Component | Minimum version |
|-----------|----------------|
| Node.js | 18.0.0 |
| Anvil (Foundry) | 0.1.0 |
| Hardhat | 2.12.0 |
| @chainproof/core | 0.1.0 |

The `ValidationScenario` schema is versioned at `1.0.0`. Breaking changes will increment the major version and include migration helpers.

---

## Migration

### Schema version 1.0.0 (current)

No migration required. This is the initial release.

### Future migrations

When `VALIDATION_SCHEMA_VERSION` is bumped:
1. Old bundles will be detected by their `schemaVersion` field
2. A migration function will be provided in `packages/core/src/validation/migrate.ts`
3. The CLI will warn on version mismatch and suggest running `chainproof validate migrate`

---

## Fixture Reference

The following Solidity fixtures are provided for testing the validation engine:

| File | Purpose |
|------|---------|
| `examples/contracts/validation/ValidationVulnerableVault.sol` | Intentionally vulnerable: reentrancy, tx.origin auth, unchecked return |
| `examples/contracts/validation/ValidationSecureVault.sol` | Patched reference: CEI pattern, msg.sender, checked transfers, nonReentrant |
| `examples/contracts/validation/ValidationReentrantAttacker.sol` | Reentrant attacker contract for reentrancy scenarios |

The vulnerable vault should produce findings for `CP-107`, `CP-115`, and `CP-104`. The secure vault should produce no critical/high findings.

---

## Example: Complete Reentrancy Validation

This example shows the full workflow for validating a reentrancy finding.

### 1. Scan

```bash
chainproof scan examples/contracts/validation/ValidationVulnerableVault.sol \
  --format json --output findings.json
```

### 2. Plan

```bash
chainproof validate plan findings.json --min-severity high --output plan.json
```

### 3. Inspect the scaffold

```json
{
  "schemaVersion": "1.0.0",
  "scenarios": [
    {
      "id": "scenario-CP-107-validationvulnerablevault-42-a1b2c3d4",
      "title": "Reentrancy reproduction scaffold: ValidationVulnerableVault.sol L42",
      "contracts": [
        { "name": "VulnerableContract", "bytecode": "0x", ... },
        { "name": "AttackerContract", "bytecode": "0x", ... }
      ],
      ...
    }
  ]
}
```

### 4. Supply bytecode

Compile with Foundry:

```bash
forge build
VAULT_BYTECODE=$(cat out/ValidationVulnerableVault.sol/ValidationVulnerableVault.json | jq -r '.bytecode.object')
ATTACKER_BYTECODE=$(cat out/ValidationReentrantAttacker.sol/ValidationReentrantAttacker.json | jq -r '.bytecode.object')
```

Edit `plan.json` to fill in the bytecode and adjust the call sequence.

### 5. Run

```bash
chainproof validate run plan.json --adapter anvil --output report.json
```

### 6. View results

```bash
chainproof validate report report.json --format markdown
```

---

*See also: [docs/invariant-dsl.md](invariant-dsl.md), [docs/governance-safety.md](governance-safety.md), [docs/staking-accounting.md](staking-accounting.md)*
