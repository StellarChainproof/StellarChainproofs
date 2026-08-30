# Lending Protocol Invariant Analysis - Technical Design

## Overview

The lending protocol invariant analysis module is a deterministic, network-free static analysis engine integrated into `@chainproof/core`. It detects critical lending protocol vulnerabilities through AST-based invariant checking without requiring live network interaction, symbolic execution, or runtime simulation.

This module follows the established architectural pattern from the staking, governance, and bridge analyzers: model extraction → framework adapter recognition → rule evaluation → structured output. It focuses on lending-specific invariants (collateral health, interest accrual, liquidation mechanics, share accounting) and complements the existing callback reentrancy analysis and planned AI economic exploit detection.

### Design Goals

1. **Deterministic analysis**: Identical inputs produce byte-identical outputs for CI reproducibility
2. **High signal-to-noise**: Evidence-driven findings with explicit assumptions and confidence levels
3. **Framework awareness**: Recognize Compound-like, Aave-like, and isolated pool patterns
4. **Resource bounded**: Configurable limits prevent unbounded execution on adversarial input
5. **Integration-ready**: Seamless TypeScript API, CLI, and existing scan pipeline integration

### Non-Goals

- Runtime simulation or fork-based testing
- Economic exploit modeling (delegated to AI analysis module #60)
- Generic reentrancy detection (handled by CP-107, CP-CB-*)
- Oracle manipulation or price feed attacks
- Network-specific deployment verification

## Architecture

The implementation follows a four-layer separation of concerns pattern established by existing analyzers:

### Layer 1: Model Extraction (`lending/model.ts`)

**Responsibility**: Parse Solidity AST and build normalized contract models

**Key Components**:
- **State Variable Classification**: Identify collateral factors, interest indexes, debt shares, health factors, liquidation parameters, oracle references, pause states
- **Function Role Detection**: Classify functions as deposit/supply, borrow, repay, withdraw, liquidate, accrue interest, update oracle, emergency operations
- **Operation Sequencing**: Record lexical-ordered reads, writes, arithmetic, guards, external calls with source locations
- **Precision Tracking**: Extract decimal scalars, fixed-point constants (WAD, RAY, PRECISION)
- **Cross-Reference Detection**: Map state dependencies across supply, borrow, and liquidation flows

**Output**: `LendingContractModel[]` with normalized state, transitions, and assumptions

### Layer 2: Framework Adapters (`lending/adapters.ts`)

**Responsibility**: Recognize structural patterns from major lending protocol architectures

**Adapter Types**:
1. **Compound-like CToken**: Exchange rate based shares, supply/borrow indices per market
2. **Aave-like Pool**: Normalized debt tracking, aTokens/variable debt/stable debt separation  
3. **Isolated Pools**: Per-market collateral restrictions, asset-specific parameters
4. **Generic Lending**: Fallback pattern when no specific framework is matched

**Adapter Selection Signals**:
- State variable patterns (e.g., `borrowIndex`, `liquidityIndex`, `utilizationRate`)
- Function naming conventions (e.g., `mint`/`redeem` vs `deposit`/`withdraw`)
- Structural relationships (e.g., separate token contracts for shares vs pool-integrated)
- Parameter storage patterns (e.g., per-market vs global configuration)

**Output**: `LendingFrameworkAdapterMatch` with matched signals and applicable assumptions

### Layer 3: Accounting Rules (`lending/analyzer.ts`)

**Responsibility**: Evaluate lending-specific invariants on normalized models

**Rule Categories**:
1. **Collateral Health** (CP-LND-001 to CP-LND-003)
   - Health factor calculation bypass
   - Under-collateralized borrow detection
   - Collateral factor vs liquidation threshold validation

2. **Interest Accrual** (CP-LND-004 to CP-LND-006)
   - Stale index detection (accrual before state mutation)
   - Interest index ordering (update before borrow/repay/liquidate)
   - Reserve factor application consistency

3. **Share Accounting** (CP-LND-007 to CP-LND-009)
   - Share-to-amount rounding direction errors
   - Debt share vs normalized amount consistency
   - Exchange rate manipulation via donation or precision loss

4. **Liquidation Safety** (CP-LND-010 to CP-LND-013)
   - Self-liquidation vulnerability
   - Liquidation bonus vs collateral factor inversion
   - Close factor over-liquidation or under-liquidation
   - Partial liquidation health factor updates

5. **State Transition Ordering** (CP-LND-014 to CP-LND-016)
   - Transfer-before-update dangerous patterns
   - Oracle-read before accrual timing issues
   - Bad debt accumulation without safeguards

6. **Protocol-Specific** (CP-LND-017 to CP-LND-020)
   - Rebasing token collateral precision loss
   - Isolation mode bypass vulnerabilities
   - Variable vs fixed rate debt inconsistencies
   - Emergency operation asset recovery risks

**Output**: `LendingFinding[]` with evidence, confidence, and assumptions

### Layer 4: Transport and Presentation (`lending/api.ts`, `lending/serialize.ts`)

**Responsibility**: Expose analysis through stable interfaces

**API Surface**:
- `analyzeLendingSource(source, file)` - Single in-memory source
- `analyzeLendingSources(sources)` - Batch in-memory analysis
- `analyzeLendingFiles(paths, options)` - Filesystem integration
- `analyzeLendingProject(targets, options)` - Project-level analysis
- `buildLendingModels(sources)` - Model extraction only (for extensions)
- `analyzeLendingModel(model, options)` - Rule evaluation on existing model

**CLI Integration**:
```bash
chainproof lending contracts/ --output lending-report.md --fail-on high
chainproof lending contracts/ --format json --include-rule CP-LND-001
```

**Output Formats**:
- JSON: Versioned, stable schema with sorted keys and deterministic ordering
- Markdown: Human-readable report with evidence and recommendations
- Integration with existing report aggregation pipeline

## Components and Interfaces

### Core Data Structures

```typescript
// ─── Rule Identifiers ────────────────────────────────────────────────────────

export type LendingRuleId =
  | "CP-LND-001" // Health factor calculation bypass
  | "CP-LND-002" // Under-collateralized borrow
  | "CP-LND-003" // Bonus inversion (bonus > collateral factor)
  | "CP-LND-004" // Stale interest index
  | "CP-LND-005" // Interest accrual ordering
  | "CP-LND-006" // Reserve factor inconsistency
  | "CP-LND-007" // Share rounding direction error
  | "CP-LND-008" // Debt share inconsistency
  | "CP-LND-009" // Exchange rate manipulation
  | "CP-LND-010" // Self-liquidation vulnerability
  | "CP-LND-011" // Liquidation bonus configuration error
  | "CP-LND-012" // Close factor violation
  | "CP-LND-013" // Partial liquidation health update missing
  | "CP-LND-014" // Transfer before update
  | "CP-LND-015" // Oracle read before accrual
  | "CP-LND-016" // Bad debt safeguard missing
  | "CP-LND-017" // Rebasing token precision loss
  | "CP-LND-018" // Isolation mode bypass
  | "CP-LND-019" // Variable/fixed rate inconsistency
  | "CP-LND-020"; // Emergency recovery asset overlap

// ─── State Variable Roles ────────────────────────────────────────────────────

export type LendingVariableRole =
  | "collateral-asset"
  | "debt-asset"
  | "interest-index"
  | "debt-index"
  | "normalized-debt"
  | "debt-shares"
  | "collateral-factor"
  | "liquidation-threshold"
  | "liquidation-bonus"
  | "close-factor"
  | "reserve-factor"
  | "exchange-rate"
  | "total-supply"
  | "total-borrows"
  | "user-balance"
  | "user-borrow"
  | "utilization-rate"
  | "oracle-price"
  | "health-factor"
  | "accrual-timestamp"
  | "pause-state"
  | "isolation-flag"
  | "debt-ceiling"
  | "administrator"
  | "unknown";

// ─── Function Roles ──────────────────────────────────────────────────────────

export type LendingFunctionRole =
  | "deposit"
  | "supply"
  | "mint"
  | "borrow"
  | "repay"
  | "withdraw"
  | "redeem"
  | "liquidate"
  | "accrue-interest"
  | "update-index"
  | "update-oracle"
  | "calculate-health"
  | "exchange-rate"
  | "set-collateral-factor"
  | "set-liquidation-params"
  | "set-reserve-factor"
  | "pause"
  | "unpause"
  | "emergency-withdraw"
  | "unknown";

// ─── Framework Adapters ──────────────────────────────────────────────────────

export type LendingFrameworkAdapter =
  | "compound-ctoken"
  | "aave-pool"
  | "isolated-pool"
  | "generic-lending"
  | "none";

export interface LendingFrameworkAdapterDefinition {
  id: Exclude<LendingFrameworkAdapter, "generic-lending" | "none">;
  displayName: string;
  requiredStateGroups: string[][]; // OR groups of state patterns
  requiredFunctions: string[];
  guarantees: string[]; // Invariants the pattern provides
  limitations: string[]; // Known blind spots
}

export interface LendingFrameworkAdapterMatch {
  adapter: LendingFrameworkAdapter;
  matchedState: string[];
  matchedFunctions: string[];
}

// ─── Evidence and Locations ──────────────────────────────────────────────────

export interface LendingSourceLocation {
  file: string;
  line: number;
  column: number;
  lineEnd?: number;
  columnEnd?: number;
}

export interface LendingEvidence {
  kind:
    | "state-read"
    | "state-write"
    | "arithmetic"
    | "branch"
    | "call"
    | "modifier"
    | "ordering"
    | "parameter-flow"
    | "adapter"
    | "absence";
  description: string;
  location: LendingSourceLocation;
  snippet?: string;
}

// ─── Contract Model ──────────────────────────────────────────────────────────

export interface LendingStateVariable {
  name: string;
  typeName: string;
  role: LendingVariableRole;
  isMapping: boolean;
  location: LendingSourceLocation;
}

export interface LendingOperation {
  order: number;
  kind: "read" | "write" | "call" | "arithmetic" | "guard";
  name: string;
  expression: string;
  parameterSources: string[]; // Taint tracking for user-controlled values
  location: LendingSourceLocation;
}

export interface LendingTransition {
  name: string;
  role: LendingFunctionRole;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  reads: string[];
  writes: string[];
  calls: string[];
  operations: LendingOperation[];
  location: LendingSourceLocation;
  source: string;
}

export interface LendingContractModel {
  name: string;
  file: string;
  adapter: LendingFrameworkAdapter;
  stateVariables: LendingStateVariable[];
  transitions: LendingTransition[];
  
  // Lending-specific metadata
  collateralAssets: string[];
  debtAssets: string[];
  oracleReferences: string[];
  precisionScalars: string[];
  
  // Configuration parameters (if detected)
  collateralFactors: Map<string, string>; // asset -> factor
  liquidationThresholds: Map<string, string>;
  liquidationBonuses: Map<string, string>;
  
  assumptions: string[];
  location: LendingSourceLocation;
}

// ─── Findings ────────────────────────────────────────────────────────────────

export interface LendingFinding {
  ruleId: LendingRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: Exclude<Severity, "gas">;
  confidence: "high" | "medium" | "low";
  category:
    | "collateral-health"
    | "interest-accrual"
    | "share-accounting"
    | "liquidation"
    | "state-ordering"
    | "protocol-specific";
  contract: string;
  location: LendingSourceLocation;
  evidence: LendingEvidence[];
  assumptions: string[];
}

// ─── Analysis Configuration ──────────────────────────────────────────────────

export const LENDING_CONFIG_SCHEMA_VERSION = 1 as const;

export interface LendingAnalysisConfigV1 {
  schemaVersion: 1;
  includeModels?: boolean;
  includeRules?: LendingRuleId[];
  excludeRules?: LendingRuleId[];
  limits?: Partial<LendingAnalysisLimits>;
  
  // Protocol-specific configuration
  protocolTerminology?: {
    deposit?: string[]; // e.g., ["mint", "supply"]
    borrow?: string[];
    repay?: string[];
    withdraw?: string[]; // e.g., ["redeem", "burn"]
  };
  
  // Manual function annotations when naming is ambiguous
  functionAnnotations?: {
    [functionName: string]: LendingFunctionRole;
  };
}

export interface LendingAnalysisLimits {
  maxSourceBytes: number;
  maxFiles: number;
  maxContracts: number;
  maxFunctionsPerFile: number;
  maxFunctionsPerContract: number;
  maxOperationsPerFunction: number;
  maxFindings: number;
  maxEvidencePerFinding: number;
}

export const DEFAULT_LENDING_LIMITS: LendingAnalysisLimits = {
  maxSourceBytes: 2 * 1024 * 1024, // 2 MB
  maxFiles: 256,
  maxContracts: 128,
  maxFunctionsPerFile: 512,
  maxFunctionsPerContract: 512,
  maxOperationsPerFunction: 2048,
  maxFindings: 1024,
  maxEvidencePerFinding: 12,
};

// ─── Analysis Report ─────────────────────────────────────────────────────────

export const LENDING_REPORT_SCHEMA_VERSION = "1.0.0" as const;

export interface LendingFileAnalysis {
  file: string;
  models: LendingContractModel[];
  findings: LendingFinding[];
  diagnostics: LendingDiagnostic[];
}

export interface LendingAnalysisReport {
  schemaVersion: typeof LENDING_REPORT_SCHEMA_VERSION;
  engineVersion: string;
  timestamp: string;
  files: LendingFileAnalysis[];
  summary: {
    filesAnalyzed: number;
    contractsModeled: number;
    findingsBySeverity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    findingsByCategory: Record<string, number>;
    truncated: boolean;
  };
  assumptions: string[]; // Global assumptions
  config: LendingAnalysisConfigV1;
}

// ─── Diagnostics ─────────────────────────────────────────────────────────────

export interface LendingDiagnostic {
  code:
    | "LND_PARSE_ERROR"
    | "LND_SOURCE_LIMIT"
    | "LND_CONTRACT_LIMIT"
    | "LND_FUNCTION_LIMIT"
    | "LND_OPERATION_LIMIT"
    | "LND_FINDING_LIMIT"
    | "LND_CANCELLED"
    | "LND_CONFIG_INVALID"
    | "LND_FILE_UNREADABLE";
  message: string;
  file?: string;
  line?: number;
  severity: "error" | "warning" | "info";
}

// ─── Cancellation ────────────────────────────────────────────────────────────

export interface LendingCancellationSignal {
  readonly aborted: boolean;
  readonly reason?: any;
}

export interface LendingAnalysisOptions {
  includeModels?: boolean;
  includeRules?: LendingRuleId[];
  excludeRules?: LendingRuleId[];
  limits?: Partial<LendingAnalysisLimits>;
  signal?: LendingCancellationSignal;
  protocolTerminology?: LendingAnalysisConfigV1["protocolTerminology"];
  functionAnnotations?: LendingAnalysisConfigV1["functionAnnotations"];
}
```

### Module Structure

```
packages/core/src/lending/
├── index.ts              # Public API exports
├── types.ts              # Type definitions (above)
├── model.ts              # AST → LendingContractModel extraction
├── adapters.ts           # Framework pattern recognition
├── analyzer.ts           # Rule evaluation engine
├── rule.ts               # Individual rule implementations
├── config.ts             # Configuration validation and migration
├── serialize.ts          # JSON and Markdown output
└── api.ts                # High-level analysis functions
```

## Data Models

### State Variable Classification

The model builder walks the AST and assigns semantic roles based on:

1. **Name patterns**: `borrowIndex`, `liquidationThreshold`, `collateralFactor`, `healthFactor`
2. **Type patterns**: `mapping(address => uint256)` for user balances, `uint256` for global state
3. **Usage patterns**: Variables read in health calculations, written in accrual functions
4. **Relationship patterns**: Variables that share update timing or mathematical relationships

**Confidence scoring**:
- High: Multiple signals align (name + type + usage)
- Medium: Name or usage matches but type is ambiguous
- Low: Inferred from single weak signal

### Function Role Detection

Functions are classified through:

1. **Signature analysis**: Parameters indicate deposit (asset, amount) vs borrow (asset, amount) vs liquidate (borrower, collateral, debt)
2. **State effect analysis**: Which variables are read vs written
3. **External call patterns**: Token transfers in (deposit) vs out (withdraw/liquidate)
4. **Ordering analysis**: Whether accrual happens before or after state changes

### Operation Sequencing

Each function body is linearized into ordered operations:

```typescript
{
  order: 42,
  kind: "write",
  name: "borrowIndex",
  expression: "borrowIndex = calculateNewIndex()",
  location: { file: "Pool.sol", line: 123, column: 5 }
}
```

This enables detection of:
- **Accrual-before-mutation**: Index updates must precede balance changes
- **Transfer-after-update**: External calls should follow accounting updates
- **Oracle-after-accrual**: Price reads should use fresh accrued state

### Precision and Rounding Tracking

The model extracts fixed-point constants:

```typescript
precisionScalars: ["1e18", "1e27", "PRECISION", "WAD", "RAY"]
```

And tracks division/multiplication patterns to detect precision loss:
- Division before multiplication: `(a / b) * c` loses precision
- Missing scalar: `shares / totalShares` without `* PRECISION` multiplier
- Incorrect rounding: `borrowed.divUp()` should round against user, `repay.divDown()` should round for protocol

## Error Handling

### Diagnostic Categories

1. **Parse Errors** (`LND_PARSE_ERROR`): Solidity AST construction failed
2. **Resource Limits** (`LND_*_LIMIT`): Budget exceeded, partial analysis
3. **Configuration Errors** (`LND_CONFIG_INVALID`): Invalid schema, rule IDs, or limits
4. **IO Errors** (`LND_FILE_UNREADABLE`): Filesystem access failed
5. **Cancellation** (`LND_CANCELLED`): User-requested abort

### Error Context

Error messages include:
- ✅ Actionable information (which file, which rule, which limit)
- ✅ Sanitized file paths (relative to project root)
- ❌ **Never** include source code contents in errors
- ❌ **Never** include absolute paths or user directories
- ❌ **Never** include credentials or configuration secrets

Example:
```
LND_CONFIG_INVALID: Configuration validation failed
  • Rule ID "CP-LND-999" is not recognized
  • Valid rule IDs: CP-LND-001 through CP-LND-020
  • Location: .chainproof/lending-config.json
```

### Graceful Degradation

When limits are reached:
1. Emit a diagnostic with severity "warning"
2. Mark `summary.truncated = true` in the report
3. Return partial results for the analyzed portion
4. **Do not** throw exceptions (except for cancellation)

### Cancellation

The analysis checks `signal.aborted` at:
- Start of each file
- Start of each contract
- Start of each rule evaluation

When cancelled:
- Throw `LendingAnalysisCancelledError` with reason
- Do not emit partial findings from interrupted rules
- Return clean diagnostic with `LND_CANCELLED` code

## Testing Strategy

The lending analyzer uses **fixture-based testing** with paired vulnerable/secure contracts, following the pattern established by staking, governance, and bridge modules. Property-based testing is **not applicable** because:

1. This is **static analysis infrastructure** that operates on AST inputs, not application logic with universal properties
2. The analyzer's correctness is validated through **concrete test cases** (vulnerable contracts that should produce findings, secure contracts that should not)
3. The existing ChainProof analyzers all use fixture-based testing, not PBT

### Test Structure

#### 1. Unit Tests

**Model Extraction Tests** (`model.test.ts`):
- ✅ Variable role classification accuracy
- ✅ Function role detection across naming conventions
- ✅ Operation sequencing correctness
- ✅ Precision scalar extraction
- ✅ Adapter signal matching

**Rule Tests** (`rule.test.ts`):
- ✅ Each rule produces expected finding on vulnerable fixture
- ✅ Each rule produces zero findings on secure fixture
- ✅ False positive controls (similar but safe patterns)
- ✅ Confidence level accuracy
- ✅ Evidence path completeness

**Configuration Tests** (`config.test.ts`):
- ✅ Schema validation (valid/invalid configs)
- ✅ Migration from v0 to v1
- ✅ Rule allowlist/denylist logic
- ✅ Limit validation (positive integers, no zero/negative)
- ✅ Corruption handling (malformed JSON)

#### 2. Integration Tests

**End-to-End Analysis**:
```typescript
test("CP-LND-001: Detects health factor bypass", () => {
  const source = readFixture("VulnerableHealthBypass.sol");
  const report = analyzeLendingSource(source, "test.sol");
  
  expect(report.findings).toHaveLength(1);
  expect(report.findings[0].ruleId).toBe("CP-LND-001");
  expect(report.findings[0].severity).toBe("critical");
  expect(report.findings[0].confidence).toBe("high");
  expect(report.findings[0].evidence.length).toBeGreaterThan(0);
});

test("CP-LND-001: No false positive on secure implementation", () => {
  const source = readFixture("SecureHealthCheck.sol");
  const report = analyzeLendingSource(source, "test.sol");
  
  expect(report.findings.filter(f => f.ruleId === "CP-LND-001")).toHaveLength(0);
});
```

**Multi-File Analysis**:
- ✅ Cross-contract relationships (e.g., Pool + CToken + Oracle)
- ✅ Import resolution and reference tracking
- ✅ Deterministic ordering across file systems

**Resource Limits**:
- ✅ Large files trigger `LND_SOURCE_LIMIT` diagnostic
- ✅ Deep nesting triggers `LND_OPERATION_LIMIT`
- ✅ Many contracts trigger `LND_CONTRACT_LIMIT`
- ✅ Analysis completes with partial results, no crash

**Cancellation**:
- ✅ AbortController integration
- ✅ Clean error on cancellation
- ✅ No partial findings from interrupted rules

#### 3. Fixture Coverage

**Vulnerable Fixtures** (`examples/contracts/lending/vulnerable/`):
- `VulnerableHealthBypass.sol` - CP-LND-001, CP-LND-002
- `VulnerableStaleIndex.sol` - CP-LND-004, CP-LND-005
- `VulnerableRounding.sol` - CP-LND-007, CP-LND-009
- `VulnerableSelfLiquidation.sol` - CP-LND-010
- `VulnerableBonusInversion.sol` - CP-LND-003, CP-LND-011
- `VulnerableTransferOrdering.sol` - CP-LND-014
- `VulnerableRebasingCollateral.sol` - CP-LND-017
- `VulnerableIsolationBypass.sol` - CP-LND-018
- `VulnerableBadDebt.sol` - CP-LND-016

**Secure Fixtures** (`examples/contracts/lending/secure/`):
- `SecureHealthCheck.sol` - Proper health factor enforcement
- `SecureAccrualOrdering.sol` - Correct index update sequencing
- `SecureRoundingDirection.sol` - Proper round-up/round-down usage
- `SecureLiquidationGuards.sol` - Self-liquidation prevention
- `SecureTransferSequence.sol` - Update-before-transfer pattern
- `SecureRebasingShares.sol` - Share-based rebasing token handling
- `SecureIsolationMode.sol` - Proper isolation enforcement

**False Positive Controls** (`examples/contracts/lending/controls/`):
- `UnrelatedHealthCalculation.sol` - Health factor in non-lending context
- `SafeAdminFunction.sol` - Privileged operations with proper access control
- `NonLendingShares.sol` - Share tokens unrelated to lending

**Boundary Conditions**:
- Zero-amount operations
- Maximum uint256 values
- Single-wei precision edge cases
- Empty pool states (zero supply, zero borrows)
- Extreme collateral factors (0%, 100%)

#### 4. Serialization Tests

**JSON Output**:
- ✅ Schema version present
- ✅ Deterministic key ordering (sorted)
- ✅ No timestamps or host-specific data
- ✅ Byte-identical output for identical input

**Markdown Output**:
- ✅ Readable formatting with code blocks
- ✅ Evidence sections with source locations
- ✅ Recommendations clearly stated
- ✅ Summary statistics table

#### 5. CLI Tests

**Command-line Interface**:
```bash
# Exit code 0: No findings above threshold
chainproof lending contracts/secure/ --fail-on high

# Exit code 1: Findings above threshold
chainproof lending contracts/vulnerable/ --fail-on medium

# Exit code 2: Configuration error
chainproof lending contracts/ --include-rule CP-LND-999

# JSON output is clean (no banner/progress)
chainproof lending contracts/ --format json | jq '.schemaVersion'
```

#### 6. Performance Tests

**Analysis Speed**:
- ✅ Large codebase (100+ files) completes within time budget
- ✅ Deep inheritance chains don't cause exponential blowup
- ✅ Complex functions stay within operation limit

**Memory Usage**:
- ✅ Streaming file processing (not loading entire project into memory)
- ✅ Model garbage collection between files
- ✅ No memory leaks in long-running CLI processes

### Test Execution

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- lending/model.test.ts

# Coverage report
npm run coverage

# Lint and type check
npm run lint
```

### Continuous Integration

The CI pipeline runs:
1. Unit tests (all rules, all adapters)
2. Integration tests (fixtures, limits, cancellation)
3. CLI tests (exit codes, JSON cleanliness)
4. Serialization determinism check (run twice, compare output)
5. TypeScript type checking
6. ESLint with no warnings
7. Coverage threshold enforcement (>80%)

## Deployment and Integration

### Installation

```bash
# Install ChainProof with lending analyzer
npm install @chainproof/core

# CLI usage (global install)
npm install -g @chainproof/cli
chainproof lending --help
```

### API Usage

```typescript
import {
  analyzeLendingFiles,
  serializeLendingReportJSON,
  type LendingAnalysisOptions,
} from "@chainproof/core";

const options: LendingAnalysisOptions = {
  includeModels: true,
  includeRules: ["CP-LND-001", "CP-LND-004", "CP-LND-010"],
  limits: {
    maxFiles: 100,
    maxSourceBytes: 1_000_000,
    maxFindings: 500,
  },
  protocolTerminology: {
    deposit: ["mint", "supply"],
    withdraw: ["redeem", "burn"],
  },
};

const report = analyzeLendingFiles(["contracts/lending/"], options);
console.log(serializeLendingReportJSON(report));
```

### CLI Usage

```bash
# Markdown report for human review
chainproof lending contracts/ --output lending-report.md --fail-on high

# JSON for CI pipeline
chainproof lending contracts/ --format json --fail-on critical > report.json

# Focused analysis
chainproof lending contracts/Pool.sol \
  --include-rule CP-LND-001 \
  --include-rule CP-LND-004 \
  --include-models

# Configuration file
chainproof lending contracts/ --config .chainproof/lending-config.json

# Resource limits
chainproof lending contracts/ \
  --max-files 200 \
  --max-source-bytes 5000000 \
  --max-findings 1000
```

### Configuration File

```json
{
  "schemaVersion": 1,
  "includeModels": false,
  "includeRules": [
    "CP-LND-001",
    "CP-LND-002",
    "CP-LND-004",
    "CP-LND-010"
  ],
  "excludeRules": [],
  "limits": {
    "maxSourceBytes": 2097152,
    "maxFiles": 256,
    "maxContracts": 128,
    "maxFunctionsPerFile": 512,
    "maxFunctionsPerContract": 512,
    "maxOperationsPerFunction": 2048,
    "maxFindings": 1024,
    "maxEvidencePerFinding": 12
  },
  "protocolTerminology": {
    "deposit": ["mint", "supply", "provide"],
    "borrow": ["loan", "draw"],
    "repay": ["payback", "return"],
    "withdraw": ["redeem", "burn", "remove"]
  },
  "functionAnnotations": {
    "executeFlashLoan": "unknown",
    "adminLiquidate": "liquidate"
  }
}
```

### Integration with Existing Scan

The lending analyzer integrates with the main `scan()` API:

```typescript
import { scan, type ScanConfig } from "@chainproof/core";

const config: ScanConfig = {
  targets: ["contracts/"],
  useSlither: true,
  useLLM: false,
  useMetrics: false,
  // Lending analysis runs automatically on detected lending contracts
};

const result = await scan(config);
// result.files includes generic findings + lending-specific findings
```

The integration:
1. Detects lending contracts through state/function signals
2. Runs lending-specific rules in addition to generic rules
3. Merges findings into unified report
4. Avoids duplication with existing reentrancy/callback detection

## Performance and Scalability

### Resource Budgets

Default limits prevent unbounded execution:

| Resource | Default Limit | Rationale |
|----------|---------------|-----------|
| Source bytes per file | 2 MB | Prevents single-file DoS |
| Files per project | 256 | Typical monorepo size |
| Contracts per file | 128 | Handles large inheritance |
| Functions per file | 512 | Prevents AST explosion |
| Operations per function | 2048 | Bounds complexity analysis |
| Findings per analysis | 1024 | Prevents report DoS |
| Evidence per finding | 12 | Keeps findings actionable |

### Performance Targets

- **Small project** (10 files, 5K LOC): < 1 second
- **Medium project** (100 files, 50K LOC): < 10 seconds
- **Large project** (500 files, 250K LOC): < 60 seconds

### Optimization Strategies

1. **Lazy AST traversal**: Don't parse functions until needed
2. **Incremental model building**: Stream contracts, don't accumulate
3. **Rule short-circuiting**: Skip remaining rules when limit reached
4. **Evidence pruning**: Keep only most relevant evidence items
5. **Deterministic caching**: Cache adapter matches per file

### Memory Management

- Use iterative AST walking (no recursion depth limits)
- Release models after rule evaluation
- Stream JSON serialization (no in-memory string building)
- Garbage collect between files

## Security and Threat Model

### Threat Model Scope

**In Scope**:
- ✅ Incorrect health factor calculation or bypass
- ✅ Stale interest index usage
- ✅ Share accounting rounding errors
- ✅ Self-liquidation vulnerabilities
- ✅ Liquidation parameter misconfiguration
- ✅ Transfer-before-update dangerous ordering
- ✅ Bad debt accumulation without safeguards
- ✅ Rebasing token precision loss
- ✅ Isolation mode bypass

**Out of Scope**:
- ❌ Oracle manipulation or price feed attacks (external assumption)
- ❌ Economic arbitrage or MEV extraction (delegated to AI analysis)
- ❌ Governance attacks on parameter updates (governance module)
- ❌ Flash loan attack vectors (callback reentrancy module)
- ❌ Network-specific deployment correctness

### Security Assumptions

The analyzer makes explicit assumptions:

1. **Oracle Trust**: "Assumes oracle provides correct prices"
2. **Token Standards**: "Assumes ERC-20 tokens follow standard return value conventions"
3. **External Contracts**: "Does not analyze external library implementations"
4. **Deployment Configuration**: "Does not verify on-chain parameter values"
5. **Access Control**: "Assumes privileged roles are secured (separate governance analysis)"

These assumptions are:
- Documented in each relevant finding
- Listed in the global `report.assumptions` array
- Explained in the documentation

### Secrets and Sensitive Data

The analyzer **never**:
- Accesses network or makes RPC calls
- Reads environment variables or `.env` files
- Logs source code contents in errors
- Includes absolute filesystem paths in reports
- Stores analysis results persistently

Error messages are sanitized:
```typescript
// ❌ BAD
throw new Error(`Parse error in /Users/alice/.ssh/contracts/Pool.sol: ${sourceCode}`);

// ✅ GOOD
throw new LendingConfigError("LND_PARSE_ERROR", "Failed to parse Solidity source", {
  file: "Pool.sol", // Relative path
  line: 42,
  // No source code included
});
```

## Documentation

### User Documentation

**Main Documentation** (`docs/lending-invariants.md`):
- Overview and threat model
- Rule reference with examples
- Framework adapter descriptions
- CLI usage guide
- API reference with TypeScript examples
- Configuration schema
- Troubleshooting guide
- Integration examples

**README Section**:
- Quick start example
- Link to full documentation
- Supported lending patterns
- Example findings

### Developer Documentation

**Architecture Document** (this document):
- System design and component breakdown
- Data model specifications
- Testing strategy
- Performance targets

**API Documentation** (TypeDoc generated):
- Full TypeScript API reference
- Type definitions with inline examples
- Function signatures and return types

**Code Comments**:
- Explain "why" not "what"
- Document assumptions and edge cases
- Link to related rules or findings

### Examples and Recipes

**Common Use Cases**:
```typescript
// Example 1: Analyze specific protocol
import { analyzeLendingFiles } from "@chainproof/core";

const report = analyzeLendingFiles(
  ["contracts/lending/Pool.sol", "contracts/lending/CToken.sol"],
  {
    includeRules: ["CP-LND-001", "CP-LND-004"],
    protocolTerminology: { deposit: ["mint"], withdraw: ["redeem"] },
  }
);

// Example 2: CI integration
const hasHighSeverity = report.summary.findingsBySeverity.critical > 0
  || report.summary.findingsBySeverity.high > 0;
process.exit(hasHighSeverity ? 1 : 0);

// Example 3: Custom rule extension
import { buildLendingModels, analyzeLendingModel } from "@chainproof/core";

const models = buildLendingModels(sources);
for (const model of models) {
  const findings = customLendingRule(model);
  // Process custom findings
}
```

## Migration and Versioning

### Configuration Migration

Legacy schema v0 migration:

| v0 Field | v1 Field | Transformation |
|----------|----------|----------------|
| `maxFileSize` | `limits.maxSourceBytes` | Direct copy |
| `maxIssues` | `limits.maxFindings` | Direct copy |
| `rules` | `includeRules` | Direct copy |

Migration function:
```typescript
export function migrateLendingConfig(input: any): LendingAnalysisConfigV1 {
  if (input.schemaVersion === 1) return input;
  
  if (!input.schemaVersion || input.schemaVersion === 0) {
    return {
      schemaVersion: 1,
      includeModels: input.includeModels ?? false,
      includeRules: input.rules ?? [],
      excludeRules: input.excludeRules ?? [],
      limits: {
        ...DEFAULT_LENDING_LIMITS,
        maxSourceBytes: input.maxFileSize ?? DEFAULT_LENDING_LIMITS.maxSourceBytes,
        maxFindings: input.maxIssues ?? DEFAULT_LENDING_LIMITS.maxFindings,
      },
    };
  }
  
  throw new LendingConfigError(
    "LND_CONFIG_INVALID",
    `Unsupported config schema version: ${input.schemaVersion}`
  );
}
```

### Report Versioning

Report schema version: `1.0.0`

**Semantic versioning**:
- **Major** (2.0.0): Breaking changes to report structure
- **Minor** (1.1.0): New rule IDs or optional fields added
- **Patch** (1.0.1): Bug fixes, no schema changes

Consumers should:
```typescript
const report = JSON.parse(reportJson);
if (report.schemaVersion !== "1.0.0") {
  throw new Error(`Unsupported report schema: ${report.schemaVersion}`);
}
// Process report fields
```

### Deprecation Policy

When deprecating features:
1. Add deprecation warning in code (TypeScript `@deprecated`)
2. Document in CHANGELOG with migration path
3. Support deprecated API for at least 2 minor versions
4. Remove in next major version

## Troubleshooting Guide

### Common Issues

**Issue: No contracts detected**
- **Cause**: Files don't match `.sol` extension or exceed size limit
- **Solution**: Check file extensions, verify `maxSourceBytes` limit
- **Debug**: Run with `--include-models` to see what was parsed

**Issue: Unexpected truncation**
- **Cause**: Resource limit reached
- **Solution**: Check `diagnostics` array for `LND_*_LIMIT` codes
- **Fix**: Increase only the exhausted limit in configuration

**Issue: Missing inherited behavior**
- **Cause**: Lending analyzer is file-scoped, doesn't resolve imports
- **Solution**: Use main `scan()` API for cross-file analysis
- **Workaround**: Provide annotated parent contracts

**Issue: False positive on safe pattern**
- **Cause**: Unusual naming convention or indirect implementation
- **Solution**: Use `functionAnnotations` to clarify intent
- **Report**: Open issue with minimal reproduction case

**Issue: CI exit code 1 on expected findings**
- **Cause**: `--fail-on` threshold includes expected severity
- **Solution**: Adjust threshold or use `--fail-on none` with custom gate
- **Best practice**: Fix high/critical issues, don't lower threshold

**Issue: Adapter not recognized**
- **Cause**: Protocol uses non-standard naming or structure
- **Solution**: Call `matchLendingFramework()` to see matched signals
- **Workaround**: Use `protocolTerminology` configuration
- **Note**: Adapter selection doesn't suppress findings

### Debug Mode

Enable verbose logging:
```bash
DEBUG=chainproof:lending chainproof lending contracts/
```

Output includes:
- Model extraction steps
- Adapter matching signals
- Rule evaluation decisions
- Evidence collection

### Performance Debugging

Profile analysis time:
```bash
time chainproof lending contracts/ --format json > /dev/null
```

If slow:
1. Check file count and total LOC
2. Identify deep nesting or large functions
3. Increase limits gradually to find bottleneck
4. Use `--include-rule` to test individual rules

### Reporting Issues

Include in bug reports:
- ChainProof version (`chainproof --version`)
- Node.js version (`node --version`)
- Command used (sanitize paths)
- Configuration file (remove sensitive data)
- Minimal reproduction case (smallest contract exhibiting issue)
- Expected vs actual behavior

Do **not** include:
- Full project source code (provide minimal example)
- Absolute filesystem paths
- Credentials or API keys
- Company-confidential contract logic

## Future Enhancements

### Planned Features (Post-MVP)

1. **Cross-Contract Analysis**: Resolve imports and track state across Pool + CToken + Oracle contracts
2. **Symbolic Execution Integration**: Combine AST analysis with symbolic path exploration for higher confidence
3. **Economic Invariant Checking**: Validate "total debt ≤ total collateral * collateral factors" through SMT solver
4. **Flash Loan Context**: Detect reentrancy through flash loan callbacks
5. **Upgrade Safety**: Analyze storage layout changes in upgradeable lending protocols
6. **Historical Vulnerability Database**: Match patterns against known exploits (Compound, Aave, Euler incidents)

### Research Directions

1. **Machine Learning**: Train model on labeled lending contracts to improve adapter recognition
2. **Fuzzing Integration**: Generate test cases that violate detected invariants
3. **Formal Verification**: Integrate with Certora or Halmos for mathematical proofs
4. **Gas Optimization**: Detect inefficient lending patterns (e.g., redundant accruals)

### Community Contributions

Contributors can extend the analyzer by:
- Adding new framework adapters (`adapters.ts`)
- Implementing new rules (`rule.ts`)
- Improving precision tracking (`model.ts`)
- Adding test fixtures (`examples/contracts/lending/`)

Contribution guidelines in `CONTRIBUTING.md`.

## Appendix A: Rule Reference

### CP-LND-001: Health Factor Calculation Bypass

**Severity**: Critical  
**Confidence**: High when borrow function lacks health factor read  
**Description**: Borrow operations complete without calculating or enforcing health factor thresholds, allowing under-collateralized positions.  
**Evidence**: Borrow function writes debt state but doesn't read collateral state or call health calculation.  
**Recommendation**: Call `_checkHealthFactor(user)` after all debt state updates.

### CP-LND-002: Under-Collateralized Borrow

**Severity**: Critical  
**Confidence**: High when health check present but returns value is unused  
**Description**: Health factor is calculated but the result is not compared against liquidation threshold.  
**Evidence**: Health calculation function called but return value discarded or not checked with `require()`.  
**Recommendation**: `require(healthFactor >= LIQUIDATION_THRESHOLD, "Under-collateralized")`.

### CP-LND-003: Bonus Inversion

**Severity**: High  
**Confidence**: High when configuration state is present  
**Description**: Liquidation bonus exceeds collateral factor, creating perverse liquidation incentives.  
**Evidence**: `liquidationBonus > collateralFactor` in configuration.  
**Recommendation**: Enforce `liquidationBonus < collateralFactor` in parameter setters.

### CP-LND-004: Stale Interest Index

**Severity**: High  
**Confidence**: High when index read precedes accrual call  
**Description**: Interest index is read for calculations before calling the accrual function, causing incorrect debt or supply amounts.  
**Evidence**: `borrowIndex` read in operation N, `accrueInterest()` called in operation N+k.  
**Recommendation**: Call `accrueInterest()` before any index-dependent calculations.

### CP-LND-005: Interest Accrual Ordering

**Severity**: High  
**Confidence**: Medium when accrual happens but after state mutation  
**Description**: Debt or supply state is modified before interest accrual updates indexes, causing accounting errors.  
**Evidence**: `totalBorrows += amount` in operation N, `accrueInterest()` in operation N+k.  
**Recommendation**: Sequence: 1) accrue interest, 2) update state, 3) external calls.

### CP-LND-006: Reserve Factor Inconsistency

**Severity**: Medium  
**Confidence**: Low when reserve factor state present but not applied  
**Description**: Interest accrual doesn't split protocol reserves correctly, causing reserve accumulation errors.  
**Evidence**: Interest calculation present but no reserve factor multiplication.  
**Recommendation**: `protocolReserves += interestAccrued * reserveFactor / PRECISION`.

### CP-LND-007: Share Rounding Direction Error

**Severity**: Medium  
**Confidence**: High when division direction is wrong  
**Description**: Share-to-amount conversions round in user's favor instead of protocol's favor, enabling value extraction.  
**Evidence**: Deposit uses `shares = amount / exchangeRate` (should round down), withdraw uses same (should round up).  
**Recommendation**: Deposits round down, withdrawals round up, borrows round up, repays round down.

### CP-LND-008: Debt Share Inconsistency

**Severity**: High  
**Confidence**: Medium when debt shares and normalized debt coexist  
**Description**: Debt shares and normalized debt amounts are inconsistent due to incorrect index usage.  
**Evidence**: Debt shares written but normalized debt read without index conversion.  
**Recommendation**: `actualDebt = debtShares * debtIndex / PRECISION` consistently.

### CP-LND-009: Exchange Rate Manipulation

**Severity**: High  
**Confidence**: Low when donation path exists  
**Description**: Direct token donations can manipulate exchange rate before first deposit, enabling inflation attacks.  
**Evidence**: Exchange rate calculated as `totalAssets / totalShares` without minimum shares or virtual supply.  
**Recommendation**: Mint minimum shares to zero address or use virtual supply in exchange rate.

### CP-LND-010: Self-Liquidation Vulnerability

**Severity**: Critical  
**Confidence**: High when liquidation allows `msg.sender == borrower`  
**Description**: Users can liquidate their own positions to extract liquidation bonuses, draining protocol.  
**Evidence**: Liquidation function lacks `require(msg.sender != borrower)` check.  
**Recommendation**: `require(msg.sender != borrower, "Self-liquidation forbidden")`.

### CP-LND-011: Liquidation Bonus Configuration Error

**Severity**: Medium  
**Confidence**: High when bonus parameter validation missing  
**Description**: Liquidation bonus can be set to extreme values (0% or >100%), breaking liquidation incentives.  
**Evidence**: `setLiquidationBonus()` lacks bounds checking.  
**Recommendation**: `require(bonus >= MIN_BONUS && bonus <= MAX_BONUS)` in setter.

### CP-LND-012: Close Factor Violation

**Severity**: High  
**Confidence**: Medium when close factor exists but not enforced  
**Description**: Liquidation can exceed close factor percentage, enabling over-liquidation attacks.  
**Evidence**: `liquidate()` doesn't check `repayAmount <= borrowBalance * closeFactor / PRECISION`.  
**Recommendation**: Enforce close factor limit in liquidation calculations.

### CP-LND-013: Partial Liquidation Health Update Missing

**Severity**: High  
**Confidence**: Medium when health factor not recalculated after partial liquidation  
**Description**: Health factor is not recalculated after partial liquidation, potentially allowing immediate re-liquidation.  
**Evidence**: Liquidation updates debt and collateral but doesn't call health check afterward.  
**Recommendation**: Recalculate and verify health factor after each liquidation.

### CP-LND-014: Transfer Before Update

**Severity**: High  
**Confidence**: High when external call precedes state write  
**Description**: Token transfers occur before internal accounting updates, enabling reentrancy or fee-on-transfer exploitation.  
**Evidence**: `token.transferFrom()` in operation N, balance state written in operation N+k.  
**Recommendation**: Update state first, perform external calls last (checks-effects-interactions).

### CP-LND-015: Oracle Read Before Accrual

**Severity**: Medium  
**Confidence**: Medium when oracle read precedes accrual  
**Description**: Oracle price is read before interest accrual, causing health calculations to use stale debt amounts.  
**Evidence**: `oracle.getPrice()` called before `accrueInterest()` in health check.  
**Recommendation**: Sequence: 1) accrue interest, 2) read oracle, 3) calculate health.

### CP-LND-016: Bad Debt Safeguard Missing

**Severity**: High  
**Confidence**: Low when liquidation allows underwater positions  
**Description**: Liquidation proceeds even when collateral value is insufficient to cover debt, creating bad debt.  
**Evidence**: Liquidation doesn't check `collateralValue >= debtValue * liquidationIncentive`.  
**Recommendation**: Revert liquidations that would create protocol insolvency.

### CP-LND-017: Rebasing Token Precision Loss

**Severity**: High  
**Confidence**: Medium when rebasing token detected with nominal balances  
**Description**: Rebasing tokens (e.g., stETH) are tracked with nominal balances instead of shares, causing value drift.  
**Evidence**: Rebasing token address hardcoded but balances stored as `uint256` without conversion.  
**Recommendation**: Convert rebasing tokens to shares: `shares = token.getSharesByPooledEth(amount)`.

### CP-LND-018: Isolation Mode Bypass

**Severity**: High  
**Confidence**: Medium when isolation flag present but not enforced  
**Description**: Isolation mode restrictions can be bypassed, allowing unauthorized asset borrowing.  
**Evidence**: `isIsolated` flag read but borrowing doesn't check approved asset list.  
**Recommendation**: `require(isApprovedForIsolation[asset], "Asset not approved")` in borrow.

### CP-LND-019: Variable/Fixed Rate Inconsistency

**Severity**: Medium  
**Confidence**: Low when both debt types present  
**Description**: Variable and fixed rate debt tracking is inconsistent, causing interest calculation errors.  
**Evidence**: Single interest index used for both variable and fixed rate debt.  
**Recommendation**: Maintain separate indexes: `variableDebtIndex` and `fixedDebtIndex`.

### CP-LND-020: Emergency Recovery Asset Overlap

**Severity**: Critical  
**Confidence**: High when recovery allows accounted assets  
**Description**: Emergency token recovery can extract collateral or debt assets, draining the protocol.  
**Evidence**: `recoverToken()` doesn't exclude `collateralAssets` or `debtAssets` arrays.  
**Recommendation**: `require(!isCollateralAsset[token] && !isDebtAsset[token])` in recovery.

## Appendix B: Framework Adapter Patterns

### Compound CToken Pattern

**Structural Signals**:
- State: `borrowIndex`, `totalBorrows`, `totalReserves`, `accrualBlockNumber`
- Functions: `mint()`, `redeem()`, `borrow()`, `repayBorrow()`, `liquidateBorrow()`, `exchangeRate()`
- Architecture: Separate token contract per market, exchange rate based shares

**Recognized Guarantees**:
- Exchange rate monotonically increases (barring exploits)
- Interest accrual tied to block numbers
- Liquidation includes close factor and liquidation incentive

**Limitations**:
- Doesn't verify Comptroller integration
- Doesn't check oracle freshness
- Assumes `accrueInterest()` is called correctly

### Aave Pool Pattern

**Structural Signals**:
- State: `liquidityIndex`, `variableBorrowIndex`, `stableBorrowRate`, `lastUpdateTimestamp`
- Functions: `supply()`, `withdraw()`, `borrow()`, `repay()`, `liquidationCall()`, `updateState()`
- Architecture: Central pool contract, separate aToken/debtToken contracts, interest rate strategies

**Recognized Guarantees**:
- Normalized debt tracking with index conversion
- Timestamp-based accrual
- Reserve normalization for collateral and debt

**Limitations**:
- Doesn't analyze aToken/debtToken contracts independently
- Doesn't verify interest rate strategy correctness
- Assumes oracle integration is secure

### Isolated Pool Pattern

**Structural Signals**:
- State: `isIsolated`, `borrowCap`, `supplyCap`, `approvedAssets` mapping
- Functions: `setIsolationMode()`, `addApprovedAsset()`, borrow checks isolation
- Architecture: Per-market restrictions with approved asset lists

**Recognized Guarantees**:
- Isolation flag enforced on borrow operations
- Caps prevent overflow attacks

**Limitations**:
- Doesn't verify governance security on mode changes
- Doesn't check cross-market attack vectors

### Generic Lending Pattern

**Structural Signals**:
- State: Any combination of `balance`, `debt`, `collateral` variables
- Functions: Deposit/withdraw/borrow/repay present but non-standard naming
- Architecture: Custom implementation

**Recognized Guarantees**:
- None (fallback adapter)

**Limitations**:
- All rules evaluated without adapter-specific suppression
- Higher false positive rate expected
