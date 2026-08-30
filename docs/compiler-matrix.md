# Multi-Compiler Solidity Compatibility & Diagnostic Matrix

## 1. Overview

Smart contracts frequently specify wide or floating pragma version ranges (such as `pragma solidity ^0.8.0;` or `pragma solidity >=0.7.0 <0.9.0;`). However, the Solidity compiler undergoes significant semantic evolutions, syntax overhauls, EVM target opcode defaults (e.g. PUSH0 in Shanghai), and code generation fixes across minor and patch releases.

Assuming that a single parser interpretation or compiler version represents all possible build targets introduces severe audit blindspots:
- **Storage Layout Drift:** Changing compiler versions or variable ordering in upgradeable proxies can silently corrupt storage slots.
- **EVM Opcode Incompatibilities:** Deploying bytecode containing `PUSH0` (`0x5f`, introduced by default in 0.8.20+ with Shanghai EVM target) to Layer-2 networks or sidechains without Shanghai support leads to contract deployment failure or runtime execution reverts.
- **Code Generation Bugs:** Historical compiler releases harbor known codegen hazards (such as dirty bytes in storage assignments, signed immutables sign-extension, calldata tuple decoder head overflows, and transient storage optimization bugs).
- **Semantics Transitions:** Built-in checked arithmetic (>=0.8.0) vs silent integer wrapping (<0.8.0), ABI encoder v1 vs v2, and custom error availability (>=0.8.4).

ChainProof's **Multi-Compiler Solidity Compatibility and Diagnostic Matrix** track provides deterministic compatibility validation, pragma constraint solving across imported dependencies, sandboxed multi-version compilation, artifact normalization, and cross-compiler differential analysis.

---

## 2. Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                              ChainProof                                │
│                   Multi-Compiler Compatibility Track                   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Pragma & SemVer │     │ Compiler Matrix  │     │ Compiler Adapter │
│ Constraint Solver│     │  & Hazard DB     │     │ & Sandbox Guard  │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │    Normalized Artifact    │
                    │   (ABI, Storage, Bytecode)│
                    └─────────────┬─────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                                                 ▼
┌─────────────────────────────────┐               ┌──────────────────┐
│ Cross-Compiler Differential     │               │ Compatibility    │
│ Comparator (ABI/Storage/Bytecode│               │ Rules CP-SOL-001 │
│ Diagnostic/Findings Drift)      │               │   to CP-SOL-010  │
└────────────────┬────────────────┘               └────────┬─────────┘
                 │                                         │
                 └────────────────────┬────────────────────┘
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │ Deterministic Reports         │
                      │ (JSON v1.0.0, Markdown, Table)│
                      │ CLI, Server, Scanner API      │
                      └───────────────────────────────┘
```

The system comprises modular, decoupled layers:

1. **SemVer & Pragma Engine (`semver.ts`, `pragma.ts`):**
   - Pure, zero-dependency Semantic Versioning parser and solver supporting Caret (`^`), Tilde (`~`), Wildcards (`*`, `x`), Hyphen ranges, inequalities (`>=`, `<=`, `>`, `<`), and disjunctions (`||`).
   - Resolves global pragma intersections across multi-file import graphs, identifying unsatisfiable pragma imports, floating pragmas, and overly broad ranges.

2. **Compiler Matrix & Codegen Hazard Database (`matrix.ts`):**
   - Registry of all major Solidity compiler releases from `0.4.11` to `0.8.28`.
   - Maps version capabilities: `checkedArithmetic`, `customErrors`, `userDefinedValueTypes`, `transientStorage`, `push0Opcode`, `viaIR`, `immutableVariables`, `tryCatch`, `receiveFallbackSplit`, `abiEncoderV2`, `storageLayoutOutput`, and default EVM targets.
   - Comprehensive database of official Solidity compiler code generation bugs (`SOL_CODEGEN_BUGS`) with affected version bounds, triggering AST conditions, and mitigations.

3. **Compiler Adapter & Sandboxed Execution (`adapter.ts`, `sandbox.ts`, `checksums.ts`):**
   - Pluggable compiler adapter interface supporting both native verified binaries and an offline deterministic compiler simulator.
   - **Integration Boundary:** Compilers are never downloaded over the network in CI or production. Local binaries are verified against known SHA-256 checksums (`OFFICIAL_SOLC_CHECKSUMS`).
   - Execution isolation: timeout enforcement, memory bounds, environment scrubbing (redacting API keys and credentials), and path sanitization (stripping user home directories).

4. **Normalized Artifact Layer (`normalizer.ts`):**
   - Normalizes compiler outputs into consistent typed records:
     - **ABI:** Canonical function signatures, 4-byte Keccak-256 selectors, 32-byte event topics, custom error signatures.
     - **Storage Layout:** Exact slot allocations, byte offsets within slots, type descriptors, and variable packing detection.
     - **Bytecode:** Deployed bytecode size, opcode analysis (detecting `PUSH0` and `TSTORE`/`TLOAD`), and separating executable code from CBOR auxiliary metadata.

5. **Differential Comparison Engine (`comparator.ts`):**
   - Compares contract artifacts compiled across two versions:
     - **ABI Diff:** Added, removed, or mutated functions/events/errors and mutability changes.
     - **Storage Diff:** Shifted slots, offset movements, type changes, and critical storage collision hazards for upgradeable proxies.
     - **Bytecode Diff:** Size delta (bytes and percentage), PUSH0 introduction hazards, and transient storage opcode usage.
     - **Diagnostic & Finding Diff:** Introduced/resolved compiler warnings and security detector findings.

6. **Rules & Reporting Layer (`rules.ts`, `serialize.ts`, `api.ts`, `config.ts`):**
   - 10 evidence-backed static rules (`CP-SOL-001` through `CP-SOL-010`).
   - Deterministic schema-versioned JSON (`1.0.0`), GitHub-flavored Markdown, and ANSI terminal table outputs.

---

## 3. Supported Compiler Capabilities & EVM Targets

| Compiler Family | Default EVM | Checked Math | Custom Errors | ABI Encoder V2 | Transient Storage | PUSH0 Opcode |
| --- | --- | --- | --- | --- | --- | --- |
| `0.4.x` | homestead / byzantium | ❌ No (wrapping) | ❌ No | Experimental (0.4.19+) | ❌ No | ❌ No |
| `0.5.x` | petersburg / istanbul | ❌ No (wrapping) | ❌ No | Experimental | ❌ No | ❌ No |
| `0.6.x` | istanbul | ❌ No (wrapping) | ❌ No | Experimental | ❌ No | ❌ No |
| `0.7.x` | istanbul | ❌ No (wrapping) | ❌ No | Experimental | ❌ No | ❌ No |
| `0.8.0` - `0.8.3` | berlin / london | ✅ Yes (built-in) | ❌ No | ✅ Default | ❌ No | ❌ No |
| `0.8.4` - `0.8.19` | london / paris | ✅ Yes (built-in) | ✅ Yes | ✅ Default | ❌ No | ❌ No |
| `0.8.20` - `0.8.23` | **shanghai** | ✅ Yes (built-in) | ✅ Yes | ✅ Default | ❌ No | ✅ **Yes (0x5f)** |
| `0.8.24` - `0.8.28` | **cancun** | ✅ Yes (built-in) | ✅ Yes | ✅ Default | ✅ **Yes (tstore)** | ✅ **Yes (0x5f)** |

---

## 4. Rule Catalog

| Rule ID | Name | Severity | Description |
| --- | --- | --- | --- |
| `CP-SOL-001` | Floating Pragma Directive | Low | Contract specifies unpinned floating pragma (`^` or `>=`). |
| `CP-SOL-002` | Unsatisfiable / Conflicting Import Pragmas | High | Imported project files have disjoint compiler version requirements. |
| `CP-SOL-003` | Overly Broad Version Range | Medium | Pragma range spans multiple breaking compiler minor families (e.g. 0.7 and 0.8). |
| `CP-SOL-004` | Outdated / End-of-Life Compiler (<0.8.0) | High | Pragma allows pre-0.8.0 compilation lacking built-in checked arithmetic. |
| `CP-SOL-005` | Known Compiler Code-Generation Bug / Hazard | Critical / High | Pragma allows compiler versions affected by known codegen bugs matching AST triggers. |
| `CP-SOL-006` | PUSH0 Opcode EVM Incompatibility Risk | Low / High | Solidity >=0.8.20 emits PUSH0 by default, which reverts on non-Shanghai L2 networks. |
| `CP-SOL-007` | Storage Layout Collision / Slot Drift | Critical | State variable slot or offset moved across compiled versions (upgradeability risk). |
| `CP-SOL-008` | ABI / Interface Breaking Drift | High | Function selector or parameter type modified across compiler versions. |
| `CP-SOL-009` | Transient Storage Lifecycle Hazard | Medium | Contract uses transient storage (`tstore`/`tload`) requiring intra-tx clearing. |
| `CP-SOL-010` | Unverified Compiler Binary / Checksum Mismatch | Critical | Compiler binary executed without verified cryptographic SHA-256 checksum. |

---

## 5. CLI Usage

### Inspect Pragmas & Dependencies
```bash
chainproof compiler inspect contracts/ --format table
```

### Run Multi-Compiler Evaluation Matrix
```bash
chainproof compiler matrix contracts/ --versions 0.7.6,0.8.0,0.8.20,0.8.28 --format table --fail-on high
```

### Compare Artifacts Across Two Compiler Versions
```bash
chainproof compiler compare contracts/Vault.sol --versions 0.8.20,0.8.28 --fail-on-drift
```

### Full Compatibility Audit
```bash
chainproof compiler audit contracts/ --format markdown --output compiler-report.md --fail-on high
```

---

## 6. Public API (`@chainproof/core`)

```typescript
import {
  inspectCompilerPragmas,
  buildCompilerMatrix,
  compareCompilerVersions,
  auditCompilerCompatibility,
  serializeCompilerAuditJSON,
  generateCompilerMarkdownReport,
} from "@chainproof/core";

// 1. Inspect Pragmas
const pragmaRes = inspectCompilerPragmas(["contracts/Vault.sol"]);
console.log("Global Range:", pragmaRes.globalRange);

// 2. Build Matrix
const matrix = await buildCompilerMatrix(["contracts/Vault.sol"], {
  targetVersions: ["0.8.20", "0.8.28"],
});

// 3. Differential Comparison
const comparisons = await compareCompilerVersions(["contracts/Vault.sol"], ["0.8.20", "0.8.28"]);

// 4. Audit
const report = await auditCompilerCompatibility(["contracts/Vault.sol"]);
const markdown = generateCompilerMarkdownReport(report);
```

---

## 7. Security Boundaries & Threat Model

- **Zero Network Download Boundary:** Compilers are never fetched dynamically at runtime. The toolchain relies on explicit configuration and local verified binaries or embedded offline simulation.
- **Resource Bounds:** Execution is strictly bounded with configurable `maxFiles`, `maxSourceBytes`, `maxContracts`, `maxVersionsToTest`, and `timeoutMs`.
- **Environment Isolation:** Child processes run in scrubbed environments with all API keys, bearer tokens, and secrets stripped.
- **Path Sanitization:** Error diagnostics scrub absolute local filesystem paths (`/home/username`) to protect contributor privacy.
