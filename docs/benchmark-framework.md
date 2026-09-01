# Detector Benchmark Corpus and Precision Regression Framework

The **ChainProof Detector Benchmark Corpus and Precision Regression Framework** provides automated, reproducible, production-grade benchmarking of vulnerability detectors across Solidity contract targets.

---

## Overview

Adding new vulnerability rules or tuning existing static analysis heuristics without measuring **precision**, **recall**, **F-scores**, **runtime**, and **diagnostic stability** risks introducing false positives or silent detector regressions.

The benchmark framework consists of:
1. **Versioned Corpus Manifest Schema (`1.0.0`)** — Structured JSON contract defining test cases across six categories (`vulnerable`, `fixed`, `ambiguous`, `multi-file`, `generated`, `real-world`) with provenance, tags, and license tracking.
2. **Expected Finding Assertions** — Fine-grained assertions matching actual findings against expected rule IDs, severities, source lines (with configurable line tolerance), code snippets, call path traces, evidence descriptions, confidence, and allowed alternatives or false positives.
3. **Metrics Calculation Engine** — Computes True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN), Precision, Recall, $F_1$, $F_2$, $F_{0.5}$ scores, per-rule coverage, per-category breakdown, runtime latency, and peak memory usage.
4. **Fixture Mutation Engine** — Automatically generates line-shift, comment-noise, and formatting-churn variants of target Solidity files to verify AST/diagnostic stability under code refactoring.
5. **Comparison Regression Gates** — Evaluates candidate benchmark runs against baseline benchmarks using configurable thresholds (`--min-precision`, `--min-recall`, `--min-f1`, `--max-prec-drop`, `--max-rec-drop`, `--max-runtime-reg`) and reviewed threshold exception files.
6. **CLI & Core API Integration** — Exposes `chainproof benchmark [run|compare|validate|init]` CLI commands and stable `@chainproof/core` APIs.

---

## Architecture

```
packages/core/src/benchmark/
├── types.ts          # Public TypeScript interfaces, versioned schemas & metric contracts
├── schema.ts         # Corpus manifest parser, validation, corruption handling & migration
├── evaluator.ts      # Assertion matcher, TP/FP/FN/TN evaluation & metrics calculator
├── mutator.ts        # Fixture variant generator (line-shift, comment-noise, format-churn)
├── runner.ts         # Benchmark runner (sharding, deterministic sampling, execution)
├── gate.ts           # Regression gate comparison engine with threshold exceptions
├── serializer.ts     # Markdown, JSON, and Table report generators
└── index.ts          # Re-exports for @chainproof/core
```

---

## Corpus Manifest Spec (`1.0.0`)

Corpus manifests are defined in JSON format. Below is an example manifest (`corpus.manifest.json`):

```json
{
  "schemaVersion": "1.0.0",
  "corpusName": "ChainProof Official Benchmark Corpus",
  "description": "Detector benchmark corpus containing vulnerable, fixed, and ambiguous cases",
  "cases": [
    {
      "id": "BENCH-VULN-001",
      "name": "Classic Reentrancy & Tx Origin Vault",
      "category": "vulnerable",
      "targets": ["contracts/VulnerableVaultBench.sol"],
      "expectedFindings": [
        {
          "ruleId": "CP-107",
          "severity": "critical",
          "line": 19,
          "lineTolerance": 5,
          "snippet": "balances",
          "confidence": "high"
        },
        {
          "ruleId": "CP-115",
          "severity": "high",
          "line": 24,
          "lineTolerance": 5,
          "snippet": "tx.origin",
          "confidence": "high"
        }
      ],
      "provenance": {
        "author": "ChainProof Security Team",
        "license": "MIT"
      }
    },
    {
      "id": "BENCH-FIXED-001",
      "name": "Patched CEI Vault Reference Implementation",
      "category": "fixed",
      "targets": ["contracts/SecureVaultBench.sol"],
      "expectedFindings": [],
      "provenance": {
        "author": "ChainProof Security Team",
        "license": "MIT"
      }
    }
  ]
}
```

---

## CLI Reference

### `chainproof benchmark run`

Run a benchmark execution against a corpus manifest.

```bash
chainproof benchmark run examples/benchmark-corpus/corpus.manifest.json
chainproof benchmark run corpus.manifest.json --format json --output report.json
chainproof benchmark run corpus.manifest.json --baseline baseline.json --min-precision 0.85
chainproof benchmark run corpus.manifest.json --shard 0/2 --sample 10 --seed 42 --mutate
```

| Flag | Default | Description |
| --- | --- | --- |
| `--baseline <file>` | none | Baseline benchmark report JSON to compare candidate against |
| `--format <format>` | `table` | Output format: `table`, `json`, or `markdown` |
| `--output <file>` | stdout | Save benchmark report output to specified file |
| `--shard <index/total>` | none | Shard corpus cases across parallel CI workers (e.g. `0/4`) |
| `--sample <count>` | none | Deterministically sample a subset of cases |
| `--seed <number>` | `42` | Random seed for deterministic sampling |
| `--mutate` | off | Run line-shift, comment-noise, and format-churn fixture variants |
| `--min-precision <val>` | `0.8` | Minimum acceptable precision threshold |
| `--min-recall <val>` | `0.8` | Minimum acceptable recall threshold |
| `--min-f1 <val>` | `0.8` | Minimum acceptable F1 score threshold |
| `--exceptions <file>` | none | Path to reviewed threshold exceptions JSON file |

### `chainproof benchmark compare`

Compare candidate benchmark output against a baseline report to detect precision/recall regressions in CI.

```bash
chainproof benchmark compare baseline.json candidate.json --max-prec-drop 0.02 --format markdown
```

| Flag | Default | Description |
| --- | --- | --- |
| `--exceptions <file>` | none | Reviewed threshold exceptions JSON file |
| `--min-precision <val>` | `0.8` | Minimum precision threshold |
| `--min-recall <val>` | `0.8` | Minimum recall threshold |
| `--min-f1 <val>` | `0.8` | Minimum F1 score threshold |
| `--max-prec-drop <val>` | `0.05` | Maximum allowed precision drop vs baseline |
| `--max-rec-drop <val>` | `0.05` | Maximum allowed recall drop vs baseline |
| `--max-runtime-reg <pct>`| `20` | Maximum allowed runtime regression percentage |
| `--format <format>` | `markdown` | Output format: `markdown` or `json` |
| `--output <file>` | stdout | Write regression gate output to file |

### `chainproof benchmark validate`

Validate corpus manifest schema and verify all target fixture paths exist.

```bash
chainproof benchmark validate examples/benchmark-corpus/corpus.manifest.json
```

### `chainproof benchmark init`

Scaffold a starter benchmark corpus manifest.

```bash
chainproof benchmark init corpus.manifest.json
```

---

## Programmatic API Usage (`@chainproof/core`)

```typescript
import {
  runBenchmark,
  evaluateRegressionGate,
  generateBenchmarkMarkdownReport,
  parseCorpusManifest,
} from "@chainproof/core";

// Run benchmark against manifest
const report = await runBenchmark({
  manifestPath: "examples/benchmark-corpus/corpus.manifest.json",
  mutateVariants: true,
  useSlither: false,
});

console.log(`Precision: ${(report.metrics.precision * 100).toFixed(1)}%`);
console.log(`F1 Score: ${report.metrics.f1Score.toFixed(3)}`);

// Evaluate regression gate
const gateResult = evaluateRegressionGate(report, undefined, {
  minPrecision: 0.85,
  minRecall: 0.85,
});

if (!gateResult.passed) {
  console.error("Regression gate failed:", gateResult.summary);
}
```

---

## Threat Model & Limitations

1. **Deterministic Static Analysis Only:** Benchmarks evaluate static AST rules and Slither output without executing contracts on live networks.
2. **Line Tolerance Boundaries:** Line matching allows line tolerances (default 2-5 lines). Heavy structural refactorings may require updating expected assertion line numbers.
3. **Zero External Dependencies:** CI benchmark runs operate entirely offline with zero external network services required.
