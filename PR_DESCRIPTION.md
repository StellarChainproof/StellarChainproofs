# Detector Benchmark Corpus and Precision Regression Framework

## Summary

This PR implements a production-grade, versioned detector benchmark corpus and precision regression framework for `@chainproof/core` and `@chainproof/cli` (#93). It enables quantitative measurement of detector precision, recall, F-scores, runtime latency, memory usage, and diagnostic stability across standardized Solidity test fixtures.

The implementation adds 1,785 lines of TypeScript implementation code across `packages/core/src/benchmark/` and `packages/cli/src/commands/benchmark.ts` (excluding tests, docs, fixtures, and generated artifacts).

## Architecture

- **Manifest & Schema Layer (`packages/core/src/benchmark/schema.ts`, `types.ts`):** Versioned JSON schema (`1.0.0`) for corpus manifests defining vulnerable, fixed, ambiguous, multi-file, generated, and real-world test cases with provenance, tags, and license metadata. Includes corrupt manifest detection and validation diagnostics.
- **Evaluation & Metrics Engine (`packages/core/src/benchmark/evaluator.ts`):** Evaluates finding assertions against actual findings using line tolerance, call path traces, evidence strings, confidence matching, and allowed alternative findings. Calculates TP, FP, FN, TN, Precision, Recall, $F_1$, $F_2$, $F_{0.5}$ scores, per-rule coverage, and false-positive classifications.
- **Fixture Mutation Engine (`packages/core/src/benchmark/mutator.ts`):** Dynamically generates line-shift, comment-noise, and format-churn fixture variants to test detector diagnostic stability under code motion and refactoring.
- **Runner & Sharding (`packages/core/src/benchmark/runner.ts`):** Executes benchmarks with deterministic pseudo-random sampling, corpus sharding (`--shard`), parallel determinism, resource profiling, and failure recovery.
- **Regression Gate (`packages/core/src/benchmark/gate.ts`):** Compares candidate benchmark reports against baseline benchmarks, enforcing minimum precision/recall/F1 thresholds and maximum allowed regression limits while evaluating reviewed threshold exception overrides.
- **CLI & Report Serialization (`packages/cli/src/commands/benchmark.ts`, `serializer.ts`):** Exposes `chainproof benchmark [run|compare|validate|init]` CLI commands with Markdown, JSON, and Table report outputs.

## Security Boundaries & Determinism

- **Zero External Network Dependencies:** Benchmark runs operate completely offline in CI without RPC, explorer, or external API calls.
- **Adversarial & Corrupt Input Handling:** Malformed JSON manifests, missing target fixture files, syntax errors, and duplicate case IDs surface typed error diagnostics without crashing the engine.
- **Sanitized Context:** Output reports omit host system paths, credentials, or sensitive environment details.

## Performance Measurements

- **Cold Benchmark Execution:** ~22ms for small test corpus on standard sandbox environment.
- **Memory Footprint:** Peak heap usage ~14.5MB during full suite execution.

## Test Evidence

Comprehensive unit and integration test coverage implemented in `packages/core/src/benchmark/__tests__/benchmark.test.ts` and `packages/cli/src/__tests__/benchmark.test.ts`.

Final verification checks passed:
- [x] `npm ci`
- [x] `npm run lint`
- [x] `npm run build`
- [x] `npm run test`
- [x] `npm run test:ci --workspace=packages/core`

## Documentation

Full maintainer and user guide added in `docs/benchmark-framework.md` with updates in `README.md`.
