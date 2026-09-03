# ERC-4337 Security Rules

ChainProof includes deterministic, source-only analysis for smart accounts, EntryPoints, factories, aggregators, and paymasters. The analyzer runs as part of the normal `@chainproof/core` `scan()` pipeline and does not call a chain, bundler, RPC provider, or external service.

## Compatibility

The versioned adapter API currently recognizes EntryPoint/UserOperation patterns for `0.6`, `0.7`, and `0.8`. Use `version: "auto"` for marker-based selection or select a version explicitly when a project uses custom interfaces. Detection is conservative about unknown architectures: findings include assumptions and confidence and should be reviewed against the implementation.

## Covered risks

Rules cover UserOperation hash and replay domains, nonce validation, validation-data handling, aggregate signatures, paymaster gas/deposit/context/postOp behavior, counterfactual initialization and CREATE2 derivation, module/session authorization, upgrade authorization, and fallback dispatch.

Stable IDs use the `CP-4337-*` prefix, including `CP-4337-HASH_BINDING`, `CP-4337-ENTRYPOINT_DOMAIN`, `CP-4337-NONCE_REPLAY`, `CP-4337-PAYMASTER_POSTOP`, and related component rules. Findings contain source locations, evidence paths, assumptions, and confidence where applicable.

## Configuration

TypeScript:

```ts
import { scan } from "@chainproof/core";

const result = await scan({
  targets: ["contracts/"],
  useSlither: false,
  useLLM: false,
  useMetrics: false,
  erc4337: {
    version: "auto",
    limits: { maxDiagnostics: 100, maxEvidenceItems: 8 },
  },
});
```

CLI options are `--erc4337-version auto|0.6|0.7|0.8` and `--erc4337-max-diagnostics <number>`. The same values can be placed in `.chainproofrc.json` under `erc4337` and passed through the REST API or GitHub Action.

## Security boundaries and limitations

The analyzer uses bounded lexical and AST evidence. It cannot prove runtime storage invariants, cryptographic correctness of custom signature schemes, deployed bytecode identity, bundler behavior, or live EntryPoint deposits. Custom encodings and generated Solidity may lower confidence or produce no finding. Do not treat an empty result as proof of safety.

Source sizes, function traversal, evidence, and diagnostics are bounded. Aborted analyses return a valid, empty result rather than leaking partial provider or local-path data. Output ordering is deterministic for stable CI diffs.

## Troubleshooting

If a custom EntryPoint is misclassified, set the adapter version explicitly and inspect the finding assumptions. If a report is too noisy, use `--min-severity` or lower the ERC-4337 diagnostic budget while reviewing the highest-confidence findings first. For architectures with generated interfaces, scan the implementation and interface sources together so recognizable field and authorization evidence is available.
