import type { ReturndataContractModel, ReturndataFrameworkAdapterDefinition, ReturndataFrameworkMatch } from "./types";

export const RETURNDATA_FRAMEWORK_ADAPTERS: readonly ReturndataFrameworkAdapterDefinition[] = Object.freeze([
  {
    id: "safe-erc20-wrapper",
    displayName: "SafeERC20 return-value wrapper",
    requiredPatterns: ["SafeERC20", "safeTransfer"],
    mitigations: ["Token transfers use SafeERC20 which checks return values"],
    limitations: ["Does not cover non-ERC20 token interfaces"],
  },
  {
    id: "address-utilities",
    displayName: "OpenZeppelin Address functionCall utilities",
    requiredPatterns: ["Address.functionCall", "functionCallWithValue"],
    mitigations: ["Low-level calls bubble failures through Address utilities"],
    limitations: ["Assembly paths bypassing Address utilities are not covered"],
  },
  {
    id: "assembly-wrapper",
    displayName: "Assembly returndata copy with bounds",
    requiredPatterns: ["returndatasize", "returndatacopy"],
    mitigations: ["Assembly checks returndatasize before copy"],
    limitations: ["Manual assembly correctness is not formally verified"],
  },
  {
    id: "multicall-batch",
    displayName: "Multicall batch with failure propagation",
    requiredPatterns: ["multicall", "require(success"],
    mitigations: ["Batch calls check individual success flags"],
    limitations: ["Partial failure policies vary by implementation"],
  },
  {
    id: "try-catch-guarded",
    displayName: "Try/catch guarded external calls",
    requiredPatterns: ["try ", "catch"],
    mitigations: ["External call failures are caught and handled"],
    limitations: ["Empty catch blocks may still swallow critical failures"],
  },
]);

export function matchReturndataFramework(
  model: Pick<ReturndataContractModel, "transitions">,
): ReturndataFrameworkMatch {
  const source = model.transitions.map((t) => t.source).join("\n");
  for (const adapter of RETURNDATA_FRAMEWORK_ADAPTERS) {
    const matched = adapter.requiredPatterns.filter((pattern) => source.includes(pattern));
    if (matched.length === adapter.requiredPatterns.length) {
      return { adapter: adapter.id, matchedPatterns: matched.sort() };
    }
  }
  if (/SafeERC20|safeTransfer/i.test(source)) {
    return { adapter: "safe-erc20-wrapper", matchedPatterns: ["SafeERC20"] };
  }
  if (model.transitions.some((t) => t.role === "external-call")) {
    return { adapter: "generic-external-call", matchedPatterns: [] };
  }
  return { adapter: "none", matchedPatterns: [] };
}

export function getReturndataFrameworkAdapter(
  id: ReturndataFrameworkAdapterDefinition["id"],
): ReturndataFrameworkAdapterDefinition {
  const adapter = RETURNDATA_FRAMEWORK_ADAPTERS.find((c) => c.id === id);
  if (!adapter) throw new Error(`Unknown returndata framework adapter: ${id}`);
  return adapter;
}
