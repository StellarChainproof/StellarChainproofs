import type {
  AmmContractModel,
  AmmFrameworkAdapter,
  AmmFrameworkAdapterDefinition,
  AmmFrameworkAdapterMatch,
} from "./types";

export const AMM_FRAMEWORK_ADAPTERS: ReadonlyArray<AmmFrameworkAdapterDefinition> = [
  {
    id: "constant-product",
    displayName: "Constant Product Pool",
    requiredStateGroups: [["reserve-balance-a", "reserve-balance-b", "total-supply"]],
    requiredFunctions: ["swap", "mint-liquidity", "burn-liquidity"],
    guarantees: ["k = x * y invariant is tracked across swaps and liquidity operations"],
    limitations: ["does not model concentrated liquidity or stable-swap fees automatically"],
  },
  {
    id: "stable-swap",
    displayName: "Stable Swap Pool",
    requiredStateGroups: [["reserve-balance-a", "reserve-balance-b", "invariant", "fee-rate"]],
    requiredFunctions: ["swap", "sync-reserves", "set-fees"],
    guarantees: ["invariant and fee logic are emphasized over constant product assumptions"],
    limitations: ["custom formulas or asset-specific pegging are out of scope for generic checks"],
  },
  {
    id: "weighted-pool",
    displayName: "Weighted Pool",
    requiredStateGroups: [["reserve-balance-a", "reserve-balance-b", "total-supply", "invariant"]],
    requiredFunctions: ["mint-liquidity", "burn-liquidity", "swap"],
    guarantees: ["weighted pool formulas use multiple reserve balances and a weighted invariant"],
    limitations: ["dynamic weight changes and custom calibration are not assumed"],
  },
  {
    id: "concentrated-liquidity",
    displayName: "Concentrated Liquidity",
    requiredStateGroups: [["price-bound", "liquidity-balances", "reserve-balance-a", "reserve-balance-b"]],
    requiredFunctions: ["mint-liquidity", "burn-liquidity", "swap", "update-oracle"],
    guarantees: ["liquidity ranges and price bounds are part of the accounting model"],
    limitations: ["custom position accounting and tick math are intentionally simplified"],
  },
];

export function matchAmmFrameworkAdapter(model: Pick<AmmContractModel, "stateVariables" | "transitions">): AmmFrameworkAdapterMatch {
  const stateNames = new Set(model.stateVariables.map((state) => state.role));
  const functionNames = new Set(model.transitions.map((transition) => transition.role));

  for (const adapter of AMM_FRAMEWORK_ADAPTERS) {
    const matchedState = adapter.requiredStateGroups.flatMap((group) =>
      group.filter((role) => stateNames.has(role as never)),
    );
    const matchedFunctions = adapter.requiredFunctions.filter((role) => functionNames.has(role as never));
    const score = matchedState.length + matchedFunctions.length;
    if (score > 0) {
      return {
        adapter: adapter.id,
        matchedState: [...new Set(matchedState)],
        matchedFunctions: [...new Set(matchedFunctions)],
      };
    }
  }

  return { adapter: "generic-amm", matchedState: [], matchedFunctions: [] };
}

export function getAmmFrameworkAdapter(model: Pick<AmmContractModel, "stateVariables" | "transitions">): AmmFrameworkAdapter {
  return matchAmmFrameworkAdapter(model).adapter;
}
