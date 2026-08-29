import type {
  BridgeContractModel,
  BridgeFrameworkAdapter,
  BridgeFrameworkAdapterDefinition,
  BridgeFrameworkMatch,
} from "./types";

export const BRIDGE_FRAMEWORK_ADAPTERS: readonly BridgeFrameworkAdapterDefinition[] =
  Object.freeze([
    {
      id: "lock-mint-bridge",
      displayName: "Lock-and-mint token bridge",
      requiredStateGroups: [["totalLocked", "lockedAmount"], ["totalMinted", "mintedAmount"]],
      requiredFunctions: ["lockTokens", "mintTokens"],
      mitigations: [
        "Lock and mint amounts are tracked independently",
        "Minting is expected to follow verified lock events",
      ],
      limitations: [
        "The adapter does not prove lock verification precedes minting",
        "Token decimal normalization and fee handling remain deployment-specific",
      ],
    },
    {
      id: "burn-release-bridge",
      displayName: "Burn-and-release token bridge",
      requiredStateGroups: [["totalBurned", "burnedAmount"], ["totalReleased", "releasedAmount"]],
      requiredFunctions: ["burnTokens", "releaseTokens"],
      mitigations: [
        "Burn and release amounts are tracked independently",
        "Release is expected to follow verified burn events",
      ],
      limitations: [
        "The adapter does not prove burn verification precedes release",
        "Liquidity availability on the destination chain is not modeled",
      ],
    },
    {
      id: "optimistic-bridge",
      displayName: "Optimistic message bridge with challenge window",
      requiredStateGroups: [["finalityWindow", "challengePeriod"], ["processedMessages", "executedMessages"]],
      requiredFunctions: ["receiveMessage", "executeMessage"],
      mitigations: [
        "A finality or challenge window is represented before execution",
        "Processed message state prevents immediate replay",
      ],
      limitations: [
        "Fraud proof correctness and challenger incentives are not verified",
        "Relayer liveness assumptions remain external",
      ],
    },
    {
      id: "multisig-validator-bridge",
      displayName: "Multisig validator threshold bridge",
      requiredStateGroups: [["validators", "signers"], ["threshold", "validatorThreshold"]],
      requiredFunctions: ["verifySignatures", "receiveMessage"],
      mitigations: [
        "Validator set and threshold are independently represented",
        "Signature verification is a distinct transition from execution",
      ],
      limitations: [
        "Validator uniqueness, sorting, and zero-address rejection are not proven",
        "Threshold transition safety during validator rotation is not verified",
      ],
    },
    {
      id: "merkle-proof-bridge",
      displayName: "Merkle proof verified message bridge",
      requiredStateGroups: [["merkleRoot", "stateRoot"], ["processedMessages", "messageId"]],
      requiredFunctions: ["verifyProof", "receiveMessage"],
      mitigations: [
        "Merkle or state root is stored and referenced during verification",
        "Message consumption state prevents replay",
      ],
      limitations: [
        "Root update authorization and staleness checks are not proven",
        "Proof construction correctness depends on off-chain indexing",
      ],
    },
    {
      id: "layerzero-style",
      displayName: "LayerZero-style endpoint messaging",
      requiredStateGroups: [["endpointId", "chainId"], ["inboundNonce", "outboundNonce"]],
      requiredFunctions: ["send", "lzReceive"],
      mitigations: [
        "Separate inbound and outbound nonce tracking",
        "Endpoint or chain ID provides domain separation",
      ],
      limitations: [
        "Trusted remote configuration and library upgrade paths are not verified",
        "DVN/Oracle configuration remains deployment-specific",
      ],
    },
    {
      id: "wormhole-style",
      displayName: "Wormhole-style guardian verified messaging",
      requiredStateGroups: [["guardians", "validators"], ["processedMessages", "consumedMessages"]],
      requiredFunctions: ["publishMessage", "receiveMessage"],
      mitigations: [
        "Guardian set is represented in state",
        "Message consumption tracking prevents replay",
      ],
      limitations: [
        "Guardian set upgrade governance and VAA parsing are not verified",
        "Finality assumptions for each connected chain remain external",
      ],
    },
    {
      id: "axelar-style",
      displayName: "Axelar-style gateway with proof verification",
      requiredStateGroups: [["validators", "threshold"], ["processedMessages"]],
      requiredFunctions: ["validateProof", "execute"],
      mitigations: [
        "Proof validation is separated from execution",
        "Validator threshold is independently stored",
      ],
      limitations: [
        "Key rotation and proof format evolution are not verified",
        "Gas token routing and express execution paths need independent review",
      ],
    },
  ]);

export function matchBridgeFramework(
  model: Pick<BridgeContractModel, "stateVariables" | "transitions">,
): BridgeFrameworkMatch {
  const states = new Map(model.stateVariables.map((variable) => [normalize(variable.name), variable.name]));
  const functions = new Map(model.transitions.map((transition) => [normalize(transition.name), transition.name]));
  for (const adapter of BRIDGE_FRAMEWORK_ADAPTERS) {
    const matchedState: string[] = [];
    let complete = true;
    for (const group of adapter.requiredStateGroups) {
      const match = group
        .map((name) => states.get(normalize(name)))
        .find((value): value is string => value !== undefined);
      if (!match) {
        complete = false;
        break;
      }
      matchedState.push(match);
    }
    if (!complete) continue;
    const matchedFunctions: string[] = [];
    for (const name of adapter.requiredFunctions) {
      const match = functions.get(normalize(name));
      if (!match) {
        complete = false;
        break;
      }
      matchedFunctions.push(match);
    }
    if (!complete) continue;
    return {
      adapter: adapter.id,
      matchedState: matchedState.sort(),
      matchedFunctions: matchedFunctions.sort(),
    };
  }

  const roles = new Set(model.transitions.map((transition) => transition.role));
  const stateRoles = new Set(model.stateVariables.map((variable) => variable.role));
  if (roles.has("lock-tokens") && roles.has("mint-tokens")) {
    return { adapter: "lock-mint-bridge", matchedState: [], matchedFunctions: [] };
  }
  if (roles.has("burn-tokens") && roles.has("release-tokens")) {
    return { adapter: "burn-release-bridge", matchedState: [], matchedFunctions: [] };
  }
  if (stateRoles.has("finality-window") && roles.has("execute-message")) {
    return { adapter: "optimistic-bridge", matchedState: [], matchedFunctions: [] };
  }
  if (stateRoles.has("validator-set") && roles.has("verify-signatures")) {
    return { adapter: "multisig-validator-bridge", matchedState: [], matchedFunctions: [] };
  }
  if (stateRoles.has("merkle-root") && roles.has("verify-proof")) {
    return { adapter: "merkle-proof-bridge", matchedState: [], matchedFunctions: [] };
  }
  if (roles.has("send-message") || roles.has("receive-message")) {
    return { adapter: "generic-bridge", matchedState: [], matchedFunctions: [] };
  }
  return { adapter: "none", matchedState: [], matchedFunctions: [] };
}

export function getBridgeFrameworkAdapter(
  id: BridgeFrameworkAdapterDefinition["id"],
): BridgeFrameworkAdapterDefinition {
  const adapter = BRIDGE_FRAMEWORK_ADAPTERS.find((candidate) => candidate.id === id);
  if (!adapter) throw new Error(`Unknown bridge framework adapter: ${id}`);
  return adapter;
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}
