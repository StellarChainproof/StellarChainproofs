import type { BridgeContractModel, BridgeTransition } from "./types";

export type MessageDirection = "outbound" | "inbound" | "bidirectional";

export interface MessageFlowEdge {
  direction: MessageDirection;
  transition: BridgeTransition;
  bindsSource: boolean;
  bindsDestination: boolean;
  consumesNonce: boolean;
  consumesMessageId: boolean;
}

/** Model outbound and inbound message flows across bridge transitions. */
export function buildMessageFlows(model: BridgeContractModel): MessageFlowEdge[] {
  const edges: MessageFlowEdge[] = [];
  for (const transition of model.transitions) {
    const direction = classifyDirection(transition.role);
    if (direction === "bidirectional") continue;
    edges.push({
      direction,
      transition,
      bindsSource: hasSourceBinding(transition),
      bindsDestination: hasDestinationBinding(transition),
      consumesNonce: hasNonceConsumption(transition),
      consumesMessageId: hasMessageIdConsumption(transition),
    });
  }
  return edges.sort((left, right) =>
    left.transition.location.line - right.transition.location.line ||
    left.transition.name.localeCompare(right.transition.name),
  );
}

function classifyDirection(role: BridgeTransition["role"]): MessageDirection {
  if (["send-message", "lock-tokens", "burn-tokens"].includes(role)) return "outbound";
  if (["receive-message", "execute-message", "relay-message"].includes(role)) return "inbound";
  return "bidirectional";
}

function hasSourceBinding(transition: BridgeTransition): boolean {
  const source = codeText(transition.source);
  return /sourceChainId|originChain|fromChain|srcChain|origin\s*==|msg\.sender\s*==.*bridge/i.test(source);
}

function hasDestinationBinding(transition: BridgeTransition): boolean {
  const source = codeText(transition.source);
  return /destChainId|destinationChain|toChain|dstChain|targetChain|endpointId/i.test(source);
}

function hasNonceConsumption(transition: BridgeTransition): boolean {
  const source = codeText(transition.source);
  const nonceWrite = transition.operations.find((op) =>
    op.kind === "write" && /nonce/i.test(op.expression),
  );
  return Boolean(nonceWrite) || /nonces\[|nonce\+\+|incrementNonce|inboundNonce/i.test(source);
}

function hasMessageIdConsumption(transition: BridgeTransition): boolean {
  const source = codeText(transition.source);
  const idWrite = transition.operations.find((op) =>
    op.kind === "write" && /processed|consumed|executed|handled/i.test(op.expression),
  );
  return Boolean(idWrite) || /processedMessages|consumedMessages|executedMessages/i.test(source);
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
