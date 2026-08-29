import type { BridgeTransition } from "./types";

/** Recognized cross-chain mitigations that suppress or downgrade findings. */
export type BridgeMitigationKind =
  | "pause-guard"
  | "rate-limit"
  | "replay-map"
  | "two-phase-validator-update"
  | "delayed-finality"
  | "nonce-consumption"
  | "domain-binding"
  | "proof-verification"
  | "signature-verification";

export interface BridgeMitigationEvidence {
  kind: BridgeMitigationKind;
  description: string;
  expression: string;
}

/** Detect structural mitigations present in a bridge transition's source and operations. */
export function detectMitigations(transition: BridgeTransition): BridgeMitigationEvidence[] {
  const source = codeText(transition.source);
  const mitigations: BridgeMitigationEvidence[] = [];

  if (/whenNotPaused|!paused|!isPaused|require\s*\(\s*!.*paused/i.test(source) ||
    transition.modifiers.some((m) => /pause|whennotpaused/i.test(m))) {
    mitigations.push({
      kind: "pause-guard",
      description: "Transition is guarded by a pause check",
      expression: "pause guard",
    });
  }

  if (/rateLimit|messageLimit|dailyLimit|hourlyLimit|maxMessagesPer/i.test(source)) {
    mitigations.push({
      kind: "rate-limit",
      description: "Rate limiting is referenced in the transition",
      expression: "rate limit",
    });
  }

  if (/processedMessages|consumedMessages|handledMessages|executedMessages|replayMap|seenMessages/i.test(source)) {
    mitigations.push({
      kind: "replay-map",
      description: "Replay or processed-message map is referenced",
      expression: "replay map",
    });
  }

  if (/pendingValidators|newValidators|validatorEpoch|twoPhase|commitValidators/i.test(source)) {
    mitigations.push({
      kind: "two-phase-validator-update",
      description: "Two-phase validator set update pattern detected",
      expression: "two-phase validator update",
    });
  }

  if (/finalityWindow|challengePeriod|confirmationBlocks|block\.number\s*>=\s*.*\+|block\.timestamp\s*>=\s*.*\+/i.test(source)) {
    mitigations.push({
      kind: "delayed-finality",
      description: "Delayed finality or challenge window referenced",
      expression: "delayed finality",
    });
  }

  if (/nonce\+\+|nonces\[|inboundNonce|outboundNonce|incrementNonce/i.test(source)) {
    mitigations.push({
      kind: "nonce-consumption",
      description: "Nonce consumption or increment detected",
      expression: "nonce consumption",
    });
  }

  if (/sourceChainId|originChain|destinationChain|domainSeparator|endpointId|block\.chainid/i.test(source)) {
    mitigations.push({
      kind: "domain-binding",
      description: "Chain domain or source/destination binding referenced",
      expression: "domain binding",
    });
  }

  if (/verifyProof|verifyMerkleProof|MerkleProof|processProof|checkProof/i.test(source)) {
    mitigations.push({
      kind: "proof-verification",
      description: "Merkle or state proof verification referenced",
      expression: "proof verification",
    });
  }

  if (/verifySignatures|checkSignatures|ecrecover|recoverSigner|validateSignatures/i.test(source)) {
    mitigations.push({
      kind: "signature-verification",
      description: "Signature or validator verification referenced",
      expression: "signature verification",
    });
  }

  return mitigations;
}

export function hasMitigation(
  transition: BridgeTransition,
  kind: BridgeMitigationKind,
): boolean {
  return detectMitigations(transition).some((item) => item.kind === kind);
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
