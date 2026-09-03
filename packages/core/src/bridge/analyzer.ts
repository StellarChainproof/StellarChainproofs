import { buildMessageFlows } from "./message-flow";
import { hasMitigation } from "./mitigations";
import { tracePayloadEffects } from "./payload-tracer";
import { analyzeProofLoop, countSignatureRecoveries, hasUnsafeQuorumArithmetic } from "./proof-analysis";
import type {
  BridgeContractModel,
  BridgeEvidence,
  BridgeFinding,
  BridgeOperation,
  BridgeRuleId,
  BridgeStateVariable,
  BridgeTransition,
  BridgeVariableRole,
} from "./types";

type Rule = (model: BridgeContractModel) => BridgeFinding[];

const RULE_ORDER: readonly BridgeRuleId[] = Array.from({ length: 16 }, (_, index) =>
  `CP-BRG-${String(index + 1).padStart(3, "0")}` as BridgeRuleId,
);

const RULES: Record<BridgeRuleId, Rule> = {
  "CP-BRG-001": detectMissingSourceBinding,
  "CP-BRG-002": detectMissingDestinationBinding,
  "CP-BRG-003": detectReplayableMessages,
  "CP-BRG-004": detectNonceCollision,
  "CP-BRG-005": detectWeakThresholdTransition,
  "CP-BRG-006": detectVerificationBypass,
  "CP-BRG-007": detectDuplicateValidators,
  "CP-BRG-008": detectUnsortedValidatorSet,
  "CP-BRG-009": detectZeroAddressValidator,
  "CP-BRG-010": detectStaleRoot,
  "CP-BRG-011": detectUnsafeQuorumArithmetic,
  "CP-BRG-012": detectUnvalidatedPayloadExecution,
  "CP-BRG-013": detectMintWithoutLock,
  "CP-BRG-014": detectReleaseWithoutBurn,
  "CP-BRG-015": detectMissingFinalityWindow,
  "CP-BRG-016": detectMissingInboundMitigations,
};

export function analyzeBridgeModel(
  model: BridgeContractModel,
  options: { includeRules?: BridgeRuleId[]; excludeRules?: BridgeRuleId[] } = {},
): BridgeFinding[] {
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const findings: BridgeFinding[] = [];
  for (const id of RULE_ORDER) {
    if (include && !include.has(id)) continue;
    if (exclude.has(id)) continue;
    findings.push(...RULES[id](model));
  }
  return findings.sort(compareFindings);
}

function detectMissingSourceBinding(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const edge of buildMessageFlows(model)) {
    if (edge.direction !== "inbound") continue;
    if (edge.bindsSource || hasMitigation(edge.transition, "domain-binding")) continue;
    const call = privilegedCall(edge.transition);
    if (!call) continue;
    findings.push(finding({
      ruleId: "CP-BRG-001",
      title: `Inbound message in ${edge.transition.name} lacks source chain binding`,
      description:
        "A received cross-chain message reaches state-changing execution without binding authorization " +
        "to a source chain ID, origin domain, or authenticated bridge endpoint. Relayers can replay " +
        "messages from unintended source chains.",
      recommendation:
        "Include sourceChainId or origin in the message hash, verify it against a trusted remote mapping, " +
        "and reject messages whose origin does not match the expected source chain.",
      severity: "critical",
      confidence: "high",
      category: "domain-separation",
      model,
      transition: edge.transition,
      evidence: [
        operationEvidence(call, "Inbound path reaches privileged execution"),
        absenceEvidence(edge.transition, "No source-chain or origin binding was identified"),
      ],
      assumptions: ["Bridge accepts messages from multiple potential source chains"],
    }));
  }
  return findings;
}

function detectMissingDestinationBinding(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const edge of buildMessageFlows(model)) {
    if (edge.direction !== "outbound") continue;
    if (edge.bindsDestination) continue;
    const call = outboundCall(edge.transition);
    if (!call) continue;
    findings.push(finding({
      ruleId: "CP-BRG-002",
      title: `Outbound message in ${edge.transition.name} lacks destination binding`,
      description:
        "An outbound cross-chain message is dispatched without explicit destination chain ID or endpoint " +
        "binding. Messages may be routed to unintended destinations or replayed on wrong chains.",
      recommendation:
        "Bind destinationChainId or endpointId in the message envelope, validate against an allowlist of " +
        "trusted destination chains, and include destination in the signed message hash.",
      severity: "high",
      confidence: "high",
      category: "domain-separation",
      model,
      transition: edge.transition,
      evidence: [
        operationEvidence(call, "Outbound dispatch reaches external call"),
        absenceEvidence(edge.transition, "No destination-chain or endpoint binding was identified"),
      ],
      assumptions: ["The bridge connects to multiple destination chains"],
    }));
  }
  return findings;
}

function detectReplayableMessages(model: BridgeContractModel): BridgeFinding[] {
  const messageState = new Set(variables(model, ["message-id", "processed-messages", "replay-map", "nonce"])
    .map((item) => item.name));
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["receive-message", "execute-message"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const write = firstWrite(transition, messageState);
    if (write && write.order < call.order) continue;
    if (hasMitigation(transition, "replay-map") || hasMitigation(transition, "nonce-consumption")) continue;
    findings.push(finding({
      ruleId: "CP-BRG-003",
      title: `Replayable cross-chain message in ${transition.name}`,
      description:
        "A received message reaches privileged execution without consuming a unique message ID or nonce " +
        "before the call. Relayers or bridges can redeliver the same message to duplicate mints, releases, " +
        "or arbitrary executions.",
      recommendation:
        "Maintain a processed-messages mapping or monotonic nonce, reject already-consumed IDs, and mark " +
        "the message consumed before any external call or token mint/release.",
      severity: "critical",
      confidence: "high",
      category: "replay-protection",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Message path reaches privileged execution"),
        ...(write ? [] : [absenceEvidence(transition, "No pre-call message or nonce consumption write")]),
      ],
      assumptions: ["The transport can deliver duplicate messages"],
    }));
  }
  return findings;
}

function detectNonceCollision(model: BridgeContractModel): BridgeFinding[] {
  const nonceVars = variables(model, ["nonce"]);
  if (!nonceVars.length) return [];
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["send-message", "receive-message"])) {
    const source = codeText(transition.source);
    const reusesNonce = /nonces\[.*\]\s*==|require\s*\(\s*nonces|mapping.*nonce.*bool/i.test(source) &&
      !/nonces\[.*\]\s*=\s*true|nonces\[.*\]\+\+|incrementNonce/i.test(source);
    const noIncrement = transition.role === "send-message" &&
      !/outboundNonce\+\+|nonces\[.*\]\s*=|incrementNonce/i.test(source);
    if (!reusesNonce && !noIncrement) continue;
    findings.push(finding({
      ruleId: "CP-BRG-004",
      title: `Weak nonce management in ${transition.name}`,
      description:
        "Nonce state is read or checked without a visible increment or consumption pattern, enabling " +
        "nonce collisions or predictable replay identifiers across concurrent message submissions.",
      recommendation:
        "Use separate inbound and outbound nonce counters, atomically increment on send, and reject " +
        "messages whose nonce does not exactly match the expected next value.",
      severity: "high",
      confidence: "medium",
      category: "replay-protection",
      model,
      transition,
      evidence: [
        variableEvidence(nonceVars[0], "Nonce state is tracked"),
        absenceEvidence(transition, "No atomic nonce increment or strict sequential check identified"),
      ],
      assumptions: ["Multiple messages can be submitted concurrently"],
    }));
  }
  return findings;
}

function detectWeakThresholdTransition(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["update-validator-set", "update-threshold"])) {
    const source = codeText(transition.source);
    const instantUpdate = !hasMitigation(transition, "two-phase-validator-update") &&
      !/pendingValidators|newThreshold|delay|timelock|schedule/i.test(source);
    const noBoundsCheck = /threshold\s*=|setThreshold/i.test(source) &&
      !/threshold\s*<=\s*validators\.length|threshold\s*>\s*0|require\s*\(\s*threshold/i.test(source);
    if (!instantUpdate && !noBoundsCheck) continue;
    findings.push(finding({
      ruleId: "CP-BRG-005",
      title: `Unsafe validator or threshold update in ${transition.name}`,
      description:
        "Validator set or threshold can be updated in a single transaction without a two-phase delay " +
        "or without bounding the new threshold to [1, validators.length]. A compromised admin can " +
        "instantly reduce quorum to one signer.",
      recommendation:
        "Implement two-phase validator updates with a timelock, require newThreshold > 0 and " +
        "newThreshold <= validators.length, and prevent threshold changes during active validator rotation.",
      severity: "critical",
      confidence: "high",
      category: "validator-governance",
      model,
      transition,
      evidence: [
        absenceEvidence(transition, "Two-phase update or threshold bounds check not identified"),
      ],
      assumptions: ["Validator set updates are controlled by a privileged role"],
    }));
  }
  return findings;
}

function detectVerificationBypass(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["receive-message", "execute-message"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const source = codeText(transition.source);
    const hasProof = hasMitigation(transition, "proof-verification") || hasMitigation(transition, "signature-verification");
    const proofBeforeCall = transition.operations.find((op) =>
      (op.kind === "call" || op.kind === "guard") &&
      /verifyProof|verifySignatures|checkSignatures|validateProof|processedMessages|require\s*\(\s*processed/i.test(op.expression) &&
      op.order < call.order,
    );
    if (hasProof && proofBeforeCall) continue;
    if (/require\s*\(\s*processedMessages|processedMessages\[|!processedMessages/i.test(source)) continue;
    if (transition.role === "receive-message" && /trustedRelayer|onlyRelayer|msg\.sender\s*==.*relayer/i.test(source)) {
      continue;
    }
    findings.push(finding({
      ruleId: "CP-BRG-006",
      title: `Message verification bypass in ${transition.name}`,
      description:
        "A cross-chain message reaches token mint, release, or arbitrary execution without a visible " +
        "proof or signature verification step before the privileged call. Forged messages can be accepted.",
      recommendation:
        "Verify Merkle proofs or validator signatures before any state change. Ensure verification " +
        "dominates the privileged call in execution order and cannot be skipped by control flow.",
      severity: "critical",
      confidence: "high",
      category: "verification",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Privileged execution without preceding verification"),
        absenceEvidence(transition, "No proof or signature verification before privileged call"),
      ],
      assumptions: ["Message payloads originate from untrusted relayers or transport"],
    }));
  }
  return findings;
}

function detectDuplicateValidators(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["verify-signatures", "verify-proof", "receive-message"])) {
    const analysis = analyzeProofLoop(transition);
    if (!analysis.hasLoop || analysis.duplicateCheck) continue;
    if (countSignatureRecoveries(transition) < 2) continue;
    findings.push(finding({
      ruleId: "CP-BRG-007",
      title: `Duplicate validator signatures accepted in ${transition.name}`,
      description:
        "Signature or proof verification iterates over validators without tracking seen signers. " +
        "A single validator can submit multiple signatures to satisfy the threshold.",
      recommendation:
        "Track seen signers in a bitmap or mapping, reject duplicate recoveries, and require distinct " +
        "validator addresses for each signature counted toward the threshold.",
      severity: "critical",
      confidence: "high",
      category: "verification",
      model,
      transition,
      evidence: [
        proofLoopEvidence(transition, "Signature loop lacks duplicate detection"),
      ],
      assumptions: ["Multiple signatures are collected in a single verification loop"],
    }));
  }
  return findings;
}

function detectUnsortedValidatorSet(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["verify-signatures", "verify-proof"])) {
    const analysis = analyzeProofLoop(transition);
    if (!analysis.hasLoop || analysis.sortingCheck) continue;
    if (countSignatureRecoveries(transition) === 0) continue;
    findings.push(finding({
      ruleId: "CP-BRG-008",
      title: `Unsorted validator set in ${transition.name}`,
      description:
        "Signature verification does not enforce sorted validator ordering. Unsorted sets enable " +
        "signature malleability and complicate duplicate detection across validator rotations.",
      recommendation:
        "Require signers to be sorted in ascending address order, verify each signer exceeds the " +
        "previous, and reject out-of-order or duplicate entries.",
      severity: "medium",
      confidence: "medium",
      category: "verification",
      model,
      transition,
      evidence: [
        proofLoopEvidence(transition, "Validator loop lacks sorting requirement"),
      ],
      assumptions: ["Threshold verification accepts variable-length signature arrays"],
    }));
  }
  return findings;
}

function detectZeroAddressValidator(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["verify-signatures", "update-validator-set", "verify-proof"])) {
    const analysis = analyzeProofLoop(transition);
    const source = codeText(transition.source);
    const checksZero = analysis.zeroAddressCheck ||
      /address\s*\(\s*0\s*\)|zeroAddress|!=\s*address\(0\)/i.test(source);
    if (checksZero) continue;
    if (transition.role === "update-validator-set" &&
      /require\s*\(\s*validator\s*!=|push\s*\(\s*validator\s*\)/i.test(source)) continue;
    if (countSignatureRecoveries(transition) === 0 && transition.role !== "update-validator-set") continue;
    findings.push(finding({
      ruleId: "CP-BRG-009",
      title: `Zero-address validator not rejected in ${transition.name}`,
      description:
        "Validator set management or signature verification does not explicitly reject the zero address. " +
        "Zero-address entries can reduce effective quorum or enable signature forgery edge cases.",
      recommendation:
        "Require validator != address(0) on add and during signature recovery. Reject ecrecover results " +
        "that resolve to the zero address.",
      severity: "high",
      confidence: "medium",
      category: "verification",
      model,
      transition,
      evidence: [
        absenceEvidence(transition, "No zero-address rejection for validators or recovered signers"),
      ],
      assumptions: ["Validator addresses are supplied by external callers or signatures"],
    }));
  }
  return findings;
}

function detectStaleRoot(model: BridgeContractModel): BridgeFinding[] {
  const roots = variables(model, ["merkle-root", "state-root"]);
  if (!roots.length) return [];
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["verify-proof", "receive-message"])) {
    const analysis = analyzeProofLoop(transition);
    const source = codeText(transition.source);
    if (analysis.staleRootCheck || /rootUpdatedAt|rootTimestamp|block\.timestamp\s*>=\s*root/i.test(source)) continue;
    if (!/verifyProof|merkleRoot|stateRoot|processProof/i.test(source)) continue;
    findings.push(finding({
      ruleId: "CP-BRG-010",
      title: `Stale Merkle or state root accepted in ${transition.name}`,
      description:
        "Proof verification references a stored root without checking recency, update timestamp, or " +
        "block height. Proofs against superseded roots can authorize outdated or forked state.",
      recommendation:
        "Track root update block/timestamp, reject proofs against roots older than a configured finality " +
        "window, and require root updates to propagate before accepting new proofs.",
      severity: "high",
      confidence: "medium",
      category: "verification",
      model,
      transition,
      evidence: [
        variableEvidence(roots[0], "Merkle or state root stored on-chain"),
        absenceEvidence(transition, "No root staleness or recency check identified"),
      ],
      assumptions: ["Roots can be updated while older proofs remain valid off-chain"],
    }));
  }
  return findings;
}

function detectUnsafeQuorumArithmetic(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["verify-signatures", "verify-proof", "receive-message"])) {
    const badArithmetic = hasUnsafeQuorumArithmetic(transition);
    const source = codeText(transition.source);
    const zeroThreshold = /threshold\s*(?:==|<=)\s*0|signatures\.length\s*>=\s*0/i.test(source);
    if (!badArithmetic && !zeroThreshold) continue;
    findings.push(finding({
      ruleId: "CP-BRG-011",
      title: `Unsafe quorum arithmetic in ${transition.name}`,
      description:
        "Validator threshold math truncates before multiplication or permits a zero threshold. " +
        "Small validator sets and integer division can collapse the required signature count.",
      recommendation:
        "Use full-precision mulDiv for threshold calculations, require threshold > 0 and " +
        "threshold <= validators.length, and document inclusive boundary behavior.",
      severity: "high",
      confidence: "high",
      category: "validator-governance",
      model,
      transition,
      evidence: [
        ...(badArithmetic ? [operationEvidence(badArithmetic, "Unsafe division in threshold math")] : []),
        absenceEvidence(transition, "Threshold lower bound not enforced"),
      ],
      assumptions: ["Solidity integer truncation applies to threshold calculations"],
    }));
  }
  return findings;
}

function detectUnvalidatedPayloadExecution(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["receive-message", "execute-message"])) {
    for (const trace of tracePayloadEffects(transition)) {
      if (trace.validated || trace.effect !== "arbitrary-call") continue;
      findings.push(finding({
        ruleId: "CP-BRG-012",
        title: `Unvalidated message payload executes arbitrary call in ${transition.name}`,
        description:
          "Message calldata flows into a low-level call or delegatecall without verified proof, " +
          "signature, or replay protection. Attackers can craft payloads for token theft, upgrades, " +
          "or role grants.",
        recommendation:
          "Constrain executable payloads to an allowlist of selectors, validate message hash and " +
          "replay state before call, and prefer typed execution over arbitrary .call(data).",
        severity: "critical",
        confidence: "high",
        category: "payload-execution",
        model,
        transition,
        evidence: [
          taintEvidence(trace.privilegedCall, "Message parameter reaches arbitrary execution"),
          ...(trace.payloadSources.length ?
            [absenceEvidence(transition, `Payload sources: ${trace.payloadSources.join(", ")}`)] : []),
        ],
        assumptions: ["Message payload bytes are attacker-controlled"],
      }));
    }
  }
  return findings;
}

function detectMintWithoutLock(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  const mintRoles: BridgeTransition["role"][] = ["mint-tokens", "receive-message", "execute-message"];
  for (const transition of byRoles(model, mintRoles)) {
    const mintCall = transition.operations.find((op) =>
      op.kind === "call" && /mint|_mint/i.test(op.expression),
    );
    if (!mintCall) continue;
    const source = codeText(transition.source);
    const verifiesLock = /verifyProof|verifySignatures|totalLocked|lockedAmount|lockVerified|processedMessages|amount\s*<=.*totalLocked/i.test(source);
    if (verifiesLock) continue;
    findings.push(finding({
      ruleId: "CP-BRG-013",
      title: `Token mint in ${transition.name} without verified lock`,
      description:
        "Wrapped or bridged tokens are minted without verifying a corresponding lock event on the " +
        "source chain. Attackers can inflate wrapped supply without depositing collateral.",
      recommendation:
        "Mint only after verifying a proof of lock on the source chain, tracking cumulative locked vs " +
        "minted amounts, and rejecting mint requests exceeding verified lock balance.",
      severity: "critical",
      confidence: "high",
      category: "token-bridge",
      model,
      transition,
      evidence: [
        operationEvidence(mintCall, "Mint call without visible lock verification"),
        absenceEvidence(transition, "No lock proof or locked-amount check before mint"),
      ],
      assumptions: ["Minted tokens represent locked collateral on another chain"],
    }));
  }
  return findings;
}

function detectReleaseWithoutBurn(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["release-tokens"])) {
    const releaseCall = transition.operations.find((op) =>
      op.kind === "call" && /transfer|release|withdraw|_transfer/i.test(op.expression),
    );
    if (!releaseCall) continue;
    const source = codeText(transition.source);
    const verifiesBurn = /verifyProof|verifySignatures|totalBurned|burnedAmount|burnVerified|processedMessages/i.test(source);
    const burnTransition = model.transitions.some((t) => t.role === "burn-tokens");
    if (verifiesBurn) continue;
    if (!burnTransition && !variables(model, ["burn-amount"]).length) continue;
    findings.push(finding({
      ruleId: "CP-BRG-014",
      title: `Token release in ${transition.name} without verified burn`,
      description:
        "Locked or escrowed tokens are released without verifying a corresponding burn on the " +
        "destination chain. Double-spending across chains becomes possible.",
      recommendation:
        "Release only after verifying a proof of burn on the destination chain, tracking cumulative " +
        "burned vs released amounts, and rejecting releases exceeding verified burn balance.",
      severity: "critical",
      confidence: "high",
      category: "token-bridge",
      model,
      transition,
      evidence: [
        operationEvidence(releaseCall, "Release call without visible burn verification"),
        absenceEvidence(transition, "No burn proof or burned-amount check before release"),
      ],
      assumptions: ["Released tokens correspond to burns on another chain"],
    }));
  }
  return findings;
}

function detectMissingFinalityWindow(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["execute-message", "receive-message"])) {
    if (hasMitigation(transition, "delayed-finality")) continue;
    const finalityVars = variables(model, ["finality-window"]);
    const source = codeText(transition.source);
    const hasFinalityCheck = finalityVars.some((v) => source.includes(v.name)) ||
      /challengePeriod|confirmationBlocks|finalityDelay|block\.number\s*>=\s*.*\+/i.test(source);
    if (hasFinalityCheck) continue;
    const call = privilegedCall(transition);
    if (!call) continue;
    const isOptimistic = model.adapter === "optimistic-bridge" ||
      model.transitions.some((t) => t.role === "relay-message");
    if (!isOptimistic && finalityVars.length === 0) continue;
    findings.push(finding({
      ruleId: "CP-BRG-015",
      title: `Missing finality window before execution in ${transition.name}`,
      description:
        "Cross-chain message execution proceeds immediately without a challenge period, confirmation " +
        "block delay, or finality window. Reorgs or fraudulent messages can finalize before detection.",
      recommendation:
        "Introduce a configurable finality delay between message acceptance and execution. Allow " +
        "challengers to dispute during the window and only finalize after the delay elapses.",
      severity: "high",
      confidence: "medium",
      category: "finality",
      model,
      transition,
      evidence: [
        operationEvidence(call, "Immediate execution without finality delay"),
        absenceEvidence(transition, "No challenge period or confirmation block check"),
      ],
      assumptions: ["Source chain reorgs or optimistic fraud are in threat model"],
    }));
  }
  return findings;
}

function detectMissingInboundMitigations(model: BridgeContractModel): BridgeFinding[] {
  const findings: BridgeFinding[] = [];
  for (const transition of byRoles(model, ["receive-message", "execute-message"])) {
    const call = privilegedCall(transition);
    if (!call) continue;
    const mitigations = [
      hasMitigation(transition, "pause-guard"),
      hasMitigation(transition, "rate-limit"),
      hasMitigation(transition, "replay-map"),
    ];
    if (mitigations.filter(Boolean).length >= 2) continue;
    const pauseVar = variables(model, ["bridge-paused"]);
    const rateVar = variables(model, ["rate-limit"]);
    if (pauseVar.length && rateVar.length) continue;
    findings.push(finding({
      ruleId: "CP-BRG-016",
      title: `High-risk inbound path lacks pause or rate-limit in ${transition.name}`,
      description:
        "An inbound message path that mints tokens or executes payloads lacks adequate operational " +
        "mitigations such as pause controls or rate limiting. Incidents cannot be contained quickly.",
      recommendation:
        "Add whenNotPaused guards, configurable rate limits on inbound message volume, and an " +
        "emergency pause controlled by a multisig or timelock.",
      severity: "medium",
      confidence: "medium",
      category: "operational-safety",
      model,
      transition,
      evidence: [
        operationEvidence(call, "High-risk inbound execution path"),
        absenceEvidence(transition, "Insufficient pause and rate-limit mitigations"),
      ],
      assumptions: ["Bridge operators need incident response controls"],
    }));
  }
  return findings;
}

interface FindingInput {
  ruleId: BridgeRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: BridgeFinding["severity"];
  confidence: BridgeFinding["confidence"];
  category: string;
  model: BridgeContractModel;
  transition?: BridgeTransition;
  location?: BridgeFinding["location"];
  evidence: BridgeEvidence[];
  assumptions: string[];
}

function finding(input: FindingInput): BridgeFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    recommendation: input.recommendation,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    contract: input.model.name,
    location: input.location ?? input.transition?.location ?? input.model.location,
    evidence: input.evidence,
    assumptions: input.assumptions,
  };
}

function byRoles(model: BridgeContractModel, roles: BridgeTransition["role"][]): BridgeTransition[] {
  const selected = new Set(roles);
  return model.transitions.filter((transition) => selected.has(transition.role));
}

function variables(model: BridgeContractModel, roles: BridgeVariableRole[]): BridgeStateVariable[] {
  const selected = new Set(roles);
  return model.stateVariables.filter((variable) => selected.has(variable.role));
}

function privilegedCall(transition: BridgeTransition): BridgeOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "call" && (/call|delegatecall|functioncall|execute|mint|release|upgradeto/i.test(operation.name) ||
      /\.call\s*\{|\.delegatecall\s*\(|\.mint\s*\(|upgradeto/i.test(operation.expression)),
  );
}

function outboundCall(transition: BridgeTransition): BridgeOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "call" && /send|dispatch|publish|emit/i.test(operation.name + operation.expression),
  );
}

function firstWrite(transition: BridgeTransition, names: Set<string>): BridgeOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "write" && [...names].some((name) =>
      operation.name.split(",").includes(name) || operation.expression.includes(name),
    ),
  );
}

function operationEvidence(operation: BridgeOperation, description: string): BridgeEvidence {
  return {
    kind: operation.kind === "write" ? "state-write" : operation.kind === "arithmetic" ?
      "arithmetic" : operation.kind === "guard" ? "branch" : "call",
    description,
    location: operation.location,
    snippet: operation.expression,
  };
}

function taintEvidence(operation: BridgeOperation, description: string): BridgeEvidence {
  return {
    kind: "taint-flow",
    description: `${description}; sources: ${operation.parameterSources.join(", ")}`,
    location: operation.location,
    snippet: operation.expression,
  };
}

function variableEvidence(variable: BridgeStateVariable, description: string): BridgeEvidence {
  return {
    kind: "state-read",
    description,
    location: variable.location,
    snippet: `${variable.typeName} ${variable.name}`,
  };
}

function absenceEvidence(transition: BridgeTransition, description: string): BridgeEvidence {
  return { kind: "absence", description, location: transition.location };
}

function proofLoopEvidence(transition: BridgeTransition, description: string): BridgeEvidence {
  return { kind: "proof-loop", description, location: transition.location, snippet: transition.source.slice(0, 200) };
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}

function compareFindings(left: BridgeFinding, right: BridgeFinding): number {
  return left.location.file.localeCompare(right.location.file) || left.location.line - right.location.line ||
    left.location.column - right.location.column || left.ruleId.localeCompare(right.ruleId) ||
    left.title.localeCompare(right.title);
}
