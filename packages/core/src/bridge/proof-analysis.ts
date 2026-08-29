import type { BridgeOperation, BridgeTransition } from "./types";

export interface ProofLoopAnalysis {
  hasLoop: boolean;
  duplicateCheck: boolean;
  sortingCheck: boolean;
  zeroAddressCheck: boolean;
  staleRootCheck: boolean;
  thresholdCheck: boolean;
  loopExpression: string;
}

/** Analyze proof and signature verification loops for common vulnerabilities. */
export function analyzeProofLoop(transition: BridgeTransition): ProofLoopAnalysis {
  const source = codeText(transition.source);
  const loopOps = transition.operations.filter((op) => op.kind === "loop" || /for\s*\(|while\s*\(/i.test(op.expression));
  const hasLoop = loopOps.length > 0 || /for\s*\(|while\s*\(/i.test(source);

  return {
    hasLoop,
    duplicateCheck: /seen|visited|duplicate|alreadySigned|hasSigned|signers\[|validators\[/i.test(source),
    sortingCheck: /sort|sorted|isSorted|previousSigner|lastSigner|signers\[i\s*-\s*1\]/i.test(source),
    zeroAddressCheck: /address\s*\(\s*0\s*\)|zeroAddress|!=\s*0x0|!=\s*address\(0\)/i.test(source),
    staleRootCheck: /rootUpdatedAt|rootTimestamp|block\.number\s*-|block\.timestamp\s*-|latestRoot/i.test(source),
    thresholdCheck: /threshold|quorum|signatures\.length|validSignatures|count\s*>=/i.test(source),
    loopExpression: loopOps[0]?.expression ?? "",
  };
}

/** Detect unsafe quorum arithmetic in threshold calculations. */
export function hasUnsafeQuorumArithmetic(transition: BridgeTransition): BridgeOperation | undefined {
  return transition.operations.find((operation) =>
    operation.kind === "arithmetic" && (
      divisionBeforeMultiplication(operation.expression) ||
      /threshold\s*(?:==|<=)\s*0|signatures\.length\s*<\s*threshold/i.test(operation.expression)
    ),
  );
}

/** Count signature recovery operations in a transition. */
export function countSignatureRecoveries(transition: BridgeTransition): number {
  const source = codeText(transition.source);
  const matches = source.match(/ecrecover|recoverSigner|recover\s*\(/gi);
  return matches?.length ?? 0;
}

function divisionBeforeMultiplication(expression: string): boolean {
  const value = expression.replace(/\s+/g, "");
  return /^[^;=]+\/[^;=]+\*/.test(value) || /\([^()]+\/[^()]+\)\s*\*/.test(expression);
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
