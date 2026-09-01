import type { ReturndataOperation, ReturndataTransition } from "./types";

export type GuardKind =
  | "safe-erc20"
  | "address-function-call"
  | "try-catch"
  | "require-success"
  | "explicit-bubble"
  | "assembly-bounds"
  | "optional-call";

export interface GuardEvidence {
  kind: GuardKind;
  description: string;
  operation?: ReturndataOperation;
}

/** Recognize SafeERC20-style wrappers, Address utilities, try/catch, and validated assembly. */
export function detectGuards(transition: ReturndataTransition): GuardEvidence[] {
  const source = codeText(transition.source);
  const guards: GuardEvidence[] = [];

  if (/SafeERC20|safeTransfer|safeTransferFrom|safeApprove|forceApprove/i.test(source)) {
    guards.push({ kind: "safe-erc20", description: "SafeERC20 wrapper used" });
  }
  if (/Address\.functionCall|Address\.functionCallWithValue|Address\.functionDelegateCall/i.test(source)) {
    guards.push({ kind: "address-function-call", description: "OpenZeppelin Address utility used" });
  }
  if (/try\s+\w+\.|catch\s*\{|catch\s+\w+/i.test(source) || transition.guards.some((g) => /try/i.test(g))) {
    guards.push({ kind: "try-catch", description: "Try/catch error handling present" });
  }
  if (/require\s*\(\s*success|if\s*\(\s*!success|if\s*\(!.*\)\s*revert/i.test(source)) {
    guards.push({ kind: "require-success", description: "Explicit success flag check" });
  }
  if (/revert\s*\(|bubble|propagate/i.test(source) && /catch/i.test(source)) {
    guards.push({ kind: "explicit-bubble", description: "Failure bubbling in catch block" });
  }
  if (/returndatasize\s*\(\)|mload|calldatasize|iszero\s*\(\s*returndatasize/i.test(source)) {
    guards.push({ kind: "assembly-bounds", description: "Assembly returndata bounds check" });
  }
  if (/@dev\s+optional|\/\/\s*optional|ignore\s+failure|best\s+effort/i.test(source)) {
    guards.push({ kind: "optional-call", description: "Documented optional call intent" });
  }

  for (const op of transition.operations) {
    if (op.kind === "guard" && op.checksSuccess) {
      guards.push({ kind: "require-success", description: "Guard checks call success", operation: op });
    }
  }
  return guards;
}

export function isOptionalCall(transition: ReturndataTransition, operation: ReturndataOperation): boolean {
  return detectGuards(transition).some((g) => g.kind === "optional-call") ||
    /optional|bestEffort|tryNotify|_try/i.test(transition.name);
}

export function hasSafeWrapper(transition: ReturndataTransition, operation: ReturndataOperation): boolean {
  if (operation.usesSafeWrapper) return true;
  const guards = detectGuards(transition);
  return guards.some((g) =>
    g.kind === "safe-erc20" || g.kind === "address-function-call" || g.kind === "try-catch",
  );
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
