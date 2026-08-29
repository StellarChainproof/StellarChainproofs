import type { BridgeOperation, BridgeTransition } from "./types";

export type PrivilegedEffect =
  | "arbitrary-call"
  | "token-mint"
  | "token-release"
  | "upgrade"
  | "role-grant";

export interface PayloadTrace {
  transition: BridgeTransition;
  privilegedCall: BridgeOperation;
  effect: PrivilegedEffect;
  payloadSources: string[];
  validated: boolean;
}

/** Trace message payload parameters into privileged state-changing effects. */
export function tracePayloadEffects(transition: BridgeTransition): PayloadTrace[] {
  const traces: PayloadTrace[] = [];
  const source = codeText(transition.source);
  const validated = /verifyProof|verifySignatures|checkSignatures|require\s*\(\s*processed|require\s*\(\s*!.*processed/i.test(source);

  for (const operation of transition.operations) {
    if (operation.kind !== "call") continue;
    const effect = classifyEffect(operation);
    if (!effect) continue;
    traces.push({
      transition,
      privilegedCall: operation,
      effect,
      payloadSources: operation.parameterSources,
      validated,
    });
  }
  return traces;
}

function classifyEffect(operation: BridgeOperation): PrivilegedEffect | null {
  const expr = operation.expression.toLowerCase();
  if (/\.call\s*\{|\.call\(|functioncall|delegatecall/.test(expr)) return "arbitrary-call";
  if (/\.mint\s*\(|minttokens|_mint\s*\(/.test(expr)) return "token-mint";
  if (/\.transfer\s*\(|release|withdraw|unlock|_transfer\s*\(/.test(expr) && /release|unlock|withdraw/.test(expr)) {
    return "token-release";
  }
  if (/upgradeto|upgradetoandcall|authorizeupgrade/.test(expr)) return "upgrade";
  if (/grantrole|_grantrole/.test(expr)) return "role-grant";
  if (/^call$|^delegatecall$|^execute$/i.test(operation.name)) return "arbitrary-call";
  if (/^mint$/i.test(operation.name)) return "token-mint";
  if (/^release$|^withdraw$|^unlock$/i.test(operation.name)) return "token-release";
  if (/^upgrade$/i.test(operation.name)) return "upgrade";
  return null;
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
