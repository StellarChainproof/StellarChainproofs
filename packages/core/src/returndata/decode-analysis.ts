import type { ReturndataOperation, ReturndataTransition } from "./types";

export interface DecodeAnalysis {
  hasLengthCheck: boolean;
  hasTryCatch: boolean;
  usesCalldataSlice: boolean;
  targetType: string;
  expression: string;
}

/** Analyze ABI decode sites for unsafe decoding patterns. */
export function analyzeDecodeSites(transition: ReturndataTransition): DecodeAnalysis[] {
  const results: DecodeAnalysis[] = [];
  const source = codeText(transition.source);
  for (const op of transition.operations) {
    if (op.kind !== "decode" && !/abi\.decode/i.test(op.expression)) continue;
    results.push({
      hasLengthCheck: /require\s*\(\s*data\.length|returndatasize\s*\(\)|\.length\s*>=/i.test(source),
      hasTryCatch: transition.guards.some((g) => /try/i.test(g)),
      usesCalldataSlice: /calldatacopy|returndatacopy|mload/i.test(op.expression),
      targetType: extractDecodeType(op.expression),
      expression: op.expression,
    });
  }
  return results;
}

/** Detect stale returndata reuse across sequential calls. */
export function hasStaleReturndataPattern(transition: ReturndataTransition): boolean {
  const calls = transition.operations.filter((op) => op.kind === "call");
  const decodes = transition.operations.filter((op) => op.kind === "decode" || /abi\.decode/i.test(op.expression));
  if (calls.length < 2 || decodes.length === 0) return false;
  const source = codeText(transition.source);
  return decodes.some((decode) => {
    const decodeOrder = decode.order;
    const priorCalls = calls.filter((c) => c.order < decodeOrder);
    const laterCalls = calls.filter((c) => c.order > decodeOrder && c.order < decodeOrder + 1000);
    return priorCalls.length > 0 && laterCalls.length > 0 &&
      !/returndatasize|returnData|fresh/i.test(source.slice(0, 500));
  });
}

function extractDecodeType(expression: string): string {
  const match = expression.match(/abi\.decode\s*\([^,]+,\s*\(([^)]+)\)/i);
  return match?.[1] ?? "unknown";
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}
