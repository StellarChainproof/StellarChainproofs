import type { CallKind } from "./types";

interface NodeRecord {
  type?: string;
  memberName?: string;
  name?: string;
  expression?: unknown;
}

/** Classify low-level and interface call kinds from AST and source snippet. */
export function classifyCallKind(snippet: string, expr?: NodeRecord): CallKind {
  const lower = snippet.toLowerCase();
  if (/\.delegatecall\s*\(/i.test(snippet)) return "delegatecall";
  if (/\.staticcall\s*\(/i.test(snippet)) return "staticcall";
  if (/\.callcode\s*\(/i.test(snippet)) return "callcode";
  if (/\.call\s*\{|\.call\s*\(/i.test(snippet)) return "call";
  if (/\.send\s*\(/i.test(snippet)) return "send";
  if (/\.transfer\s*\(/i.test(snippet)) return "transfer";
  if (expr?.type === "MemberAccess") {
    const member = expr.memberName?.toLowerCase();
    if (member === "delegatecall") return "delegatecall";
    if (member === "staticcall") return "staticcall";
    if (member === "call") return "call";
    if (member === "send") return "send";
    if (member === "transfer") return "transfer";
  }
  if (/transfer\s*\(|transferfrom\s*\(/i.test(lower)) return "interface-call";
  return "unknown";
}

/** Low-level call kinds that return a success boolean requiring explicit check. */
export const REQUIRES_SUCCESS_CHECK: ReadonlySet<CallKind> = new Set([
  "call", "callcode", "delegatecall", "staticcall", "send",
]);

/** Token interface calls that may return false instead of reverting. */
export const TOKEN_RETURN_CALLS: ReadonlySet<CallKind> = new Set([
  "interface-call", "transfer",
]);

/** Call kinds where failure typically reverts (no return check needed for standard tokens). */
export const REVERT_ON_FAILURE: ReadonlySet<CallKind> = new Set([
  "transfer",
]);
