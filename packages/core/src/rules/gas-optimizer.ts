import { visit, getSnippet } from "../ast/parser";
import type { GasHint, ASTNode } from "../types";

/**
 * Detect gas optimization opportunities in Solidity source.
 */
export function detectGasIssues(
  ast: ASTNode,
  source: string,
  filePath: string,
): GasHint[] {
  const hints: GasHint[] = [];

  // ── 1. Storage reads inside loops ──────────────────────────────────────────
  visit(ast, {
    ForStatement(node: ASTNode) {
      const forNode = node as {
        body?: ASTNode;
        loc?: { start?: { line?: number } };
      };
      const bodyStr = JSON.stringify(forNode.body);

      // Heuristic: storage-like names (e.g. `balances[`, `owner`) accessed in loop
      if (bodyStr.includes("IndexAccess") || bodyStr.includes("MemberAccess")) {
        hints.push({
          file: filePath,
          line: forNode.loc?.start?.line ?? 0,
          description:
            "Potential storage read inside a loop. Each SLOAD costs 2100 gas on cold access. " +
            "Cache storage variables in memory before the loop.",
          estimatedSaving: "~2000 gas per iteration",
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  // ── 2. Public state variables that should be external ──────────────────────
  visit(ast, {
    StateVariableDeclaration(node: ASTNode) {
      const decl = node as {
        variables?: Array<{
          visibility?: string;
          typeName?: { name?: string };
          name?: string;
          loc?: { start?: { line?: number } };
        }>;
      };
      decl.variables?.forEach((v) => {
        if (
          v.visibility === "public" &&
          (v.typeName?.name === "string" || v.typeName?.name === "bytes")
        ) {
          hints.push({
            file: filePath,
            line: v.loc?.start?.line ?? 0,
            description:
              `Public string/bytes variable "${v.name}" generates an auto-getter. ` +
              "If only accessed externally, marking it as private and adding a manual " +
              "external getter saves deployment gas.",
            estimatedSaving: "~50–200 gas on deployment",
            snippet: `${v.visibility} ${v.typeName?.name} ${v.name}`,
          });
        }
      });
    },
  });

  // ── 3. Use of < vs <= in loops (saves one ISZERO opcode) ──────────────────
  visit(ast, {
    ForStatement(node: ASTNode) {
      const forNode = node as {
        conditionExpression?: ASTNode;
        loc?: { start?: { line?: number } };
      };
      const condStr = JSON.stringify(forNode.conditionExpression);
      if (condStr.includes('"operator":"<="')) {
        hints.push({
          file: filePath,
          line: forNode.loc?.start?.line ?? 0,
          description:
            "Loop uses <= comparison. Replacing `i <= n` with `i < n + 1` or restructuring " +
            "avoids an ISZERO opcode per iteration.",
          estimatedSaving: "~3 gas per iteration",
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  // ── 4. Repeated keccak256 of the same constant ────────────────────────────
  visit(ast, {
    FunctionCall(node: ASTNode) {
      const call = node as {
        expression?: { name?: string };
        loc?: { start?: { line?: number } };
      };
      if (call.expression?.name === "keccak256") {
        hints.push({
          file: filePath,
          line: call.loc?.start?.line ?? 0,
          description:
            "keccak256() called at runtime. If the input is a constant, precompute it " +
            "as a constant bytes32 to save ~30 gas per call.",
          estimatedSaving: "~30 gas per call",
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  // ── 5. uint8/uint16 in function params (EVM pads to 32 bytes) ────────────
  visit(ast, {
    StateVariableDeclaration(node: ASTNode) {
      const decl = node as {
        variables?: Array<{
          typeName?: { name?: string };
          name?: string;
          loc?: { start?: { line?: number } };
        }>;
      };
      decl.variables?.forEach((v) => {
        const t = v.typeName?.name ?? "";
        if (["uint8", "uint16", "uint32", "int8", "int16"].includes(t)) {
          hints.push({
            file: filePath,
            line: v.loc?.start?.line ?? 0,
            description:
              `State variable "${v.name}" uses ${t}. The EVM operates on 32-byte words; ` +
              "smaller types only save gas when packed together in a single storage slot. " +
              "Ensure adjacent variables are packed, or consider uint256.",
            estimatedSaving: "Depends on packing",
            snippet: `${t} ${v.name}`,
          });
        }
      });
    },
  });

  // ── 6. Storage packing: struct member ordering ────────────────────────────
  visit(ast, {
    StructDefinition(node: ASTNode) {
      const structNode = node as {
        name?: string;
        members?: Array<{ typeName?: ASTNode; name?: string; loc?: { start?: { line?: number } } }>;
        loc?: { start?: { line?: number } };
      };
      const members = structNode.members ?? [];
      if (members.length < 2) return;

      const currentSlots = simulateSlots(members);
      const optimizedMembers = optimizeOrder(members);
      const optimizedSlots = simulateSlots(optimizedMembers);

      if (optimizedSlots < currentSlots) {
        const savedSlots = currentSlots - optimizedSlots;
        const suggestedOrder = optimizedMembers.map((m) => m.name).join(", ");
        hints.push({
          file: filePath,
          line: structNode.loc?.start?.line ?? 0,
          description:
            `GAS-PACK-001 | Struct "${structNode.name}" uses ${currentSlots} storage slots. ` +
            `Reordering members saves ${savedSlots} slot(s) (~${savedSlots * 2100} gas per SLOAD).`,
          estimatedSaving: `~${savedSlots * 2100} gas per SLOAD`,
          snippet: `Suggested order: ${suggestedOrder}`,
        });
      }
    },
  });

  // ── 7. Storage packing: contract-level state variables ───────────────────
  const stateVars: Array<{ typeName?: ASTNode; name?: string; loc?: { start?: { line?: number } } }> = [];
  visit(ast, {
    StateVariableDeclaration(node: ASTNode) {
      const decl = node as {
        variables?: Array<{ typeName?: ASTNode; name?: string; loc?: { start?: { line?: number } } }>;
      };
      decl.variables?.forEach((v) => {
        // Skip mappings, arrays, strings — they are never packed
        const typeStr = JSON.stringify(v.typeName);
        if (typeStr.includes('"Mapping"') || typeStr.includes('"ArrayTypeName"') ||
            (v.typeName as { name?: string })?.name === "string" ||
            (v.typeName as { name?: string })?.name === "bytes") return;
        stateVars.push(v);
      });
    },
  });

  if (stateVars.length >= 2) {
    const currentSlots = simulateSlots(stateVars);
    const optimizedSlots = simulateSlots(optimizeOrder(stateVars));
    if (optimizedSlots < currentSlots) {
      const savedSlots = currentSlots - optimizedSlots;
      const suggestedOrder = optimizeOrder(stateVars).map((v) => v.name).join(", ");
      hints.push({
        file: filePath,
        line: stateVars[0]?.loc?.start?.line ?? 0,
        description:
          `GAS-PACK-002 | Contract state variables use ${currentSlots} storage slots. ` +
          `Reordering saves ${savedSlots} slot(s) (~${savedSlots * 2100} gas per SLOAD).`,
        estimatedSaving: `~${savedSlots * 2100} gas per SLOAD`,
        snippet: `Suggested order: ${suggestedOrder}`,
      });
    }
  }

  return hints;
}

// ── Storage slot simulation helpers ──────────────────────────────────────────

/** Returns byte-size of a Solidity type. Returns 32 for unpacked reference types. */
function typeSize(typeName: ASTNode | undefined): number {
  if (!typeName) return 32;
  const t = typeName as { type?: string; name?: string; namePath?: string };

  // Reference types — never packed, each takes a full slot
  if (t.type === "Mapping" || t.type === "ArrayTypeName") return 32;

  const name = t.name ?? t.namePath ?? "";
  if (name === "bool") return 1;
  if (name === "address") return 20;
  if (name === "bytes1") return 1;
  if (name === "bytes2") return 2;
  if (name === "bytes4") return 4;
  if (name === "bytes8") return 8;
  if (name === "bytes16") return 16;
  if (name === "bytes20") return 20;
  if (name === "bytes32") return 32;

  const uintMatch = name.match(/^u?int(\d+)$/);
  if (uintMatch) return Math.ceil(parseInt(uintMatch[1], 10) / 8);

  const bytesMatch = name.match(/^bytes(\d+)$/);
  if (bytesMatch) return parseInt(bytesMatch[1], 10);

  // Structs, strings, unknown — full slot
  return 32;
}

/** Simulate EVM slot assignment and return total slot count. */
function simulateSlots(
  members: Array<{ typeName?: ASTNode; name?: string }>
): number {
  let slots = 0;
  let used = 0; // bytes used in current slot

  for (const m of members) {
    const size = typeSize(m.typeName);
    if (size === 32) {
      // Always takes its own slot(s); flush current slot first
      if (used > 0) { slots++; used = 0; }
      slots++;
    } else if (used + size > 32) {
      slots++;
      used = size;
    } else {
      used += size;
    }
  }
  if (used > 0) slots++;
  return slots;
}

/** Sort members: uint256/bytes32 first, then by descending size, bools last. */
function optimizeOrder<T extends { typeName?: ASTNode }>(members: T[]): T[] {
  return [...members].sort((a, b) => {
    const sa = typeSize(a.typeName);
    const sb = typeSize(b.typeName);
    // Full-slot types first, then pack smaller types together
    if (sa === 32 && sb !== 32) return -1;
    if (sb === 32 && sa !== 32) return 1;
    return sb - sa; // larger first within sub-32 group
  });
}
