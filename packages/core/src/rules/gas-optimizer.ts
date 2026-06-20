import { visit, getSnippet } from "../ast/parser";
import type { GasHint } from "../types";
import type { ASTNode } from "../ast/parser";

/**
 * Detect gas optimization opportunities in Solidity source.
 */
export function detectGasIssues(
  ast: ASTNode,
  source: string,
  filePath: string
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
      if (
        bodyStr.includes("IndexAccess") ||
        bodyStr.includes("MemberAccess")
      ) {
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

  return hints;
}
