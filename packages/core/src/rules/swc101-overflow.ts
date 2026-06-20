import { visit, getSnippet } from "../ast/parser";
import type { Finding } from "../types";
import type { ASTNode } from "../ast/parser";

/**
 * SWC-101: Integer Overflow and Underflow
 *
 * Detects arithmetic operations on integer types without SafeMath or
 * Solidity ^0.8.0 (which has built-in overflow checks).
 */
export function detectIntegerOverflow(
  ast: ASTNode,
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];
  let pragmaVersion = "";

  // Extract pragma version first
  visit(ast, {
    PragmaDirective(node: ASTNode) {
      const pragma = node as { value?: string };
      if (pragma.value) pragmaVersion = pragma.value;
    },
  });

  // If Solidity >= 0.8.0, overflow is checked natively — skip
  const is08Plus =
    pragmaVersion.includes("^0.8") ||
    pragmaVersion.includes(">=0.8") ||
    pragmaVersion.includes("0.8.") ||
    pragmaVersion.includes("0.9.");

  if (is08Plus) return findings;

  visit(ast, {
    BinaryOperation(node: ASTNode) {
      const op = node as {
        operator?: string;
        loc?: { start?: { line?: number } };
      };

      if (["+", "-", "*", "**"].includes(op.operator ?? "")) {
        // Check if SafeMath is likely in use (heuristic: look for .add( .sub( .mul( in snippet)
        const snippet = getSnippet(source, node);
        const usesSafeMath =
          snippet.includes(".add(") ||
          snippet.includes(".sub(") ||
          snippet.includes(".mul(");

        if (!usesSafeMath) {
          const line = op.loc?.start?.line ?? 0;
          findings.push({
            id: "CP-101",
            swcId: "SWC-101",
            title: "Integer overflow / underflow",
            description:
              `Arithmetic operation "${op.operator}" on a Solidity version < 0.8.0 without ` +
              "SafeMath. If the value exceeds the uint/int bounds, it silently wraps around.",
            recommendation:
              "Upgrade to Solidity ^0.8.0 where overflow reverts by default, or wrap " +
              "arithmetic with OpenZeppelin's SafeMath library.",
            severity: "high",
            file: filePath,
            line,
            snippet,
          });
        }
      }
    },
  });

  return findings;
}

/**
 * SWC-104: Unchecked Call Return Value
 *
 * .call() and .send() return a boolean that must be checked.
 * Ignoring it silently swallows failures.
 */
export function detectUncheckedReturn(
  ast: ASTNode,
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];

  visit(ast, {
    ExpressionStatement(node: ASTNode) {
      const exprNode = node as {
        expression?: ASTNode;
        loc?: { start?: { line?: number } };
      };
      const expr = exprNode.expression as {
        type?: string;
        memberName?: string;
        loc?: { start?: { line?: number } };
      } | undefined;

      // A bare .call() / .send() not assigned to anything
      if (
        expr?.type === "FunctionCall" &&
        JSON.stringify(expr).includes('"memberName":"call"') ||
        expr?.type === "FunctionCall" &&
        JSON.stringify(expr).includes('"memberName":"send"')
      ) {
        const line = exprNode.loc?.start?.line ?? 0;
        findings.push({
          id: "CP-104",
          swcId: "SWC-104",
          title: "Unchecked call return value",
          description:
            ".call() and .send() return a boolean indicating success. " +
            "Ignoring this return value means failures are silently swallowed, " +
            "potentially leaving the contract in an inconsistent state.",
          recommendation:
            "Always check the return value: `(bool success, ) = addr.call{value: amount}(\"\"); " +
            "require(success, \"Transfer failed\");`. Prefer .transfer() for simple ETH sends " +
            "if reentrancy is not a concern.",
          severity: "medium",
          file: filePath,
          line,
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  return findings;
}
