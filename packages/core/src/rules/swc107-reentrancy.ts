import { visit, getSnippet } from "../ast/parser";
import type { Finding } from "../types";
import type { ASTNode } from "@solidity-parser/parser/dist/src/ast-types";

/**
 * SWC-107: Reentrancy
 *
 * Flags functions that make external calls before updating state variables.
 * Pattern: detect call.value / .call{value: ...} / transfer / send
 * followed by storage writes in the same function body.
 */
export function detectReentrancy(
  ast: ASTNode,
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];

  visit(ast, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as {
        name?: string;
        body?: { statements?: ASTNode[] };
        loc?: { start?: { line?: number } };
      };
      if (!fn.body?.statements) return;

      const statements = fn.body.statements;
      let externalCallIdx = -1;
      let stateWriteAfterCall = false;

      statements.forEach((stmt: ASTNode, i: number) => {
        const stmtStr = JSON.stringify(stmt);

        // Detect external call patterns
        const isExternalCall =
          stmtStr.includes('"call"') ||
          stmtStr.includes('"transfer"') ||
          stmtStr.includes('"send"') ||
          stmtStr.includes('"value"');

        if (isExternalCall && externalCallIdx === -1) {
          externalCallIdx = i;
        }

        // Detect state variable write after an external call
        if (
          externalCallIdx !== -1 &&
          i > externalCallIdx &&
          (stmt as { type?: string }).type === "ExpressionStatement"
        ) {
          const exprStr = JSON.stringify(stmt);
          // Heuristic: assignment after call with no msg.sender guard
          if (exprStr.includes('"operator":"="') || exprStr.includes('"operator":"-="')) {
            stateWriteAfterCall = true;
          }
        }
      });

      if (stateWriteAfterCall) {
        const line = fn.loc?.start?.line ?? 0;
        findings.push({
          id: "CP-107",
          swcId: "SWC-107",
          title: "Reentrancy vulnerability",
          description:
            `Function "${fn.name ?? "anonymous"}" makes an external call before updating ` +
            `state variables. An attacker can re-enter the function before the state is updated, ` +
            `potentially draining funds (e.g. the DAO hack).`,
          recommendation:
            "Apply the Checks-Effects-Interactions pattern: update all state variables " +
            "before making any external calls. Alternatively, use OpenZeppelin's " +
            "ReentrancyGuard modifier.",
          severity: "critical",
          file: filePath,
          line,
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  return findings;
}
