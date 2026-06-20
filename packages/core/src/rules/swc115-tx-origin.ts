import { visit, getSnippet } from "../ast/parser";
import type { Finding } from "../types";
import type { ASTNode } from "@solidity-parser/parser/dist/src/ast-types";

/**
 * SWC-115: Authorization through tx.origin
 *
 * Using tx.origin for authorization is dangerous because a malicious
 * intermediate contract can trick the original EOA into calling it,
 * then relay that call — with the original tx.origin — to the target.
 */
export function detectTxOrigin(
  ast: ASTNode,
  source: string,
  filePath: string
): Finding[] {
  const findings: Finding[] = [];

  visit(ast, {
    MemberAccess(node: ASTNode) {
      const member = node as {
        memberName?: string;
        expression?: { name?: string };
        loc?: { start?: { line?: number } };
      };

      if (
        member.memberName === "origin" &&
        member.expression?.name === "tx"
      ) {
        const line = member.loc?.start?.line ?? 0;
        findings.push({
          id: "CP-115",
          swcId: "SWC-115",
          title: "Use of tx.origin for authentication",
          description:
            "tx.origin refers to the original external account that initiated the transaction, " +
            "not the immediate caller. A phishing contract can exploit this to perform " +
            "unauthorized actions on behalf of the victim.",
          recommendation:
            "Replace tx.origin with msg.sender for authorization checks. " +
            "If you need to distinguish EOAs from contracts, use " +
            "msg.sender == tx.origin as a secondary check, not the primary guard.",
          severity: "high",
          file: filePath,
          line,
          snippet: getSnippet(source, node),
        });
      }
    },
  });

  return findings;
}
