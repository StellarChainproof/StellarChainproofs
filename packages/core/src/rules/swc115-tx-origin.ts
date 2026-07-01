import { visit, getSnippet } from "../ast/parser";
import type { MergedMember } from "../ast/import-graph";
import type { Finding, ASTNode } from "../types";
import { applyFindingContext, type RuleOptions } from "./rule-context";
import type { MergedMember } from "../ast/import-graph";

/**
 * SWC-115: Authorization through tx.origin
 *
 * Using tx.origin for authorization is dangerous because a malicious
 * intermediate contract can trick the original EOA into calling it,
 * then relay that call — with the original tx.origin — to the target.
 *
 * Operates on merged contract views to catch inherited modifiers and functions.
 */
export function detectTxOrigin(
  ast: ASTNode,
  source: string,
  filePath: string,
  ruleOptions?: RuleOptions,
): Finding[] {
  const findings: Finding[] = [];

  if (options?.contractView) {
    for (const member of options.contractView.members) {
      if (member.kind === "modifier" || member.kind === "function") {
        visit(member.node, {
          MemberAccess(node: ASTNode) {
            const finding = checkTxOriginNode(
              node,
              member.source,
              filePath,
              member,
              options
            );
            if (finding) findings.push(finding);
          },
        });
      }
    },
  });

  return findings;
}
