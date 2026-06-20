import type { MergedContractView, MergedMember } from "../ast/import-graph";
import type { Finding } from "../types";

export interface RuleOptions {
  /** Contract being analyzed (inherits merged members) */
  contractView?: MergedContractView;
}

export function applyFindingContext(
  finding: Finding,
  member: MergedMember | undefined,
  contractView?: MergedContractView
): Finding {
  if (!contractView || !member) return finding;

  const inherited = member.definedIn !== contractView.file;

  return {
    ...finding,
    file: inherited ? contractView.file : member.definedIn,
    definedIn: member.definedIn,
    inheritedBy: inherited ? contractView.file : undefined,
    importPath: inherited ? contractView.importPath : undefined,
  };
}

export function getAnalysisMembers(
  contractView?: MergedContractView
): MergedMember[] {
  if (!contractView) return [];
  return contractView.members;
}
