import type { ASTNode, Finding } from "../types";
import { analyzeAmmSource } from "./api";

const AMM_SOURCE_SIGNAL = /\b(?:reserveA|reserveB|totalSupply|swapFee|protocolFee|liquidity|amountOutMin|deadline|flashSwap|donate|pool|sqrtPrice|k\b|invariant)\b/i;

export function detectAmmAccounting(_ast: ASTNode, source: string, filePath: string): Finding[] {
  if (!AMM_SOURCE_SIGNAL.test(source)) return [];
  const report = analyzeAmmSource({ file: filePath, source });
  return report.files.flatMap((file) => file.findings.map((finding): Finding => ({
    id: finding.ruleId,
    title: finding.title,
    description: finding.description,
    recommendation: finding.recommendation,
    severity: finding.severity,
    file: finding.location.file,
    line: finding.location.line,
    lineEnd: finding.location.lineEnd,
    confidence: finding.confidence,
    assumptions: finding.assumptions,
    evidence: finding.evidence.map((evidence) => ({
      description: evidence.description + (evidence.snippet ? `: ${evidence.snippet}` : ""),
      file: evidence.location.file,
      line: evidence.location.line,
    })),
  })));
}

export function detectAmmInvariants(ast: ASTNode, source: string, filePath: string): Finding[] {
  return detectAmmAccounting(ast, source, filePath);
}
