import type { ASTNode, Finding } from "../types";
import { analyzeReturndataSource } from "./api";
import { toScanFinding } from "./slither-merge";

const RETURNDATA_PREFILTER =
  /\.call\s*\(|\.send\s*\(|\.transfer\s*\(|\.delegatecall\s*\(|\.staticcall\s*\(|abi\.decode|returndatacopy|SafeERC20|safeTransfer|functionCall|transferFrom/i;

/** Integrates returndata safety analysis into the ordinary ChainProof scan. */
export function detectReturndataSafety(
  _ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  if (!RETURNDATA_PREFILTER.test(stripCommentsAndStrings(source))) return [];
  const report = analyzeReturndataSource(source, filePath);
  return report.files.flatMap((file) =>
    file.findings.map((finding) => toScanFinding(finding, filePath)),
  );
}

function stripCommentsAndStrings(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n\r]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
}
