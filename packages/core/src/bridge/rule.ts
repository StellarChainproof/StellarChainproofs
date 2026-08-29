import type { ASTNode, Finding } from "../types";
import { analyzeBridgeSource } from "./api";

const BRIDGE_PREFILTER =
  /\b(?:sendMessage|receiveMessage|handleMessage|processMessage|relayMessage|verifyProof|verifySignatures|lockTokens|mintTokens|burnTokens|releaseTokens|processedMessages|sourceChainId|destChainId|destinationChain|merkleRoot|validatorThreshold|inboundNonce|outboundNonce|bridge|crossChain|cross-chain|endpointId|domainSeparator|finalityWindow|challengePeriod)\b/i;

/** Integrates the specialized bridge engine into the ordinary ChainProof scan. */
export function detectBridgeSafety(
  _ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  // Most contracts are unrelated. Avoid a second parse/model pass unless strong bridge signals exist.
  if (!BRIDGE_PREFILTER.test(stripCommentsAndStrings(source))) return [];
  const report = analyzeBridgeSource(source, filePath);
  return report.files.flatMap((file) => file.findings.map((finding): Finding => ({
    id: finding.ruleId,
    title: finding.title,
    description: finding.description,
    recommendation: finding.recommendation,
    severity: finding.severity,
    file: finding.location.file,
    line: finding.location.line,
    ...(finding.location.lineEnd ? { lineEnd: finding.location.lineEnd } : {}),
    evidence: finding.evidence.map((evidence) => ({
      description: evidence.description,
      file: evidence.location.file,
      line: evidence.location.line,
    })),
    assumptions: finding.assumptions,
    confidence: finding.confidence,
  })));
}

function stripCommentsAndStrings(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n\r]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
}
