import { REQUIRES_SUCCESS_CHECK, TOKEN_RETURN_CALLS } from "./call-classifier";
import { analyzeDecodeSites, hasStaleReturndataPattern } from "./decode-analysis";
import { detectGuards, hasSafeWrapper, isOptionalCall } from "./guard-detection";
import type {
  ReturndataContractModel,
  ReturndataEvidence,
  ReturndataFinding,
  ReturndataOperation,
  ReturndataRuleId,
  ReturndataTransition,
} from "./types";

type Rule = (model: ReturndataContractModel) => ReturndataFinding[];

const RULE_ORDER: readonly ReturndataRuleId[] = Array.from({ length: 16 }, (_, i) =>
  `CP-RTD-${String(i + 1).padStart(3, "0")}` as ReturndataRuleId,
);

const RULES: Record<ReturndataRuleId, Rule> = {
  "CP-RTD-001": detectIgnoredSuccessFlag,
  "CP-RTD-002": detectOverwrittenResult,
  "CP-RTD-003": detectUncheckedTokenReturn,
  "CP-RTD-004": detectUncheckedLowLevelReturn,
  "CP-RTD-005": detectUnsafeAbiDecode,
  "CP-RTD-006": detectStaleReturndata,
  "CP-RTD-007": detectPartialBatchFailure,
  "CP-RTD-008": detectIgnoredDelegatecallReturn,
  "CP-RTD-009": detectIgnoredStaticcallReturn,
  "CP-RTD-010": detectIgnoredSendReturn,
  "CP-RTD-011": detectUnsafeTransfer,
  "CP-RTD-012": detectUnsafeAssemblyCopy,
  "CP-RTD-013": detectSwallowedTryCatch,
  "CP-RTD-014": detectMulticallPartialFailure,
  "CP-RTD-015": detectProxyDecodeAssumption,
  "CP-RTD-016": detectMisclassifiedOptionalCall,
};

export function analyzeReturndataModel(
  model: ReturndataContractModel,
  options: { includeRules?: ReturndataRuleId[]; excludeRules?: ReturndataRuleId[] } = {},
): ReturndataFinding[] {
  const include = options.includeRules ? new Set(options.includeRules) : null;
  const exclude = new Set(options.excludeRules ?? []);
  const findings: ReturndataFinding[] = [];
  for (const id of RULE_ORDER) {
    if (include && !include.has(id)) continue;
    if (exclude.has(id)) continue;
    findings.push(...RULES[id](model));
  }
  return findings.sort(compareFindings);
}

function detectIgnoredSuccessFlag(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (op.kind !== "call" || !REQUIRES_SUCCESS_CHECK.has(op.callKind)) continue;
      if (hasSafeWrapper(transition, op) || successCheckedAfter(transition, op)) continue;
      if (isOptionalCall(transition, op)) continue;
      if (isBareStatement(transition, op)) {
        findings.push(makeFinding({
          ruleId: "CP-RTD-001",
          title: `Ignored ${op.callKind} success flag`,
          description: `A ${op.callKind} call's success boolean is not captured or checked. Failures are silently ignored.`,
          recommendation: "Capture the return value and require(success) or use Address.functionCall.",
          severity: "high",
          confidence: "high",
          category: "ignored-return",
          model, transition, operation: op,
        }));
      }
    }
  }
  return findings;
}

function detectOverwrittenResult(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    const source = codeText(transition.source);
    if (!/(bool\s+success|\(bool\s+success).*=.*\.call/s.test(source)) continue;
    if (/require\s*\(\s*success|if\s*\(\s*!success/i.test(source)) continue;
    const call = transition.operations.find((op) => op.callKind === "call");
    if (!call) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-002",
      title: `Call result overwritten before check in ${transition.name}`,
      description: "The success flag from a low-level call is assigned but overwritten or never checked before subsequent state changes.",
      recommendation: "Check the success flag immediately after assignment before any other operations.",
      severity: "high",
      confidence: "medium",
      category: "overwritten-return",
      model, transition, operation: call,
    }));
  }
  return findings;
}

function detectUncheckedTokenReturn(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (!TOKEN_RETURN_CALLS.has(op.callKind)) continue;
      if (/transfer\s*\(/i.test(op.expression) && !/\.transfer\s*\(/i.test(op.expression)) continue;
      if (hasSafeWrapper(transition, op)) continue;
      if (/require\s*\(|if\s*\(!/i.test(codeText(transition.source))) continue;
      if (!/\.transfer\s*\(|\.transferFrom\s*\(|IERC20|token\./i.test(op.expression)) continue;
      findings.push(makeFinding({
        ruleId: "CP-RTD-003",
        title: `Unchecked ERC20 return in ${transition.name}`,
        description: "An ERC20 transfer or transferFrom return value is not checked. Non-standard tokens may return false instead of reverting.",
        recommendation: "Use SafeERC20.safeTransfer/safeTransferFrom or check the boolean return value.",
        severity: "medium",
        confidence: "high",
        category: "token-return",
        model, transition, operation: op,
      }));
    }
  }
  return findings;
}

function detectUncheckedLowLevelReturn(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (op.callKind !== "call") continue;
      if (hasSafeWrapper(transition, op) || successCheckedAfter(transition, op)) continue;
      if (isOptionalCall(transition, op)) continue;
      findings.push(makeFinding({
        ruleId: "CP-RTD-004",
        title: `Unchecked low-level call return in ${transition.name}`,
        description: "A .call() return boolean is not verified. The callee may fail while the caller continues execution.",
        recommendation: "Require the call to succeed or bubble the failure with Address.functionCall.",
        severity: "medium",
        confidence: "high",
        category: "low-level-return",
        model, transition, operation: op,
      }));
    }
  }
  return findings;
}

function detectUnsafeAbiDecode(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const decode of analyzeDecodeSites(transition)) {
      if (decode.hasLengthCheck || decode.hasTryCatch) continue;
      findings.push(makeFinding({
        ruleId: "CP-RTD-005",
        title: `Unsafe ABI decode in ${transition.name}`,
        description: "abi.decode is applied to returndata or calldata without verifying sufficient length, enabling malformed data panics or type confusion.",
        recommendation: "Check returndatasize() or data.length before decoding. Wrap in try/catch for external data.",
        severity: "medium",
        confidence: "medium",
        category: "decode-safety",
        model, transition,
        evidence: [decodeEvidence(transition, decode.expression)],
      }));
    }
  }
  return findings;
}

function detectStaleReturndata(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    if (!hasStaleReturndataPattern(transition)) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-006",
      title: `Stale returndata reuse in ${transition.name}`,
      description: "Returndata from a prior call may be decoded after a subsequent call overwrites the returndata buffer.",
      recommendation: "Copy returndata to memory immediately after each call before making additional external calls.",
      severity: "high",
      confidence: "medium",
      category: "stale-returndata",
      model, transition,
    }));
  }
  return findings;
}

function detectPartialBatchFailure(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    const source = codeText(transition.source);
    const isBatch = transition.role === "batch-operation" ||
      (/batch/i.test(transition.name) && /for\s*\(/i.test(transition.source));
    if (!isBatch) continue;
    if (/require\s*\(\s*success|safeTransfer|safeTransferFrom/i.test(source)) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-007",
      title: `Partial batch failure ignored in ${transition.name}`,
      description: "A loop of external calls does not abort or roll back on individual failure, leaving partial state updates.",
      recommendation: "Check each call's success flag and revert the entire batch on any failure.",
      severity: "high",
      confidence: "medium",
      category: "batch-failure",
      model, transition,
    }));
  }
  return findings;
}

function detectIgnoredDelegatecallReturn(model: ReturndataContractModel): ReturndataFinding[] {
  return ignoredCallKind(model, "delegatecall", "CP-RTD-008", "Delegatecall failures can corrupt storage silently.");
}

function detectIgnoredStaticcallReturn(model: ReturndataContractModel): ReturndataFinding[] {
  return ignoredCallKind(model, "staticcall", "CP-RTD-009", "Staticcall failures may indicate invalid view data assumptions.");
}

function detectIgnoredSendReturn(model: ReturndataContractModel): ReturndataFinding[] {
  return ignoredCallKind(model, "send", "CP-RTD-010", "send() returns false on failure; ignoring it loses ETH transfer confirmation.");
}

function detectUnsafeTransfer(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (op.callKind !== "transfer") continue;
      if (hasSafeWrapper(transition, op)) continue;
      findings.push(makeFinding({
        ruleId: "CP-RTD-011",
        title: `transfer() used without return check in ${transition.name}`,
        description: "Solidity transfer() forwards only 2300 gas and reverts on standard recipients, but some contracts may not revert reliably.",
        recommendation: "Use call{value: amount}(\"\") with success check or Address.sendValue.",
        severity: "low",
        confidence: "medium",
        category: "transfer-safety",
        model, transition, operation: op,
      }));
    }
  }
  return findings;
}

function detectUnsafeAssemblyCopy(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    const source = codeText(transition.source);
    if (!/returndatacopy|call\s*\(/i.test(source)) continue;
    const guards = detectGuards(transition);
    if (guards.some((g) => g.kind === "assembly-bounds")) continue;
    if (!/assembly\s*\{/i.test(transition.source)) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-012",
      title: `Assembly returndata copy without bounds in ${transition.name}`,
      description: "Inline assembly copies returndata without checking returndatasize(), risking out-of-bounds reads.",
      recommendation: "Check returndatasize() >= expected length before returndatacopy.",
      severity: "high",
      confidence: "medium",
      category: "assembly-safety",
      model, transition,
    }));
  }
  return findings;
}

function detectSwallowedTryCatch(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    const source = transition.source;
    if (!/try\s+/i.test(source) || !/catch\s*\(\s*\)\s*\{\s*\}/s.test(source)) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-013",
      title: `Try/catch swallows failure in ${transition.name}`,
      description: "An empty catch block silently absorbs external call failures on a security-critical path.",
      recommendation: "Log, revert, or propagate failures in catch blocks for security-critical calls.",
      severity: "medium",
      confidence: "high",
      category: "try-catch",
      model, transition,
      optionalCall: isOptionalCall(transition, transition.operations[0]),
    }));
  }
  return findings;
}

function detectMulticallPartialFailure(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    if (transition.role !== "multicall") continue;
    const source = codeText(transition.source);
    if (/require\s*\(\s*success|revert/i.test(source)) continue;
    findings.push(makeFinding({
      ruleId: "CP-RTD-014",
      title: `Multicall partial failure not propagated in ${transition.name}`,
      description: "Multicall batch does not revert or flag when individual subcalls fail.",
      recommendation: "Return per-call success flags or revert the entire batch on any failure.",
      severity: "high",
      confidence: "medium",
      category: "multicall",
      model, transition,
    }));
  }
  return findings;
}

function detectProxyDecodeAssumption(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (op.callKind !== "delegatecall") continue;
      const source = codeText(transition.source);
      if (!/abi\.decode/i.test(source)) continue;
      if (/returndatasize|try\s+/i.test(source)) continue;
      findings.push(makeFinding({
        ruleId: "CP-RTD-015",
        title: `Proxy delegatecall decode assumption in ${transition.name}`,
        description: "Return data from a delegatecall is decoded without verifying the implementation returned expected types and length.",
        recommendation: "Validate returndata length and wrap decode in try/catch for upgradeable proxy paths.",
        severity: "medium",
        confidence: "medium",
        category: "proxy-decode",
        model, transition, operation: op,
      }));
    }
  }
  return findings;
}

function detectMisclassifiedOptionalCall(model: ReturndataContractModel): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    const optional = isOptionalCall(transition, transition.operations[0]);
    if (!optional) continue;
    for (const op of transition.operations) {
      if (!REQUIRES_SUCCESS_CHECK.has(op.callKind)) continue;
      if (successCheckedAfter(transition, op)) continue;
      const source = codeText(transition.source);
      if (/withdraw|transfer|mint|burn|upgrade|grant/i.test(source) && !/@dev\s+optional/i.test(transition.source)) {
        findings.push(makeFinding({
          ruleId: "CP-RTD-016",
          title: `Security-critical call marked optional in ${transition.name}`,
          description: "A call on a security-critical path appears intentionally optional but lacks explicit documentation or evidence distinguishing it from an accidental ignored failure.",
          recommendation: "Document optional call intent with @dev comments and ensure critical paths always check returns.",
          severity: "info",
          confidence: "low",
          category: "optional-call",
          model, transition, operation: op,
          optionalCall: true,
        }));
      }
    }
  }
  return findings;
}

function ignoredCallKind(
  model: ReturndataContractModel,
  kind: ReturndataOperation["callKind"],
  ruleId: ReturndataRuleId,
  description: string,
): ReturndataFinding[] {
  const findings: ReturndataFinding[] = [];
  for (const transition of model.transitions) {
    for (const op of transition.operations) {
      if (op.callKind !== kind) continue;
      if (hasSafeWrapper(transition, op) || successCheckedAfter(transition, op)) continue;
      if (isOptionalCall(transition, op)) continue;
      findings.push(makeFinding({
        ruleId,
        title: `Ignored ${kind} return in ${transition.name}`,
        description,
        recommendation: `Check the ${kind} success return or use a safe wrapper.`,
        severity: "medium",
        confidence: "high",
        category: "ignored-return",
        model, transition, operation: op,
      }));
    }
  }
  return findings;
}

interface FindingInput {
  ruleId: ReturndataRuleId;
  title: string;
  description: string;
  recommendation: string;
  severity: ReturndataFinding["severity"];
  confidence: ReturndataFinding["confidence"];
  category: string;
  model: ReturndataContractModel;
  transition: ReturndataTransition;
  operation?: ReturndataOperation;
  evidence?: ReturndataEvidence[];
  optionalCall?: boolean;
}

function makeFinding(input: FindingInput): ReturndataFinding {
  return {
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    recommendation: input.recommendation,
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    contract: input.model.name,
    location: input.operation?.location ?? input.transition.location,
    evidence: input.evidence ?? (input.operation ?
      [callEvidence(input.operation, input.description)] :
      [absenceEvidence(input.transition, input.description)]),
    assumptions: input.model.assumptions,
    optionalCall: input.optionalCall ?? false,
  };
}

function successCheckedAfter(transition: ReturndataTransition, op: ReturndataOperation): boolean {
  const source = codeText(transition.source);
  return op.checksSuccess ||
    /require\s*\(\s*success|if\s*\(\s*!success|if\s*\(!.*\)\s*revert/i.test(source) ||
    transition.guards.some((g) => /success|require/i.test(g)) ||
    detectGuards(transition).some((g) => g.kind === "require-success" || g.kind === "safe-erc20");
}

function isBareStatement(transition: ReturndataTransition, op: ReturndataOperation): boolean {
  const line = op.location.line;
  const sourceLines = transition.source.split("\n");
  for (const lineText of sourceLines) {
    if (/^\s*\w+\.(call|send|delegatecall|staticcall)\s*[\({]/i.test(lineText) &&
      !/=\s*|require\s*\(|if\s*\(/i.test(lineText)) return true;
  }
  return !op.capturesReturn;
}

function callEvidence(op: ReturndataOperation, description: string): ReturndataEvidence {
  return { kind: "call-site", description, location: op.location, snippet: op.expression };
}

function decodeEvidence(transition: ReturndataTransition, expression: string): ReturndataEvidence {
  return { kind: "decode-site", description: "Unsafe decode site", location: transition.location, snippet: expression };
}

function absenceEvidence(transition: ReturndataTransition, description: string): ReturndataEvidence {
  return { kind: "absence", description, location: transition.location };
}

function codeText(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n\r]*/g, " ").replace(/\s+/g, " ");
}

function compareFindings(a: ReturndataFinding, b: ReturndataFinding): number {
  return a.location.line - b.location.line || a.ruleId.localeCompare(b.ruleId);
}
