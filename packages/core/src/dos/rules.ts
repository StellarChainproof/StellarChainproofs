/**
 * @packageDocumentation
 * @chainproof/core — DoS, Gas-Griefing & Unbounded-Work Rules (CP-DOS-001 to CP-DOS-010)
 */

import type { ASTNode } from "../types";
import { visit, getSnippet } from "../ast/parser";
import type {
  DosFinding,
  DosRuleId,
  DosAnalysisOptions,
  LoopBoundAnalysis,
  CallFanOutAnalysis,
  ArrayGrowthAnalysis,
  MitigationEvidence,
} from "./types";
import { extractLoopBounds } from "./loop-analyzer";
import { extractCallFanOuts } from "./call-fanout";
import { extractArrayGrowths } from "./growth-analyzer";
import { detectMitigations } from "./mitigation-detector";

export function shouldRunDosRule(ruleId: DosRuleId, options?: DosAnalysisOptions): boolean {
  if (options?.includeRules && options.includeRules.length > 0) {
    return options.includeRules.includes(ruleId);
  }
  if (options?.excludeRules && options.excludeRules.length > 0) {
    return !options.excludeRules.includes(ruleId);
  }
  return true;
}

export function detectDosVulnerabilities(
  ast: ASTNode,
  source: string,
  filePath: string,
  options?: DosAnalysisOptions,
): DosFinding[] {
  const allFindings: DosFinding[] = [];
  const contracts: any[] = [];

  if (ast.children && Array.isArray(ast.children)) {
    for (const child of ast.children) {
      if (child.type === "ContractDefinition") {
        contracts.push(child);
      }
    }
  } else {
    visit(ast, {
      ContractDefinition: (contractNode: any) => {
        contracts.push(contractNode);
      },
    });
  }

  for (const contractNode of contracts) {
    const contractName = contractNode.name || "Contract";
    const loops = extractLoopBounds(contractNode, contractName, source, filePath);
    const calls = extractCallFanOuts(contractNode, contractName, source, filePath);
    const growths = extractArrayGrowths(contractNode, contractName, source, filePath);
    const mitigations = detectMitigations(contractNode, contractName, source, filePath);

      // Check CP-DOS-001: Unbounded Loop Iteration
      if (shouldRunDosRule("CP-DOS-001", options)) {
        allFindings.push(...checkUnboundedLoops(loops, mitigations, source, filePath));
      }

      // Check CP-DOS-002: Push-Payment Pattern
      if (shouldRunDosRule("CP-DOS-002", options)) {
        allFindings.push(...checkPushPayments(calls, mitigations, source, filePath));
      }

      // Check CP-DOS-003: External Call Fan-Out in Loop
      if (shouldRunDosRule("CP-DOS-003", options)) {
        allFindings.push(...checkCallFanOut(calls, mitigations, source, filePath));
      }

      // Check CP-DOS-004: Return Bomb / Returndata Griefing
      if (shouldRunDosRule("CP-DOS-004", options)) {
        allFindings.push(...checkReturnBombs(calls, loops, source, filePath));
      }

      // Check CP-DOS-005: Unbounded Storage Clearing / Mass Deletion
      if (shouldRunDosRule("CP-DOS-005", options)) {
        allFindings.push(...checkMassStorageDeletion(loops, source, filePath));
      }

      // Check CP-DOS-006: Insufficient Gas Forwarding (63/64th Rule)
      if (shouldRunDosRule("CP-DOS-006", options)) {
        allFindings.push(...checkInsufficientGasForwarding(calls, source, filePath));
      }

      // Check CP-DOS-007: Single-Transaction Block Gas Limit Deadlock
      if (shouldRunDosRule("CP-DOS-007", options)) {
        allFindings.push(...checkBlockGasLimitDeadlock(loops, mitigations, source, filePath));
      }

      // Check CP-DOS-008: Unbounded Recursion
      if (shouldRunDosRule("CP-DOS-008", options)) {
        allFindings.push(...checkUnboundedRecursion(contractNode, contractName, source, filePath));
      }

      // Check CP-DOS-009: Array Poisoning / Unconstrained Growth
      if (shouldRunDosRule("CP-DOS-009", options)) {
        allFindings.push(...checkArrayPoisoning(growths, source, filePath));
      }

      // Check CP-DOS-010: Revert Propagation in Batch Operations
      if (shouldRunDosRule("CP-DOS-010", options)) {
        allFindings.push(...checkBatchRevertPropagation(calls, loops, mitigations, source, filePath));
      }
    }

  return allFindings;
}

// ─── Rule Implementations ─────────────────────────────────────────────────────

function checkUnboundedLoops(
  loops: LoopBoundAnalysis[],
  mitigations: MitigationEvidence[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];
  const hasPagination = mitigations.some((m) => m.type === "pagination");

  for (const loop of loops) {
    if (loop.boundType === "storage_array_bounded" || loop.boundType === "unbounded") {
      if (!loop.isCapped && !hasPagination) {
        findings.push({
          id: "CP-DOS-001",
          dosRuleId: "CP-DOS-001",
          swcId: "SWC-128",
          title: "Unbounded Loop Iteration Over Dynamic Storage Array",
          description: `Function '${loop.associatedFunction}' contains a loop bounded by '${loop.boundExpression || "unbounded condition"}'. If the storage collection grows large, transaction gas will exceed the block gas limit (30M gas), causing permanent denial of service.`,
          recommendation: "Implement pagination (offset and limit parameters) or process items in capped batches to ensure execution stays within block gas limits.",
          severity: "high",
          confidence: "high",
          category: "denial_of_service",
          boundType: loop.boundType,
          uncertainty: loop.uncertaintyReason,
          file: filePath,
          line: loop.line,
          snippet: getSnippet(source, loop.line),
        });
      }
    }
  }

  return findings;
}

function checkPushPayments(
  calls: CallFanOutAnalysis[],
  mitigations: MitigationEvidence[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];
  const hasPullPayment = mitigations.some((m) => m.type === "pull_payment");

  for (const call of calls) {
    if (call.isPushPayment && call.isInsideLoop) {
      if (!call.isWrappedInTryCatch && !hasPullPayment) {
        findings.push({
          id: "CP-DOS-002",
          dosRuleId: "CP-DOS-002",
          swcId: "SWC-113",
          title: "Push-Payment Pattern with Unexpected Revert Risk",
          description: `Function '${call.associatedFunction}' sends funds to '${call.targetExpression}' inside a loop. If any recipient is a contract that rejects payments (fallback without payable or intentional revert), the entire transaction reverts, preventing all honest users from receiving funds.`,
          recommendation: "Adopt the Pull-Payment pattern: credit user balances in an internal mapping and provide a separate withdraw() function for individual claims.",
          severity: "high",
          confidence: "high",
          category: "denial_of_service",
          file: filePath,
          line: call.line,
          snippet: getSnippet(source, call.line),
        });
      }
    }
  }

  return findings;
}

function checkCallFanOut(
  calls: CallFanOutAnalysis[],
  mitigations: MitigationEvidence[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];
  const hasFailureIsolation = mitigations.some((m) => m.type === "failure_isolation");

  for (const call of calls) {
    if (call.isInsideLoop && (call.callType === "high_level" || call.callType === "low_level_call")) {
      if (!call.isWrappedInTryCatch && !hasFailureIsolation && !call.isPushPayment) {
        findings.push({
          id: "CP-DOS-003",
          dosRuleId: "CP-DOS-003",
          title: "External Call Fan-Out in Loop Iteration",
          description: `Function '${call.associatedFunction}' makes repeated external calls to '${call.targetExpression}' inside a loop. External calls in loops create quadratic gas overhead and allow external contracts to grief execution.`,
          recommendation: "Avoid fan-out calls in loops. Batch calls using pull architectures, or isolate individual call failures using try/catch blocks.",
          severity: "medium",
          confidence: "medium",
          category: "gas_griefing",
          file: filePath,
          line: call.line,
          snippet: getSnippet(source, call.line),
        });
      }
    }
  }

  return findings;
}

function checkReturnBombs(
  calls: CallFanOutAnalysis[],
  loops: LoopBoundAnalysis[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];

  for (const call of calls) {
    if (call.callType === "low_level_call" && !call.hasReturndataSizeCheck && !call.hasGasLimit) {
      findings.push({
        id: "CP-DOS-004",
        dosRuleId: "CP-DOS-004",
        title: "Return Bomb / Unbounded Returndata Memory Expansion",
        description: `External low-level call to '${call.targetExpression}' does not cap returndata copying or check returndatasize. A malicious contract can return a massive byte payload, forcing quadratic memory expansion gas costs that exhaust caller gas.`,
        recommendation: "Use excessivelySafeCall or inline assembly to limit returndatacopy to the expected response size (e.g. max 32 bytes).",
        severity: "medium",
        confidence: "medium",
        category: "gas_griefing",
        file: filePath,
        line: call.line,
        snippet: getSnippet(source, call.line),
      });
    }
  }

  return findings;
}

function checkMassStorageDeletion(
  loops: LoopBoundAnalysis[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];

  for (const loop of loops) {
    if (loop.hasStorageDeletions && (loop.boundType === "storage_array_bounded" || loop.boundType === "unbounded")) {
      findings.push({
        id: "CP-DOS-005",
        dosRuleId: "CP-DOS-005",
        title: "Unbounded Storage Clearing / Mass Deletion",
        description: `Function '${loop.associatedFunction}' executes storage deletions ('delete') inside an unbounded loop. Because EIP-3529 limits gas refunds to at most 20% of tx gas, mass storage clearing can exceed the block gas limit and permanently brick state resets.`,
        recommendation: "Use incremental/paginated clearing or epoch/generation counters instead of deleting dynamic storage in a single transaction.",
        severity: "medium",
        confidence: "high",
        category: "unbounded_work",
        file: filePath,
        line: loop.line,
        snippet: getSnippet(source, loop.line),
      });
    }
  }

  return findings;
}

function checkInsufficientGasForwarding(
  calls: CallFanOutAnalysis[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];

  for (const call of calls) {
    if (call.callType === "low_level_call" && !call.hasGasLimit && call.isPushPayment) {
      findings.push({
        id: "CP-DOS-006",
        dosRuleId: "CP-DOS-006",
        title: "Insufficient Gas Forwarding / 63/64th Rule Griefing",
        description: `External call to '${call.targetExpression}' forwards all remaining gas subject to the 63/64th rule. A relayer or attacker can provide barely enough gas for the outer transaction, causing the inner call to fail silently or revert while consuming gas.`,
        recommendation: "Specify an explicit gas stipend or verify gasleft() >= REQUIRED_GAS before dispatching critical sub-calls.",
        severity: "medium",
        confidence: "medium",
        category: "gas_griefing",
        file: filePath,
        line: call.line,
        snippet: getSnippet(source, call.line),
      });
    }
  }

  return findings;
}

function checkBlockGasLimitDeadlock(
  loops: LoopBoundAnalysis[],
  mitigations: MitigationEvidence[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];
  const hasCheckpoint = mitigations.some((m) => m.type === "checkpoint_state_machine");

  for (const loop of loops) {
    if (loop.hasExternalCalls && loop.hasStateWrites && !loop.isCapped && !hasCheckpoint) {
      const fnLower = loop.associatedFunction.toLowerCase();
      if (
        fnLower.includes("execute") ||
        fnLower.includes("settle") ||
        fnLower.includes("liquidate") ||
        fnLower.includes("distribute") ||
        fnLower.includes("finalize")
      ) {
        findings.push({
          id: "CP-DOS-007",
          dosRuleId: "CP-DOS-007",
          title: "Single-Transaction Block Gas Limit Deadlock",
          description: `Critical lifecycle function '${loop.associatedFunction}' requires completing all state mutations and external calls in a single transaction. If the batch size grows, the transaction will perpetually exceed the block gas limit, freezing the protocol state machine.`,
          recommendation: "Implement checkpointed multi-transaction execution allowing permissionless partial progress.",
          severity: "high",
          confidence: "high",
          category: "denial_of_service",
          file: filePath,
          line: loop.line,
          snippet: getSnippet(source, loop.line),
        });
      }
    }
  }

  return findings;
}

function checkUnboundedRecursion(
  contractNode: any,
  _contractName: string,
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];

  visit(contractNode, {
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name;
      if (!fnName) return;

      let hasRecursiveCall = false;
      let hasDepthGuard = false;
      let recursiveCallLine = fnNode.loc?.start?.line || 1;

      visit(fnNode, {
        FunctionCall: (callNode: any) => {
          const callee = callNode.expression?.name;
          if (callee === fnName) {
            hasRecursiveCall = true;
            recursiveCallLine = callNode.loc?.start?.line || recursiveCallLine;
          }
          if (callNode.expression?.name === "require") {
            const cond = JSON.stringify(callNode.arguments);
            if (cond.includes("depth") || cond.includes("level")) {
              hasDepthGuard = true;
            }
          }
        },
      });

      if (hasRecursiveCall && !hasDepthGuard) {
        findings.push({
          id: "CP-DOS-008",
          dosRuleId: "CP-DOS-008",
          swcId: "SWC-128",
          title: "Unbounded Recursion Without Depth Guard",
          description: `Function '${fnName}' makes recursive calls to itself without an explicit recursion depth limit or stack guard. An attacker can trigger deep recursion to exhaust the 1024 EVM call stack depth limit or run out of gas.`,
          recommendation: "Convert recursion into an iterative loop with bounded iterations, or enforce an explicit depth counter: require(depth < MAX_DEPTH).",
          severity: "high",
          confidence: "high",
          category: "denial_of_service",
          file: filePath,
          line: recursiveCallLine,
          snippet: getSnippet(source, recursiveCallLine),
        });
      }
    },
  });

  return findings;
}

function checkArrayPoisoning(
  growths: ArrayGrowthAnalysis[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];

  for (const g of growths) {
    if (g.isPublicOrExternal && !g.hasAccessControl && !g.hasLengthCap && !g.hasRateLimitOrFee) {
      if (g.isIteratedInContract) {
        findings.push({
          id: "CP-DOS-009",
          dosRuleId: "CP-DOS-009",
          title: "Attacker-Controlled Array Growth / Storage Poisoning",
          description: `Unrestricted public function '${g.associatedFunction}' pushes elements to array '${g.arrayName}' without access control, length caps, or fees. An attacker can cheaply spam entries to bloat '${g.arrayName}', causing subsequent iterations in '${g.iteratingFunctions.join(", ")}' to exceed the block gas limit.`,
          recommendation: "Add length caps (require(arr.length < MAX)), deposit fees, or permissioned access to prevent unbounded array expansion.",
          severity: "medium",
          confidence: "high",
          category: "denial_of_service",
          file: filePath,
          line: g.line,
          snippet: getSnippet(source, g.line),
        });
      }
    }
  }

  return findings;
}

function checkBatchRevertPropagation(
  calls: CallFanOutAnalysis[],
  loops: LoopBoundAnalysis[],
  mitigations: MitigationEvidence[],
  source: string,
  filePath: string,
): DosFinding[] {
  const findings: DosFinding[] = [];
  const hasFailureIsolation = mitigations.some((m) => m.type === "failure_isolation");

  for (const loop of loops) {
    if (loop.hasExternalCalls && !hasFailureIsolation) {
      const fnLower = loop.associatedFunction.toLowerCase();
      if (fnLower.includes("batch") || fnLower.includes("multicall") || fnLower.includes("processall")) {
        findings.push({
          id: "CP-DOS-010",
          dosRuleId: "CP-DOS-010",
          title: "Revert Propagation in Critical Batch Operation",
          description: `Batch function '${loop.associatedFunction}' executes external operations in a loop without try/catch error isolation. A single failing sub-transaction causes the entire batch to revert, enabling griefing against other batched users.`,
          recommendation: "Wrap batch item execution in try/catch blocks and record failed item IDs in an event or mapping instead of reverting the whole transaction.",
          severity: "low",
          confidence: "medium",
          category: "gas_griefing",
          file: filePath,
          line: loop.line,
          snippet: getSnippet(source, loop.line),
        });
      }
    }
  }

  return findings;
}
