/**
 * @packageDocumentation
 * @chainproof/core — DoS & Gas-Griefing Mitigation Pattern Recognizer
 */

import { visit } from "../ast/parser";
import type { MitigationEvidence } from "./types";

export function detectMitigations(
  contractNode: any,
  contractName: string,
  source: string,
  _filePath: string,
): MitigationEvidence[] {
  if (
    !source.includes("withdraw") &&
    !source.includes("claim") &&
    !source.includes("offset") &&
    !source.includes("cursor") &&
    !source.includes("try") &&
    !source.includes("require")
  ) {
    return [];
  }

  const mitigations: MitigationEvidence[] = [];

  let hasPendingBalancesMapping = false;
  let hasWithdrawFunction = false;
  let withdrawFnLine = 1;

  // 1. Check for Pull Payment Pattern
  visit(contractNode, {
    StateVariableDeclaration: (decl: any) => {
      for (const v of decl.variables || []) {
        const name = v.name?.toLowerCase() || "";
        if (
          name.includes("pending") ||
          name.includes("withdrawal") ||
          name.includes("credit") ||
          name.includes("claimable")
        ) {
          if (v.typeName?.type === "Mapping") {
            hasPendingBalancesMapping = true;
          }
        }
      }
    },
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name?.toLowerCase() || "";
      if (
        fnName === "withdraw" ||
        fnName === "claim" ||
        fnName === "claimreward" ||
        fnName === "claimrewards" ||
        fnName === "withdrawfunds"
      ) {
        hasWithdrawFunction = true;
        withdrawFnLine = fnNode.loc?.start?.line || 1;
      }
    },
  });

  if (hasPendingBalancesMapping && hasWithdrawFunction) {
    mitigations.push({
      type: "pull_payment",
      description: "Pull-over-push payment pattern recognized: separate withdrawal/claim mechanism with pending balance tracking.",
      line: withdrawFnLine,
      confidence: "high",
      contract: contractName,
      functionName: "withdraw",
    });
  }

  // 2. Check per-function mitigations (Pagination, Capped Batches, Failure Isolation, Checkpoint State Machine)
  visit(contractNode, {
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name || (fnNode.isConstructor ? "constructor" : "fallback");
      const line = fnNode.loc?.start?.line || 1;

      // Extract parameter names
      const rawParams = Array.isArray(fnNode.parameters)
        ? fnNode.parameters
        : fnNode.parameters?.parameters || [];
      const paramNames = rawParams.map((p: any) => p.name?.toLowerCase() || "");

      // Pagination check (offset + limit)
      const hasOffset = paramNames.some((n: string) => n.includes("offset") || n.includes("cursor") || n.includes("start"));
      const hasLimit = paramNames.some((n: string) => n.includes("limit") || n.includes("count") || n.includes("pagesize") || n.includes("max"));

      if (hasOffset && hasLimit) {
        mitigations.push({
          type: "pagination",
          description: `Pagination pattern recognized in function '${fnName}': using offset and limit parameters to bound iteration.`,
          line,
          confidence: "high",
          contract: contractName,
          functionName: fnName,
        });
      }

      // Check try/catch (failure isolation) inside function
      let hasTryCatch = false;
      visit(fnNode, {
        TryStatement: () => {
          hasTryCatch = true;
        },
      });

      if (hasTryCatch) {
        mitigations.push({
          type: "failure_isolation",
          description: `Failure isolation recognized in function '${fnName}': external calls are wrapped in try/catch to prevent revert propagation.`,
          line,
          confidence: "high",
          contract: contractName,
          functionName: fnName,
        });
      }

      // Check batch caps (require(recipients.length <= MAX))
      let hasBatchCap = false;
      visit(fnNode, {
        FunctionCall: (callNode: any) => {
          const callee = callNode.expression?.name || callNode.expression?.memberName;
          if (callee === "require") {
            const cond = JSON.stringify(callNode.arguments);
            if (cond.includes(".length") && (cond.includes("<=") || cond.includes("<"))) {
              hasBatchCap = true;
            }
          }
        },
      });

      if (hasBatchCap) {
        mitigations.push({
          type: "capped_batch",
          description: `Capped batch pattern recognized in function '${fnName}': array length is bounded with explicit limit validation.`,
          line,
          confidence: "high",
          contract: contractName,
          functionName: fnName,
        });
      }

      // Check checkpoint state machine pattern (cursor / lastProcessedIndex update)
      let hasStateIndexUpdate = false;
      visit(fnNode, {
        BinaryOperation: (binNode: any) => {
          const leftStr = JSON.stringify(binNode.left);
          if (
            leftStr.includes("lastProcessed") ||
            leftStr.includes("nextIndex") ||
            leftStr.includes("currentIndex") ||
            leftStr.includes("cursor")
          ) {
            if (binNode.operator === "=" || binNode.operator === "+=") {
              hasStateIndexUpdate = true;
            }
          }
        },
      });

      if (hasStateIndexUpdate) {
        mitigations.push({
          type: "checkpoint_state_machine",
          description: `Checkpoint state-machine pattern recognized in function '${fnName}': processes items in chunks and persists progress across transactions.`,
          line,
          confidence: "medium",
          contract: contractName,
          functionName: fnName,
        });
      }
    },
  });

  return mitigations;
}
