/**
 * @packageDocumentation
 * @chainproof/core — External Call Fan-Out, Push-Payment & Return-Bomb Analyzer
 */

import { visit } from "../ast/parser";
import type { CallFanOutAnalysis } from "./types";

function extractExpressionString(node: any): string {
  if (!node) return "";
  if (node.type === "Identifier") return node.name || "";
  if (node.type === "NumberLiteral") return String(node.number || node.value || "");
  if (node.type === "MemberAccess") {
    return `${extractExpressionString(node.expression)}.${node.memberName}`;
  }
  if (node.type === "IndexAccess") {
    return `${extractExpressionString(node.base)}[${extractExpressionString(node.index)}]`;
  }
  if (node.type === "FunctionCall") {
    const callee = extractExpressionString(node.expression);
    const args = (node.arguments || []).map(extractExpressionString).join(", ");
    return `${callee}(${args})`;
  }
  if (node.type === "NameValueExpression") {
    return `${extractExpressionString(node.expression)}{${(node.arguments?.names || []).join(", ")}}`;
  }
  return "";
}

export function extractCallFanOuts(
  contractNode: any,
  contractName: string,
  source: string,
  _filePath: string,
): CallFanOutAnalysis[] {
  if (!source.includes("call") && !source.includes("transfer") && !source.includes("send")) {
    return [];
  }

  const callAnalyses: CallFanOutAnalysis[] = [];

  visit(contractNode, {
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name || (fnNode.isConstructor ? "constructor" : "fallback");

      interface Range {
        start: number;
        end: number;
        line: number;
      }

      const loopRanges: Range[] = [];
      const tryRanges: Range[] = [];

      visit(fnNode, {
        ForStatement: (forNode: any) => {
          const start = forNode.loc?.start?.line || 0;
          const end = forNode.loc?.end?.line || start;
          loopRanges.push({ start, end, line: start });
        },
        WhileStatement: (whileNode: any) => {
          const start = whileNode.loc?.start?.line || 0;
          const end = whileNode.loc?.end?.line || start;
          loopRanges.push({ start, end, line: start });
        },
        DoWhileStatement: (doWhileNode: any) => {
          const start = doWhileNode.loc?.start?.line || 0;
          const end = doWhileNode.loc?.end?.line || start;
          loopRanges.push({ start, end, line: start });
        },
        TryStatement: (tryNode: any) => {
          const start = tryNode.loc?.start?.line || 0;
          const end = tryNode.loc?.end?.line || start;
          tryRanges.push({ start, end, line: start });
        },
      });

      visit(fnNode, {
        FunctionCall: (callNode: any) => {
          const callLine = callNode.loc?.start?.line || 0;
          const enclosingLoop = loopRanges.find(
            (r) => callLine >= r.start && callLine <= r.end,
          );
          const isWrappedInTryCatch = tryRanges.some(
            (r) => callLine >= r.start && callLine <= r.end,
          );

          const analysis = inspectFunctionCall(
            callNode,
            !!enclosingLoop,
            enclosingLoop?.line,
            isWrappedInTryCatch,
            fnName,
            contractName,
          );
          if (analysis) {
            callAnalyses.push(analysis);
          }
        },
      });
    },
  });

  return callAnalyses;
}

function inspectFunctionCall(
  callNode: any,
  isInsideLoop: boolean,
  loopLine: number | undefined,
  isWrappedInTryCatch: boolean,
  fnName: string,
  contractName: string,
): CallFanOutAnalysis | null {
  const expr = callNode.expression;
  if (!expr) return null;

  const line = callNode.loc?.start?.line || 1;
  const exprStr = extractExpressionString(expr);

  // 1. Check recipient.transfer(...) or recipient.send(...)
  if (expr.type === "MemberAccess") {
    const member = expr.memberName;
    const targetExpr = extractExpressionString(expr.expression);

    if (member === "transfer" && callNode.arguments?.length === 1) {
      return {
        line,
        callType: "value_transfer",
        targetExpression: targetExpr,
        valueExpression: extractExpressionString(callNode.arguments[0]),
        isInsideLoop,
        loopLine,
        hasRevertCheck: true, // transfer automatically reverts on failure
        isWrappedInTryCatch,
        hasGasLimit: true, // transfer is capped at 2300 gas
        gasLimitExpression: "2300",
        hasReturndataSizeCheck: true,
        isPushPayment: true,
        associatedFunction: fnName,
        associatedContract: contractName,
      };
    }

    if (member === "send" && callNode.arguments?.length === 1) {
      return {
        line,
        callType: "value_transfer",
        targetExpression: targetExpr,
        valueExpression: extractExpressionString(callNode.arguments[0]),
        isInsideLoop,
        loopLine,
        hasRevertCheck: false, // send returns bool
        isWrappedInTryCatch,
        hasGasLimit: true,
        gasLimitExpression: "2300",
        hasReturndataSizeCheck: true,
        isPushPayment: true,
        associatedFunction: fnName,
        associatedContract: contractName,
      };
    }
  }

  // 2. Check recipient.call{value: ...}("") or recipient.call(...)
  if (expr.type === "NameValueExpression" || exprStr.includes(".call{") || exprStr.endsWith(".call")) {
    let target = "";
    let valueExpr: string | undefined = undefined;
    let gasLimit: string | undefined = undefined;
    let hasGas = false;

    if (expr.type === "NameValueExpression") {
      target = extractExpressionString(expr.expression);
      if (expr.arguments) {
        const names = expr.arguments.names || [];
        const args = expr.arguments.arguments || [];
        for (let i = 0; i < names.length; i++) {
          if (names[i] === "value") {
            valueExpr = extractExpressionString(args[i]);
          }
          if (names[i] === "gas") {
            hasGas = true;
            gasLimit = extractExpressionString(args[i]);
          }
        }
      }
    } else if (expr.type === "MemberAccess" && expr.memberName === "call") {
      target = extractExpressionString(expr.expression);
    }

    const isValueTransfer = !!valueExpr || exprStr.includes("value");

    return {
      line,
      callType: isValueTransfer ? "value_transfer" : "low_level_call",
      targetExpression: target || exprStr,
      valueExpression: valueExpr,
      isInsideLoop,
      loopLine,
      hasRevertCheck: false,
      isWrappedInTryCatch,
      hasGasLimit: hasGas,
      gasLimitExpression: gasLimit,
      hasReturndataSizeCheck: false,
      isPushPayment: isValueTransfer,
      associatedFunction: fnName,
      associatedContract: contractName,
    };
  }

  // 3. High-level external call
  if (expr.type === "MemberAccess" && expr.expression?.type !== "Identifier" && expr.memberName !== "push") {
    return {
      line,
      callType: "high_level",
      targetExpression: extractExpressionString(expr.expression),
      isInsideLoop,
      loopLine,
      hasRevertCheck: true,
      isWrappedInTryCatch,
      hasGasLimit: false,
      hasReturndataSizeCheck: false,
      isPushPayment: false,
      associatedFunction: fnName,
      associatedContract: contractName,
    };
  }

  return null;
}
