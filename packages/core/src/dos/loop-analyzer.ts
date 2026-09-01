/**
 * @packageDocumentation
 * @chainproof/core — AST Loop Bounds & Work Complexity Analyzer
 */

import { visit } from "../ast/parser";
import type { LoopBoundAnalysis, LoopBoundType } from "./types";

interface VariableScope {
  stateVariables: Set<string>;
  storageArrays: Set<string>;
  constantVariables: Map<string, number>;
  functionParameters: Set<string>;
  parameterCaps: Map<string, number>;
}

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
  if (node.type === "BinaryOperation") {
    return `${extractExpressionString(node.left)} ${node.operator} ${extractExpressionString(node.right)}`;
  }
  if (node.type === "UnaryOperation") {
    return node.isPrefix
      ? `${node.operator}${extractExpressionString(node.subExpression)}`
      : `${extractExpressionString(node.subExpression)}${node.operator}`;
  }
  if (node.type === "FunctionCall") {
    const callee = extractExpressionString(node.expression);
    const args = (node.arguments || []).map(extractExpressionString).join(", ");
    return `${callee}(${args})`;
  }
  return "";
}

function analyzeContractScope(contractNode: any): VariableScope {
  const stateVariables = new Set<string>();
  const storageArrays = new Set<string>();
  const constantVariables = new Map<string, number>();

  visit(contractNode, {
    StateVariableDeclaration: (decl: any) => {
      for (const v of decl.variables || []) {
        if (v.name) {
          stateVariables.add(v.name);
          const typeStr = v.typeName?.name || v.typeName?.namePath || "";
          if (v.typeName?.type === "ArrayTypeName" || typeStr.endsWith("[]")) {
            storageArrays.add(v.name);
          }
          if (v.isDeclaredConst || v.isImmutable) {
            if (v.expression?.type === "NumberLiteral") {
              const num = Number(v.expression.number || v.expression.value);
              if (Number.isFinite(num)) {
                constantVariables.set(v.name, num);
              }
            }
          }
        }
      }
    },
  });

  return {
    stateVariables,
    storageArrays,
    constantVariables,
    functionParameters: new Set(),
    parameterCaps: new Map(),
  };
}

export function extractLoopBounds(
  contractNode: any,
  contractName: string,
  source: string,
  _filePath: string,
): LoopBoundAnalysis[] {
  if (!source.includes("for") && !source.includes("while") && !source.includes("do")) {
    return [];
  }

  const baseScope = analyzeContractScope(contractNode);
  const loopAnalyses: LoopBoundAnalysis[] = [];

  visit(contractNode, {
    FunctionDefinition: (fnNode: any) => {
      const fnName = fnNode.name || (fnNode.isConstructor ? "constructor" : "fallback");
      const fnScope: VariableScope = {
        stateVariables: new Set(baseScope.stateVariables),
        storageArrays: new Set(baseScope.storageArrays),
        constantVariables: new Map(baseScope.constantVariables),
        functionParameters: new Set(),
        parameterCaps: new Map(),
      };

      // Collect parameters
      const rawParams = Array.isArray(fnNode.parameters)
        ? fnNode.parameters
        : fnNode.parameters?.parameters || [];
      for (const p of rawParams) {
        if (p.name) fnScope.functionParameters.add(p.name);
      }

      // Single pass over function AST for parameter caps and loops
      visit(fnNode, {
        FunctionCall: (callNode: any) => {
          const callee = extractExpressionString(callNode.expression);
          if (callee === "require" && callNode.arguments && callNode.arguments.length > 0) {
            const cond = callNode.arguments[0];
            if (cond.type === "BinaryOperation" && (cond.operator === "<=" || cond.operator === "<")) {
              const left = extractExpressionString(cond.left);
              const right = cond.right;
              if (fnScope.functionParameters.has(left) && right.type === "NumberLiteral") {
                const cap = Number(right.number || right.value);
                if (Number.isFinite(cap)) {
                  fnScope.parameterCaps.set(left, cap);
                }
              }
            }
          }
        },
        ForStatement: (forNode: any) => {
          const analysis = analyzeLoop(
            forNode,
            "for",
            fnScope,
            fnName,
            contractName,
            source,
          );
          loopAnalyses.push(analysis);
        },
        WhileStatement: (whileNode: any) => {
          const analysis = analyzeLoop(
            whileNode,
            "while",
            fnScope,
            fnName,
            contractName,
            source,
          );
          loopAnalyses.push(analysis);
        },
        DoWhileStatement: (doWhileNode: any) => {
          const analysis = analyzeLoop(
            doWhileNode,
            "do-while",
            fnScope,
            fnName,
            contractName,
            source,
          );
          loopAnalyses.push(analysis);
        },
      });
    },
  });

  return loopAnalyses;
}

function analyzeLoop(
  loopNode: any,
  loopType: "for" | "while" | "do-while",
  scope: VariableScope,
  fnName: string,
  contractName: string,
  _source: string,
): LoopBoundAnalysis {
  const line = loopNode.loc?.start?.line || 1;
  const cond = loopNode.conditionExpression || loopNode.condition;
  const conditionExpr = extractExpressionString(cond);

  let boundType: LoopBoundType = "unknown";
  let boundExpression: string | undefined = undefined;
  let targetVariable: string | undefined = undefined;
  let isCapped = false;
  let maxIterationsEstimate: number | undefined = undefined;
  let uncertaintyReason: string | undefined = undefined;

  // Classify bound
  if (cond) {
    if (cond.type === "BinaryOperation" && (cond.operator === "<" || cond.operator === "<=" || cond.operator === "!=")) {
      const rightStr = extractExpressionString(cond.right);
      boundExpression = rightStr;

      // Check if right side is a storage array .length (e.g. holders.length)
      if (rightStr.endsWith(".length")) {
        const arrayBase = rightStr.slice(0, -7);
        targetVariable = arrayBase;
        if (scope.storageArrays.has(arrayBase) || scope.stateVariables.has(arrayBase)) {
          boundType = "storage_array_bounded";
          isCapped = false;
          uncertaintyReason = `Loop bound derives from dynamic storage array '${arrayBase}.length' which can grow arbitrarily.`;
        } else if (scope.functionParameters.has(arrayBase)) {
          boundType = "parameter_bounded";
          const cap = scope.parameterCaps.get(arrayBase);
          if (cap !== undefined) {
            isCapped = true;
            maxIterationsEstimate = cap;
          } else {
            isCapped = false;
            uncertaintyReason = `Calldata array '${arrayBase}' length is not explicitly bounded by a require statement.`;
          }
        } else {
          boundType = "storage_array_bounded";
        }
      } else if (scope.constantVariables.has(rightStr)) {
        boundType = "constant_bounded";
        isCapped = true;
        maxIterationsEstimate = scope.constantVariables.get(rightStr);
      } else if (cond.right.type === "NumberLiteral") {
        boundType = "constant_bounded";
        isCapped = true;
        maxIterationsEstimate = Number(cond.right.number || cond.right.value);
      } else if (scope.functionParameters.has(rightStr)) {
        boundType = "parameter_bounded";
        targetVariable = rightStr;
        const cap = scope.parameterCaps.get(rightStr);
        if (cap !== undefined) {
          isCapped = true;
          maxIterationsEstimate = cap;
        } else {
          isCapped = false;
          uncertaintyReason = `Loop parameter '${rightStr}' lacks explicit upper bound assertion.`;
        }
      } else if (scope.stateVariables.has(rightStr)) {
        boundType = "state_variable_bounded";
        targetVariable = rightStr;
        isCapped = false;
        uncertaintyReason = `State variable '${rightStr}' can be manipulated across transactions.`;
      } else if (conditionExpr.includes("offset") && conditionExpr.includes("limit")) {
        boundType = "paginated";
        isCapped = true;
      }
    } else if (cond.type === "BooleanLiteral" && cond.value === true) {
      boundType = "unbounded";
      isCapped = false;
      uncertaintyReason = "Infinite loop condition (while true).";
    }
  }

  // Analyze operations inside loop body
  let hasExternalCalls = false;
  let externalCallsCount = 0;
  let hasStateWrites = false;
  let hasStorageDeletions = false;
  let hasReturndataCopying = false;
  let hasEventEmissions = false;
  let hasBreakOrReturn = false;

  const loopBody = loopNode.body || loopNode.loopExpression || loopNode;

  visit(loopBody, {
    FunctionCall: (callNode: any) => {
      const callee = extractExpressionString(callNode.expression);
      if (
        callee.endsWith(".call") ||
        callee.endsWith(".delegatecall") ||
        callee.endsWith(".staticcall") ||
        callee.endsWith(".transfer") ||
        callee.endsWith(".send") ||
        (callNode.expression?.type === "MemberAccess" && callNode.expression.expression?.type === "FunctionCall")
      ) {
        hasExternalCalls = true;
        externalCallsCount++;
      } else if (callNode.expression?.type === "MemberAccess") {
        const member = callNode.expression.memberName;
        if (member === "push" || member === "pop") {
          hasStateWrites = true;
        }
      }
    },
    BinaryOperation: (binNode: any) => {
      if (
        binNode.operator === "=" ||
        binNode.operator === "+=" ||
        binNode.operator === "-=" ||
        binNode.operator === "*="
      ) {
        hasStateWrites = true;
      }
    },
    UnaryOperation: (unNode: any) => {
      if (unNode.operator === "delete") {
        hasStorageDeletions = true;
        hasStateWrites = true;
      } else if (unNode.operator === "++" || unNode.operator === "--") {
        hasStateWrites = true;
      }
    },
    EmitStatement: () => {
      hasEventEmissions = true;
    },
    BreakStatement: () => {
      hasBreakOrReturn = true;
    },
    ReturnStatement: () => {
      hasBreakOrReturn = true;
    },
    InlineAssemblyStatement: (asmNode: any) => {
      const asmStr = JSON.stringify(asmNode);
      if (asmStr.includes("returndatacopy") || asmStr.includes("returndatasize")) {
        hasReturndataCopying = true;
      }
      if (asmStr.includes("call") || asmStr.includes("delegatecall") || asmStr.includes("staticcall")) {
        hasExternalCalls = true;
        externalCallsCount++;
      }
      if (asmStr.includes("sstore")) {
        hasStateWrites = true;
      }
    },
  });

  return {
    loopType,
    line,
    conditionExpression: conditionExpr,
    boundType,
    boundExpression,
    targetVariable,
    isCapped,
    maxIterationsEstimate,
    uncertaintyReason,
    hasExternalCalls,
    externalCallsCount,
    hasStateWrites,
    hasStorageDeletions,
    hasReturndataCopying,
    hasEventEmissions,
    hasBreakOrReturn,
    associatedFunction: fnName,
    associatedContract: contractName,
  };
}
